"""
Tests for passkeys and recovery codes (improvement #5).

WHY THESE TESTS ARE BUILT THE WAY THEY ARE
The WebAuthn server here is hand-written (no library is available in this
environment), so asserting that a valid credential is accepted proves very
little on its own — a verifier that accepts everything also passes that test.
What matters is the *negative* space, so this file builds a REAL credential with
`cryptography` — genuine P-256 and RSA keys, genuine CBOR, genuine signatures —
and then breaks exactly one thing at a time:

    wrong signature · wrong challenge · wrong origin · wrong RP ID ·
    wrong ceremony type · absent user presence · replayed challenge ·
    another user's credential · a regressed signature counter

Each must be refused, and each has its own test, because a single "invalid input
is rejected" test cannot tell you *which* check did the rejecting.

The CBOR encoder below is test-only: it exists to produce authentic input for
the decoder, which is the component under test.
"""
import hashlib
import json
import os
import struct

import pytest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from engine import db, recovery_codes, webauthn
from engine.cbor_min import CborError, loads, loads_prefix
from engine.webauthn import (WebAuthnError, b64url_decode, b64url_encode,
                             config)

RP_ID = "localhost"
ORIGIN = "http://localhost:5000"


# =============================================================================
# Test-only CBOR encoder — produces authentic input for the decoder under test
# =============================================================================
def cbor_encode(value) -> bytes:
    def head(major: int, arg: int) -> bytes:
        if arg < 24:
            return bytes([major << 5 | arg])
        if arg < 0x100:
            return bytes([major << 5 | 24, arg])
        if arg < 0x10000:
            return bytes([major << 5 | 25]) + struct.pack(">H", arg)
        if arg < 0x100000000:
            return bytes([major << 5 | 26]) + struct.pack(">I", arg)
        return bytes([major << 5 | 27]) + struct.pack(">Q", arg)

    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if value is None:
        return bytes([0xF6])
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes):
        return head(2, len(value)) + value
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list):
        return head(4, len(value)) + b"".join(cbor_encode(v) for v in value)
    if isinstance(value, dict):
        out = head(5, len(value))
        for k, v in value.items():
            out += cbor_encode(k) + cbor_encode(v)
        return out
    raise TypeError(f"cannot encode {type(value)}")


# =============================================================================
# A synthetic authenticator
# =============================================================================
class FakeAuthenticator:
    """A software authenticator good enough to produce real, valid ceremonies."""

    def __init__(self, algorithm: str = "es256", rp_id: str = RP_ID):
        self.rp_id = rp_id
        self.algorithm = algorithm
        self.credential_id = os.urandom(32)
        self.sign_count = 0
        if algorithm == "es256":
            self.key = ec.generate_private_key(ec.SECP256R1())
        else:
            self.key = rsa.generate_private_key(public_exponent=65537,
                                                key_size=2048)

    # --- key material ---------------------------------------------------------
    def cose_key(self) -> dict:
        if self.algorithm == "es256":
            nums = self.key.public_key().public_numbers()
            return {1: 2, 3: -7, -1: 1,
                    -2: nums.x.to_bytes(32, "big"),
                    -3: nums.y.to_bytes(32, "big")}
        nums = self.key.public_key().public_numbers()
        return {1: 3, 3: -257,
                -1: nums.n.to_bytes((nums.n.bit_length() + 7) // 8, "big"),
                -2: nums.e.to_bytes((nums.e.bit_length() + 7) // 8, "big")}

    def sign(self, data: bytes) -> bytes:
        if self.algorithm == "es256":
            return self.key.sign(data, ec.ECDSA(hashes.SHA256()))
        return self.key.sign(data, padding.PKCS1v15(), hashes.SHA256())

    # --- ceremony pieces ------------------------------------------------------
    def client_data(self, ceremony: str, challenge: bytes,
                    origin: str = ORIGIN) -> bytes:
        return json.dumps({"type": ceremony,
                           "challenge": b64url_encode(challenge),
                           "origin": origin,
                           "crossOrigin": False}).encode("utf-8")

    def auth_data(self, *, attested: bool, flags: int | None = None,
                  rp_id: str | None = None, sign_count: int | None = None) -> bytes:
        rp_hash = hashlib.sha256((rp_id or self.rp_id).encode()).digest()
        if flags is None:
            flags = 0x01 | 0x04 | (0x40 if attested else 0)   # UP | UV | AT
        count = self.sign_count if sign_count is None else sign_count
        data = rp_hash + bytes([flags]) + struct.pack(">I", count)
        if attested:
            data += (b"\x00" * 16
                     + struct.pack(">H", len(self.credential_id))
                     + self.credential_id
                     + cbor_encode(self.cose_key()))
        return data

    def make_credential(self, challenge: bytes, *, origin: str = ORIGIN,
                        rp_id: str | None = None, flags: int | None = None,
                        ceremony: str = "webauthn.create") -> dict:
        client = self.client_data(ceremony, challenge, origin)
        auth = self.auth_data(attested=True, flags=flags, rp_id=rp_id)
        attestation = cbor_encode({"fmt": "none", "attStmt": {}, "authData": auth})
        return {"id": b64url_encode(self.credential_id),
                "response": {"clientDataJSON": b64url_encode(client),
                             "attestationObject": b64url_encode(attestation)}}

    def get_assertion(self, challenge: bytes, *, origin: str = ORIGIN,
                      rp_id: str | None = None, flags: int | None = None,
                      ceremony: str = "webauthn.get",
                      sign_count: int | None = None,
                      corrupt_signature: bool = False) -> dict:
        self.sign_count += 1
        client = self.client_data(ceremony, challenge, origin)
        auth = self.auth_data(attested=False, flags=flags, rp_id=rp_id,
                              sign_count=sign_count)
        signature = self.sign(auth + hashlib.sha256(client).digest())
        if corrupt_signature:
            signature = os.urandom(len(signature))
        return {"id": b64url_encode(self.credential_id),
                "response": {"clientDataJSON": b64url_encode(client),
                             "authenticatorData": b64url_encode(auth),
                             "signature": b64url_encode(signature)}}


@pytest.fixture()
def subscriber(user_factory):
    user, _pw = user_factory(profile_id="aarav_safe")
    return user


@pytest.fixture()
def authenticator():
    return FakeAuthenticator()


def _register(user, auth_device) -> dict:
    options = webauthn.registration_options(user)
    challenge = b64url_decode(options["publicKey"]["challenge"])
    credential = auth_device.make_credential(challenge)
    return webauthn.register(user, options["handle"], credential, label="Test key")


# =============================================================================
# CBOR decoder
# =============================================================================
class TestCborDecoder:

    @pytest.mark.parametrize("value", [
        0, 1, 23, 24, 255, 256, 65535, 65536, -1, -24, -1000,
        b"", b"\x00\xff", "hello", "नेपाली", [], [1, 2, 3],
        {}, {1: 2, -7: b"x"}, {"a": [1, {"b": 2}]}, True, False, None,
    ])
    def test_round_trips_every_supported_type(self, value):
        assert loads(cbor_encode(value)) == value

    def test_trailing_bytes_are_rejected(self):
        with pytest.raises(CborError, match="trailing"):
            loads(cbor_encode(1) + b"\xff")

    def test_loads_prefix_reports_the_length_consumed(self):
        encoded = cbor_encode({1: 2})
        value, used = loads_prefix(encoded + b"EXTRA")
        assert value == {1: 2}
        assert used == len(encoded)

    def test_truncated_input_is_rejected(self):
        with pytest.raises(CborError, match="truncated"):
            loads(cbor_encode(b"12345")[:-2])

    def test_indefinite_length_is_rejected(self):
        with pytest.raises(CborError, match="indefinite"):
            loads(bytes([0x5F, 0x41, 0x61, 0xFF]))

    def test_duplicate_map_keys_are_rejected(self):
        """Two parsers disagreeing about one message is a signature-bypass shape."""
        payload = bytes([0xA2]) + cbor_encode(1) + cbor_encode(1) \
                  + cbor_encode(1) + cbor_encode(2)
        with pytest.raises(CborError, match="duplicate"):
            loads(payload)

    def test_deep_nesting_is_rejected(self):
        payload = b"\x81" * 100 + b"\x00"
        with pytest.raises(CborError, match="too deep"):
            loads(payload)

    def test_an_oversized_declared_string_cannot_allocate(self):
        """A 4 GB length header must fail on the limit, not on memory."""
        header = bytes([0x02 << 5 | 26]) + struct.pack(">I", 4_000_000_000)
        with pytest.raises(CborError, match="too long"):
            loads(header)

    def test_non_bytes_input_is_rejected(self):
        with pytest.raises(CborError):
            loads("not bytes")                     # type: ignore[arg-type]


# =============================================================================
# Registration
# =============================================================================
class TestRegistration:

    def test_a_valid_es256_credential_registers(self, subscriber, authenticator):
        result = _register(subscriber, authenticator)
        assert result["credential_id"]
        assert result["attestation_verified"] is False   # stated, not implied
        assert len(webauthn.list_credentials(subscriber["id"])) == 1

    def test_a_valid_rs256_credential_registers(self, subscriber):
        result = _register(subscriber, FakeAuthenticator(algorithm="rs256"))
        assert result["credential_id"]

    def test_a_wrong_challenge_is_refused(self, subscriber, authenticator):
        options = webauthn.registration_options(subscriber)
        credential = authenticator.make_credential(os.urandom(32))   # not ours
        with pytest.raises(WebAuthnError, match="challenge did not match"):
            webauthn.register(subscriber, options["handle"], credential)

    def test_a_wrong_origin_is_refused(self, subscriber, authenticator):
        options = webauthn.registration_options(subscriber)
        challenge = b64url_decode(options["publicKey"]["challenge"])
        credential = authenticator.make_credential(
            challenge, origin="https://evil.example.com")
        with pytest.raises(WebAuthnError, match="origin"):
            webauthn.register(subscriber, options["handle"], credential)

    def test_a_wrong_rp_id_is_refused(self, subscriber):
        device = FakeAuthenticator(rp_id="attacker.example.com")
        options = webauthn.registration_options(subscriber)
        challenge = b64url_decode(options["publicKey"]["challenge"])
        credential = device.make_credential(challenge, rp_id="attacker.example.com")
        with pytest.raises(WebAuthnError, match="different site"):
            webauthn.register(subscriber, options["handle"], credential)

    def test_a_get_ceremony_cannot_be_replayed_as_a_create(self, subscriber,
                                                           authenticator):
        options = webauthn.registration_options(subscriber)
        challenge = b64url_decode(options["publicKey"]["challenge"])
        credential = authenticator.make_credential(challenge,
                                                   ceremony="webauthn.get")
        with pytest.raises(WebAuthnError, match="wrong ceremony type"):
            webauthn.register(subscriber, options["handle"], credential)

    def test_absent_user_presence_is_refused(self, subscriber, authenticator):
        options = webauthn.registration_options(subscriber)
        challenge = b64url_decode(options["publicKey"]["challenge"])
        credential = authenticator.make_credential(challenge, flags=0x40)  # AT only
        with pytest.raises(WebAuthnError, match="user presence"):
            webauthn.register(subscriber, options["handle"], credential)

    def test_a_challenge_is_single_use(self, subscriber, authenticator):
        options = webauthn.registration_options(subscriber)
        challenge = b64url_decode(options["publicKey"]["challenge"])
        webauthn.register(subscriber, options["handle"],
                          authenticator.make_credential(challenge))
        with pytest.raises(WebAuthnError, match="expired"):
            webauthn.register(subscriber, options["handle"],
                              authenticator.make_credential(challenge))

    def test_another_users_challenge_is_refused(self, subscriber, user_factory,
                                                authenticator):
        other, _pw = user_factory()
        options = webauthn.registration_options(other)
        challenge = b64url_decode(options["publicKey"]["challenge"])
        with pytest.raises(WebAuthnError, match="another account"):
            webauthn.register(subscriber, options["handle"],
                              authenticator.make_credential(challenge))

    def test_the_same_passkey_cannot_be_registered_twice(self, subscriber,
                                                         authenticator):
        _register(subscriber, authenticator)
        with pytest.raises(WebAuthnError, match="already registered"):
            _register(subscriber, authenticator)

    def test_a_malformed_attestation_object_is_refused(self, subscriber):
        options = webauthn.registration_options(subscriber)
        challenge = b64url_decode(options["publicKey"]["challenge"])
        device = FakeAuthenticator()
        credential = device.make_credential(challenge)
        credential["response"]["attestationObject"] = b64url_encode(b"\xff\xff\xff")
        with pytest.raises(WebAuthnError, match="attestation object"):
            webauthn.register(subscriber, options["handle"], credential)

    def test_registration_options_exclude_existing_credentials(self, subscriber,
                                                               authenticator):
        _register(subscriber, authenticator)
        options = webauthn.registration_options(subscriber)
        assert len(options["publicKey"]["excludeCredentials"]) == 1

    def test_the_user_handle_is_not_the_email(self, subscriber):
        """A user handle can be synced to a vendor cloud; it must be opaque."""
        options = webauthn.registration_options(subscriber)
        handle = options["publicKey"]["user"]["id"]
        assert subscriber["email"] not in b64url_decode(handle).decode(
            "utf-8", "ignore")


# =============================================================================
# Authentication — one broken thing at a time
# =============================================================================
class TestAuthentication:

    @pytest.fixture()
    def enrolled(self, subscriber, authenticator):
        _register(subscriber, authenticator)
        return subscriber, authenticator

    def _assert_options(self, user=None):
        options = webauthn.authentication_options(user)
        return options["handle"], b64url_decode(options["publicKey"]["challenge"])

    def test_a_valid_assertion_authenticates(self, enrolled):
        user, device = enrolled
        handle, challenge = self._assert_options(user)
        result = webauthn.authenticate(handle, device.get_assertion(challenge))
        assert result["user_id"] == user["id"]
        assert result["clone_warning"] is False

    def test_an_rs256_assertion_authenticates(self, subscriber):
        device = FakeAuthenticator(algorithm="rs256")
        _register(subscriber, device)
        handle, challenge = self._assert_options(subscriber)
        assert webauthn.authenticate(
            handle, device.get_assertion(challenge))["user_id"] == subscriber["id"]

    def test_a_corrupt_signature_is_refused(self, enrolled):
        _user, device = enrolled
        handle, challenge = self._assert_options()
        with pytest.raises(WebAuthnError, match="signature verification failed"):
            webauthn.authenticate(
                handle, device.get_assertion(challenge, corrupt_signature=True))

    def test_a_signature_from_a_different_key_is_refused(self, enrolled):
        """The core forgery test: right credential id, wrong private key."""
        _user, device = enrolled
        impostor = FakeAuthenticator()
        impostor.credential_id = device.credential_id
        handle, challenge = self._assert_options()
        with pytest.raises(WebAuthnError, match="signature verification failed"):
            webauthn.authenticate(handle, impostor.get_assertion(challenge))

    def test_a_replayed_challenge_is_refused(self, enrolled):
        _user, device = enrolled
        handle, challenge = self._assert_options()
        assertion = device.get_assertion(challenge)
        webauthn.authenticate(handle, assertion)
        with pytest.raises(WebAuthnError, match="expired"):
            webauthn.authenticate(handle, assertion)

    def test_a_challenge_from_another_ceremony_is_refused(self, enrolled):
        _user, device = enrolled
        handle, challenge = self._assert_options()
        with pytest.raises(WebAuthnError, match="wrong ceremony type"):
            webauthn.authenticate(
                handle, device.get_assertion(challenge, ceremony="webauthn.create"))

    def test_a_wrong_origin_is_refused(self, enrolled):
        _user, device = enrolled
        handle, challenge = self._assert_options()
        with pytest.raises(WebAuthnError, match="origin"):
            webauthn.authenticate(
                handle, device.get_assertion(challenge, origin="https://evil.test"))

    def test_a_wrong_rp_id_is_refused(self, enrolled):
        _user, device = enrolled
        handle, challenge = self._assert_options()
        with pytest.raises(WebAuthnError, match="different site"):
            webauthn.authenticate(
                handle, device.get_assertion(challenge, rp_id="evil.test"))

    def test_absent_user_presence_is_refused(self, enrolled):
        _user, device = enrolled
        handle, challenge = self._assert_options()
        with pytest.raises(WebAuthnError, match="user presence"):
            webauthn.authenticate(handle, device.get_assertion(challenge, flags=0x00))

    def test_an_unregistered_credential_is_refused(self):
        stranger = FakeAuthenticator()
        handle, challenge = self._assert_options()
        with pytest.raises(WebAuthnError, match="not registered"):
            webauthn.authenticate(handle, stranger.get_assertion(challenge))

    def test_a_credential_belonging_to_another_account_is_refused(
            self, enrolled, user_factory):
        _user, device = enrolled
        other, _pw = user_factory()
        handle, challenge = self._assert_options(other)
        with pytest.raises(WebAuthnError, match="different account"):
            webauthn.authenticate(handle, device.get_assertion(challenge))

    def test_a_regressed_signature_counter_raises_a_clone_warning(self, enrolled):
        user, device = enrolled
        handle, challenge = self._assert_options(user)
        webauthn.authenticate(handle, device.get_assertion(challenge, sign_count=10))
        handle, challenge = self._assert_options(user)
        result = webauthn.authenticate(
            handle, device.get_assertion(challenge, sign_count=4))
        assert result["clone_warning"] is True
        alert = db.query_one(
            "SELECT message FROM alerts WHERE user_id = ? ORDER BY id DESC LIMIT 1",
            (user["id"],))
        assert "cloned" in alert["message"]

    def test_a_constant_zero_counter_is_not_treated_as_a_clone(self, subscriber):
        """Synced passkeys legitimately report 0 forever; they must still work."""
        device = FakeAuthenticator()
        _register(subscriber, device)
        for _ in range(3):
            handle, challenge = self._assert_options(subscriber)
            result = webauthn.authenticate(
                handle, device.get_assertion(challenge, sign_count=0))
            assert result["clone_warning"] is False


# =============================================================================
# Management and posture
# =============================================================================
class TestManagement:

    def test_a_subscriber_can_remove_their_own_passkey(self, subscriber,
                                                       authenticator):
        _register(subscriber, authenticator)
        row = webauthn.list_credentials(subscriber["id"])[0]
        assert webauthn.delete_credential(subscriber["id"], row["id"]) is True
        assert webauthn.list_credentials(subscriber["id"]) == []

    def test_a_subscriber_cannot_remove_someone_elses(self, subscriber,
                                                      authenticator, user_factory):
        _register(subscriber, authenticator)
        row = webauthn.list_credentials(subscriber["id"])[0]
        other, _pw = user_factory()
        assert webauthn.delete_credential(other["id"], row["id"]) is False
        assert len(webauthn.list_credentials(subscriber["id"])) == 1

    def test_posture_warns_when_every_factor_depends_on_the_phone(self, subscriber):
        posture = webauthn.posture(subscriber["id"])
        assert posture["sim_swap_resistant"] is False
        assert "SIM swap" in posture["advice"]

    def test_posture_clears_once_a_passkey_exists(self, subscriber, authenticator):
        _register(subscriber, authenticator)
        posture = webauthn.posture(subscriber["id"])
        assert posture["sim_swap_resistant"] is True
        assert posture["passkeys"] == 1

    def test_posture_states_its_limitations(self, subscriber):
        limits = " ".join(webauthn.posture(subscriber["id"])["limitations"])
        assert "Attestation is not verified" in limits
        assert "HTTPS" in limits

    def test_origins_are_an_exact_allowlist(self):
        assert "http://localhost:5000" in config()["origins"]
        assert all(o.startswith("http") for o in config()["origins"])


# =============================================================================
# Recovery codes
# =============================================================================
class TestRecoveryCodes:

    def test_a_fresh_set_is_generated_and_counted(self, subscriber):
        codes = recovery_codes.generate_for_user(subscriber["id"])
        assert len(codes) == recovery_codes.CODE_COUNT
        assert recovery_codes.remaining(subscriber["id"]) == len(codes)

    def test_plaintext_codes_are_never_stored(self, subscriber):
        codes = recovery_codes.generate_for_user(subscriber["id"])
        rows = db.query_all("SELECT code_hash FROM recovery_codes WHERE user_id = ?",
                            (subscriber["id"],))
        stored = " ".join(r["code_hash"] for r in rows)
        for code in codes:
            assert code not in stored
            assert recovery_codes.normalise(code) not in stored
        assert all(r["code_hash"].startswith("pbkdf2_sha256$") for r in rows)

    def test_a_valid_code_is_accepted_once(self, subscriber):
        codes = recovery_codes.generate_for_user(subscriber["id"])
        assert recovery_codes.consume(subscriber["id"], codes[0]) is True
        assert recovery_codes.consume(subscriber["id"], codes[0]) is False

    def test_consuming_reduces_the_remaining_count(self, subscriber):
        codes = recovery_codes.generate_for_user(subscriber["id"])
        recovery_codes.consume(subscriber["id"], codes[0])
        assert recovery_codes.remaining(subscriber["id"]) == len(codes) - 1

    def test_formatting_and_case_are_forgiving(self, subscriber):
        """Someone reading a code off paper mid-attack must not fail on a space."""
        codes = recovery_codes.generate_for_user(subscriber["id"])
        messy = codes[0].lower().replace("-", " ")
        assert recovery_codes.consume(subscriber["id"], messy) is True

    def test_an_invalid_code_is_rejected(self, subscriber):
        recovery_codes.generate_for_user(subscriber["id"])
        assert recovery_codes.consume(subscriber["id"], "AAAAA-BBBBB") is False
        assert recovery_codes.consume(subscriber["id"], "") is False

    def test_another_users_code_does_not_work(self, subscriber, user_factory):
        codes = recovery_codes.generate_for_user(subscriber["id"])
        other, _pw = user_factory()
        recovery_codes.generate_for_user(other["id"])
        assert recovery_codes.consume(other["id"], codes[0]) is False

    def test_regenerating_invalidates_the_previous_set(self, subscriber):
        old = recovery_codes.generate_for_user(subscriber["id"])
        recovery_codes.generate_for_user(subscriber["id"])
        assert recovery_codes.consume(subscriber["id"], old[0]) is False

    def test_ambiguous_characters_are_excluded_from_the_alphabet(self):
        for ch in "IO01":
            assert ch not in recovery_codes.ALPHABET

    def test_codes_are_not_predictable(self, subscriber):
        seen = set()
        for _ in range(5):
            seen.update(recovery_codes.generate_for_user(subscriber["id"]))
        assert len(seen) == 5 * recovery_codes.CODE_COUNT

    def test_concurrent_use_of_one_code_succeeds_only_once(self, subscriber):
        """
        The same class of bug as the double-release finding: check-then-act on a
        single-use token. Ten threads, one code, exactly one winner.
        """
        import threading
        codes = recovery_codes.generate_for_user(subscriber["id"])
        results, lock = [], threading.Lock()

        def attempt():
            ok = recovery_codes.consume(subscriber["id"], codes[0])
            with lock:
                results.append(ok)

        threads = [threading.Thread(target=attempt) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert sum(1 for r in results if r) == 1, results
        assert recovery_codes.remaining(subscriber["id"]) == len(codes) - 1


# =============================================================================
# HTTP surface
# =============================================================================
class TestPasskeyRoutes:

    def test_recovery_codes_are_returned_exactly_once(self, client, signed_in):
        _user, headers = signed_in()
        body = client.post("/api/me/recovery-codes", headers=headers).get_json()
        codes = body["codes"]
        assert len(codes) == recovery_codes.CODE_COUNT

        # The posture endpoint reports the COUNT but must never re-issue the
        # codes themselves — they exist in readable form exactly once.
        factors = client.get("/api/me/security/factors").get_json()
        blob = json.dumps(factors)
        for code in codes:
            assert code not in blob
        assert factors["recovery_codes"]["remaining"] == recovery_codes.CODE_COUNT

    def test_generating_recovery_codes_requires_csrf(self, client, signed_in):
        _user, _headers = signed_in()
        assert client.post("/api/me/recovery-codes").status_code in (400, 403)

    def test_factors_require_authentication(self, client):
        assert client.get("/api/me/security/factors").status_code == 401

    def test_a_full_passkey_registration_over_http(self, client, signed_in):
        user, headers = signed_in()
        options = client.post("/api/me/passkeys/register/options",
                              headers=headers).get_json()
        challenge = b64url_decode(options["publicKey"]["challenge"])
        device = FakeAuthenticator()
        r = client.post("/api/me/passkeys/register",
                        json={"handle": options["handle"], "label": "Phone",
                              "credential": device.make_credential(challenge)},
                        headers=headers)
        assert r.status_code == 201, r.get_json()
        assert r.get_json()["attestation_verified"] is False

    def test_a_full_passkey_sign_in_over_http(self, client, signed_in,
                                              user_factory):
        user, headers = signed_in()
        options = client.post("/api/me/passkeys/register/options",
                              headers=headers).get_json()
        device = FakeAuthenticator()
        client.post("/api/me/passkeys/register",
                    json={"handle": options["handle"],
                          "credential": device.make_credential(
                              b64url_decode(options["publicKey"]["challenge"]))},
                    headers=headers)
        client.post("/api/auth/logout", headers=headers)

        opts = client.post("/api/auth/passkey/options",
                           json={"email": user["email"]}).get_json()
        r = client.post("/api/auth/passkey/login",
                        json={"handle": opts["handle"],
                              "credential": device.get_assertion(
                                  b64url_decode(opts["publicKey"]["challenge"]))})
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["user"]["email"] == user["email"]

    def test_passkey_options_do_not_reveal_whether_an_account_exists(self, client):
        """Otherwise the endpoint becomes an account-existence oracle."""
        known = client.post("/api/auth/passkey/options",
                            json={"email": "nobody@example.np"})
        assert known.status_code == 200
        assert "publicKey" in known.get_json()

    def test_a_forged_assertion_is_refused_over_http(self, client, signed_in):
        user, headers = signed_in()
        options = client.post("/api/me/passkeys/register/options",
                              headers=headers).get_json()
        device = FakeAuthenticator()
        client.post("/api/me/passkeys/register",
                    json={"handle": options["handle"],
                          "credential": device.make_credential(
                              b64url_decode(options["publicKey"]["challenge"]))},
                    headers=headers)
        opts = client.post("/api/auth/passkey/options",
                           json={"email": user["email"]}).get_json()
        r = client.post("/api/auth/passkey/login",
                        json={"handle": opts["handle"],
                              "credential": device.get_assertion(
                                  b64url_decode(opts["publicKey"]["challenge"]),
                                  corrupt_signature=True)})
        assert r.status_code == 401

    def test_recovery_login_completes_the_second_factor(self, client, user_factory):
        user, password = user_factory(profile_id="aarav_safe")
        codes = recovery_codes.generate_for_user(user["id"])
        start = client.post("/api/auth/login",
                            json={"email": user["email"], "password": password,
                                  "fingerprint": "fp-recovery"})
        assert start.status_code == 200, start.get_json()
        r = client.post("/api/auth/recovery-login",
                        json={"email": user["email"], "code": codes[0],
                              "challenge": start.get_json()["challenge"],
                              "fingerprint": "fp-recovery"})
        assert r.status_code == 200, r.get_json()
        assert r.get_json()["recovery_codes_remaining"] == len(codes) - 1

    def test_a_spent_recovery_code_cannot_be_reused(self, client, user_factory):
        user, password = user_factory(profile_id="aarav_safe")
        codes = recovery_codes.generate_for_user(user["id"])
        for attempt, expected in ((1, 200), (2, 401)):
            start = client.post("/api/auth/login",
                                json={"email": user["email"], "password": password,
                                      "fingerprint": f"fp-{attempt}"})
            r = client.post("/api/auth/recovery-login",
                            json={"email": user["email"], "code": codes[0],
                                  "challenge": start.get_json()["challenge"],
                                  "fingerprint": f"fp-{attempt}"})
            assert r.status_code == expected

    def test_recovery_login_requires_the_password_step_first(self, client,
                                                             user_factory):
        """A recovery code replaces the OTP; it does not replace the password."""
        user, _password = user_factory(profile_id="aarav_safe")
        codes = recovery_codes.generate_for_user(user["id"])
        r = client.post("/api/auth/recovery-login",
                        json={"email": user["email"], "code": codes[0],
                              "challenge": "made-up-challenge",
                              "fingerprint": "fp-x"})
        assert r.status_code == 401
        assert recovery_codes.remaining(user["id"]) == len(codes)
