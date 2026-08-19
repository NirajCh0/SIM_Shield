"""P1 controls: atomic finance, validation, audit/retention, artefact integrity."""
import json
import os
import threading

import pytest


# ============================================================================
# P1.7 — atomic financial simulation (findings F14, F15)
# ============================================================================
class TestFinancialAtomicity:
    def _fund(self, user_id, amount):
        from engine import db
        db.execute("UPDATE users SET balance = ? WHERE id = ?", (amount, user_id))

    def _reload(self, user_id):
        from engine import auth
        return auth.get_user(user_id)

    def test_balance_cannot_go_negative_under_concurrency(self, user_factory):
        """
        The core race: ten threads each try to spend the whole balance. Exactly
        one may succeed. Before the fix all ten read the same balance and all
        ten debited it.
        """
        from engine import auth, transactions
        user, _ = user_factory()
        self._fund(user["id"], 1000.0)

        results, errors = [], []
        barrier = threading.Barrier(10)

        def spend():
            try:
                barrier.wait(timeout=10)
                u = auth.get_user(user["id"])
                results.append(transactions.assess(u, 1000.0, merchant="race"))
            except Exception as e:              # pragma: no cover
                errors.append(e)

        threads = [threading.Thread(target=spend) for _ in range(10)]
        [t.start() for t in threads]
        [t.join(timeout=30) for t in threads]

        assert not errors, errors
        accepted = [r for r in results if r.get("accepted") and r.get("status") == "posted"]
        final = self._reload(user["id"])["balance"]
        assert len(accepted) == 1, f"{len(accepted)} concurrent debits succeeded"
        assert final >= 0, f"balance overdrawn to {final}"
        assert final == pytest.approx(0.0)

    def test_insufficient_funds_refused(self, user_factory):
        from engine import auth, transactions
        user, _ = user_factory()
        self._fund(user["id"], 100.0)
        r = transactions.assess(auth.get_user(user["id"]), 500.0)
        assert r["accepted"] is False
        assert self._reload(user["id"])["balance"] == 100.0

    def test_frozen_account_refuses_transactions(self, user_factory):
        from engine import auth, transactions
        user, _ = user_factory()
        self._fund(user["id"], 5000.0)
        auth.set_frozen(user["id"], True)
        r = transactions.assess(auth.get_user(user["id"]), 100.0)
        assert r["accepted"] is False
        assert self._reload(user["id"])["balance"] == 5000.0

    def test_held_transaction_cannot_be_released_twice(self, user_factory):
        """
        Concurrent releases of the same hold must debit exactly once. The old
        check-then-act let two callers both pass `status == 'held'`.
        """
        from engine import auth, db, transactions
        user, _ = user_factory()
        self._fund(user["id"], 10_000.0)
        txn_id = db.execute(
            "INSERT INTO transactions (user_id, amount, currency, merchant, "
            "category, flagged, anomaly_score, reasons, status, occurred_at) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (user["id"], 4000.0, "NPR", "held-test", "", 1, 90.0, "[]",
             "held", db.now()))

        ok, failed = [], []
        barrier = threading.Barrier(6)

        def release():
            barrier.wait(timeout=10)
            try:
                u = auth.get_user(user["id"])
                ok.append(transactions.release_held(u, txn_id))
            except ValueError as e:
                failed.append(str(e))

        threads = [threading.Thread(target=release) for _ in range(6)]
        [t.start() for t in threads]
        [t.join(timeout=30) for t in threads]

        assert len(ok) == 1, f"{len(ok)} releases succeeded — double spend"
        assert len(failed) == 5
        assert self._reload(user["id"])["balance"] == pytest.approx(6000.0)
        row = db.query_one("SELECT status FROM transactions WHERE id = ?", (txn_id,))
        assert row["status"] == "released"

    def test_release_of_unknown_transaction_raises(self, user_factory):
        from engine import auth, transactions
        user, _ = user_factory()
        with pytest.raises(ValueError):
            transactions.release_held(auth.get_user(user["id"]), 999999)

    def test_api_labels_transactions_as_simulation(self, client, signed_in):
        _, headers = signed_in()
        r = client.post("/api/me/transactions", headers=headers,
                        json={"amount": 100, "merchant": "Test"})
        assert r.get_json().get("simulation_only") is True


# ============================================================================
# P1.8 — payload validation (findings F16, F17)
# ============================================================================
class TestValidation:
    @pytest.mark.parametrize("payload", [
        {"user_id": "aarav_safe", "current_location": {"lat": float("nan"), "lon": 85.0}},
        {"user_id": "aarav_safe", "current_location": {"lat": float("inf"), "lon": 85.0}},
        {"user_id": "aarav_safe", "current_location": {"lat": 999, "lon": 85.0}},
        {"user_id": "aarav_safe", "current_location": {"lat": 27.7}},
        {"user_id": "aarav_safe", "timestamp": "not-a-timestamp"},
        {"user_id": "aarav_safe", "logins_last_24h": -5},
        {"user_id": "aarav_safe", "imsi_change_flag": 7},
        {"user_id": "aarav_safe", "imei": "x" * 5000},
        {"user_id": "../../etc/passwd"},
        {"user_id": ""},
    ])
    def test_bad_scoring_payloads_are_400_not_500(self, client, payload):
        # NaN/inf must be sent as raw JSON — Python's json emits them literally.
        r = client.post("/api/score", data=json.dumps(payload),
                        content_type="application/json")
        assert r.status_code == 400, f"{payload} -> {r.status_code}"
        assert "error" in r.get_json()

    def test_valid_scoring_payload_still_works(self, client):
        r = client.post("/api/score", json={
            "user_id": "aarav_safe",
            "current_location": {"lat": 27.7154, "lon": 85.3123},
            "imei": "356938035643809", "logins_last_24h": 1})
        assert r.status_code == 200
        body = r.get_json()
        assert body["decision"] in ("ALLOW", "MONITOR", "VERIFY", "BLOCK")
        assert body["synthetic"] is True

    @pytest.mark.parametrize("amount", [0, -50, "abc", None, float("nan"), 1e12])
    def test_invalid_transaction_amounts_rejected(self, client, signed_in, amount):
        _, headers = signed_in()
        r = client.post("/api/me/transactions", headers=headers,
                        data=json.dumps({"amount": amount}),
                        content_type="application/json")
        assert r.status_code == 400

    def test_invalid_operator_choice_rejected(self, client):
        r = client.post("/api/auth/register", json={
            "email": "x@example.np", "password": "TestPass!2345",
            "display_name": "X", "operator": "NOT_AN_OPERATOR"})
        assert r.status_code == 400

    def test_error_response_carries_no_stack_trace(self, client):
        r = client.post("/api/score", json={"user_id": ""})
        assert "Traceback" not in r.get_data(as_text=True)


# ============================================================================
# P1.9 — audit integrity and retention (findings F18, F19, F23)
# ============================================================================
class TestAuditAndRetention:
    def test_chain_verifies_and_is_labelled_tamper_evident(self):
        from engine import compliance
        result = compliance.verify_audit_chain()
        assert result["intact"] is True
        assert result["guarantee"] == "tamper-evident (local)"
        # The wording must not over-claim: "evident", never "proof".
        assert "tamper-evident" in result["message"].lower()
        assert "tamper-proof" not in result["message"].lower()

    def test_concurrent_appends_do_not_fork_the_chain(self, tmp_path, monkeypatch):
        """Twenty threads appending at once must still produce a valid chain."""
        from engine import compliance
        log = tmp_path / "audit.log"
        monkeypatch.setattr(compliance, "backend_path",
                            lambda *p: str(log) if p[-1].endswith(".log")
                            else str(tmp_path.joinpath(*p)))

        barrier = threading.Barrier(20)

        def write(i):
            barrier.wait(timeout=10)
            compliance.record_decision(f"subject-{i}", {"imei": f"imei{i}"},
                                       {"decision": "ALLOW", "risk_score": 1.0})

        threads = [threading.Thread(target=write, args=(i,)) for i in range(20)]
        [t.start() for t in threads]
        [t.join(timeout=30) for t in threads]

        result = compliance.verify_audit_chain()
        assert result["intact"] is True, result["message"]
        assert result["entries"] == 20

    def test_tampering_is_detected(self, tmp_path, monkeypatch):
        from engine import compliance
        log = tmp_path / "audit.log"
        monkeypatch.setattr(compliance, "backend_path",
                            lambda *p: str(log) if p[-1].endswith(".log")
                            else str(tmp_path.joinpath(*p)))
        for i in range(3):
            compliance.record_decision(f"s{i}", {}, {"decision": "ALLOW",
                                                     "risk_score": 1.0})
        lines = log.read_text(encoding="utf-8").splitlines()
        rec = json.loads(lines[1])
        rec["decision"] = "BLOCK"                       # forge a past decision
        lines[1] = json.dumps(rec)
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = compliance.verify_audit_chain()
        assert result["intact"] is False
        assert "modified" in result["message"] or "broken" in result["message"]

    def test_truncation_is_detected_via_checkpoint(self, tmp_path, monkeypatch):
        from engine import compliance
        log = tmp_path / "audit.log"
        monkeypatch.setattr(compliance, "backend_path",
                            lambda *p: str(tmp_path / os.path.basename(p[-1])))
        for i in range(5):
            compliance.record_decision(f"s{i}", {}, {"decision": "ALLOW",
                                                     "risk_score": 1.0})
        compliance.checkpoint_audit(reason="test")
        # attacker deletes the last two entries and rewrites nothing else
        lines = log.read_text(encoding="utf-8").splitlines()[:3]
        log.write_text("\n".join(lines) + "\n", encoding="utf-8")

        result = compliance.verify_audit_chain()
        assert result["intact"] is False
        assert "Truncation" in result["message"]

    def test_retention_covers_every_store(self, signed_in):
        from engine import compliance
        report = compliance.enforce_retention()
        for key in ("audit_purged", "alerts_log_purged", "study_purged",
                    "database_purged"):
            assert key in report, f"retention must report on {key}"
        for table in ("alerts", "outbox", "chat_logs", "activity_log",
                      "login_locations", "risk_history", "otp_codes", "sessions"):
            assert table in report["database_purged"], \
                f"retention must cover the {table} table"

    def test_retention_writes_a_checkpoint_first(self, signed_in):
        from engine import compliance
        report = compliance.enforce_retention()
        # a checkpoint is only written when an audit log exists
        assert "checkpoint" in report or report["audit_purged"] == 0


# ============================================================================
# P1.10 — ML artefact integrity (finding F20)
# ============================================================================
class TestArtifactIntegrity:
    def test_manifest_exists_and_matches_on_disk(self):
        from engine import artifacts
        manifest = artifacts.load_manifest()
        if not manifest:
            pytest.skip("models not trained in this environment")
        for name in manifest:
            ok, reason = artifacts.verify(artifacts.backend_path("models", name))
            assert ok, f"{name}: {reason}"

    def test_undeclared_artifact_is_refused(self, tmp_path):
        from engine import artifacts
        rogue = artifacts.backend_path("models", "rogue_model.joblib")
        try:
            with open(rogue, "wb") as f:
                f.write(b"not a real model")
            ok, reason = artifacts.verify(rogue)
            assert ok is False
            assert "not declared" in reason or "no manifest" in reason
            assert artifacts.safe_load(rogue) is None
        finally:
            if os.path.exists(rogue):
                os.remove(rogue)

    def test_modified_artifact_is_refused(self, tmp_path):
        from engine import artifacts
        manifest = artifacts.load_manifest()
        if not manifest:
            pytest.skip("models not trained in this environment")
        name = next(iter(manifest))
        path = artifacts.backend_path("models", name)
        original = open(path, "rb").read()
        try:
            with open(path, "ab") as f:
                f.write(b"\x00tampered")
            ok, reason = artifacts.verify(path)
            assert ok is False and "hash mismatch" in reason
            assert artifacts.safe_load(path) is None
        finally:
            with open(path, "wb") as f:
                f.write(original)

    def test_path_traversal_is_refused(self):
        from engine import artifacts
        ok, reason = artifacts.verify(
            artifacts.backend_path("models", "..", "config.yaml"))
        assert ok is False
        assert "escapes" in reason or "not declared" in reason

    def test_failure_degrades_to_rules_only(self, monkeypatch):
        """A refused artefact must not stop the engine — it drops to rules."""
        from engine import artifacts, ml_model
        monkeypatch.setattr(artifacts, "safe_load", lambda p: None)
        ml_model._loaded = False
        ml_model._model = None
        assert ml_model.is_available() is False
        assert ml_model.get_fraud_probability({}) is None


# =============================================================================
# Inference configuration
# =============================================================================
class TestModelsAreTunedForSingleRowInference:
    """
    `n_jobs` is pickled INTO a scikit-learn artefact. Both models were fitted
    with `n_jobs=-1`, which is right for training 300 trees once and wrong for
    scoring one login: joblib dispatch costs more than the work it distributes.

    Two consequences, both real:
      * single-row `predict_proba` was ~3.5x slower than necessary (48 ms vs
        14 ms measured), on the hot path of every sign-in;
      * the parallel path emitted a `sklearn.utils.parallel.delayed` UserWarning
        per dispatch — tens of thousands of lines during the evaluation
        harnesses, burying their actual output.
    """

    def test_the_random_forest_predicts_single_threaded(self):
        # Force a fresh load: an earlier test in this file deliberately tampers
        # with a .joblib to prove the integrity check refuses it, which leaves
        # the module cached as degraded. Without this the assertion would skip
        # rather than run — a hidden pass.
        from engine import ml_model
        ml_model._load()
        if ml_model._model is None:
            pytest.skip("no trained model in this checkout")
        assert getattr(ml_model._model, "n_jobs", 1) == 1, (
            "the forest will spawn joblib workers to score one row")

    def test_the_isolation_forest_predicts_single_threaded(self):
        from engine import anomaly
        anomaly._load_iso()
        if anomaly._iso_model is None:
            pytest.skip("no isolation forest in this checkout")
        assert getattr(anomaly._iso_model, "n_jobs", 1) == 1

    def test_scoring_a_login_emits_no_sklearn_parallel_warnings(self):
        """The harness output must not be buried in library noise."""
        import warnings

        from engine.detector import score_login
        from engine.profiles import load as load_profile
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            score_login({"current_location": {"lat": 27.7154, "lon": 85.3123},
                         "imei": "356938035643809", "logins_last_24h": 1,
                         "failed_logins_last_24h": 0},
                        load_profile("aarav_safe"))
        noisy = [w for w in caught if "sklearn.utils.parallel" in str(w.message)]
        assert noisy == [], f"{len(noisy)} sklearn parallel warnings per scored login"

    def test_training_still_uses_every_core(self):
        """The fix must not slow down training, where parallelism does help."""
        with open("train_model.py", encoding="utf-8") as f:
            src = f.read()
        assert "n_jobs=-1" in src, "training should still parallelise"
