"""
A deliberately minimal CBOR decoder — only what WebAuthn needs.

WHY NOT A LIBRARY
`cbor2` is not available in this environment and adding a dependency for two
call sites is a poor trade in a project whose supply-chain surface is already a
documented finding (F20). WebAuthn uses a small, fixed subset of CBOR: the
attestation object is a 3-key map, and a COSE key is a map of small integers to
integers and byte strings. That subset is short enough to implement and, more
importantly, short enough to *review*.

WHY DECODE-ONLY, AND STRICT
This parses attacker-supplied bytes, so the failure modes that matter are
resource exhaustion and silent misparsing, not missing features. Accordingly:

  * No encoder. Nothing here needs to produce CBOR.
  * Indefinite-length items, tags, and floats are REJECTED rather than skipped.
    WebAuthn never sends them, so anything that does is either broken or
    probing.
  * Nesting depth and total item count are capped, so a small payload cannot
    expand into millions of allocations.
  * Trailing bytes after the top-level item are an error in `loads`. Silently
    ignoring them is how two parsers end up disagreeing about the same message.

Every failure raises `CborError`; callers treat that as a malformed credential.
"""
from __future__ import annotations

MAX_DEPTH = 16
MAX_ITEMS = 4096
#: A byte/text string longer than this cannot be legitimate here — an RSA
#: modulus is 512 bytes at 4096 bits.
MAX_STRING = 8192


class CborError(ValueError):
    """Raised for any malformed, unsupported or oversized CBOR input."""


class _Decoder:
    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0
        self.items = 0

    # --- primitives -----------------------------------------------------------
    def _take(self, n: int) -> bytes:
        if n < 0 or self.pos + n > len(self.data):
            raise CborError("truncated CBOR input")
        chunk = self.data[self.pos:self.pos + n]
        self.pos += n
        return chunk

    def _head(self) -> tuple[int, int]:
        """Return (major_type, argument)."""
        first = self._take(1)[0]
        major, minor = first >> 5, first & 0x1F
        if minor < 24:
            return major, minor
        if minor == 24:
            return major, self._take(1)[0]
        if minor == 25:
            return major, int.from_bytes(self._take(2), "big")
        if minor == 26:
            return major, int.from_bytes(self._take(4), "big")
        if minor == 27:
            return major, int.from_bytes(self._take(8), "big")
        if minor == 31:
            raise CborError("indefinite-length items are not supported")
        raise CborError(f"reserved additional-information value {minor}")

    # --- items ----------------------------------------------------------------
    def decode(self, depth: int = 0):
        if depth > MAX_DEPTH:
            raise CborError("CBOR nesting too deep")
        self.items += 1
        if self.items > MAX_ITEMS:
            raise CborError("CBOR item count exceeds the limit")

        major, arg = self._head()

        if major == 0:                     # unsigned integer
            return arg
        if major == 1:                     # negative integer
            return -1 - arg
        if major == 2:                     # byte string
            if arg > MAX_STRING:
                raise CborError("CBOR byte string too long")
            return self._take(arg)
        if major == 3:                     # text string
            if arg > MAX_STRING:
                raise CborError("CBOR text string too long")
            try:
                return self._take(arg).decode("utf-8")
            except UnicodeDecodeError as exc:
                raise CborError("invalid UTF-8 in CBOR text string") from exc
        if major == 4:                     # array
            if arg > MAX_ITEMS:
                raise CborError("CBOR array too long")
            return [self.decode(depth + 1) for _ in range(arg)]
        if major == 5:                     # map
            if arg > MAX_ITEMS:
                raise CborError("CBOR map too large")
            out = {}
            for _ in range(arg):
                key = self.decode(depth + 1)
                if not isinstance(key, (int, str)):
                    raise CborError("CBOR map keys must be integers or strings")
                if key in out:
                    # Duplicate keys let two parsers disagree about the same
                    # message, which is a signature-bypass shape.
                    raise CborError(f"duplicate CBOR map key {key!r}")
                out[key] = self.decode(depth + 1)
            return out
        if major == 7:                     # simple values
            if arg == 20:
                return False
            if arg == 21:
                return True
            if arg == 22:
                return None
            raise CborError(f"unsupported CBOR simple value {arg}")
        raise CborError(f"unsupported CBOR major type {major}")


def loads(data: bytes) -> object:
    """Decode exactly one CBOR item. Trailing bytes are an error."""
    if not isinstance(data, (bytes, bytearray)):
        raise CborError("CBOR input must be bytes")
    decoder = _Decoder(bytes(data))
    value = decoder.decode()
    if decoder.pos != len(decoder.data):
        raise CborError("unexpected trailing bytes after the CBOR item")
    return value


def loads_prefix(data: bytes) -> tuple[object, int]:
    """
    Decode one item and report how many bytes it used.

    Needed for authenticator data, where the COSE public key is followed by
    optional extension data, so the key's length is not known in advance.
    """
    decoder = _Decoder(bytes(data))
    value = decoder.decode()
    return value, decoder.pos
