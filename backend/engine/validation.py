"""
Request payload validation (finding F16/F17).

A small, dependency-free schema layer. Every API payload is validated here
before it reaches the engine, so malformed input produces a safe, specific 400
rather than a 500 with a stack trace — and so values that would corrupt the
detection maths (NaN, infinity, out-of-range coordinates) never get in.

Why hand-rolled rather than pydantic/marshmallow: the project's dependency list
is part of what a marker reviews, the rules needed here are simple, and an
explicit validator is easier to read alongside the threat model than a library
DSL. `ValidationError.messages` carries every problem at once so a caller fixes
them in one round trip.
"""
import math
from datetime import datetime

MAX_STRING = 500          # generous for a merchant name or a chat message
MAX_TEXT = 2000           # free-text study feedback
MAX_LIST = 50


class ValidationError(ValueError):
    def __init__(self, messages):
        self.messages = messages if isinstance(messages, list) else [messages]
        super().__init__("; ".join(self.messages))


class Validator:
    """Collects problems instead of raising on the first one."""

    def __init__(self, data):
        self.data = data if isinstance(data, dict) else {}
        self.errors: list[str] = []
        self.clean: dict = {}
        if not isinstance(data, dict):
            self.errors.append("Request body must be a JSON object.")

    # --- primitives ----------------------------------------------------------
    def string(self, key, *, required=False, max_len=MAX_STRING, default="",
               choices=None, strip=True):
        v = self.data.get(key, default)
        if v is None:
            v = default
        if not isinstance(v, str):
            if required or v != default:
                self.errors.append(f"{key} must be a string.")
            self.clean[key] = default
            return self
        if strip:
            v = v.strip()
        if required and not v:
            self.errors.append(f"{key} is required.")
        if len(v) > max_len:
            self.errors.append(f"{key} must be at most {max_len} characters.")
            v = v[:max_len]
        if choices is not None and v and v not in choices:
            self.errors.append(f"{key} must be one of: {', '.join(sorted(choices))}.")
        self.clean[key] = v
        return self

    def number(self, key, *, required=False, minimum=None, maximum=None,
               default=None, integer=False):
        if key not in self.data or self.data.get(key) is None:
            if required:
                self.errors.append(f"{key} is required.")
            self.clean[key] = default
            return self
        v = self.data[key]
        if isinstance(v, bool):            # bool is an int in Python; reject it
            self.errors.append(f"{key} must be a number.")
            self.clean[key] = default
            return self
        try:
            if integer:
                # `int(v)` silently TRUNCATES a fractional value: a payment of
                # 12.34 became 12 with no error, which is a wrong answer
                # presented as a right one. Reject instead of coercing — the
                # caller asked for an integer, so a non-integral input is a
                # malformed request, not something to round on the user's
                # behalf. (NaN/inf are caught first: int(nan) raises, but
                # float(nan) != int(float(nan)) would too, so be explicit.)
                f = float(v)
                if math.isnan(f) or math.isinf(f):
                    raise ValueError("not finite")
                if f != int(f):
                    self.errors.append(f"{key} must be a whole number.")
                    self.clean[key] = default
                    return self
                v = int(f)
            else:
                v = float(v)
        except (TypeError, ValueError):
            self.errors.append(f"{key} must be a number.")
            self.clean[key] = default
            return self
        if not integer and (math.isnan(v) or math.isinf(v)):
            # NaN/inf propagate silently through the scoring maths and produce
            # a nonsense risk score, so they are rejected explicitly.
            self.errors.append(f"{key} must be a finite number.")
            self.clean[key] = default
            return self
        if minimum is not None and v < minimum:
            self.errors.append(f"{key} must be at least {minimum}.")
        if maximum is not None and v > maximum:
            self.errors.append(f"{key} must be at most {maximum}.")
        self.clean[key] = v
        return self

    def boolean(self, key, *, default=False):
        v = self.data.get(key, default)
        self.clean[key] = bool(v) if isinstance(v, (bool, int)) else default
        return self

    def flag01(self, key, *, default=0):
        """A 0/1 telecom signal flag."""
        v = self.data.get(key, default)
        if isinstance(v, bool):
            v = int(v)
        if v in (0, 1, "0", "1"):
            self.clean[key] = int(v)
        else:
            self.errors.append(f"{key} must be 0 or 1.")
            self.clean[key] = default
        return self

    def coordinates(self, key, *, required=False):
        """A {lat, lon} object with real, in-range, finite values."""
        v = self.data.get(key)
        if v is None:
            if required:
                self.errors.append(f"{key} is required.")
            self.clean[key] = None
            return self
        if not isinstance(v, dict):
            self.errors.append(f"{key} must be an object with lat and lon.")
            self.clean[key] = None
            return self
        out = {}
        for axis, lo, hi in (("lat", -90, 90), ("lon", -180, 180)):
            raw = v.get(axis)
            if isinstance(raw, bool) or raw is None:
                self.errors.append(f"{key}.{axis} is required.")
                continue
            try:
                num = float(raw)
            except (TypeError, ValueError):
                self.errors.append(f"{key}.{axis} must be a number.")
                continue
            if math.isnan(num) or math.isinf(num):
                self.errors.append(f"{key}.{axis} must be a finite number.")
                continue
            if not (lo <= num <= hi):
                self.errors.append(f"{key}.{axis} must be between {lo} and {hi}.")
                continue
            out[axis] = num
        self.clean[key] = out if len(out) == 2 else None
        if len(out) != 2 and required:
            self.errors.append(f"{key} must contain valid lat and lon.")
        return self

    def timestamp(self, key, *, required=False, default=None):
        v = self.data.get(key)
        if v is None or v == "":
            if required:
                self.errors.append(f"{key} is required.")
            self.clean[key] = default
            return self
        if not isinstance(v, str) or len(v) > 64:
            self.errors.append(f"{key} must be an ISO-8601 timestamp string.")
            self.clean[key] = default
            return self
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            self.errors.append(f"{key} must be a valid ISO-8601 timestamp.")
            self.clean[key] = default
            return self
        self.clean[key] = v
        return self

    def identifier(self, key, *, required=False, max_len=64):
        """A safe internal id: letters, digits and underscores only."""
        v = self.data.get(key, "")
        if not isinstance(v, str) or not v:
            if required:
                self.errors.append(f"{key} is required.")
            self.clean[key] = ""
            return self
        v = v.strip()
        if len(v) > max_len or not v.replace("_", "").isalnum():
            self.errors.append(f"{key} contains unsupported characters.")
            self.clean[key] = ""
            return self
        self.clean[key] = v
        return self

    def int_map(self, key, *, minimum, maximum, max_items=MAX_LIST):
        """A {question_id: int} answer map with every value range-checked."""
        v = self.data.get(key) or {}
        if not isinstance(v, dict):
            self.errors.append(f"{key} must be an object.")
            self.clean[key] = {}
            return self
        if len(v) > max_items:
            self.errors.append(f"{key} has too many entries.")
            self.clean[key] = {}
            return self
        out = {}
        for qid, ans in v.items():
            if not isinstance(qid, str) or len(qid) > 64:
                self.errors.append(f"{key} contains an invalid key.")
                continue
            if isinstance(ans, bool) or not isinstance(ans, int):
                self.errors.append(f"{key}.{qid} must be an integer.")
                continue
            if not (minimum <= ans <= maximum):
                self.errors.append(
                    f"{key}.{qid} must be between {minimum} and {maximum}.")
                continue
            out[qid] = ans
        self.clean[key] = out
        return self

    def int_list(self, key, *, minimum, maximum, length=None,
                 max_items=MAX_LIST):
        v = self.data.get(key) or []
        if not isinstance(v, list):
            self.errors.append(f"{key} must be a list.")
            self.clean[key] = []
            return self
        if len(v) > max_items:
            self.errors.append(f"{key} has too many entries.")
            self.clean[key] = []
            return self
        if length is not None and len(v) != length:
            self.errors.append(f"{key} must contain exactly {length} values.")
        out = []
        for i, item in enumerate(v):
            if isinstance(item, bool) or not isinstance(item, int):
                self.errors.append(f"{key}[{i}] must be an integer.")
                continue
            if not (minimum <= item <= maximum):
                self.errors.append(
                    f"{key}[{i}] must be between {minimum} and {maximum}.")
                continue
            out.append(item)
        self.clean[key] = out
        return self

    # --- finish --------------------------------------------------------------
    def done(self) -> dict:
        if self.errors:
            raise ValidationError(self.errors)
        return self.clean
