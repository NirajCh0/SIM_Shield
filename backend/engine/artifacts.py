"""
ML artefact integrity verification (finding F20).

WHY THIS MATTERS
`joblib.load()` unpickles, and unpickling is arbitrary code execution. Loading a
model file that an attacker has substituted is equivalent to handing them the
process. In a project distributed to markers and re-run on other machines, "the
file was in the models directory" is not evidence that it is the file we trained.

CONTROLS
  1. Allowlist. Only paths declared in the manifest may be loaded at all; a
     configured path pointing anywhere else is refused.
  2. Integrity. Each artefact's SHA-256 must match the manifest.
  3. Containment. The manifest must live beside the artefacts and is regenerated
     only by `train_model.py`, i.e. by the code that produced them.
  4. Fail safe. A mismatch logs loudly and returns None so the detector degrades
     to rules-only — it never loads an unverified artefact "just this once".

📋 Production would sign the manifest itself (e.g. Sigstore/cosign) so an
   attacker who can rewrite artefacts cannot simply rewrite the hashes too, and
   would pin the training pipeline that produced them.
"""
import hashlib
import json
import logging
import os

from .config_loader import backend_path

log = logging.getLogger("simshield.artifacts")

MANIFEST_PATH = backend_path("models", "manifest.json")
MODELS_DIR = os.path.realpath(backend_path("models"))


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def load_manifest() -> dict:
    if not os.path.exists(MANIFEST_PATH):
        return {}
    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            return json.load(f).get("artifacts", {})
    except (ValueError, OSError) as e:
        log.error("Could not read the artefact manifest: %s", e)
        return {}


def write_manifest(paths: list[str], extra: dict | None = None) -> dict:
    """Record the SHA-256 of each artefact. Called only by train_model.py."""
    artifacts = {}
    for p in paths:
        if os.path.exists(p):
            artifacts[os.path.basename(p)] = {
                "sha256": sha256_file(p),
                "bytes": os.path.getsize(p),
            }
    doc = {
        "_comment": "Integrity manifest for SIMShield ML artefacts. Regenerate "
                    "with `python train_model.py`. engine/artifacts.py refuses "
                    "to load any artefact whose hash does not match.",
        "artifacts": artifacts,
        **(extra or {}),
    }
    os.makedirs(os.path.dirname(MANIFEST_PATH), exist_ok=True)
    with open(MANIFEST_PATH, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    return doc


def verify(path: str) -> tuple[bool, str]:
    """(ok, reason) — is this artefact declared, present and unmodified?"""
    real = os.path.realpath(path)
    # 1. containment: never load from outside the models directory
    if os.path.commonpath([real, MODELS_DIR]) != MODELS_DIR:
        return False, f"path escapes the models directory: {path}"
    if not os.path.exists(real):
        return False, "artefact not found"

    manifest = load_manifest()
    if not manifest:
        return False, ("no manifest — run `python train_model.py` to train the "
                       "models and record their hashes")
    name = os.path.basename(real)
    entry = manifest.get(name)
    if entry is None:
        return False, f"{name} is not declared in the manifest"

    actual = sha256_file(real)
    if actual != entry.get("sha256"):
        return False, (f"{name} hash mismatch — expected "
                       f"{entry.get('sha256', '')[:16]}…, got {actual[:16]}…")
    return True, "verified"


def safe_load(path: str):
    """
    Verify then load a joblib artefact. Returns None (never raises) so the
    caller degrades gracefully; the reason is always logged.
    """
    ok, reason = verify(path)
    if not ok:
        log.error("REFUSING to load ML artefact %s: %s", path, reason)
        return None
    try:
        import joblib
        return joblib.load(path)
    except Exception as e:
        log.error("Failed to load verified artefact %s: %s", path, e)
        return None
