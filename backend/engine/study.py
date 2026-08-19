"""
User-study module - the instrumentation behind the 'mixed-methods evaluation'.

Supports a small, ethically-run user study of SIMShield's awareness value:

  QUANTITATIVE
    * pre/post awareness quiz  -> knowledge gain (post - pre), per participant
    * SUS (System Usability Scale, 10 items) -> a 0-100 usability score
    * Likert confidence ratings

  QUALITATIVE
    * free-text feedback ("what would you change?", "what confused you?")

Every submission requires informed consent (compliance.check_consent) and is
stored pseudonymously (a random participant id, never a name) as one JSON file
under data/study/. aggregate() produces the numbers you report; export_csv()
produces a flat CSV for analysis in R/SPSS/pandas.

All questionnaire content lives here so the study instrument is transparent and
reviewable (important for an ethics board).
"""
import csv
import io
import json
import os
import statistics
import uuid
from datetime import datetime

from . import compliance
from .config_loader import backend_path
from .validation import ValidationError, Validator

STUDY_DIR = backend_path("data", "study")
FEEDBACK_DIR = backend_path("data", "study_feedback")
MAX_QUIZ_OPTION = 9          # generous upper bound; real quizzes have 4 options

WITHDRAWAL_NOTE = (
    "Keep your participant ID if you may wish to withdraw. Because responses are "
    "anonymous, we can only delete your data if you quote that ID — we hold no "
    "other way to identify you. Withdrawal is possible until the results are "
    "aggregated for submission."
)

# Participant Information Sheet. Shown before consent so participation is
# genuinely informed (research-integrity requirement, finding F21).
PARTICIPANT_INFO = {
    "title": "SIMShield: SIM-swap awareness and usability study",
    "what_is_it": (
        "You will answer a short quiz about SIM-swap fraud, read a short "
        "awareness guide, then answer the quiz again along with ten standard "
        "usability questions and an optional free-text comment."),
    "how_long": "About 10 minutes.",
    "voluntary": (
        "Participation is entirely voluntary. You may stop at any point before "
        "submitting, and you do not have to answer the free-text question."),
    "what_we_collect": (
        "Your quiz answers, usability ratings, two confidence ratings and any "
        "comment you choose to write. We do NOT collect your name, email, phone "
        "number, IP address or any other identifier."),
    "anonymity": (
        "You are stored under a randomly generated participant ID. Nothing links "
        "that ID to you, which also means we cannot recover your data for you if "
        "you lose the ID."),
    "retention": (
        "Responses are retained for up to 365 days and then automatically "
        "deleted. Aggregated, non-identifying results may appear in the "
        "dissertation and any resulting publication."),
    "withdrawal": WITHDRAWAL_NOTE,
    "risks": (
        "There are no anticipated risks. The material concerns fraud awareness "
        "and is not distressing. No deception is used."),
    "contact": (
        "Questions or withdrawal requests: contact the researcher via your "
        "module/supervisor channel. Concerns about how the study was conducted "
        "can be raised with the university research-ethics committee."),
    "data_controller": "Student researcher, under university supervision.",
}

# --- The study instrument (transparent & versioned) -------------------------
AWARENESS_QUIZ = [
    {"id": "q1", "prompt": "What is a SIM-swap attack?",
     "options": ["A phone software update",
                 "A fraudster moving your number onto a SIM they control",
                 "A way to get a cheaper data plan",
                 "A type of computer virus"],
     "answer": 1},
    {"id": "q2", "prompt": "Why is SMS OTP risky during a SIM swap?",
     "options": ["OTPs expire too quickly",
                 "The OTP is sent to the attacker's SIM, not yours",
                 "SMS costs money",
                 "OTPs are always 6 digits"],
     "answer": 1},
    {"id": "q3", "prompt": "Which is an early warning sign of a SIM swap?",
     "options": ["Your phone battery lasts longer",
                 "You suddenly lose all mobile signal for no reason",
                 "You receive more app notifications",
                 "Your screen brightness changes"],
     "answer": 1},
    {"id": "q4", "prompt": "What should you do FIRST if you suspect a SIM swap?",
     "options": ["Post about it on social media",
                 "Wait a day to see if it fixes itself",
                 "Contact your mobile operator and bank immediately",
                 "Factory-reset your phone"],
     "answer": 2},
    {"id": "q5", "prompt": "Which is the safest second factor?",
     "options": ["SMS OTP", "An authenticator app or hardware key",
                 "Your date of birth", "A memorable word"],
     "answer": 1},
]

# Standard SUS items (odd = positive, even = negative). Responses are 1..5.
SUS_ITEMS = [
    "I think I would like to use SIMShield frequently.",
    "I found SIMShield unnecessarily complex.",
    "I thought SIMShield was easy to use.",
    "I would need support from a technical person to use SIMShield.",
    "I found the various functions in SIMShield were well integrated.",
    "I thought there was too much inconsistency in SIMShield.",
    "I imagine most people would learn to use SIMShield very quickly.",
    "I found SIMShield very cumbersome to use.",
    "I felt very confident using SIMShield.",
    "I needed to learn a lot before I could get going with SIMShield.",
]


def instrument() -> dict:
    """Return the full study instrument for the frontend to render."""
    # Hide the answer key from the client-facing quiz.
    quiz = [{k: v for k, v in q.items() if k != "answer"} for q in AWARENESS_QUIZ]
    comp = compliance.load_compliance()
    return {
        "consent_version": comp["consent"]["consent_version"],
        "purposes": comp["consent"]["purposes"],
        "participant_information": PARTICIPANT_INFO,
        "withdrawal_note": WITHDRAWAL_NOTE,
        "retention_days": comp["retention"]["study_responses_days"],
        "quiz": quiz,
        "sus_items": SUS_ITEMS,
    }


def _quiz_score(answers: dict) -> int:
    """Count correct answers against the hidden key."""
    correct = 0
    for q in AWARENESS_QUIZ:
        if answers and int(answers.get(q["id"], -1)) == q["answer"]:
            correct += 1
    return correct


def _sus_score(responses: list) -> float | None:
    """
    Standard SUS scoring: odd items -> (x-1), even items -> (5-x); sum * 2.5.
    Returns a 0..100 usability score, or None if not all 10 answered.
    """
    if not responses or len(responses) != 10:
        return None
    total = 0
    for i, x in enumerate(responses):
        x = int(x)
        total += (x - 1) if i % 2 == 0 else (5 - x)
    return round(total * 2.5, 1)


def submit(payload: dict, client_ip: str | None = None) -> dict:
    """
    Store one participant's submission (consent-gated, pseudonymous).

    Research-integrity controls (finding F21):
      * every SUS and quiz value is range-validated — a submission with a SUS
        item of 99 or a quiz index of -5 silently corrupted the means before
      * anonymous rate limiting, keyed on a SALTED HASH of the caller's IP that
        is never stored, so one participant cannot flood the dataset without the
        study collecting an identifier
      * the consent version AND a consent timestamp are recorded
      * free-text feedback is stored in a SEPARATE file from the quantitative
        record so the two can be exported independently
    """
    from . import privacy, ratelimit
    from .config_loader import load_config

    # Anonymous, identifier-free rate limiting. The key is a keyed hash used
    # only in memory; no IP is written to disk.
    if client_ip:
        cfg = load_config()["auth"].get("rate_limits", {}).get("study_submit")
        if cfg and not ratelimit.allow("study:" + privacy.hash_id(client_ip),
                                       cfg["limit"], cfg["window_seconds"]):
            return {"ok": False, "rate_limited": True,
                    "error": "Too many submissions from this connection. If you "
                             "believe this is an error, contact the researcher."}

    ok, msg = compliance.check_consent(payload.get("consent"), purpose="study")
    if not ok:
        return {"ok": False, "error": msg}

    v = Validator(payload)
    v.int_map("pre_quiz", minimum=0, maximum=MAX_QUIZ_OPTION)
    v.int_map("post_quiz", minimum=0, maximum=MAX_QUIZ_OPTION)
    v.int_list("sus", minimum=1, maximum=5, length=len(SUS_ITEMS))
    v.number("confidence_before", integer=True, minimum=1, maximum=5, default=None)
    v.number("confidence_after", integer=True, minimum=1, maximum=5, default=None)
    v.string("feedback", max_len=2000)
    v.string("group", max_len=40, default="default")
    try:
        data = v.done()
    except ValidationError as e:
        return {"ok": False, "error": "Invalid responses.", "details": e.messages}

    pre = _quiz_score(data["pre_quiz"])
    post = _quiz_score(data["post_quiz"])
    pid = "P-" + uuid.uuid4().hex[:8]
    now = datetime.now().isoformat(timespec="seconds")

    record = {
        "participant_id": pid,
        "ts": now,
        "consent_version": payload["consent"].get("version"),
        "consent_ts": payload["consent"].get("ts") or now,
        "group": data["group"] or "default",
        "pre_quiz_score": pre,
        "post_quiz_score": post,
        "knowledge_gain": post - pre,
        "quiz_max": len(AWARENESS_QUIZ),
        "sus_score": _sus_score(data["sus"]),
        "confidence_before": data["confidence_before"],
        "confidence_after": data["confidence_after"],
    }
    os.makedirs(STUDY_DIR, exist_ok=True)
    with open(os.path.join(STUDY_DIR, pid + ".json"), "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2)

    # Qualitative data lives apart from the quantitative record so an export of
    # one does not disclose the other.
    if data["feedback"]:
        os.makedirs(FEEDBACK_DIR, exist_ok=True)
        with open(os.path.join(FEEDBACK_DIR, pid + ".json"), "w",
                  encoding="utf-8") as f:
            json.dump({"participant_id": pid, "ts": now,
                       "feedback": data["feedback"]}, f, indent=2)

    return {"ok": True, "participant_id": pid,
            "withdrawal_note": WITHDRAWAL_NOTE,
            "summary": {"knowledge_gain": record["knowledge_gain"],
                        "post_score": record["post_quiz_score"],
                        "sus_score": record["sus_score"]}}


def _load_all() -> list:
    if not os.path.isdir(STUDY_DIR):
        return []
    out = []
    for name in sorted(os.listdir(STUDY_DIR)):
        if name.endswith(".json"):
            with open(os.path.join(STUDY_DIR, name), "r", encoding="utf-8") as f:
                out.append(json.load(f))
    return out


def _mean(xs):
    xs = [x for x in xs if isinstance(x, (int, float))]
    return round(statistics.mean(xs), 2) if xs else None


def aggregate() -> dict:
    """
    The quantitative headline of the mixed-methods evaluation: n, mean pre/post
    quiz, mean knowledge gain, mean SUS, confidence shift, and the pooled
    qualitative feedback for thematic coding.
    """
    recs = _load_all()
    n = len(recs)
    pre = [r["pre_quiz_score"] for r in recs]
    post = [r["post_quiz_score"] for r in recs]
    gain = [r["knowledge_gain"] for r in recs]
    sus = [r["sus_score"] for r in recs if r.get("sus_score") is not None]

    sus_mean = _mean(sus)
    sus_grade = None
    if sus_mean is not None:  # common SUS adjective bands
        sus_grade = ("A (excellent)" if sus_mean >= 80.3 else
                     "B (good)" if sus_mean >= 68 else
                     "C (ok)" if sus_mean >= 51 else "F (poor)")

    return {
        "n": n,
        "quiz_max": len(AWARENESS_QUIZ),
        "pre_quiz_mean": _mean(pre),
        "post_quiz_mean": _mean(post),
        "knowledge_gain_mean": _mean(gain),
        "sus_mean": sus_mean,
        "sus_grade": sus_grade,
        "confidence_before_mean": _mean([r.get("confidence_before") for r in recs]),
        "confidence_after_mean": _mean([r.get("confidence_after") for r in recs]),
        "feedback": _load_feedback_texts(),
    }


def _load_feedback_texts() -> list:
    """Qualitative comments only — no participant ids attached."""
    if not os.path.isdir(FEEDBACK_DIR):
        return []
    out = []
    for name in sorted(os.listdir(FEEDBACK_DIR)):
        if name.endswith(".json"):
            with open(os.path.join(FEEDBACK_DIR, name), "r", encoding="utf-8") as f:
                text = json.load(f).get("feedback")
                if text:
                    out.append(text)
    return out


def export_csv(include_feedback: bool = False) -> str:
    """
    Quantitative submissions as CSV. Free-text is EXCLUDED by default so the
    routine export cannot leak qualitative data (finding F21); use
    export_feedback_csv() for that, behind its own audited endpoint.
    """
    recs = _load_all()
    cols = ["participant_id", "ts", "consent_version", "consent_ts", "group",
            "pre_quiz_score", "post_quiz_score", "knowledge_gain", "quiz_max",
            "sus_score", "confidence_before", "confidence_after"]
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=cols, extrasaction="ignore")
    w.writeheader()
    for r in recs:
        w.writerow(r)
    return buf.getvalue()


def export_feedback_csv() -> str:
    """
    Qualitative comments for thematic coding, under a PER-EXPORT pseudonym so a
    feedback export cannot be joined back to the quantitative export by
    participant id.
    """
    import secrets as _secrets
    salt = _secrets.token_hex(8)
    rows = []
    if os.path.isdir(FEEDBACK_DIR):
        for i, name in enumerate(sorted(os.listdir(FEEDBACK_DIR)), 1):
            if not name.endswith(".json"):
                continue
            with open(os.path.join(FEEDBACK_DIR, name), "r", encoding="utf-8") as f:
                rec = json.load(f)
            rows.append({"export_ref": f"F{salt}-{i:03d}",
                         "ts": rec.get("ts"), "feedback": rec.get("feedback", "")})
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=["export_ref", "ts", "feedback"])
    w.writeheader()
    w.writerows(rows)
    return buf.getvalue()
