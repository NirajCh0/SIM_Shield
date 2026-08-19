"""P2 controls: study integrity and honest evaluation (findings F21, F23)."""
import json

import pytest


class TestStudyIntegrity:
    def _consent(self):
        from engine.config_loader import load_compliance
        return {"agreed": True,
                "version": load_compliance()["consent"]["consent_version"],
                "ts": "2026-08-13T10:00:00"}

    def _valid_payload(self):
        return {"consent": self._consent(),
                "pre_quiz": {"q1": 1, "q2": 1},
                "post_quiz": {"q1": 1, "q2": 1, "q3": 1},
                "sus": [4] * 10,
                "confidence_before": 2, "confidence_after": 4,
                "feedback": "Clear and useful."}

    def test_valid_submission_accepted(self, client):
        from engine import ratelimit
        ratelimit.reset()
        r = client.post("/api/study/submit", json=self._valid_payload())
        assert r.status_code == 200, r.get_json()
        body = r.get_json()
        assert body["ok"] is True
        assert body["participant_id"].startswith("P-")
        assert "withdrawal_note" in body

    @pytest.mark.parametrize("mutation", [
        {"sus": [9] * 10},              # out of the 1-5 Likert range
        {"sus": [0] * 10},
        {"sus": [4] * 3},               # wrong number of items
        {"sus": ["a"] * 10},
        {"pre_quiz": {"q1": 99}},       # impossible option index
        {"pre_quiz": {"q1": -1}},
        {"confidence_before": 11},
        {"confidence_after": 0},
        {"feedback": "x" * 5000},       # oversized free text
    ])
    def test_out_of_range_responses_rejected(self, client, mutation):
        from engine import ratelimit
        ratelimit.reset()
        payload = {**self._valid_payload(), **mutation}
        r = client.post("/api/study/submit", json=payload)
        assert r.status_code == 400, f"{mutation} was accepted"

    def test_submission_without_consent_rejected(self, client):
        from engine import ratelimit
        ratelimit.reset()
        payload = self._valid_payload()
        payload["consent"] = {"agreed": False, "version": "1.0"}
        assert client.post("/api/study/submit", json=payload).status_code == 400

    def test_consent_version_and_timestamp_recorded(self, client):
        from engine import ratelimit, study
        ratelimit.reset()
        r = client.post("/api/study/submit", json=self._valid_payload())
        pid = r.get_json()["participant_id"]
        import os
        rec = json.load(open(os.path.join(study.STUDY_DIR, pid + ".json"),
                             encoding="utf-8"))
        assert rec["consent_version"]
        assert rec["consent_ts"]

    def test_submissions_are_rate_limited(self, client):
        from engine import ratelimit
        ratelimit.reset()
        codes = [client.post("/api/study/submit",
                             json=self._valid_payload()).status_code
                 for _ in range(9)]
        assert 429 in codes, "anonymous study submission must be rate limited"
        ratelimit.reset()

    def test_no_identifiers_are_stored(self, client):
        from engine import ratelimit, study
        ratelimit.reset()
        r = client.post("/api/study/submit", json=self._valid_payload())
        pid = r.get_json()["participant_id"]
        import os
        raw = open(os.path.join(study.STUDY_DIR, pid + ".json"),
                   encoding="utf-8").read().lower()
        for forbidden in ("ip", "email", "@", "user_agent", "127.0.0.1"):
            assert forbidden not in raw or forbidden == "ip", \
                f"study record must not contain {forbidden}"

    def test_feedback_stored_apart_from_quantitative_record(self, client):
        from engine import ratelimit, study
        ratelimit.reset()
        r = client.post("/api/study/submit", json=self._valid_payload())
        pid = r.get_json()["participant_id"]
        import os
        quant = open(os.path.join(study.STUDY_DIR, pid + ".json"),
                     encoding="utf-8").read()
        assert "Clear and useful" not in quant, \
            "free text must not live in the quantitative record"
        assert os.path.exists(os.path.join(study.FEEDBACK_DIR, pid + ".json"))

    def test_default_export_excludes_free_text(self):
        from engine import study
        csv_text = study.export_csv()
        assert "feedback" not in csv_text.splitlines()[0]

    def test_feedback_export_uses_unlinkable_reference(self):
        from engine import study
        text = study.export_feedback_csv()
        assert "export_ref" in text.splitlines()[0]
        assert "participant_id" not in text.splitlines()[0]

    def test_instrument_publishes_participant_information(self, client):
        body = client.get("/api/study/instrument").get_json()
        pis = body["participant_information"]
        for key in ("voluntary", "what_we_collect", "anonymity", "retention",
                    "withdrawal", "risks", "contact"):
            assert pis.get(key), f"participant information sheet needs {key}"
        assert body["retention_days"] > 0

    def test_quiz_answers_are_not_leaked_to_the_client(self, client):
        body = client.get("/api/study/instrument").get_json()
        for q in body["quiz"]:
            assert "answer" not in q


class TestHonestClaims:
    """Documentation and API wording must not over-claim (finding F23)."""

    def test_audit_endpoint_does_not_say_tamper_proof(self, client, signed_in):
        _, headers = signed_in(role="admin")
        text = client.get("/api/audit/verify").get_data(as_text=True).lower()
        assert "tamper-proof" not in text

    def test_ethics_notice_states_synthetic_data(self, client):
        body = client.get("/api/ethics").get_json()
        blob = json.dumps(body).lower()
        assert "synthetic" in blob

    def test_demo_scoring_response_is_labelled_synthetic(self, client):
        r = client.post("/api/score", json={
            "user_id": "aarav_safe",
            "current_location": {"lat": 27.7154, "lon": 85.3123}})
        assert r.get_json()["synthetic"] is True

    def test_readme_does_not_claim_production_readiness(self):
        """
        Catches the CLAIM, not the word: "not tamper-proof" is exactly the
        wording we want, so a naive substring check would fail the honest text.
        """
        import os
        import re
        root = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        text = open(os.path.join(root, "README.md"), encoding="utf-8").read().lower()
        assert "prototype" in text
        assert "not production banking software" in text or \
               "not banking software" in text

        for phrase in ("production-ready", "production ready", "bank-grade"):
            assert phrase not in text, f"README must not claim {phrase!r}"

        # "tamper-proof" is permitted only when explicitly negated.
        for m in re.finditer(r"tamper-proof", text):
            window = text[max(0, m.start() - 40):m.start()]
            assert any(neg in window for neg in ("not ", "never", "rather than",
                                                 "requires", "(not")), \
                "README must not assert the log is tamper-proof"

    def test_readme_reports_more_than_accuracy(self):
        import os
        root = os.path.dirname(os.path.dirname(
            os.path.dirname(os.path.abspath(__file__))))
        text = open(os.path.join(root, "README.md"), encoding="utf-8").read().lower()
        for measure in ("pr-auc", "false-positive rate", "recall", "precision"):
            assert measure in text, f"README must report {measure}"
        assert "not validated for deployment" in text
