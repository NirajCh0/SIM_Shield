"""
Incident-response playbook for a suspected/confirmed SIM-swap attack.

Structured, bilingual content served to the UI, the chatbot and the awareness
pages. Phases follow the standard IR lifecycle (contain -> eradicate ->
recover -> report -> harden) translated into steps an ordinary banking
customer in the Kathmandu Valley can actually take.
"""

_PLAYBOOK = {
    "en": {
        "title": "🚨 SIM-Swap Incident Response Playbook",
        "subtitle": "Follow the phases in order. Minutes matter in a SIM swap.",
        "phases": [
            {"name": "Phase 1 — Contain (first 10 minutes)", "steps": [
                "Freeze your bank account (SIMShield dashboard → Freeze, or call the bank hotline).",
                "Call your mobile operator (NTC 1498 / Ncell 9005 / Smart Cell 4242) and ask them to suspend the new SIM and restore yours.",
                "Do NOT approve, read out, or forward any OTP — a code you didn't request means an attack is in progress.",
            ]},
            {"name": "Phase 2 — Eradicate access", "steps": [
                "From a trusted device, change your mobile-banking and email passwords.",
                "Revoke all active sessions in your email and banking apps.",
                "Remove any devices you don't recognise from your account's device list.",
            ]},
            {"name": "Phase 3 — Recover", "steps": [
                "Once the operator confirms your SIM is restored, test that you receive calls/SMS.",
                "Unfreeze your account (requires an email OTP) and review recent transactions.",
                "Dispute any unauthorised transactions with the bank in writing within 24 hours.",
            ]},
            {"name": "Phase 4 — Report", "steps": [
                "File a report with the Nepal Police Cyber Bureau (Bhotahity, Kathmandu, or dial 100).",
                "Ask your operator for the SIM-change record (date, channel, agent) — it is evidence.",
                "Keep screenshots of alerts, SMS and transactions.",
            ]},
            {"name": "Phase 5 — Harden for the future", "steps": [
                "Set a SIM PIN and an operator account PIN so a swap needs more than an ID photocopy.",
                "Move OTPs to an authenticator app where the bank supports it.",
                "Turn on login and transaction alerts, and review SIMShield's risk score weekly.",
            ]},
        ],
    },
    "ne": {
        "title": "🚨 SIM-Swap घटना प्रतिक्रिया योजना",
        "subtitle": "चरणहरू क्रमैसँग गर्नुहोस्। SIM swap मा हरेक मिनेट महत्त्वपूर्ण छ।",
        "phases": [
            {"name": "चरण १ — नियन्त्रण (पहिलो १० मिनेट)", "steps": [
                "बैंक खाता फ्रिज गर्नुहोस् (SIMShield ड्यासबोर्ड → Freeze, वा बैंक हटलाइन)।",
                "मोबाइल अपरेटरलाई कल गर्नुहोस् (NTC १४९८ / Ncell ९००५ / Smart Cell ४२४२) र नयाँ SIM रोकेर आफ्नो फर्काउन भन्नुहोस्।",
                "कुनै पनि OTP स्वीकृत, साझा वा फर्वार्ड नगर्नुहोस् — नमागेको कोड आउनु भनेको आक्रमण भइरहेको संकेत हो।",
            ]},
            {"name": "चरण २ — पहुँच हटाउनुहोस्", "steps": [
                "भरपर्दो डिभाइसबाट मोबाइल-बैंकिङ र इमेलको पासवर्ड बदल्नुहोस्।",
                "इमेल र बैंकिङ एपका सबै सक्रिय सत्रहरू रद्द गर्नुहोस्।",
                "नचिनेका डिभाइसहरू खाताको सूचीबाट हटाउनुहोस्।",
            ]},
            {"name": "चरण ३ — पुनर्प्राप्ति", "steps": [
                "अपरेटरले SIM फर्कायो भनेपछि कल/SMS आउँछ कि जाँच्नुहोस्।",
                "खाता अनफ्रिज गर्नुहोस् (इमेल OTP चाहिन्छ) र पछिल्ला कारोबारहरू हेर्नुहोस्।",
                "अनधिकृत कारोबार भए २४ घण्टाभित्र बैंकमा लिखित उजुरी दिनुहोस्।",
            ]},
            {"name": "चरण ४ — उजुरी", "steps": [
                "नेपाल प्रहरी साइबर ब्युरो (भोटाहिटी, काठमाडौँ, वा १००) मा उजुरी दर्ता गर्नुहोस्।",
                "अपरेटरसँग SIM-परिवर्तनको विवरण (मिति, माध्यम, एजेन्ट) माग्नुहोस् — त्यो प्रमाण हो।",
                "अलर्ट, SMS र कारोबारका स्क्रिनसट सुरक्षित राख्नुहोस्।",
            ]},
            {"name": "चरण ५ — भविष्यका लागि सुरक्षा", "steps": [
                "SIM PIN र अपरेटर खाता PIN राख्नुहोस्, ताकि नागरिकताको फोटोकपीले मात्र swap नहोस्।",
                "बैंकले सपोर्ट गर्छ भने OTP लाई authenticator app मा सार्नुहोस्।",
                "लगइन/कारोबार अलर्ट अन गर्नुहोस् र SIMShield को जोखिम स्कोर साप्ताहिक हेर्नुहोस्।",
            ]},
        ],
    },
}


def get_playbook(lang: str = "en") -> dict:
    return _PLAYBOOK.get(lang, _PLAYBOOK["en"])
