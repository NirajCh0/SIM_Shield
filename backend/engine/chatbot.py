"""
SIMShield awareness chatbot — bilingual (English + Nepali), intent-based.

A deliberately transparent, rule-based NLU: each intent carries keyword sets
(English, Nepali script and romanised Nepali) and the best keyword-overlap
match wins. That keeps every answer auditable — important for a security
assistant — and needs no external service. Production could swap this matcher
for Rasa/Dialogflow behind the same reply() contract.

Capabilities required by the brief:
    * FAQs on SIM-swap risk, warning signs, protection, OTP safety
    * step-by-step recovery guidance (from the incident playbook)
    * explains the user's own latest ML/risk alert in plain language
    * escalation to the fraud team (creates an 'escalation' alert)
    * Nepali + English, switchable mid-conversation
Every exchange is logged to chat_logs (query, intent, response, timestamp).
"""
import json
import re

from . import db, playbook
from .awareness import EDUCATION

# --------------------------------------------------------------------------
# Intent definitions: keywords per language + response builders
# --------------------------------------------------------------------------

T = {
    "greeting": {
        "en": ("Namaste! 🙏 I'm the SIMShield assistant. Ask me about SIM-swap "
               "attacks, warning signs, how to protect yourself, what to do if "
               "you're attacked — or say “explain my alert” / “talk to the fraud team”."),
        "ne": ("नमस्ते! 🙏 म SIMShield सहायक हुँ। SIM-swap आक्रमण, खतराका संकेतहरू, "
               "आफूलाई कसरी सुरक्षित राख्ने, वा आक्रमण भएमा के गर्ने भनेर सोध्नुहोस् — "
               "अथवा “मेरो अलर्ट बुझाइदिनुहोस्” वा “fraud team सँग कुरा गर्छु” भन्नुहोस्।"),
    },
    "what_is": {
        "en": EDUCATION["what_is_sim_swap"],
        "ne": ("SIM-swap आक्रमण भनेको ठगले तपाईंको मोबाइल अपरेटर (NTC, Ncell, Smart Cell) "
               "लाई झुक्याएर तपाईंको नम्बर आफ्नो नयाँ SIM मा सार्नु हो। नम्बर उनीहरूको "
               "हातमा पुगेपछि बैंकले पठाउने OTP तपाईंकहाँ होइन, ठगकहाँ पुग्छ — र उनीहरूले "
               "तपाईंको खाता रित्याउन सक्छन्।"),
    },
    "signs_head": {"en": "⚠️ Warning signs of a SIM swap:",
                   "ne": "⚠️ SIM-swap भइरहेको खतराका संकेतहरू:"},
    "signs_ne": [
        "तपाईंको फोनको सिग्नल अचानक जान्छ र 'No Service' देखिन्छ।",
        "अरूले तपाईंको नम्बरमा घण्टी जान्छ भन्छन्, तर तपाईंलाई कल/SMS आउँदैन।",
        "'SIM activated' वा 'SIM change' जस्तो अनपेक्षित सन्देश आउँछ।",
        "बैंक एपले नयाँ ठाउँ/डिभाइसबाट लगइन भयो भनेर लगआउट गर्छ।",
    ],
    "protect_head": {"en": "🔒 How to protect yourself:",
                     "ne": "🔒 आफूलाई कसरी सुरक्षित राख्ने:"},
    "protect_ne": [
        "SIM PIN लगाउनुहोस् र अपरेटरमा छुट्टै खाता PIN राख्नुहोस्।",
        "सम्भव भएसम्म SMS OTP भन्दा authenticator app प्रयोग गर्नुहोस्।",
        "OTP कहिल्यै कसैलाई नभन्नुहोस् — बैंक/टेलिकमको नाम लिएर मागे पनि।",
        "मोबाइल सेवा अचानक गए तुरुन्तै अपरेटर र बैंकलाई फोन गर्नुहोस्।",
        "बैंकिङ एपमा लगइन/कारोबार अलर्ट अन गर्नुहोस्।",
    ],
    "otp": {
        "en": ("Never share an OTP with anyone — not your bank, not your telecom, "
               "not SIMShield staff. A real institution will NEVER ask for it. If "
               "someone asks for a code, it is a scam: hang up and call your bank's "
               "official number."),
        "ne": ("OTP कहिल्यै कसैसँग साझा नगर्नुहोस् — बैंक, टेलिकम वा SIMShield कर्मचारी "
               "भनेर आए पनि। साँचो संस्थाले OTP कहिल्यै माग्दैन। कसैले कोड माग्यो भने "
               "त्यो ठगी हो: फोन काट्नुहोस् र बैंकको आधिकारिक नम्बरमा कल गर्नुहोस्।"),
    },
    "escalated": {
        "en": ("✅ I've escalated your case to the fraud team with your recent account "
               "activity attached. They treat SIM-swap escalations as urgent. Meanwhile: "
               "1) consider freezing your account from the dashboard, 2) call your "
               "operator to check your SIM status, 3) don't approve any OTP you didn't request."),
        "ne": ("✅ तपाईंको केस fraud टोलीमा पठाइयो। SIM-swap केसलाई उनीहरूले अत्यावश्यक "
               "रूपमा हेर्छन्। यसबीच: १) ड्यासबोर्डबाट खाता फ्रिज गर्ने विचार गर्नुहोस्, "
               "२) SIM स्थिति जाँच्न अपरेटरलाई कल गर्नुहोस्, ३) आफूले नमागेको OTP कहिल्यै "
               "स्वीकृत नगर्नुहोस्।"),
    },
    "escalate_anon": {
        "en": ("To escalate to the fraud team I need you to be signed in, so the team "
               "can see your account. Please sign in and ask me again — or call the "
               "bank hotline / Nepal Police Cyber Bureau (see “contacts”)."),
        "ne": ("Fraud टोलीमा पठाउन तपाईं साइन-इन हुनुपर्छ, ताकि टोलीले तपाईंको खाता "
               "हेर्न सकोस्। कृपया साइन-इन गरेर फेरि भन्नुहोस् — वा बैंक हटलाइन / "
               "नेपाल प्रहरी साइबर ब्युरोमा सम्पर्क गर्नुहोस् (“contacts” भन्नुहोस्)।"),
    },
    "contacts": {
        "en": ("📞 Useful contacts (Nepal):\n"
               "• NTC customer care: 1498\n• Ncell: 9005 (from Ncell) / 980-555-0505\n"
               "• Smart Cell: 4242\n• Nepal Police Cyber Bureau: 100 / bureau at Bhotahity, Kathmandu\n"
               "• Your bank's card/account block hotline is printed on the back of your card.\n"
               "(Demo note: verify current numbers with the operator's official site.)"),
        "ne": ("📞 उपयोगी सम्पर्कहरू (नेपाल):\n"
               "• NTC ग्राहक सेवा: १४९८\n• Ncell: ९००५ (Ncell बाट) / ९८०-५५५-०५०५\n"
               "• Smart Cell: ४२४२\n• नेपाल प्रहरी साइबर ब्युरो: १०० / भोटाहिटी, काठमाडौँ\n"
               "• बैंकको ब्लक हटलाइन कार्डको पछाडि छापिएको हुन्छ।\n"
               "(डेमो नोट: आधिकारिक साइटबाट हालका नम्बरहरू पुष्टि गर्नुहोस्।)"),
    },
    "no_alerts": {
        "en": ("Good news — you have no open alerts right now. Your account posture "
               "is shown as the risk score on your dashboard; ask me “why is my risk "
               "score high?” anytime."),
        "ne": ("शुभ समाचार — अहिले तपाईंको कुनै खुला अलर्ट छैन। तपाईंको खाताको जोखिम "
               "स्कोर ड्यासबोर्डमा देखिन्छ; “मेरो जोखिम स्कोर किन उच्च छ?” भनेर जहिले पनि "
               "सोध्न सक्नुहुन्छ।"),
    },
    "signin_for_alerts": {
        "en": "Sign in first and I can read your own alerts and explain them in plain language.",
        "ne": "पहिला साइन-इन गर्नुहोस्, अनि म तपाईंकै अलर्टहरू पढेर सरल भाषामा बुझाइदिन्छु।",
    },
    "fallback": {
        "en": ("I'm not sure I understood. I can explain: “what is a SIM swap”, "
               "“warning signs”, “how to protect myself”, “what to do if attacked”, "
               "“is OTP safe to share”, “explain my alert”, “recovery steps”, "
               "“contacts”, or “escalate to the fraud team”. "
               "नेपालीमा सोध्न 'नेपाली' लेख्नुहोस्।"),
        "ne": ("माफ गर्नुहोस्, बुझिनँ। म यी कुरा बताउन सक्छु: “SIM swap के हो”, "
               "“खतराका संकेत”, “कसरी सुरक्षित रहने”, “आक्रमण भए के गर्ने”, "
               "“OTP साझा गर्न हुन्छ?”, “मेरो अलर्ट बुझाऊ”, “रिकभरी चरणहरू”, "
               "“सम्पर्क”, वा “fraud team लाई पठाऊ”। To switch back, type 'english'."),
    },
}

INTENTS = [
    {"name": "lang_ne", "kw": ["नेपाली", "nepali", "nepalima", "नेपालीमा"]},
    {"name": "lang_en", "kw": ["english", "angreji", "अंग्रेजी"]},
    {"name": "greeting", "kw": ["hello", "hi", "hey", "namaste", "नमस्ते", "namaskar"]},
    {"name": "escalate", "kw": ["escalate", "fraud team", "human", "agent", "report fraud",
                                "complaint", "help me now", "hacked", "attack happening",
                                "उजुरी", "टोली", "मान्छे", "एजेन्ट", "ह्याक"]},
    {"name": "explain_alert", "kw": ["my alert", "explain alert", "why flagged", "why blocked",
                                     "risk score", "my score", "alert mean", "मेरो अलर्ट",
                                     "किन", "स्कोर", "जोखिम"]},
    {"name": "recovery", "kw": ["attacked", "recover", "recovery", "victim", "lost my number",
                                "sim swapped", "what to do if", "steps", "playbook",
                                "आक्रमण भयो", "के गर्ने", "चरण", "रिकभरी", "नम्बर गयो"]},
    {"name": "otp", "kw": ["otp", "code", "one time", "share otp", "ओटीपी", "कोड"]},
    {"name": "signs", "kw": ["warning", "signs", "symptom", "no service", "signal",
                             "how do i know", "detect", "संकेत", "चिन्ह", "सिग्नल"]},
    {"name": "protect", "kw": ["protect", "prevent", "safe", "safety", "avoid", "secure",
                               "सुरक्षित", "बचाव", "रोक"]},
    {"name": "what_is", "kw": ["what is", "sim swap", "simswap", "sim-swap", "explain sim",
                               "attack", "के हो", "भनेको"]},
    {"name": "contacts", "kw": ["contact", "number", "phone", "police", "cyber bureau",
                                "hotline", "ntc", "ncell", "सम्पर्क", "प्रहरी", "नम्बर"]},
    {"name": "freeze", "kw": ["freeze", "lock account", "block account", "फ्रिज", "खाता बन्द"]},
]


def _match_intent(text: str) -> str:
    t = text.lower().strip()
    best, best_score = "fallback", 0
    for intent in INTENTS:
        score = sum(1 for kw in intent["kw"] if kw in t)
        # bigram keywords count double (more specific)
        score += sum(1 for kw in intent["kw"] if " " in kw and kw in t)
        if score > best_score:
            best, best_score = intent["name"], score
    return best


def _bullets(head: str, items: list[str]) -> str:
    return head + "\n" + "\n".join(f"• {i}" for i in items)


def _explain_alert(user: dict, lang: str) -> str:
    alert = db.query_one(
        "SELECT * FROM alerts WHERE user_id = ? ORDER BY created_at DESC LIMIT 1",
        (user["id"],))
    if not alert:
        return T["no_alerts"][lang]
    meta = json.loads(alert["meta"] or "{}")
    reasons = meta.get("reasons") or []
    if lang == "ne":
        out = (f"तपाईंको पछिल्लो अलर्ट ({alert['created_at']}): {alert['message']}\n"
               f"स्थिति: {alert['status']} · गम्भीरता: {alert['severity']}")
        if reasons:
            out += "\nकारणहरू:\n" + "\n".join(f"• {r}" for r in reasons)
        out += ("\nयो स्कोर नियम-आधारित जाँच र मेसिन-लर्निङ मोडेल मिलाएर निकालिएको हो — "
                "यसले तपाईंलाई दण्ड दिँदैन, केवल थप प्रमाणीकरण माग्छ।")
        return out
    out = (f"Your latest alert ({alert['created_at']}): {alert['message']}\n"
           f"Status: {alert['status']} · severity: {alert['severity']}")
    if reasons:
        out += "\nReasons the system saw:\n" + "\n".join(f"• {r}" for r in reasons)
    out += ("\nThis score fuses transparent rules with two ML models (a Random "
            "Forest and an Isolation Forest). A high score never punishes you — "
            "it only asks for extra verification, and a human reviews escalations.")
    return out


def _recovery(lang: str) -> str:
    pb = playbook.get_playbook(lang)
    lines = [pb["title"]]
    for phase in pb["phases"]:
        lines.append(f"\n{phase['name']}")
        lines += [f"{i+1}. {s}" for i, s in enumerate(phase["steps"])]
    return "\n".join(lines)


def reply(message: str, user: dict | None = None, lang: str = "en") -> dict:
    """
    Answer one chat message. `user` is the signed-in user row or None.
    Returns {reply, intent, lang, escalated} and logs the exchange.
    """
    lang = lang if lang in ("en", "ne") else "en"
    intent = _match_intent(message or "")
    escalated = False

    if intent == "lang_ne":
        lang, text = "ne", "हुन्छ, अब म नेपालीमा जवाफ दिन्छु। के जान्न चाहनुहुन्छ?"
    elif intent == "lang_en":
        lang, text = "en", "Sure — switching to English. What would you like to know?"
    elif intent == "greeting":
        text = T["greeting"][lang]
    elif intent == "what_is":
        text = T["what_is"][lang]
    elif intent == "signs":
        items = T["signs_ne"] if lang == "ne" else EDUCATION["warning_signs"]
        text = _bullets(T["signs_head"][lang], items)
    elif intent == "protect":
        items = T["protect_ne"] if lang == "ne" else EDUCATION["protect_yourself"]
        text = _bullets(T["protect_head"][lang], items)
    elif intent == "otp":
        text = T["otp"][lang]
    elif intent == "recovery":
        text = _recovery(lang)
    elif intent == "contacts":
        text = T["contacts"][lang]
    elif intent == "freeze":
        text = ("You can freeze your account instantly from your dashboard "
                "(Settings → Freeze account). While frozen, every transaction is "
                "refused. Unfreezing requires an email OTP." if lang == "en" else
                "ड्यासबोर्ड (Settings → Freeze account) बाट तुरुन्तै खाता फ्रिज गर्न "
                "सक्नुहुन्छ। फ्रिज हुँदा सबै कारोबार अस्वीकार हुन्छ। अनफ्रिज गर्न "
                "इमेल OTP चाहिन्छ।")
    elif intent == "explain_alert":
        text = _explain_alert(user, lang) if user else T["signin_for_alerts"][lang]
    elif intent == "escalate":
        if user:
            db.add_alert(user["id"], "escalation",
                         f"User requested fraud-team review via chatbot: “{message[:200]}”",
                         severity="critical", status="escalated")
            text, escalated = T["escalated"][lang], True
        else:
            text = T["escalate_anon"][lang]
    else:
        text = T["fallback"][lang]

    db.execute(
        "INSERT INTO chat_logs (user_id, lang, query, intent, response, escalated, created_at) "
        "VALUES (?,?,?,?,?,?,?)",
        (user["id"] if user else None, lang, (message or "")[:500], intent,
         text[:2000], 1 if escalated else 0, db.now()))
    return {"reply": text, "intent": intent, "lang": lang, "escalated": escalated}


def history(user_id: int, limit: int = 30) -> list[dict]:
    return db.query_all(
        "SELECT lang, query, intent, response, created_at FROM chat_logs "
        "WHERE user_id = ? ORDER BY id DESC LIMIT ?", (user_id, limit))[::-1]
