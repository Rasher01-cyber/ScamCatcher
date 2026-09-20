"""Rule-based + optional ML fraud risk analysis for UPI Guard."""

from __future__ import annotations

import re
from typing import Any

import database as db

# Optional ML — loaded lazily so the site works without a trained model.
_ml_predict = None


def _load_ml():
    global _ml_predict
    if _ml_predict is not None:
        return _ml_predict
    try:
        from ml.model import predict_risk_score

        _ml_predict = predict_risk_score
    except Exception:
        _ml_predict = False
    return _ml_predict


UPI_PATTERN = re.compile(
    r"^[a-zA-Z0-9.\-_]{2,256}@[a-zA-Z]{2,64}$"
)

# Common Indian UPI PSP / bank handles (not exhaustive).
KNOWN_PSPS = {
    "ybl", "oksbi", "okaxis", "okhdfcbank", "okicici", "paytm", "ibl", "axl",
    "upi", "apl", "waaxis", "waicici", "wahdfcbank", "jupiteraxis", "kb",
    "yesbank", "yesbankltd", "cnrb", "cub", "federal", "sbi", "okbizaxis",
    "pingpay", "pz", "tapicici", "timecosmos", "abfspay", "idfcbank",
    "hsbc", "barodampay", "rbl", "kotak", "indus", "freecharge", "amazonpay",
    "gpay", "googlepay", "phonepe", "bhim",
}

# Handles that look invented for social-engineering (not proof of non-existence).
FABRICATED_HINTS = {
    "refund", "lottery", "prize", "kyc", "support", "helpline", "cashback",
    "reward", "otp", "verify", "update", "secure", "official", "bankcare",
    "customercare", "claim", "winner", "bonus", "offer", "free", "govt",
    "income", "tax", "rbi", "npci", "police", "cyber", "award",
}

SUSPICIOUS_HANDLES = set(FABRICATED_HINTS)

FAKE_LOOKING_HANDLES = {
    "npci", "rbi", "gov", "government", "incometax", "gst", "uidai", "aadhaar",
    "police", "cybercrime", "ministry", "pmcare", "incometaxindia",
}

INDIAN_MOBILE_RE = re.compile(r"^(?:\+91[\-\s]?|91[\-\s]?|0)?([6-9]\d{9})$")

VERIFY_STEPS_UPI = [
    "Open your official bank / UPI app and enter the UPI ID — do not pay yet.",
    "On the confirmation screen, carefully read the payee name shown by the bank.",
    "Match that name with the real person/merchant you intend to pay (call them if unsure).",
    "If the app says 'invalid UPI ID' / 'no such user', the ID is not registered (never invented or mistyped).",
    "Never trust only a screenshot — fake apps and edited images are common.",
]

VERIFY_STEPS_QR = [
    "Scan with your official UPI app (GPay / PhonePe / BHIM / bank app), not a random camera app.",
    "Before entering PIN, check payee name + UPI ID on the payment screen.",
    "Prefer printed merchant QR boards over QR images sent on WhatsApp.",
    "If payee name does not match the shop/person, cancel immediately.",
]

VERIFY_STEPS_MOBILE = [
    "Call the number from your contacts / a known channel — do not rely on SMS alone.",
    "Ask them to share their UPI ID live, then confirm the name that appears in your UPI app.",
    "Indian mobiles are 10 digits starting with 6–9; odd formats are often fake.",
    "Do not send money to 'verify' a mobile number.",
]

SUSPICIOUS_MESSAGE_PATTERNS = [
    (r"\botp\b", "Asks for OTP — banks never ask for OTP over chat"),
    (r"urgent|immediately|within\s+\d+\s*(hour|min)", "uses urgency pressure tactics"),
    (r"kyc\s*(update|expire|block)", "fake KYC / account-block threat"),
    (r"lottery|won\s+(a\s+)?prize|congratulations.*won", "lottery / prize scam language"),
    (r"send\s+(money|rs|₹|amount)|pay\s+(first|now)", "asks you to send money first"),
    (r"click\s+(this\s+)?link|bit\.ly|tinyurl", "suspicious short / external link"),
    (r"refund\s+(process|pending|claim)", "fake refund lure"),
    (r"share\s+(your\s+)?(pin|password|cvv)", "asks for PIN/password/CVV"),
    (r"account\s+(will\s+be\s+)?(blocked|suspended)", "fear of account suspension"),
    (r"verify\s+upi|confirm\s+upi", "UPI verification phishing"),
]

HIGH_AMOUNT = 10000
MEDIUM_AMOUNT = 2000


def normalize_upi(upi_id: str) -> str:
    return (upi_id or "").strip().lower()


def is_valid_upi_format(upi_id: str) -> bool:
    return bool(UPI_PATTERN.match(upi_id.strip()))


def normalize_mobile(raw: str) -> str:
    digits = re.sub(r"\D", "", raw or "")
    if digits.startswith("91") and len(digits) == 12:
        digits = digits[2:]
    if digits.startswith("0") and len(digits) == 11:
        digits = digits[1:]
    return digits


def is_valid_indian_mobile(mobile: str) -> bool:
    return bool(re.fullmatch(r"[6-9]\d{9}", mobile or ""))


def _level_from_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 35:
        return "medium"
    if score >= 15:
        return "low"
    return "safe"


def _authenticity_for_upi(
    upi: str,
    handle: str,
    psp: str,
    format_ok: bool,
    *,
    known: dict | None = None,
    report_count: int = 0,
    fake_signals: list[str] | None = None,
    live: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Explain format vs existence vs genuineness (live API or in-app confirm)."""
    fake_signals = fake_signals or []
    live = live or {}
    psp_known = psp in KNOWN_PSPS
    live_exists = live.get("exists")  # True / False / None
    live_name = live.get("payee_name")
    live_checked = bool(live.get("checked_live"))
    live_provider = live.get("provider")
    name_matches = live.get("name_matches")  # True / False / None
    source = live.get("source") or ("api" if live_provider and live_provider != "upi_app_confirm" else "pending")

    if not format_ok:
        status = "invalid_format"
        label = "Invalid format — never a real UPI ID"
        existence = "cannot_exist"
        existence_label = "Not generated / cannot exist (bad format)"
        genuine = "not_genuine_format"
        genuine_label = "Not a genuine UPI ID structure"
        summary = (
            "This string does not follow username@bankhandle rules, so it was never a "
            "valid UPI ID. Fix the typing or ask the payee again."
        )
        exist_ok: bool | None = False
        exist_detail = (
            "Confirmed by format rules: this cannot be registered on UPI."
        )
    elif live_checked and live_exists is False:
        status = "not_registered"
        label = "Not registered on UPI"
        existence = "not_registered"
        existence_label = "Never generated / not in use on UPI"
        genuine = "not_genuine"
        genuine_label = "Not a live payee"
        summary = (
            f"Check via {live_provider or 'verification'} says this VPA is invalid "
            "or not registered — it has not been generated for use."
        )
        exist_ok = False
        exist_detail = live.get("raw_message") or "VPA not registered."
    elif live_checked and live_exists is True:
        if known or fake_signals or name_matches is False:
            status = "exists_but_risky"
            label = "Registered on UPI — but not safe as genuine payee"
            existence = "registered"
            existence_label = f"Exists / in use (name: {live_name or 'shown in app'})"
            genuine = "likely_not_safe"
            genuine_label = (
                "Name does not match who you intend to pay"
                if name_matches is False
                else "Exists, but risk signals / unverified match"
            )
            summary = (
                "The ID is real on the UPI network, but it is not safe to treat as your "
                "intended genuine payee until the name matches."
            )
        else:
            status = "registered"
            label = "Registered on UPI — existence confirmed"
            existence = "registered"
            existence_label = f"Exists / in use — linked name: {live_name or '(confirmed in app)'}"
            if name_matches is True:
                genuine = "confirmed_match"
                genuine_label = f"Genuine match confirmed — “{live_name or 'payee'}”"
                summary = (
                    "Existence confirmed and you verified the payee name matches the "
                    "real person/merchant."
                )
            else:
                genuine = "name_available"
                genuine_label = (
                    f"Bank-linked name: {live_name}" if live_name else "Confirm name match below"
                )
                summary = (
                    "Existence confirmed. Complete the genuine-person check by confirming "
                    "the name matches who you want to pay."
                )
        exist_ok = True
        exist_detail = live.get("raw_message") or f"Registered via {live_provider}."
        if live_name:
            exist_detail += f" Payee name: {live_name}."
    elif not psp_known:
        status = "unknown_provider"
        label = "Bank/PSP handle looks unknown or invented"
        existence = "unlikely_registered"
        existence_label = "Likely never generated (unknown @provider)"
        genuine = "suspicious"
        genuine_label = "Provider part looks fake / uncommon"
        summary = (
            f"The part after @ (`{psp}`) is not a common UPI provider. "
            "Most never-generated scam IDs invent fake bank handles."
        )
        exist_ok = False
        exist_detail = (
            f"`@{psp}` is not in the known-provider list — treat as not generated."
        )
    elif known or report_count >= 1 or fake_signals:
        status = "suspicious_or_reported"
        label = "Looks risky — treat as not trustworthy"
        existence = "unknown_or_risky"
        existence_label = "May exist, but trustworthiness is poor"
        genuine = "likely_not_safe"
        genuine_label = "Not safe to treat as genuine payee"
        summary = (
            "Format may be valid, but warning signs / reports suggest fraud patterns. "
            "A scammer can register a real UPI ID — 'exists' ≠ 'safe'."
        )
        exist_ok = None if not live_checked else live_exists
        exist_detail = (
            live.get("raw_message")
            if live_checked
            else "Complete the in-app confirmation below to resolve existence."
        )
    else:
        status = "format_plausible"
        label = "Format OK — confirm existence below"
        existence = "unknown_live"
        existence_label = "Awaiting live / in-app confirmation"
        genuine = "unverified"
        genuine_label = "Awaiting name match confirmation"
        summary = (
            "Format and provider look correct. Complete the two steps below "
            "(or add Razorpay/Cashfree keys) to resolve the remaining checks."
        )
        exist_ok = None
        exist_detail = (
            live.get("raw_message")
            if live.get("error") == "api_not_configured"
            else "Use Confirm below (UPI app) or enable live API in Setup."
        )

    # Genuine person check — resolved when user confirms name match or risk says no
    if not format_ok or live_exists is False or (not psp_known and not live_checked):
        genuine_ok: bool | None = False
        genuine_detail = genuine_label
    elif name_matches is True and live_exists is True:
        genuine_ok = True
        genuine_detail = (
            f"You confirmed the name “{live_name or 'payee'}” matches the real person/merchant."
        )
    elif name_matches is False:
        genuine_ok = False
        genuine_detail = "You reported the name does NOT match — treat as not genuine for this payment."
    elif fake_signals or known:
        genuine_ok = False
        genuine_detail = "Risk signals suggest this is not a trustworthy payee."
    elif live_name and live_exists is True:
        genuine_ok = None
        genuine_detail = (
            f"Name on record: “{live_name}”. Confirm below whether this is who you intend to pay."
        )
    else:
        genuine_ok = None
        genuine_detail = (
            "Open your UPI app, read the payee name, then confirm below whether it matches."
        )

    checks = [
        {
            "name": "Format / correct UPI structure",
            "ok": format_ok,
            "detail": (
                "Correct username@provider pattern"
                if format_ok
                else "Incorrect pattern — cannot be a generated UPI ID"
            ),
        },
        {
            "name": "Provider (after @) check",
            "ok": format_ok and psp_known,
            "detail": (
                f"`@{psp}` is a known UPI provider"
                if psp_known
                else f"`@{psp}` is uncommon — often invented / never generated"
            ),
        },
        {
            "name": "Fraud / keyword check",
            "ok": not fake_signals and not known,
            "detail": (
                "No strong fake-keyword or blacklist hit"
                if not fake_signals and not known
                else "; ".join(fake_signals[:3]) or (known or {}).get("reason", "Listed as risky")
            ),
        },
        {
            "name": "Live existence on UPI network (generated / in use?)",
            "ok": exist_ok,
            "detail": exist_detail,
        },
        {
            "name": "Genuine person / merchant",
            "ok": genuine_ok,
            "detail": genuine_detail,
        },
    ]

    mobile_link = None
    if format_ok and re.fullmatch(r"[6-9]\d{9}", handle):
        mobile_link = {
            "mobile": handle,
            "note": (
                "This UPI ID is mobile-number based (common). Still verify the name that "
                "appears in your app — anyone can create number@ybl style IDs."
            ),
        }

    from verification_api import verification_status

    api_status = verification_status()
    needs_confirm = format_ok and (exist_ok is None or genuine_ok is None)

    return {
        "status": status,
        "label": label,
        "existence": existence,
        "existence_label": existence_label,
        "genuine": genuine,
        "genuine_label": genuine_label,
        "summary": summary,
        "psp_known": psp_known,
        "checks": checks,
        "how_to_verify": VERIFY_STEPS_UPI,
        "mobile_link": mobile_link,
        "live": live,
        "payee_name_live": live_name,
        "api_status": api_status,
        "needs_confirm": needs_confirm,
        "exist_ok": exist_ok,
        "genuine_ok": genuine_ok,
        "confirm_source": source,
        "limitation": (
            "Live existence: Razorpay/Cashfree API (Setup page) OR confirm from your UPI app below. "
            + api_status["setup_hint"]
        ),
    }

def analyze_upi(upi_id: str, manual_live: dict[str, Any] | None = None) -> dict[str, Any]:
    upi = normalize_upi(upi_id)
    warnings: list[str] = []
    score = 0
    fake_signals: list[str] = []

    if not upi:
        auth = _authenticity_for_upi("", "", "", False)
        return {
            "valid": False,
            "upi_id": upi,
            "risk_score": 0,
            "risk_level": "unknown",
            "warnings": ["UPI ID is required."],
            "explanations": [],
            "recommendations": ["Enter a UPI ID like name@oksbi or merchant@paytm."],
            "authenticity": auth,
        }

    if not is_valid_upi_format(upi):
        auth = _authenticity_for_upi(upi, upi, "", False)
        return {
            "valid": False,
            "upi_id": upi,
            "risk_score": 70,
            "risk_level": "high",
            "warnings": ["UPI ID format looks invalid — this cannot be a real registered VPA."],
            "explanations": [
                "A real UPI ID looks like username@bankhandle (e.g. rahul@oksbi or 98XXXXXXXX@ybl).",
                "If your bank app also rejects it, the ID was never invented/registered or is mistyped.",
            ],
            "recommendations": [
                "Ask the payee to share the ID again carefully.",
                "Confirm inside your official UPI app before paying.",
            ],
            "authenticity": auth,
        }

    handle, psp = upi.split("@", 1)

    # Live gateway check (Razorpay / Cashfree) when API keys are configured
    live: dict[str, Any] = {"checked_live": False, "exists": None}
    try:
        from verification_api import validate_upi_live

        live = validate_upi_live(upi)
    except Exception as exc:
        live = {
            "success": False,
            "exists": None,
            "payee_name": None,
            "checked_live": False,
            "error": "exception",
            "raw_message": str(exc),
        }

    # In-app / manual confirmation overrides or fills gaps when API is off
    if manual_live:
        if manual_live.get("exists") is not None:
            live["exists"] = bool(manual_live["exists"])
            live["checked_live"] = True
            live["provider"] = live.get("provider") or "upi_app_confirm"
            live["source"] = "upi_app_confirm"
            live["raw_message"] = manual_live.get("raw_message") or (
                "Confirmed from your UPI app response."
                if live["exists"]
                else "Your UPI app reported this ID as invalid / not registered."
            )
        if manual_live.get("payee_name"):
            live["payee_name"] = str(manual_live["payee_name"]).strip()
        if "name_matches" in manual_live:
            live["name_matches"] = manual_live["name_matches"]
            live["checked_live"] = True
            live["provider"] = live.get("provider") or "upi_app_confirm"
            if live.get("exists") is None and live["name_matches"] is not None:
                # If they saw a name, it exists
                if live["name_matches"] is True or live.get("payee_name"):
                    live["exists"] = True
                    live["raw_message"] = live.get("raw_message") or (
                        "Existence inferred: UPI app showed a payee name."
                    )

    if live.get("checked_live") and live.get("exists") is False:
        score += 45
        warnings.append("Live check: UPI ID is NOT registered / never generated")
        fake_signals.append("Live lookup: not registered")
    elif live.get("checked_live") and live.get("exists") is True:
        name = live.get("payee_name")
        warnings.append(
            "Live check: UPI ID is registered"
            + (f" (name: {name})" if name else "")
        )
    if live.get("name_matches") is False:
        score += 25
        warnings.append("Payee name does not match who you intend to pay")
        fake_signals.append("Name mismatch — not genuine for this payment")

    known = db.get_known_risk(upi)
    if known:
        score += 70
        msg = f"Listed in risk database: {known['reason']}"
        warnings.append(msg)
        fake_signals.append(msg)

    report_count = db.count_reports_for_upi(upi)
    if report_count >= 3:
        score += 35
        warnings.append(f"Reported {report_count} times by community users")
        fake_signals.append("Multiple community fraud reports")
    elif report_count >= 1:
        score += 18
        warnings.append(f"Has {report_count} community report(s) pending/verified")

    for word in SUSPICIOUS_HANDLES:
        if word in handle:
            score += 12
            msg = f"Handle contains suspicious keyword: '{word}'"
            warnings.append(msg)
            fake_signals.append(msg)
            break

    for word in FAKE_LOOKING_HANDLES:
        if word in handle or word == psp:
            score += 25
            msg = f"Uses government/authority-looking word '{word}' (often fake)"
            warnings.append(msg)
            fake_signals.append(msg)
            break

    if re.search(r"\d{6,}", handle) and not re.fullmatch(r"[6-9]\d{9}", handle):
        score += 8
        warnings.append("Handle contains a long digit sequence (often auto-generated)")

    if len(handle) <= 3:
        score += 10
        warnings.append("Very short UPI handle — harder to verify identity")

    if psp not in KNOWN_PSPS:
        score += 22
        warnings.append(f"Provider `@{psp}` is uncommon — may be invented")
        fake_signals.append(f"Unknown provider @{psp}")
    elif len(psp) < 2:
        score += 15
        warnings.append("Unusual payment service provider (PSP) handle")

    if re.search(r"(official|secure|verify|support)", handle):
        score += 10
        msg = "Handle impersonates official/support branding"
        warnings.append(msg)
        fake_signals.append(msg)

    ml_fn = _load_ml()
    ml_score = None
    if callable(ml_fn):
        try:
            ml_score = int(ml_fn(upi, amount=0.0, message=""))
            # Blend lightly so rules remain primary for awareness UX
            score = int(round(0.75 * min(score, 100) + 0.25 * ml_score))
            warnings.append(f"ML model suggested risk contribution (~{ml_score})")
        except Exception:
            ml_score = None

    score = max(0, min(100, score))
    level = _level_from_score(score)
    authenticity = _authenticity_for_upi(
        upi,
        handle,
        psp,
        True,
        known=known,
        report_count=report_count,
        fake_signals=fake_signals,
        live=live,
    )

    explanations = list(warnings) if warnings else [
        "No strong warning signs found in format, database, or keyword checks."
    ]
    explanations.append(authenticity["summary"])
    recommendations = _recommendations(level)
    if live.get("checked_live") and live.get("exists") is True:
        recommendations = [
            f"Live name from gateway: {live.get('payee_name') or '(not returned)'} — match it with your real payee.",
            *recommendations,
        ]
    elif live.get("checked_live") and live.get("exists") is False:
        recommendations = [
            "Do not pay — live check says this UPI ID was never registered.",
            *recommendations,
        ]
    else:
        recommendations = [
            "To confirm if generated: add Razorpay/Cashfree keys in .env, or type the ID in your UPI app.",
            *recommendations,
        ]

    return {
        "valid": True,
        "upi_id": upi,
        "handle": handle,
        "psp": psp,
        "risk_score": score,
        "risk_level": level,
        "warnings": warnings,
        "explanations": explanations,
        "recommendations": recommendations,
        "report_count": report_count,
        "known_match": known,
        "ml_score": ml_score,
        "authenticity": authenticity,
    }


def analyze_transaction(
    upi_id: str,
    amount: float,
    manual_live: dict[str, Any] | None = None,
) -> dict[str, Any]:
    base = analyze_upi(upi_id, manual_live=manual_live)
    warnings = list(base.get("warnings", []))
    score = int(base.get("risk_score", 0))
    explanations = list(base.get("explanations", []))

    try:
        amount = float(amount)
    except (TypeError, ValueError):
        amount = 0.0

    if amount <= 0:
        warnings.append("Amount missing or invalid")
        explanations.append("Enter the intended payment amount for better risk context.")
        score = min(100, score + 5)
    else:
        if amount >= HIGH_AMOUNT:
            score = min(100, score + 25)
            warnings.append(f"High-value transfer (₹{amount:,.0f})")
            explanations.append(
                "Large first-time payments to unknown UPI IDs are a common fraud pattern."
            )
        elif amount >= MEDIUM_AMOUNT:
            score = min(100, score + 12)
            warnings.append(f"Elevated amount (₹{amount:,.0f})")
            explanations.append(
                "Medium-to-large amounts deserve extra verification of the payee."
            )

        if amount in {1, 2, 3} or (0 < amount < 5):
            score = min(100, score + 15)
            warnings.append("Tiny 'test' payment amount")
            explanations.append(
                "Scammers sometimes ask for ₹1–₹5 to 'verify' your UPI — decline and report."
            )

    ml_fn = _load_ml()
    if callable(ml_fn) and base.get("valid"):
        try:
            ml_score = int(ml_fn(base["upi_id"], amount=amount, message=""))
            score = int(round(0.7 * score + 0.3 * ml_score))
            base["ml_score"] = ml_score
        except Exception:
            pass

    score = max(0, min(100, score))
    level = _level_from_score(score)
    if not warnings and base.get("valid"):
        explanations = [
            "Transaction details did not trigger strong rule-based warnings."
        ]

    return {
        **base,
        "amount": amount,
        "risk_score": score,
        "risk_level": level,
        "warnings": warnings,
        "explanations": explanations or warnings,
        "recommendations": [
            "To know if the payee exists: enter the UPI ID in your app and match the displayed name.",
            *_recommendations(level),
        ],
        "check_type": "transaction",
        "authenticity": base.get("authenticity"),
    }


def analyze_mobile(raw_mobile: str) -> dict[str, Any]:
    """Check Indian mobile format + fake-looking patterns (not a telecom lookup)."""
    original = (raw_mobile or "").strip()
    mobile = normalize_mobile(original)
    warnings: list[str] = []
    explanations: list[str] = []
    score = 0
    format_ok = is_valid_indian_mobile(mobile)

    if not original:
        return {
            "valid": False,
            "check_type": "mobile",
            "mobile": "",
            "risk_score": 0,
            "risk_level": "unknown",
            "warnings": ["Mobile number is required."],
            "explanations": [],
            "recommendations": ["Enter a 10-digit Indian mobile number."],
            "authenticity": {
                "status": "missing",
                "label": "No number provided",
                "existence_label": "Unknown",
                "genuine_label": "Unknown",
                "summary": "Enter a mobile number to analyse.",
                "checks": [],
                "how_to_verify": VERIFY_STEPS_MOBILE,
                "limitation": (
                    "This tool cannot query telecom operators to prove a number is allotted."
                ),
                "suggested_upi_ids": [],
            },
        }

    if not format_ok:
        score = 75
        warnings.append("Not a valid Indian mobile format (need 10 digits starting 6–9)")
        explanations.append(
            "Fake messages often use wrong-length numbers, landline-looking strings, or random digits."
        )
        existence_label = "Cannot be a normal Indian mobile"
        genuine_label = "Format looks fake / invalid"
        status = "invalid_format"
        label = "Invalid mobile format"
        summary = (
            "This does not look like a real Indian mobile number, so treat related UPI / OTP "
            "requests as highly suspicious."
        )
    else:
        # Pattern heuristics
        if len(set(mobile)) == 1:
            score += 40
            warnings.append("All digits are the same (often fabricated)")
        if mobile in {"9876543210", "1234567890", "9999999999", "8888888888", "7777777777"}:
            score += 35
            warnings.append("Number matches a commonly faked / example pattern")
        if re.search(r"(0123456789|9876543210|123456789)", mobile):
            score += 30
            warnings.append("Sequential digit pattern looks invented")
        if mobile[:3] * 3 + mobile[9:] == mobile:  # weak repeated prefix
            pass
        # Same digit repeated 5+ times
        if re.search(r"(\d)\1{4,}", mobile):
            score += 20
            warnings.append("Long run of repeated digits")

        # Check if this mobile appears in known risky UPIs
        related_hits = 0
        for psp in ("ybl", "oksbi", "paytm", "axl", "ibl"):
            hit = db.get_known_risk(f"{mobile}@{psp}")
            if hit:
                related_hits += 1
                warnings.append(f"Related UPI `{mobile}@{psp}` is in the risk database")
        if related_hits:
            score += 40

        report_hits = sum(
            db.count_reports_for_upi(f"{mobile}@{psp}")
            for psp in ("ybl", "oksbi", "paytm", "axl", "ibl")
        )
        if report_hits:
            score += min(30, 10 * report_hits)
            warnings.append(f"Community reports found on related mobile@upi IDs ({report_hits})")

        if score == 0:
            explanations.append(
                "Format looks like a normal Indian mobile. That does not prove who owns it "
                "or that any UPI ID using this number is genuine."
            )
            existence_label = "Format OK — live allotment unknown"
            genuine_label = "Owner not verified"
            status = "format_plausible"
            label = "Looks like a valid Indian mobile format"
            summary = (
                "Number format is plausible, but websites cannot prove who owns a SIM. "
                "Call the person on a known channel and verify the UPI payee name in your app."
            )
        else:
            existence_label = "May be real or fake — trust is low"
            genuine_label = "Treat as suspicious"
            status = "suspicious"
            label = "Mobile looks risky or fabricated"
            summary = (
                "Format may pass, but patterns / reports suggest caution. "
                "Do not send money based on this number alone."
            )

    # Optional live mobile API (Numverify)
    live_mobile: dict[str, Any] = {"checked_live": False}
    try:
        from verification_api import validate_mobile_live

        live_mobile = validate_mobile_live(mobile if format_ok else "")
    except Exception as exc:
        live_mobile = {
            "checked_live": False,
            "error": "exception",
            "raw_message": str(exc),
        }

    if live_mobile.get("checked_live") and live_mobile.get("exists") is True:
        carrier = live_mobile.get("carrier") or "unknown carrier"
        explanations.append(f"Live mobile API: number looks valid ({carrier})")
        if format_ok and score < 35:
            label = "Mobile line looks active (live check)"
            existence_label = f"In use / valid line — {carrier}"
            summary = (
                f"Live lookup suggests this is a valid Indian number ({carrier}). "
                "It still does not prove the person messaging you owns it."
            )
    elif live_mobile.get("checked_live") and live_mobile.get("exists") is False:
        score = max(score, 70)
        warnings.append("Live mobile API: number appears invalid / not in service")
        status = "not_in_service"
        label = "Mobile appears not in service"
        existence_label = "Not in use (live check)"
        genuine_label = "Not a usable genuine number"
        summary = "Live lookup says this number is not valid — treat related payment asks as fake."

    score = max(0, min(100, score if format_ok else max(score, 70)))
    level = _level_from_score(score)
    suggested = [f"{mobile}@{p}" for p in ("ybl", "oksbi", "paytm", "axl")] if format_ok else []

    live_ok = live_mobile.get("exists") if live_mobile.get("checked_live") else (False if not format_ok else None)

    authenticity = {
        "status": status,
        "label": label,
        "existence": "unknown_live" if format_ok else "cannot_exist",
        "existence_label": existence_label,
        "genuine": "unverified" if format_ok and score < 35 else "likely_not_safe",
        "genuine_label": genuine_label,
        "summary": summary,
        "checks": [
            {
                "name": "Indian format (10 digits, starts 6–9)",
                "ok": format_ok,
                "detail": f"Normalised as {mobile}" if mobile else "Could not normalise",
            },
            {
                "name": "Fabricated-pattern check",
                "ok": format_ok and score < 35,
                "detail": (
                    "No strong fake-number patterns"
                    if format_ok and score < 35
                    else "; ".join(warnings[:3]) or "Patterns look odd"
                ),
            },
            {
                "name": "Live line / in-use check",
                "ok": live_ok,
                "detail": live_mobile.get("raw_message")
                or "Set NUMVERIFY_ACCESS_KEY in .env for live mobile lookups.",
            },
            {
                "name": "Genuine owner / linked UPI",
                "ok": None,
                "detail": (
                    "Call on a known channel, then confirm number@ybl (etc.) name in your UPI app."
                ),
            },
        ],
        "how_to_verify": VERIFY_STEPS_MOBILE,
        "limitation": (
            "Telecom ownership is private. Optional Numverify only hints if a line looks valid."
        ),
        "live": live_mobile,
        "suggested_upi_ids": suggested,
    }

    return {
        "valid": format_ok,
        "check_type": "mobile",
        "mobile": mobile,
        "input": original,
        "risk_score": score,
        "risk_level": level,
        "warnings": warnings,
        "explanations": explanations or [summary],
        "recommendations": [
            *VERIFY_STEPS_MOBILE[:2],
            *_recommendations(level),
        ],
        "authenticity": authenticity,
        "suggested_upi_ids": suggested,
    }


def analyze_message(message: str, upi_id: str = "") -> dict[str, Any]:
    text = (message or "").strip()
    warnings: list[str] = []
    score = 0
    explanations: list[str] = []

    if not text:
        return {
            "valid": False,
            "risk_score": 0,
            "risk_level": "unknown",
            "warnings": ["Message text is required."],
            "explanations": [],
            "recommendations": ["Paste the SMS/WhatsApp/email content to scan."],
            "extracted_upis": [],
            "extracted_mobiles": [],
            "check_type": "message",
        }

    extracted = re.findall(
        r"[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}", text
    )
    extracted = sorted({e.lower() for e in extracted})
    mobiles = sorted({m for m in (normalize_mobile(x) for x in re.findall(r"[\d+\-\s]{10,16}", text)) if is_valid_indian_mobile(m)})

    for pattern, explanation in SUSPICIOUS_MESSAGE_PATTERNS:
        if re.search(pattern, text, flags=re.IGNORECASE):
            score += 14
            warnings.append(explanation)
            explanations.append(explanation)

    if re.search(r"₹\s?\d+|rs\.?\s?\d+|inr\s?\d+", text, re.I):
        score += 5
        explanations.append("Message mentions money amounts — verify independently.")

    upi_result = None
    target_upi = normalize_upi(upi_id) if upi_id else (extracted[0] if extracted else "")
    if target_upi:
        upi_result = analyze_upi(target_upi)
        score = min(100, score + int(upi_result["risk_score"] * 0.5))
        for w in upi_result.get("warnings", [])[:3]:
            warnings.append(f"Linked UPI: {w}")

    mobile_result = None
    if mobiles:
        mobile_result = analyze_mobile(mobiles[0])
        score = min(100, score + int(mobile_result["risk_score"] * 0.25))

    ml_fn = _load_ml()
    ml_score = None
    if callable(ml_fn):
        try:
            ml_score = int(ml_fn(target_upi or "unknown@upi", amount=0.0, message=text))
            score = int(round(0.65 * min(score, 100) + 0.35 * ml_score))
        except Exception:
            ml_score = None

    score = max(0, min(100, score))
    level = _level_from_score(score)
    if not explanations:
        explanations = ["No common scam phrases detected, but stay cautious."]

    authenticity = (upi_result or {}).get("authenticity") or (mobile_result or {}).get("authenticity")

    return {
        "valid": True,
        "message_preview": text[:280],
        "risk_score": score,
        "risk_level": level,
        "warnings": warnings,
        "explanations": explanations,
        "recommendations": _recommendations(level),
        "extracted_upis": extracted,
        "extracted_mobiles": mobiles,
        "upi_analysis": upi_result,
        "mobile_analysis": mobile_result,
        "ml_score": ml_score,
        "authenticity": authenticity,
        "check_type": "message",
    }


def analyze_qr_payload(payload: str) -> dict[str, Any]:
    """Parse UPI QR / deep-link payloads (upi://pay?... )."""
    raw = (payload or "").strip()
    warnings: list[str] = []
    score = 10  # unknown QR starts with mild caution
    explanations: list[str] = []
    fields: dict[str, str] = {}

    if not raw:
        return {
            "valid": False,
            "risk_score": 0,
            "risk_level": "unknown",
            "warnings": ["Could not read QR content."],
            "explanations": ["Upload a clearer QR image or paste the UPI link."],
            "recommendations": [],
            "fields": {},
            "authenticity": {
                "status": "empty",
                "label": "No QR content",
                "existence_label": "Unknown",
                "genuine_label": "Unknown",
                "summary": "Provide a QR image or upi:// link.",
                "checks": [],
                "how_to_verify": VERIFY_STEPS_QR,
                "limitation": "Cannot analyse an empty QR.",
            },
            "check_type": "qr",
        }

    lower = raw.lower()
    structure_ok = False
    if "upi://" in lower or "pa=" in lower:
        structure_ok = True
        query = raw.split("?", 1)[1] if "?" in raw else raw
        for part in re.split(r"[&;]", query):
            if "=" in part:
                k, v = part.split("=", 1)
                fields[k.lower()] = _url_decode(v)
    else:
        if is_valid_upi_format(raw):
            fields["pa"] = normalize_upi(raw)
            structure_ok = True
        else:
            warnings.append("QR content is not a standard UPI payment link")
            score += 25
            explanations.append(
                "Legitimate merchant QRs usually encode a upi://pay link with pa= (payee)."
            )

    pa = fields.get("pa", "")
    am = fields.get("am", "")
    pn = fields.get("pn", "")
    tn = fields.get("tn", "")
    cu = fields.get("cu", "")

    upi_analysis = None
    amount = 0.0
    if am:
        try:
            amount = float(am)
        except ValueError:
            warnings.append("Amount field in QR is malformed")
            score += 10

    if pa:
        upi_analysis = analyze_transaction(pa, amount) if amount else analyze_upi(pa)
        score = max(score, upi_analysis["risk_score"])
        warnings.extend(upi_analysis.get("warnings", [])[:5])
        explanations.extend(upi_analysis.get("explanations", [])[:5])
    else:
        warnings.append("No payee UPI ID (pa) found in QR")
        score += 30
        explanations.append("Never pay a QR that does not clearly show the payee VPA.")

    name_mismatch = False
    if pn and pa:
        handle = pa.split("@")[0]
        if len(pn) >= 3 and handle[:3] not in pn.lower().replace(" ", ""):
            score = min(100, score + 8)
            name_mismatch = True
            explanations.append(
                "Payee name and UPI handle do not obviously match — verify merchant board."
            )

    if tn and re.search(r"otp|kyc|refund|lottery", tn, re.I):
        score = min(100, score + 20)
        warnings.append("QR note/transaction text looks like a scam lure")

    if cu and cu.upper() not in {"INR", ""}:
        score = min(100, score + 15)
        warnings.append(f"Unusual currency in QR: {cu}")

    score = max(0, min(100, score))
    level = _level_from_score(score)

    upi_auth = (upi_analysis or {}).get("authenticity") if upi_analysis else None
    if not pa:
        qr_status = "not_upi_payee"
        qr_label = "Not a usable UPI payee QR"
        existence_label = "No payee ID to register"
        genuine_label = "Treat as fake / unsafe QR"
        summary = "This QR does not expose a payee UPI ID (pa=). Do not pay."
    elif upi_auth and upi_auth.get("status") == "invalid_format":
        qr_status = "invalid_payee"
        qr_label = "QR payee UPI format is invalid"
        existence_label = "Payee ID cannot exist"
        genuine_label = "Fake / broken QR payee"
        summary = "QR points to an invalid UPI ID — it cannot be a genuine payee."
    elif score >= 60:
        qr_status = "suspicious"
        qr_label = "QR looks risky"
        existence_label = "Payee may exist but trust is low"
        genuine_label = "Not safe to trust as genuine"
        summary = (
            "QR structure may be valid, but payee/risk signals are poor. "
            "Scan only in your official app and cancel if the name is wrong."
        )
    else:
        qr_status = "structure_ok"
        qr_label = "Looks like a standard UPI QR structure"
        existence_label = "Payee registration: verify in UPI app"
        genuine_label = "Merchant/person not verified yet"
        summary = (
            "QR encodes a normal-looking UPI payment. Still confirm the name on your "
            "payment screen before entering PIN."
        )

    authenticity = {
        "status": qr_status,
        "label": qr_label,
        "existence_label": existence_label,
        "genuine_label": genuine_label,
        "summary": summary,
        "checks": [
            {
                "name": "UPI QR structure",
                "ok": structure_ok and bool(pa),
                "detail": (
                    "Contains upi:// / pa= payee field"
                    if structure_ok and pa
                    else "Missing standard UPI payee fields"
                ),
            },
            {
                "name": "Payee UPI authenticity",
                "ok": (upi_auth or {}).get("status") == "format_plausible" if upi_auth else False,
                "detail": (upi_auth or {}).get("label", "No payee to check"),
            },
            {
                "name": "Payee name vs handle",
                "ok": (not name_mismatch) if pn else None,
                "detail": (
                    "Name present — still confirm on device"
                    if pn and not name_mismatch
                    else (
                        "Name and handle look mismatched"
                        if name_mismatch
                        else "No payee name (pn) in QR — rely on app display"
                    )
                ),
            },
            {
                "name": "Live genuineness",
                "ok": None,
                "detail": "Only your UPI app shows the bank-verified payee name after scanning.",
            },
        ],
        "how_to_verify": VERIFY_STEPS_QR,
        "limitation": (
            "A QR can be copied/printed by anyone. Structure OK ≠ trustworthy merchant."
        ),
        "upi": upi_auth,
    }

    return {
        "valid": bool(pa),
        "raw_preview": raw[:300],
        "fields": fields,
        "upi_id": pa,
        "amount": amount,
        "payee_name": pn,
        "note": tn,
        "risk_score": score,
        "risk_level": level,
        "warnings": warnings,
        "explanations": explanations or ["QR parsed; review payee carefully."],
        "recommendations": [
            "Scan in your official UPI app and match the payee name before PIN.",
            *_recommendations(level),
        ],
        "upi_analysis": upi_analysis,
        "authenticity": authenticity,
        "check_type": "qr",
    }


def _url_decode(value: str) -> str:
    try:
        from urllib.parse import unquote

        return unquote(value.replace("+", " "))
    except Exception:
        return value


def _recommendations(level: str) -> list[str]:
    common = [
        "Never share OTP, PIN, or CVV with anyone.",
        "Call the person/merchant on a known number before paying large amounts.",
        "Use official bank apps only — ignore links from SMS/WhatsApp.",
    ]
    if level in {"critical", "high"}:
        return [
            "Do not proceed with this payment.",
            "Report the UPI ID using the Report page.",
            "If money was already sent, contact your bank fraud desk immediately.",
            *common,
        ]
    if level == "medium":
        return [
            "Verify the payee through another channel before paying.",
            "Prefer collecting payments rather than sending to unknown IDs.",
            *common,
        ]
    return [
        "Looks comparatively safer, but always confirm the payee identity.",
        *common,
    ]


def detect_input_kind(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        return "empty"
    lower = text.lower()
    if "upi://" in lower or "pa=" in lower:
        return "qr"
    if "@" in text and is_valid_upi_format(text.split()[0] if " " not in text else text):
        return "upi"
    if "@" in text and re.search(r"[a-zA-Z0-9.\-_]+@[a-zA-Z]+", text):
        # could be message containing UPI
        if len(text) > 40 or "\n" in text:
            return "message"
        return "upi" if is_valid_upi_format(text) else "message"
    mobile = normalize_mobile(text)
    if is_valid_indian_mobile(mobile) and len(re.sub(r"\D", "", text)) <= 13:
        return "mobile"
    if len(text) > 40:
        return "message"
    if "@" in text:
        return "upi"
    return "unknown"


def build_upi_pay_link(upi_id: str, amount: float = 0.0, note: str = "Payment") -> str:
    from urllib.parse import quote

    pa = normalize_upi(upi_id)
    parts = [f"pa={quote(pa)}", "cu=INR"]
    if amount and amount > 0:
        parts.append(f"am={amount:.2f}")
    if note:
        parts.append(f"tn={quote(note[:40])}")
    return "upi://pay?" + "&".join(parts)


def analyze_smart(
    *,
    raw_input: str = "",
    amount: float | str = 0,
    message: str = "",
    qr_payload: str = "",
    manual_live: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """One combined check: detect input, run all related analyses, Safe/Unsafe + pay link."""
    try:
        amount_f = float(amount or 0)
    except (TypeError, ValueError):
        amount_f = 0.0

    raw = (raw_input or "").strip()
    msg = (message or "").strip()
    qr = (qr_payload or "").strip()

    kind = "unknown"
    if qr:
        kind = "qr"
    elif msg and not raw:
        kind = "message"
        raw = msg
    else:
        kind = detect_input_kind(raw)
        if msg:
            kind = "message"

    modules: dict[str, Any] = {}
    warnings: list[str] = []
    explanations: list[str] = []
    defects: list[str] = []
    score = 0
    upi_id = ""
    mobile = ""
    authenticity = None

    if kind == "empty" and not qr:
        return {
            "check_type": "smart",
            "detected_as": "empty",
            "valid": False,
            "is_safe": False,
            "verdict": "unsafe",
            "verdict_label": "Nothing to check",
            "risk_score": 0,
            "risk_level": "unknown",
            "warnings": ["Enter a UPI ID, mobile number, QR link, or paste a suspicious message."],
            "explanations": [],
            "recommendations": [],
            "defects": ["Empty input"],
            "modules": {},
            "allow_pay": False,
            "pay_link": None,
            "upi_id": "",
            "amount": amount_f,
            "needs_confirm": False,
        }

    if kind == "qr" or qr:
        qr_result = analyze_qr_payload(qr or raw)
        modules["qr"] = qr_result
        score = max(score, int(qr_result.get("risk_score", 0)))
        warnings.extend(qr_result.get("warnings", [])[:6])
        explanations.extend(qr_result.get("explanations", [])[:4])
        upi_id = qr_result.get("upi_id") or ""
        authenticity = qr_result.get("authenticity")
        if not qr_result.get("valid"):
            defects.append("QR is incomplete or not a real UPI payee code")
        if amount_f <= 0 and qr_result.get("amount"):
            amount_f = float(qr_result["amount"])
        if upi_id and manual_live:
            refreshed = (
                analyze_transaction(upi_id, amount_f, manual_live=manual_live)
                if amount_f > 0
                else analyze_upi(upi_id, manual_live=manual_live)
            )
            modules["upi"] = refreshed
            authenticity = refreshed.get("authenticity")
            score = max(score, int(refreshed.get("risk_score", 0)))

    if kind == "mobile" or (
        kind != "qr"
        and is_valid_indian_mobile(normalize_mobile(raw))
        and "@" not in raw
    ):
        mob_result = analyze_mobile(raw)
        modules["mobile"] = mob_result
        score = max(score, int(mob_result.get("risk_score", 0)))
        warnings.extend(mob_result.get("warnings", [])[:5])
        explanations.extend(mob_result.get("explanations", [])[:3])
        mobile = mob_result.get("mobile") or ""
        authenticity = authenticity or mob_result.get("authenticity")
        if not mob_result.get("valid"):
            defects.append("Mobile number format is invalid / cannot be genuine Indian mobile")
        for sug in (mob_result.get("suggested_upi_ids") or [])[:2]:
            u = analyze_upi(sug)
            modules.setdefault("related_upi", []).append(u)
            score = max(score, int(u.get("risk_score", 0) * 0.5))

    if kind in {"upi", "unknown"} and raw and ("@" in raw or kind == "upi"):
        target = raw.split()[0] if " " in raw and "@" in raw.split()[0] else raw
        if amount_f > 0:
            tx = analyze_transaction(target, amount_f, manual_live=manual_live)
            modules["transaction"] = tx
            modules["upi"] = tx
            score = max(score, int(tx.get("risk_score", 0)))
            warnings.extend(tx.get("warnings", [])[:6])
            explanations.extend(tx.get("explanations", [])[:4])
            upi_id = tx.get("upi_id") or target
            authenticity = tx.get("authenticity")
            if not tx.get("valid"):
                defects.append("UPI ID format is invalid — never a real VPA")
        else:
            u = analyze_upi(target, manual_live=manual_live)
            modules["upi"] = u
            score = max(score, int(u.get("risk_score", 0)))
            warnings.extend(u.get("warnings", [])[:6])
            explanations.extend(u.get("explanations", [])[:4])
            upi_id = u.get("upi_id") or target
            authenticity = u.get("authenticity")
            if not u.get("valid"):
                defects.append("UPI ID format is invalid — never a real VPA")

    if kind == "message" or msg:
        text = msg or raw
        m = analyze_message(text, upi_id)
        modules["message"] = m
        score = max(score, int(m.get("risk_score", 0)))
        warnings.extend(m.get("warnings", [])[:6])
        explanations.extend(m.get("explanations", [])[:4])
        authenticity = authenticity or m.get("authenticity")
        if m.get("extracted_upis") and not upi_id:
            upi_id = m["extracted_upis"][0]
            if manual_live:
                u = analyze_upi(upi_id, manual_live=manual_live)
                modules["upi"] = u
                authenticity = u.get("authenticity")
                score = max(score, int(u.get("risk_score", 0)))
        if m.get("extracted_mobiles") and not mobile:
            mobile = m["extracted_mobiles"][0]
        if m.get("warnings"):
            defects.append("Suspicious phrases found in the message")

    if authenticity:
        st = authenticity.get("status", "")
        if st in {"invalid_format", "not_registered", "unknown_provider", "not_upi_payee", "invalid_payee"}:
            defects.append(authenticity.get("label") or "Authenticity failed")
        if authenticity.get("existence") in {"cannot_exist", "not_registered", "unlikely_registered"}:
            defects.append(authenticity.get("existence_label") or "Does not appear registered")
        if authenticity.get("genuine") in {"likely_not_safe", "not_genuine", "not_genuine_format"}:
            defects.append(authenticity.get("genuine_label") or "Not trustworthy as genuine payee")
        if authenticity.get("needs_confirm"):
            defects.append("Complete existence + genuine confirmation below")

    warnings = list(dict.fromkeys(warnings))
    explanations = list(dict.fromkeys(explanations))
    defects = list(dict.fromkeys(defects))

    score = max(0, min(100, score))
    level = _level_from_score(score)

    auth_status = (authenticity or {}).get("status", "")
    hard_block = auth_status in {
        "invalid_format",
        "not_registered",
        "unknown_provider",
        "suspicious_or_reported",
        "suspicious",
        "not_upi_payee",
        "invalid_payee",
        "exists_but_risky",
    }
    needs_confirm = bool((authenticity or {}).get("needs_confirm"))
    exist_ok = (authenticity or {}).get("exist_ok")
    genuine_ok = (authenticity or {}).get("genuine_ok")

    allow_pay = bool(
        upi_id
        and is_valid_upi_format(upi_id)
        and exist_ok is True
        and genuine_ok is True
        and not hard_block
        and score < 40
        and not needs_confirm
    )
    is_safe = allow_pay
    pay_link = build_upi_pay_link(upi_id, amount_f) if allow_pay else None

    if allow_pay:
        verdict = "safe"
        verdict_label = "SAFE — existence & genuine payee confirmed. You can open UPI to pay"
    elif needs_confirm:
        verdict = "caution"
        verdict_label = "CONFIRM BELOW — resolve the ? checks (existence + genuine name)"
    elif level == "medium":
        verdict = "caution"
        verdict_label = "CAUTION — defects / risk found. Do not pay yet"
    else:
        verdict = "unsafe"
        verdict_label = "UNSAFE — do not pay. Report if it is a scam"

    related = []
    if upi_id:
        related.append(f"UPI ID under review: {upi_id}")
    if mobile:
        related.append(f"Mobile linked/detected: {mobile}")
    if amount_f > 0:
        related.append(f"Amount: ₹{amount_f:,.2f}")
    if modules.get("message"):
        related.append("Message content was scanned for OTP/KYC/lottery traps")
    if modules.get("qr"):
        related.append("QR payload was decoded and payee fields inspected")
    if manual_live:
        related.append("In-app confirmation answers were applied to resolve ? checks")

    return {
        "check_type": "smart",
        "detected_as": kind,
        "valid": bool(upi_id or mobile or modules),
        "is_safe": is_safe,
        "verdict": verdict,
        "verdict_label": verdict_label,
        "risk_score": score,
        "risk_level": level,
        "warnings": warnings,
        "explanations": explanations or ["Combined check completed."],
        "recommendations": _recommendations(level),
        "defects": [d for d in defects if not (allow_pay and "confirmation below" in d)],
        "related": related,
        "modules": modules,
        "authenticity": authenticity,
        "allow_pay": allow_pay,
        "pay_link": pay_link,
        "upi_id": upi_id,
        "mobile": mobile,
        "amount": amount_f,
        "ml_score": (modules.get("upi") or modules.get("transaction") or {}).get("ml_score"),
        "needs_confirm": needs_confirm,
        "app_preview_link": (
            build_upi_pay_link(upi_id, 0)
            if upi_id and is_valid_upi_format(upi_id)
            else None
        ),
    }
