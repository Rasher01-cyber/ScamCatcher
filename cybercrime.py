"""Cybercrime reporting helpers for UPI Guard (official portal routing)."""

from __future__ import annotations

from typing import Any

# National portal + financial fraud helpline (India).
CYBERCRIME_PORTAL = "https://www.cybercrime.gov.in/"
CYBERCRIME_HELPLINE = "1930"

# State / UT cybercrime cells (public helplines / portals — awareness list).
# The National Portal routes complaints to the correct jurisdiction.
STATE_CYBER_CELLS: dict[str, dict[str, str]] = {
    "andhra pradesh": {
        "name": "Andhra Pradesh Cyber Crime",
        "helpline": "1930",
        "note": "File on cybercrime.gov.in — selects your state automatically.",
    },
    "telangana": {
        "name": "Telangana Cyber Security Bureau",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "karnataka": {
        "name": "Karnataka Cyber Crime",
        "helpline": "1930 / 080-22943225",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "tamil nadu": {
        "name": "Tamil Nadu Cyber Crime Wing",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "kerala": {
        "name": "Kerala Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "maharashtra": {
        "name": "Maharashtra Cyber",
        "helpline": "1930",
        "portal": "https://cybercrime.gov.in/",
    },
    "delhi": {
        "name": "Delhi Police Cyber Cell",
        "helpline": "1930 / 011-20892596",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "uttar pradesh": {
        "name": "UP Police Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "rajasthan": {
        "name": "Rajasthan Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "gujarat": {
        "name": "Gujarat Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "west bengal": {
        "name": "West Bengal Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "bihar": {
        "name": "Bihar Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "madhya pradesh": {
        "name": "MP Cyber Police",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "punjab": {
        "name": "Punjab Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "haryana": {
        "name": "Haryana Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "odisha": {
        "name": "Odisha Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "assam": {
        "name": "Assam Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "jharkhand": {
        "name": "Jharkhand Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "chhattisgarh": {
        "name": "Chhattisgarh Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
    "goa": {
        "name": "Goa Cyber Crime",
        "helpline": "1930",
        "portal": "https://www.cybercrime.gov.in/",
    },
}


def nearest_cyber_cell(state: str, city: str = "") -> dict[str, Any]:
    key = (state or "").strip().lower()
    cell = STATE_CYBER_CELLS.get(key)
    if not cell:
        return {
            "found": False,
            "state": state,
            "city": city,
            "name": "National Cyber Crime Reporting Portal",
            "helpline": CYBERCRIME_HELPLINE,
            "portal": CYBERCRIME_PORTAL,
            "guidance": (
                f"Select your state/city on {CYBERCRIME_PORTAL} — the portal forwards "
                "the complaint to the correct cybercrime unit for your area."
            ),
        }
    return {
        "found": True,
        "state": state,
        "city": city,
        "name": cell["name"],
        "helpline": cell.get("helpline", CYBERCRIME_HELPLINE),
        "portal": cell.get("portal", CYBERCRIME_PORTAL),
        "guidance": (
            f"For {city + ', ' if city else ''}{state.title()}: use helpline "
            f"{cell.get('helpline', CYBERCRIME_HELPLINE)} and file on the National Portal "
            "so it reaches your nearest cybercrime branch."
        ),
    }


def build_complaint_text(
    *,
    upi_id: str,
    reason: str,
    description: str,
    state: str,
    city: str,
    victim_phone: str,
    amount: str = "",
) -> str:
    cell = nearest_cyber_cell(state, city)
    lines = [
        "UPI / ONLINE FINANCIAL FRAUD — COMPLAINT DRAFT (from UPI Guard)",
        "=" * 56,
        f"Suspicious UPI ID: {upi_id}",
        f"Reason: {reason}",
        f"Amount involved (if any): {amount or 'Not specified'}",
        f"Victim mobile: {victim_phone or 'Not provided'}",
        f"Victim city / state: {city or '-'}, {state or '-'}",
        f"Nearest unit guidance: {cell['name']} | Helpline {cell['helpline']}",
        "",
        "What happened:",
        description or "(Please add details: date, time, app used, chat screenshots.)",
        "",
        "Requested action:",
        "- Block / investigate the UPI ID and linked accounts",
        "- Trace money trail if funds were transferred",
        "",
        f"File officially at: {CYBERCRIME_PORTAL}",
        f"Financial fraud helpline: {CYBERCRIME_HELPLINE}",
        "",
        "Note: This draft is for filing on the official portal / sharing with cyber police.",
        "UPI Guard cannot file the police complaint automatically.",
    ]
    return "\n".join(lines)
