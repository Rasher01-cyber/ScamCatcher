"""
Live verification adapters for UPI VPA / mobile.

Official NPCI does not expose a free public “does this UPI exist?” API to websites.
Merchants use payment-gateway verification APIs instead. This module supports:

  1. Razorpay  — POST /v1/payments/validate/vpa   (env: RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET)
  2. Cashfree  — POST /verification/upi           (env: CASHFREE_CLIENT_ID, CASHFREE_CLIENT_SECRET)
  3. Optional mobile lookup via Numverify         (env: NUMVERIFY_ACCESS_KEY)

If no keys are configured, callers should fall back to rule-based existence estimates.
Never invent a “bank confirmed” result without a real API response.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

# Optional .env support without hard dependency
try:
    from dotenv import load_dotenv

    load_dotenv()
except Exception:
    pass


def verification_status() -> dict[str, Any]:
    providers = []
    if os.getenv("RAZORPAY_KEY_ID") and os.getenv("RAZORPAY_KEY_SECRET"):
        providers.append("razorpay")
    if os.getenv("CASHFREE_CLIENT_ID") and os.getenv("CASHFREE_CLIENT_SECRET"):
        providers.append("cashfree")
    mobile = bool(os.getenv("NUMVERIFY_ACCESS_KEY"))
    return {
        "upi_live_enabled": bool(providers),
        "upi_providers": providers,
        "mobile_live_enabled": mobile,
        "setup_hint": (
            "Add Razorpay or Cashfree API keys to enable live UPI existence checks. "
            "See .env.example"
            if not providers
            else f"Live UPI checks via: {', '.join(providers)}"
        ),
    }


def validate_upi_live(vpa: str) -> dict[str, Any]:
    """
    Ask a payment gateway whether the VPA is registered.

    Returns:
      success, exists (bool|None), payee_name, provider, raw_message, error
    """
    vpa = (vpa or "").strip().lower()
    status = verification_status()
    if not status["upi_live_enabled"]:
        return {
            "success": False,
            "exists": None,
            "payee_name": None,
            "provider": None,
            "raw_message": status["setup_hint"],
            "error": "api_not_configured",
            "checked_live": False,
        }

    # Prefer Razorpay, then Cashfree
    if "razorpay" in status["upi_providers"]:
        result = _razorpay_validate_vpa(vpa)
        if result.get("success") or result.get("error") != "http_error":
            return result
    if "cashfree" in status["upi_providers"]:
        return _cashfree_validate_vpa(vpa)
    return {
        "success": False,
        "exists": None,
        "payee_name": None,
        "provider": None,
        "raw_message": "No working provider",
        "error": "no_provider",
        "checked_live": False,
    }


def validate_mobile_live(mobile: str) -> dict[str, Any]:
    """Optional Numverify carrier/line lookup (not a guarantee of who owns the SIM)."""
    key = os.getenv("NUMVERIFY_ACCESS_KEY", "").strip()
    mobile = "".join(ch for ch in (mobile or "") if ch.isdigit())
    if mobile.startswith("91") and len(mobile) == 12:
        mobile = mobile[2:]
    if not key:
        return {
            "success": False,
            "exists": None,
            "carrier": None,
            "line_type": None,
            "checked_live": False,
            "error": "api_not_configured",
            "raw_message": "Set NUMVERIFY_ACCESS_KEY for live mobile lookups.",
        }
    if len(mobile) != 10:
        return {
            "success": False,
            "exists": False,
            "carrier": None,
            "line_type": None,
            "checked_live": True,
            "error": "invalid_format",
            "raw_message": "Mobile must be 10 digits for lookup.",
        }

    url = (
        "http://apilayer.net/api/validate"
        f"?access_key={urllib.parse.quote(key)}"
        f"&number=91{mobile}&country_code=IN&format=1"
    )
    try:
        data = _http_json(url, method="GET")
        valid = bool(data.get("valid"))
        return {
            "success": True,
            "exists": valid,
            "carrier": data.get("carrier") or None,
            "line_type": data.get("line_type") or None,
            "location": data.get("location") or None,
            "checked_live": True,
            "error": None,
            "raw_message": (
                f"Numverify: valid={valid}, carrier={data.get('carrier') or 'n/a'}"
            ),
            "provider": "numverify",
        }
    except Exception as exc:
        return {
            "success": False,
            "exists": None,
            "carrier": None,
            "line_type": None,
            "checked_live": False,
            "error": "request_failed",
            "raw_message": str(exc),
        }


def _razorpay_validate_vpa(vpa: str) -> dict[str, Any]:
    key_id = os.getenv("RAZORPAY_KEY_ID", "")
    key_secret = os.getenv("RAZORPAY_KEY_SECRET", "")
    url = "https://api.razorpay.com/v1/payments/validate/vpa"
    body = json.dumps({"vpa": vpa}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    token = _basic_auth(key_id, key_secret)
    req.add_header("Authorization", f"Basic {token}")
    try:
        data = _http_json_request(req)
        # Typical success: {"success": true, "customer_name": "...", "vpa": "..."}
        # Or {"success": false}
        success_flag = data.get("success")
        if success_flag is True or str(data.get("account_status", "")).lower() in {
            "active",
            "valid",
        }:
            name = (
                data.get("customer_name")
                or data.get("payee_name")
                or (data.get("customer") or {}).get("name")
            )
            return {
                "success": True,
                "exists": True,
                "payee_name": name,
                "provider": "razorpay",
                "raw_message": "Razorpay confirmed this VPA is registered.",
                "error": None,
                "checked_live": True,
                "raw": data,
            }
        if success_flag is False:
            return {
                "success": True,
                "exists": False,
                "payee_name": None,
                "provider": "razorpay",
                "raw_message": "Razorpay reports this VPA is invalid / not registered.",
                "error": None,
                "checked_live": True,
                "raw": data,
            }
        # Unexpected shape — treat as inconclusive
        return {
            "success": False,
            "exists": None,
            "payee_name": None,
            "provider": "razorpay",
            "raw_message": f"Unexpected Razorpay response: {data}",
            "error": "unexpected_response",
            "checked_live": True,
            "raw": data,
        }
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        # 400 often means invalid VPA
        if exc.code in {400, 404}:
            lower = detail.lower()
            if "invalid" in lower or "not found" in lower or "does not exist" in lower:
                return {
                    "success": True,
                    "exists": False,
                    "payee_name": None,
                    "provider": "razorpay",
                    "raw_message": "Gateway rejected VPA as invalid / not registered.",
                    "error": None,
                    "checked_live": True,
                    "raw": detail,
                }
        return {
            "success": False,
            "exists": None,
            "payee_name": None,
            "provider": "razorpay",
            "raw_message": f"HTTP {exc.code}: {detail[:300]}",
            "error": "http_error",
            "checked_live": False,
        }
    except Exception as exc:
        return {
            "success": False,
            "exists": None,
            "payee_name": None,
            "provider": "razorpay",
            "raw_message": str(exc),
            "error": "request_failed",
            "checked_live": False,
        }


def _cashfree_validate_vpa(vpa: str) -> dict[str, Any]:
    client_id = os.getenv("CASHFREE_CLIENT_ID", "")
    client_secret = os.getenv("CASHFREE_CLIENT_SECRET", "")
    env = (os.getenv("CASHFREE_ENV") or "sandbox").lower()
    base = (
        "https://api.cashfree.com"
        if env == "production"
        else "https://sandbox.cashfree.com"
    )
    url = f"{base}/verification/upi"
    import uuid

    body = json.dumps(
        {"verification_id": f"upiguard-{uuid.uuid4().hex[:16]}", "vpa": vpa}
    ).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "x-client-id": client_id,
            "x-client-secret": client_secret,
            "x-api-version": "2022-01-01",
        },
    )
    try:
        data = _http_json_request(req)
        # Cashfree often returns account_status / name_at_bank / status
        status = str(
            data.get("account_status") or data.get("status") or ""
        ).lower()
        name = data.get("name_at_bank") or data.get("name") or data.get("vpa_name")
        if status in {"valid", "active", "success"} or data.get("valid") is True:
            return {
                "success": True,
                "exists": True,
                "payee_name": name,
                "provider": "cashfree",
                "raw_message": "Cashfree confirmed this VPA is registered.",
                "error": None,
                "checked_live": True,
                "raw": data,
            }
        if status in {"invalid", "failed", "inactive"} or data.get("valid") is False:
            return {
                "success": True,
                "exists": False,
                "payee_name": None,
                "provider": "cashfree",
                "raw_message": "Cashfree reports this VPA is invalid / not registered.",
                "error": None,
                "checked_live": True,
                "raw": data,
            }
        return {
            "success": False,
            "exists": None,
            "payee_name": name,
            "provider": "cashfree",
            "raw_message": f"Unexpected Cashfree response: {data}",
            "error": "unexpected_response",
            "checked_live": True,
            "raw": data,
        }
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="ignore")
        return {
            "success": False,
            "exists": None,
            "payee_name": None,
            "provider": "cashfree",
            "raw_message": f"HTTP {exc.code}: {detail[:300]}",
            "error": "http_error",
            "checked_live": False,
        }
    except Exception as exc:
        return {
            "success": False,
            "exists": None,
            "payee_name": None,
            "provider": "cashfree",
            "raw_message": str(exc),
            "error": "request_failed",
            "checked_live": False,
        }


def _basic_auth(username: str, password: str) -> str:
    import base64

    raw = f"{username}:{password}".encode("utf-8")
    return base64.b64encode(raw).decode("ascii")


def _http_json(url: str, method: str = "GET") -> dict[str, Any]:
    req = urllib.request.Request(url, method=method)
    return _http_json_request(req)


def _http_json_request(req: urllib.request.Request) -> dict[str, Any]:
    with urllib.request.urlopen(req, timeout=12) as resp:
        payload = resp.read().decode("utf-8")
        if not payload:
            return {}
        return json.loads(payload)
