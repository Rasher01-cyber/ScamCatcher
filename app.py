"""UPI Guard — Flask application for UPI fraud detection awareness."""

from __future__ import annotations

import os
import re
from functools import wraps

from dotenv import load_dotenv
from flask import (
    Flask,
    flash,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from werkzeug.utils import secure_filename

import database as db
import fraud_detector as detector

load_dotenv()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp"}

app = Flask(__name__)
app.secret_key = os.environ.get("UPI_GUARD_SECRET", "upi-guard-dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB

os.makedirs(UPLOAD_DIR, exist_ok=True)


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login", next=request.path))
        if session.get("role") != "admin":
            flash("Admin access required.", "danger")
            return redirect(url_for("index"))
        return view(*args, **kwargs)

    return wrapped


@app.context_processor
def inject_user():
    user = None
    if session.get("user_id"):
        user = db.get_user_by_id(session["user_id"])
    api = {}
    try:
        from verification_api import verification_status

        api = verification_status()
    except Exception:
        api = {"upi_live_enabled": False, "setup_hint": "verification_api unavailable"}
    return {"current_user": user, "verification_api": api}


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/checker", methods=["GET", "POST"])
def checker():
    """Unified smart check — one form for UPI / QR / mobile / message."""
    if request.method == "GET":
        return redirect(url_for("index"))

    qr_payload = (request.form.get("qr_text") or "").strip()
    file = request.files.get("qr_image")
    if file and file.filename:
        filename = secure_filename(file.filename)
        ext = os.path.splitext(filename)[1].lower()
        if ext in ALLOWED_EXT:
            path = os.path.join(UPLOAD_DIR, filename)
            file.save(path)
            decoded = _decode_qr_image(path)
            try:
                os.remove(path)
            except OSError:
                pass
            if decoded:
                qr_payload = decoded

    result = detector.analyze_smart(
        raw_input=request.form.get("smart_input", ""),
        amount=request.form.get("amount", "0"),
        message=request.form.get("message", ""),
        qr_payload=qr_payload,
    )
    summary = (
        result.get("upi_id")
        or result.get("mobile")
        or (request.form.get("smart_input") or "")[:120]
        or "smart-check"
    )
    db.log_check(
        session.get("user_id"),
        "smart",
        str(summary),
        int(result.get("risk_score", 0)),
        str(result.get("risk_level", "unknown")),
    )
    return render_template("result.html", result=result)


@app.route("/confirm-vpa", methods=["POST"])
def confirm_vpa():
    """Resolve ? checks using what the user saw in their official UPI app."""
    upi_id = (request.form.get("upi_id") or "").strip()
    amount = request.form.get("amount") or "0"
    existence = request.form.get("existence")  # registered | invalid
    payee_name = (request.form.get("payee_name") or "").strip()
    name_match = request.form.get("name_match")  # yes | no

    manual: dict = {"upi_id": upi_id}
    if existence == "invalid":
        manual["exists"] = False
        manual["name_matches"] = False
        manual["raw_message"] = "Your UPI app said invalid / not registered."
    elif existence == "registered":
        manual["exists"] = True
        manual["payee_name"] = payee_name
        manual["raw_message"] = (
            f"Your UPI app showed this ID is registered"
            + (f" as “{payee_name}”" if payee_name else "")
            + "."
        )
        if name_match == "yes":
            manual["name_matches"] = True
        elif name_match == "no":
            manual["name_matches"] = False

    result = detector.analyze_smart(
        raw_input=upi_id,
        amount=amount,
        manual_live=manual,
    )
    db.log_check(
        session.get("user_id"),
        "confirm-vpa",
        f"{upi_id}|{existence}|{name_match}",
        int(result.get("risk_score", 0)),
        str(result.get("risk_level", "unknown")),
    )
    flash("Confirmation applied — ? checks updated.", "success")
    return render_template("result.html", result=result)


@app.route("/setup", methods=["GET", "POST"])
def setup_apis():
    """Save Razorpay/Cashfree keys so live existence works automatically."""
    env_path = os.path.join(BASE_DIR, ".env")
    if request.method == "POST":
        pairs = {
            "RAZORPAY_KEY_ID": request.form.get("RAZORPAY_KEY_ID", "").strip(),
            "RAZORPAY_KEY_SECRET": request.form.get("RAZORPAY_KEY_SECRET", "").strip(),
            "CASHFREE_CLIENT_ID": request.form.get("CASHFREE_CLIENT_ID", "").strip(),
            "CASHFREE_CLIENT_SECRET": request.form.get("CASHFREE_CLIENT_SECRET", "").strip(),
            "CASHFREE_ENV": request.form.get("CASHFREE_ENV", "sandbox").strip() or "sandbox",
            "NUMVERIFY_ACCESS_KEY": request.form.get("NUMVERIFY_ACCESS_KEY", "").strip(),
        }
        existing: dict[str, str] = {}
        if os.path.exists(env_path):
            with open(env_path, encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    k, _, v = line.partition("=")
                    existing[k.strip()] = v.strip()
        for k, v in pairs.items():
            if v and not v.startswith("•"):
                existing[k] = v
            elif k not in existing:
                existing[k] = ""
        if "UPI_GUARD_SECRET" not in existing:
            existing["UPI_GUARD_SECRET"] = os.environ.get(
                "UPI_GUARD_SECRET", "upi-guard-dev-secret-change-me"
            )
        with open(env_path, "w", encoding="utf-8") as fh:
            fh.write("# UPI Guard live verification keys\n")
            for k, v in existing.items():
                fh.write(f"{k}={v}\n")
        for k, v in pairs.items():
            if v and not v.startswith("•"):
                os.environ[k] = v
        try:
            from dotenv import load_dotenv

            load_dotenv(env_path, override=True)
        except Exception:
            pass
        flash(
            "API keys saved. Live existence will query Razorpay/Cashfree on the next check. "
            "If status still shows OFF, restart: python app.py",
            "success",
        )
        return redirect(url_for("setup_apis"))

    from verification_api import verification_status

    status = verification_status()
    current = {
        "RAZORPAY_KEY_ID": os.getenv("RAZORPAY_KEY_ID", ""),
        "RAZORPAY_KEY_SECRET": "••••••" if os.getenv("RAZORPAY_KEY_SECRET") else "",
        "CASHFREE_CLIENT_ID": os.getenv("CASHFREE_CLIENT_ID", ""),
        "CASHFREE_CLIENT_SECRET": "••••••" if os.getenv("CASHFREE_CLIENT_SECRET") else "",
        "CASHFREE_ENV": os.getenv("CASHFREE_ENV", "sandbox"),
        "NUMVERIFY_ACCESS_KEY": "••••••" if os.getenv("NUMVERIFY_ACCESS_KEY") else "",
    }
    return render_template(
        "setup.html",
        status=status,
        current=current,
        test_result=None,
        test_vpa="",
    )


@app.route("/setup/test", methods=["POST"])
def test_live_api():
    """Hit Razorpay/Cashfree for a sample VPA to prove open-world detection."""
    from verification_api import validate_upi_live, verification_status

    vpa = (request.form.get("vpa") or "").strip()
    result = validate_upi_live(vpa)
    status = verification_status()
    current = {
        "RAZORPAY_KEY_ID": os.getenv("RAZORPAY_KEY_ID", ""),
        "RAZORPAY_KEY_SECRET": "••••••" if os.getenv("RAZORPAY_KEY_SECRET") else "",
        "CASHFREE_CLIENT_ID": os.getenv("CASHFREE_CLIENT_ID", ""),
        "CASHFREE_CLIENT_SECRET": "••••••" if os.getenv("CASHFREE_CLIENT_SECRET") else "",
        "CASHFREE_ENV": os.getenv("CASHFREE_ENV", "sandbox"),
        "NUMVERIFY_ACCESS_KEY": "••••••" if os.getenv("NUMVERIFY_ACCESS_KEY") else "",
    }
    if result.get("checked_live"):
        flash("Live API responded — open-world check ran.", "success")
    else:
        flash(result.get("raw_message") or "Live API did not run. Check keys.", "warning")
    return render_template(
        "setup.html",
        status=status,
        current=current,
        test_result=result,
        test_vpa=vpa,
    )


def _decode_qr_image(path: str) -> str | None:
    """Try pyzbar first; fall back to regex scan of common UPI strings via Pillow only."""
    try:
        from PIL import Image
        from pyzbar.pyzbar import decode as zbar_decode

        img = Image.open(path)
        codes = zbar_decode(img)
        if codes:
            data = codes[0].data
            return data.decode("utf-8", errors="ignore")
    except Exception:
        pass

    # Soft fallback: if user somehow uploaded text-like content — unlikely for images
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
        text = blob.decode("utf-8", errors="ignore")
        match = re.search(r"upi://[^\s\"']+", text, re.I)
        if match:
            return match.group(0)
        match = re.search(r"[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}", text)
        if match:
            return match.group(0)
    except Exception:
        pass
    return None


@app.route("/report", methods=["GET", "POST"])
def report():
    import cybercrime as cc

    states = sorted(s.title() for s in cc.STATE_CYBER_CELLS.keys())
    if request.method == "POST":
        upi_id = request.form.get("upi_id", "")
        reason = request.form.get("reason", "")
        description = request.form.get("description", "")
        state = request.form.get("victim_state", "")
        city = request.form.get("victim_city", "")
        phone = request.form.get("victim_phone", "")
        amount = request.form.get("amount_involved", "")
        complaint = cc.build_complaint_text(
            upi_id=upi_id,
            reason=reason,
            description=description,
            state=state,
            city=city,
            victim_phone=phone,
            amount=amount,
        )
        ok, msg, report_id = db.add_fraud_report(
            upi_id,
            reason,
            description,
            session.get("user_id"),
            victim_state=state,
            victim_city=city,
            victim_phone=phone,
            amount_involved=amount,
            complaint_text=complaint,
        )
        flash(msg, "success" if ok else "danger")
        if ok and report_id:
            return redirect(url_for("report_sent", report_id=report_id))
    return render_template(
        "report.html",
        states=states,
        portal=cc.CYBERCRIME_PORTAL,
        helpline=cc.CYBERCRIME_HELPLINE,
    )


@app.route("/report/sent/<int:report_id>")
def report_sent(report_id: int):
    import cybercrime as cc

    row = db.get_fraud_report(report_id)
    if not row:
        flash("Report not found.", "danger")
        return redirect(url_for("report"))
    cell = cc.nearest_cyber_cell(row.get("victim_state") or "", row.get("victim_city") or "")
    return render_template(
        "report_sent.html",
        report=row,
        cell=cell,
        portal=cc.CYBERCRIME_PORTAL,
        helpline=cc.CYBERCRIME_HELPLINE,
    )


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        user = db.authenticate_user(
            request.form.get("username", ""),
            request.form.get("password", ""),
        )
        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['username']}!", "success")
            nxt = request.args.get("next") or url_for("index")
            return redirect(nxt)
        flash("Invalid username or password.", "danger")
    return render_template("login.html", mode="login")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        ok, msg = db.create_user(
            request.form.get("username", ""),
            request.form.get("email", ""),
            request.form.get("password", ""),
        )
        flash(msg, "success" if ok else "danger")
        if ok:
            return redirect(url_for("login"))
    return render_template("login.html", mode="register")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("index"))


@app.route("/admin")
@admin_required
def admin():
    stats = db.get_admin_stats()
    return render_template("admin.html", stats=stats)


@app.route("/admin/report/<int:report_id>/<status>", methods=["POST"])
@admin_required
def admin_update_report(report_id: int, status: str):
    if db.update_report_status(report_id, status):
        flash(f"Report #{report_id} marked as {status}.", "success")
    else:
        flash("Could not update report.", "danger")
    return redirect(url_for("admin"))


@app.route("/awareness")
def awareness():
    tips = [
        {
            "title": "How to know if a UPI ID exists",
            "body": "Type it in your official UPI app. If a payee name appears, it is registered. If the app says invalid, it was never invented or is mistyped.",
        },
        {
            "title": "Exists ≠ genuine",
            "body": "Scammers register real UPI IDs. Always match the name on the payment screen with the person/shop you intend to pay.",
        },
        {
            "title": "Never share OTP",
            "body": "Banks and UPI apps never ask for OTP, PIN, or CVV on phone or chat.",
        },
        {
            "title": "Beware of refund traps",
            "body": "Fake refund agents ask you to 'verify' by entering a UPI PIN — that sends money out.",
        },
        {
            "title": "Check the UPI ID carefully",
            "body": "Look-alike handles (support, kyc, lottery) and unknown @providers are classic red flags.",
        },
        {
            "title": "Scan QR with caution",
            "body": "Confirm payee name on screen before entering PIN. Prefer collecting, not paying, strangers.",
        },
        {
            "title": "Mobile number tricks",
            "body": "A 10-digit number can look real and still belong to a scammer. Call on a known channel before paying.",
        },
        {
            "title": "Report suspicious IDs",
            "body": "Community reports help others stay safe — use the Report page.",
        },
    ]
    return render_template("awareness.html", tips=tips)


def create_app():
    db.init_db()
    try:
        from ml.model import train_and_save

        train_and_save(force=False)
    except Exception as exc:  # pragma: no cover - optional ML
        app.logger.warning("ML model init skipped: %s", exc)
    return app


if __name__ == "__main__":
    create_app()
    app.run(debug=True, host="0.0.0.0", port=5000)
