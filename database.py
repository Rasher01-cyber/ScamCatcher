"""SQLite database helpers for UPI Guard."""

from __future__ import annotations

import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_DIR = os.path.join(BASE_DIR, "database")
DB_PATH = os.path.join(DB_DIR, "upi_fraud.db")


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


@contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create tables and seed default admin + sample known-risk UPI IDs."""
    with get_connection() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                email TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL DEFAULT 'user',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS fraud_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                upi_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                description TEXT,
                reporter_id INTEGER,
                status TEXT NOT NULL DEFAULT 'pending',
                created_at TEXT NOT NULL,
                reviewed_at TEXT,
                victim_state TEXT,
                victim_city TEXT,
                victim_phone TEXT,
                amount_involved TEXT,
                complaint_text TEXT,
                FOREIGN KEY (reporter_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS known_risky_upis (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                upi_id TEXT NOT NULL UNIQUE,
                risk_level TEXT NOT NULL,
                reason TEXT NOT NULL,
                source TEXT NOT NULL DEFAULT 'seed',
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS check_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                check_type TEXT NOT NULL,
                input_summary TEXT,
                risk_score INTEGER,
                risk_level TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
            """
        )

        admin = conn.execute(
            "SELECT id FROM users WHERE username = ?", ("admin",)
        ).fetchone()
        if not admin:
            conn.execute(
                """
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, 'admin', ?)
                """,
                (
                    "admin",
                    "admin@upiguard.local",
                    generate_password_hash("admin123"),
                    _utcnow(),
                ),
            )

        seed_upis = [
            ("scamrefund@paytm", "critical", "Known refund scam handle"),
            ("lotterywin@oksbi", "critical", "Fake lottery prize UPI"),
            ("kycupdate@ybl", "high", "Fake KYC update campaign"),
            ("support-care@axl", "high", "Impersonates bank support"),
            ("cashbackdeal@ibl", "medium", "Aggressive cashback phishing"),
            ("helpline24x7@upi", "high", "Fake helpline collection ID"),
        ]
        for upi_id, level, reason in seed_upis:
            exists = conn.execute(
                "SELECT id FROM known_risky_upis WHERE upi_id = ?", (upi_id,)
            ).fetchone()
            if not exists:
                conn.execute(
                    """
                    INSERT INTO known_risky_upis
                    (upi_id, risk_level, reason, source, created_at)
                    VALUES (?, ?, ?, 'seed', ?)
                    """,
                    (upi_id, level, reason, _utcnow()),
                )

        # Lightweight migrations for older DBs
        cols = {
            row["name"]
            for row in conn.execute("PRAGMA table_info(fraud_reports)").fetchall()
        }
        for col, typedef in (
            ("victim_state", "TEXT"),
            ("victim_city", "TEXT"),
            ("victim_phone", "TEXT"),
            ("amount_involved", "TEXT"),
            ("complaint_text", "TEXT"),
        ):
            if col not in cols:
                conn.execute(f"ALTER TABLE fraud_reports ADD COLUMN {col} {typedef}")


def create_user(username: str, email: str, password: str) -> tuple[bool, str]:
    username = username.strip()
    email = email.strip().lower()
    if not username or not email or not password:
        return False, "All fields are required."
    if len(password) < 6:
        return False, "Password must be at least 6 characters."
    try:
        with get_connection() as conn:
            conn.execute(
                """
                INSERT INTO users (username, email, password_hash, role, created_at)
                VALUES (?, ?, ?, 'user', ?)
                """,
                (username, email, generate_password_hash(password), _utcnow()),
            )
        return True, "Account created successfully. Please log in."
    except sqlite3.IntegrityError:
        return False, "Username or email already exists."


def authenticate_user(username: str, password: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM users WHERE username = ?", (username.strip(),)
        ).fetchone()
    if row and check_password_hash(row["password_hash"], password):
        return dict(row)
    return None


def get_user_by_id(user_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT id, username, email, role, created_at FROM users WHERE id = ?",
            (user_id,),
        ).fetchone()
    return dict(row) if row else None


def get_known_risk(upi_id: str) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM known_risky_upis WHERE lower(upi_id) = lower(?)",
            (upi_id.strip(),),
        ).fetchone()
    return dict(row) if row else None


def count_reports_for_upi(upi_id: str) -> int:
    with get_connection() as conn:
        row = conn.execute(
            """
            SELECT COUNT(*) AS c FROM fraud_reports
            WHERE lower(upi_id) = lower(?) AND status != 'rejected'
            """,
            (upi_id.strip(),),
        ).fetchone()
    return int(row["c"]) if row else 0


def add_fraud_report(
    upi_id: str,
    reason: str,
    description: str,
    reporter_id: int | None,
    *,
    victim_state: str = "",
    victim_city: str = "",
    victim_phone: str = "",
    amount_involved: str = "",
    complaint_text: str = "",
) -> tuple[bool, str, int | None]:
    upi_id = upi_id.strip().lower()
    reason = reason.strip()
    if not upi_id or "@" not in upi_id:
        return False, "Enter a valid UPI ID (example@bank).", None
    if not reason:
        return False, "Please select or enter a reason.", None
    with get_connection() as conn:
        cur = conn.execute(
            """
            INSERT INTO fraud_reports
            (upi_id, reason, description, reporter_id, status, created_at,
             victim_state, victim_city, victim_phone, amount_involved, complaint_text)
            VALUES (?, ?, ?, ?, 'pending', ?, ?, ?, ?, ?, ?)
            """,
            (
                upi_id,
                reason,
                description.strip(),
                reporter_id,
                _utcnow(),
                victim_state.strip(),
                victim_city.strip(),
                victim_phone.strip(),
                amount_involved.strip(),
                complaint_text.strip(),
            ),
        )
        report_id = cur.lastrowid
    return True, "Report saved. Continue to the National Cyber Crime Portal.", report_id


def get_fraud_report(report_id: int) -> dict[str, Any] | None:
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM fraud_reports WHERE id = ?", (report_id,)
        ).fetchone()
    return dict(row) if row else None


def log_check(
    user_id: int | None,
    check_type: str,
    input_summary: str,
    risk_score: int,
    risk_level: str,
) -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO check_logs
            (user_id, check_type, input_summary, risk_score, risk_level, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (user_id, check_type, input_summary[:500], risk_score, risk_level, _utcnow()),
        )


def get_admin_stats() -> dict[str, Any]:
    with get_connection() as conn:
        users = conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()["c"]
        reports = conn.execute("SELECT COUNT(*) AS c FROM fraud_reports").fetchone()["c"]
        pending = conn.execute(
            "SELECT COUNT(*) AS c FROM fraud_reports WHERE status = 'pending'"
        ).fetchone()["c"]
        checks = conn.execute("SELECT COUNT(*) AS c FROM check_logs").fetchone()["c"]
        high = conn.execute(
            """
            SELECT COUNT(*) AS c FROM check_logs
            WHERE risk_level IN ('high', 'critical')
            """
        ).fetchone()["c"]
        recent_reports = conn.execute(
            """
            SELECT fr.*, u.username AS reporter_name
            FROM fraud_reports fr
            LEFT JOIN users u ON u.id = fr.reporter_id
            ORDER BY fr.id DESC
            LIMIT 25
            """
        ).fetchall()
        recent_checks = conn.execute(
            """
            SELECT cl.*, u.username
            FROM check_logs cl
            LEFT JOIN users u ON u.id = cl.user_id
            ORDER BY cl.id DESC
            LIMIT 25
            """
        ).fetchall()
        known = conn.execute(
            "SELECT * FROM known_risky_upis ORDER BY id DESC LIMIT 20"
        ).fetchall()
    return {
        "users": users,
        "reports": reports,
        "pending": pending,
        "checks": checks,
        "high_risk_checks": high,
        "recent_reports": [dict(r) for r in recent_reports],
        "recent_checks": [dict(r) for r in recent_checks],
        "known_risky": [dict(r) for r in known],
    }


def update_report_status(report_id: int, status: str) -> bool:
    if status not in {"pending", "verified", "rejected"}:
        return False
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM fraud_reports WHERE id = ?", (report_id,)
        ).fetchone()
        if not row:
            return False
        conn.execute(
            """
            UPDATE fraud_reports
            SET status = ?, reviewed_at = ?
            WHERE id = ?
            """,
            (status, _utcnow(), report_id),
        )
        if status == "verified":
            exists = conn.execute(
                "SELECT id FROM known_risky_upis WHERE lower(upi_id) = lower(?)",
                (row["upi_id"],),
            ).fetchone()
            if not exists:
                conn.execute(
                    """
                    INSERT INTO known_risky_upis
                    (upi_id, risk_level, reason, source, created_at)
                    VALUES (?, 'high', ?, 'user_report', ?)
                    """,
                    (row["upi_id"].lower(), row["reason"], _utcnow()),
                )
    return True


def list_all_reports() -> list[dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT fr.*, u.username AS reporter_name
            FROM fraud_reports fr
            LEFT JOIN users u ON u.id = fr.reporter_id
            ORDER BY fr.id DESC
            """
        ).fetchall()
    return [dict(r) for r in rows]
