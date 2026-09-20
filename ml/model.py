"""Lightweight scikit-learn model for optional UPI fraud scoring (no pandas)."""

from __future__ import annotations

import csv
import os
import re
from typing import Any

import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATASET_PATH = os.path.join(BASE_DIR, "dataset.csv")
MODEL_PATH = os.path.join(BASE_DIR, "fraud_model.joblib")

SUSPICIOUS_TOKENS = [
    "refund", "lottery", "prize", "kyc", "support", "helpline", "cashback",
    "otp", "verify", "official", "claim", "bonus", "urgent", "blocked",
]

FEATURE_COLUMNS = [
    "token_hits",
    "digit_len",
    "handle_len",
    "has_at",
    "amount_bin",
    "msg_urgency",
    "msg_len",
    "psp_common",
]


def extract_features(upi_id: str, amount: float = 0.0, message: str = "") -> list[float]:
    upi = (upi_id or "").strip().lower()
    msg = (message or "").lower()
    handle, _, psp = upi.partition("@")

    token_hits = sum(1 for t in SUSPICIOUS_TOKENS if t in handle or t in msg)
    digit_len = len(re.findall(r"\d", handle))
    handle_len = len(handle)
    has_at = 1.0 if "@" in upi else 0.0
    amount_bin = 0.0
    if amount >= 10000:
        amount_bin = 3.0
    elif amount >= 2000:
        amount_bin = 2.0
    elif 0 < amount < 5:
        amount_bin = 2.5
    elif amount > 0:
        amount_bin = 1.0

    msg_urgency = 1.0 if re.search(r"urgent|otp|kyc|lottery|refund", msg) else 0.0
    msg_len = min(len(msg), 500) / 500.0
    psp_common = 1.0 if psp in {
        "ybl", "oksbi", "okaxis", "okhdfcbank", "paytm", "ibl", "axl", "upi"
    } else 0.0

    return [
        float(token_hits),
        float(digit_len),
        float(handle_len),
        has_at,
        float(amount_bin),
        msg_urgency,
        msg_len,
        psp_common,
    ]


def _read_dataset_rows() -> list[dict[str, str]]:
    if not os.path.exists(DATASET_PATH):
        samples = [
            ("rahul.sharma@oksbi", "500", "", "0"),
            ("merchant.store@ybl", "1200", "order payment", "0"),
            ("scamrefund@paytm", "1", "claim your refund otp", "1"),
            ("lotterywin@oksbi", "0", "you won a prize send otp", "1"),
            ("kycupdate@ybl", "50", "urgent kyc update or blocked", "1"),
            ("cafe.corner@ibl", "280", "tea snacks", "0"),
            ("support-care@axl", "9999", "verify account now", "1"),
            ("anita1998@okhdfcbank", "750", "", "0"),
            ("cashbackdeal@ibl", "100", "limited cashback claim", "1"),
            ("helpline24x7@upi", "5000", "helpline payment", "1"),
        ]
        os.makedirs(BASE_DIR, exist_ok=True)
        with open(DATASET_PATH, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(
                fh, fieldnames=["upi_id", "amount", "message", "label"]
            )
            writer.writeheader()
            for upi, amt, msg, label in samples:
                writer.writerow(
                    {"upi_id": upi, "amount": amt, "message": msg, "label": label}
                )
    with open(DATASET_PATH, newline="", encoding="utf-8") as fh:
        return list(csv.DictReader(fh))


def train_and_save(force: bool = False) -> dict[str, Any]:
    if os.path.exists(MODEL_PATH) and not force:
        return {"status": "exists", "path": MODEL_PATH}

    rows = _read_dataset_rows()
    feature_rows: list[list[float]] = []
    labels: list[int] = []
    for row in rows:
        if "upi_id" in row:
            feature_rows.append(
                extract_features(
                    str(row.get("upi_id", "")),
                    float(row.get("amount", 0) or 0),
                    str(row.get("message", "")),
                )
            )
            labels.append(int(float(row.get("label", 0) or 0)))
        else:
            # Already feature-encoded CSV
            feature_rows.append([float(row.get(c, 0) or 0) for c in FEATURE_COLUMNS])
            labels.append(int(float(row.get("label", 0) or 0)))

    X = np.array(feature_rows, dtype=float)
    y = np.array(labels, dtype=int)

    if len(np.unique(y)) < 2 or len(y) < 4:
        clf = RandomForestClassifier(n_estimators=50, random_state=42)
        clf.fit(X, y)
        acc = None
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.25, random_state=42, stratify=y if len(y) >= 8 else None
        )
        clf = RandomForestClassifier(
            n_estimators=120,
            max_depth=6,
            random_state=42,
            class_weight="balanced",
        )
        clf.fit(X_train, y_train)
        acc = float(clf.score(X_test, y_test)) if len(X_test) else None

    joblib.dump({"model": clf, "features": FEATURE_COLUMNS, "accuracy": acc}, MODEL_PATH)
    return {"status": "trained", "path": MODEL_PATH, "accuracy": acc}


def _load_model():
    if not os.path.exists(MODEL_PATH):
        train_and_save()
    bundle = joblib.load(MODEL_PATH)
    return bundle["model"]


def predict_risk_score(upi_id: str, amount: float = 0.0, message: str = "") -> int:
    """Return 0–100 risk score from the classifier probability."""
    model = _load_model()
    feats = np.array([extract_features(upi_id, amount, message)], dtype=float)
    if hasattr(model, "predict_proba"):
        proba = model.predict_proba(feats)[0]
        classes = list(model.classes_)
        if 1 in classes:
            p = float(proba[classes.index(1)])
        else:
            p = float(proba[-1])
        return int(round(p * 100))
    pred = int(model.predict(feats)[0])
    return 80 if pred == 1 else 15


if __name__ == "__main__":
    info = train_and_save(force=True)
    print(info)
    print("sample:", predict_risk_score("scamrefund@paytm", 1, "claim refund otp"))
