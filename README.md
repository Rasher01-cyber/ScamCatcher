# UPI Guard — UPI Fraud Detection & Awareness System

Educational web app that helps users **check before they pay**: UPI ID risk, transaction context, QR payloads, and suspicious messages — with a fraud-risk score, plain-language explanations, community reports, and an admin dashboard.

> Not a bank product. For awareness, demos, and coursework. Always verify payees through official channels.

## Live existence APIs (optional but recommended)

NPCI does **not** offer a free public “is this UPI registered?” API to websites.
UPI Guard integrates real merchant verification APIs when you add keys:

| Check | Provider | Env vars |
|-------|----------|----------|
| UPI VPA exists? + linked name | [Razorpay Validate VPA](https://razorpay.com/docs/payments/payment-methods/upi/vpa-validation/) | `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET` |
| UPI VPA exists? (alt) | Cashfree Verification | `CASHFREE_CLIENT_ID`, `CASHFREE_CLIENT_SECRET`, `CASHFREE_ENV` |
| Mobile line valid? | Numverify | `NUMVERIFY_ACCESS_KEY` |

```bash
copy .env.example .env
# edit .env with your keys, then restart: python app.py
```

Without keys:
- Invalid format / unknown `@provider` → shown as **not generated** (✖)
- Live network rows may show **?** until keys are added
- Your official UPI app remains the ultimate existence check

## Features

- User registration / login (session-based)
- UPI ID authenticity (format + live API when configured)
- Transaction-risk analysis
- QR-code analyzer (image decode + `upi://` paste)
- Mobile number checker
- Suspicious-message analyzer
- Fraud-risk score (0–100) with warning explanations
- Report suspicious UPI IDs
- SQLite fraud-report database
- Admin dashboard (verify/reject reports)
- Optional ML scoring (scikit-learn Random Forest)
- Mobile-friendly Bootstrap UI

## Stack

| Layer    | Tech                          |
|----------|-------------------------------|
| Frontend | HTML, CSS, JavaScript, Bootstrap 5 |
| Backend  | Python, Flask                 |
| Database | SQLite                        |
| QR       | Pillow + pyzbar               |
| ML       | scikit-learn, pandas, joblib  |

## Quick start

```bash
cd UPI-Fraud-Detection-System
python -m venv .venv

# Windows
.venv\Scripts\activate

# macOS / Linux
# source .venv/bin/activate

pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000)

### Demo admin

- Username: `admin`
- Password: `admin123`

Change the password in production and set `UPI_GUARD_SECRET`.

## Try these samples

| Input | Expected |
|-------|----------|
| `scamrefund@paytm` + ₹1 | High / critical |
| `rahul.sharma@oksbi` + ₹500 | Safer / low |
| Message: “Urgent KYC update share OTP” | High |
| QR paste: `upi://pay?pa=lotterywin@oksbi&am=1&pn=Prize` | High |

## Project layout

```
UPI-Fraud-Detection-System/
├── app.py
├── database.py
├── fraud_detector.py
├── requirements.txt
├── database/upi_fraud.db   (created on first run)
├── templates/
├── static/
└── ml/
    ├── dataset.csv
    └── model.py
```

## QR decoding note

`pyzbar` needs the **zbar** shared library on some systems:

- Windows: install a zbar build or use the paste-`upi://` fallback
- Debian/Ubuntu: `sudo apt install libzbar0`
- macOS: `brew install zbar`

If image decode fails, paste the UPI payment link — analysis still works.

## Retrain ML model

```bash
python -m ml.model
```

## License

Educational / demo use.
