# Deploy notes

## Why Netlify will not work

**Netlify** hosts static HTML/JS (and small serverless functions).  
**ScamCatcherrr** is a **Python Flask** app (templates, SQLite, sessions, ML, QR decode).

Use **Render**, Railway, Fly.io, or PythonAnywhere instead.

## Deploy on Render (recommended) — name: ScamCatcherrr

1. Push this repo to GitHub (already: `Rasher01-cyber/UPI-Fraud-Detection-System`).
2. Go to https://dashboard.render.com/ and sign in with GitHub.
3. **New → Web Service** → select this repository.
4. Settings:
   - **Name:** `scamcatcherrr`
   - **Runtime:** Python
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn wsgi:app --bind 0.0.0.0:$PORT --workers 1 --threads 4 --timeout 120`
5. Add env vars (optional for live UPI checks):
   - `UPI_GUARD_SECRET` = any long random string
   - `RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` (optional)
6. Click **Create Web Service**.
7. After build, open: `https://scamcatcherrr.onrender.com` (exact URL shown in Render).

Free tier may sleep after idle; first load can take ~30–60s.

## Local run (Windows CMD)

```cmd
cd /d C:\Users\User\Projects\UPI-Fraud-Detection-System
.venv\Scripts\python.exe app.py
```

Open http://127.0.0.1:5000/
