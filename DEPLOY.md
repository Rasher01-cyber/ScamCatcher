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
5. **Important — Environment → Environment Variables:**
   - `PYTHON_VERSION` = `3.11.9`  ← required (Render’s default 3.14 breaks installs)
   - `UPI_GUARD_SECRET` = any long random string
   - `RAZORPAY_KEY_ID` / `RAZORPAY_KEY_SECRET` (optional)
6. Click **Manual Deploy → Deploy latest commit**.


Free tier may sleep after idle; first load can take ~30–60s.

## Local run (like `npm run dev`)

```cmd
cd /d C:\Users\User\Projects\UPI-Fraud-Detection-System
npm run setup
npm run dev
```

Then open **http://127.0.0.1:5000/**

(`npm run dev` starts Flask — this is not a Node app.)
