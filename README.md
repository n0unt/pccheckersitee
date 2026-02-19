# PC Checker — Deployment Guide

## Website (Railway/Render)

### Railway
1. Push the `pccheckersite/` folder to a GitHub repo
2. Go to railway.app → New Project → Deploy from GitHub
3. Set environment variable: `SECRET_KEY` = any long random string
4. Railway auto-detects Procfile and deploys
5. Copy your URL (e.g. https://your-app.railway.app)

### Render
1. Push to GitHub
2. render.com → New Web Service → Connect repo
3. Build command: `pip install -r requirements.txt`
4. Start command: `gunicorn app:app --bind 0.0.0.0:$PORT`
5. Add env var: `SECRET_KEY`

---

## Scanner App

1. Open `pc_checker_v3.py`
2. Set `WEBSITE_URL` to your deployed URL:
   ```python
   WEBSITE_URL = "https://your-app.railway.app"
   ```
3. Build to EXE:
   ```
   pip install pyinstaller
   pyinstaller --onefile --noconsole pc_checker_v3.py
   ```

---

## Login

- **Username:** `ars`
- **Password:** `123456`
- **Role:** owner (sees all scans from both leagues)

---

## How the flow works

1. Agent logs into website → PIN Manager → picks league → Generate PIN
2. Agent gives the 8-char PIN to the player being screenshared
3. Player opens pc_checker_v3.exe → enters PIN → picks league → clicks Run Scan
4. Scan results send to Discord webhook AND website dashboard simultaneously
5. PIN is marked used and cannot be reused

---

## Justice Team Setup

1. Agent goes to `/register`, creates account, picks their league
2. You log in as `ars` → Users tab → change their role from `pending` → `agent`
3. Set their leagues (e.g. `UFF` or `FFL` or `UFF,FFL`)
4. They can now log in and generate PINs for their league only

---

## Dashboards

| Dashboard | Who sees it |
|-----------|-------------|
| UFF Scans | UFF agents + owner |
| FFL Scans | FFL agents + owner |
| All Scans | Owner only |
| PIN Manager | All agents (own PINs only) |
| Users | Owner only |
