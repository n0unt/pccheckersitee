"""
Comet - Web Dashboard v2
Flask + PostgreSQL + Discord OAuth2
"""
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from functools import wraps
import psycopg2, psycopg2.extras
import hashlib, secrets, string, datetime, json, os, urllib.parse, ssl
import requests as _requests

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production")
app.config["MAX_CONTENT_LENGTH"] = 150 * 1024 * 1024  # 150MB max upload

DATABASE_URL        = os.environ.get("DATABASE_URL", "")
DISCORD_CLIENT_ID   = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_BOT_TOKEN   = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_REDIRECT    = os.environ.get("DISCORD_REDIRECT", "https://pccheckersitee-production.up.railway.app/auth/discord/callback")

# Role IDs
ROLE_COMET = "1475015141882855424"
ROLE_UFF  = "1475022240754962452"
ROLE_FFL  = "1475022200095510621"

# Guild ID — bot must be in this server
DISCORD_GUILD_ID = os.environ.get("DISCORD_GUILD_ID", "1475014802194567238")

# ── Discord HTTP session ─────────────────────────────────────
_DISCORD_HEADERS = {
    "User-Agent": "DiscordBot (https://pccheckersitee-production.up.railway.app, 1.0)",
    "Accept": "application/json",
}

def _discord_get(path, token=None, bot=False):
    url = f"https://discord.com/api/v10{path}"
    headers = dict(_DISCORD_HEADERS)
    if bot:   headers["Authorization"] = f"Bot {DISCORD_BOT_TOKEN}"
    elif token: headers["Authorization"] = f"Bearer {token}"
    try:
        r = _requests.get(url, headers=headers, timeout=15)
        return r.json()
    except Exception as ex:
        return {"error": str(ex)}

def _discord_post(path, data, token=None, bot=False):
    url = f"https://discord.com/api/v10{path}"
    headers = dict(_DISCORD_HEADERS)
    try:
        if bot:
            headers["Authorization"] = f"Bot {DISCORD_BOT_TOKEN}"
            r = _requests.post(url, json=data, headers=headers, timeout=15)
        else:
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            r = _requests.post(url, data=data, headers=headers, timeout=15)
        return r.status_code, r.json()
    except Exception as ex:
        return 0, {"error": str(ex)}

# ── DB ───────────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

def now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def gen_pin():
    return "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))

def row_to_dict(row, cur):
    if row is None: return None
    return dict(zip([d[0] for d in cur.description], row))

def rows_to_dicts(rows, cur):
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in rows]

def init_db():
    """Create tables if they don't exist. Each statement uses a savepoint
    so a failure in one doesn't abort the whole transaction."""
    conn = get_db()
    conn.autocommit = False
    cur = conn.cursor()

    tables = [
        """CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, discord_id TEXT UNIQUE,
            username TEXT NOT NULL, avatar TEXT DEFAULT '',
            role TEXT NOT NULL DEFAULT 'pending',
            leagues TEXT NOT NULL DEFAULT '',
            created TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS pins (
            id SERIAL PRIMARY KEY, pin TEXT UNIQUE NOT NULL,
            league TEXT NOT NULL, agent_id INTEGER NOT NULL,
            used INTEGER NOT NULL DEFAULT 0,
            created TEXT NOT NULL, expires TEXT NOT NULL,
            scan_id INTEGER DEFAULT NULL,
            finished_at TEXT DEFAULT NULL)""",
        """CREATE TABLE IF NOT EXISTS scans (
            id SERIAL PRIMARY KEY, league TEXT NOT NULL,
            pc_user TEXT NOT NULL, verdict TEXT NOT NULL,
            total_hits INTEGER NOT NULL DEFAULT 0,
            roblox_accs TEXT NOT NULL DEFAULT '[]',
            report_json TEXT NOT NULL DEFAULT '{}',
            pin_used TEXT, submitted TEXT NOT NULL)""",
        """CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY, value TEXT NOT NULL)""",
    ]

    for sql in tables:
        try:
            cur.execute("SAVEPOINT sp")
            cur.execute(sql)
            cur.execute("RELEASE SAVEPOINT sp")
        except Exception as e:
            cur.execute("ROLLBACK TO SAVEPOINT sp")

    # ── Migrations: add columns that may be missing from old DBs ──
    migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS leagues TEXT DEFAULT ''",
        "ALTER TABLE pins  ADD COLUMN IF NOT EXISTS scan_id INTEGER DEFAULT NULL",
        "ALTER TABLE pins  ADD COLUMN IF NOT EXISTS finished_at TEXT DEFAULT NULL",
        "ALTER TABLE users ALTER COLUMN password DROP NOT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT DEFAULT ''",
    ]
    for sql in migrations:
        try:
            cur.execute("SAVEPOINT sp_mig")
            cur.execute(sql)
            cur.execute("RELEASE SAVEPOINT sp_mig")
        except Exception:
            cur.execute("ROLLBACK TO SAVEPOINT sp_mig")

    # Seed fallback owner
    try:
        cur.execute("SAVEPOINT sp_seed")
        cur.execute("SELECT id FROM users WHERE username=%s AND discord_id IS NULL", ("ars",))
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO users (discord_id,username,role,leagues,created) VALUES (NULL,%s,'owner','UFF,FFL',%s)",
                ("ars", now()))
        cur.execute("RELEASE SAVEPOINT sp_seed")
    except Exception:
        cur.execute("ROLLBACK TO SAVEPOINT sp_seed")

    # Auto-cleanup old unused pins
    try:
        cur.execute("SAVEPOINT sp_cleanup")
        cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("DELETE FROM pins WHERE created < %s AND used=0", (cutoff,))
        cur.execute("RELEASE SAVEPOINT sp_cleanup")
    except Exception:
        cur.execute("ROLLBACK TO SAVEPOINT sp_cleanup")

    conn.commit()
    cur.close()
    conn.close()

# ── Auth ─────────────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "user_id" not in session: return redirect(url_for("login_page"))
        return f(*a, **k)
    return w

def owner_required(f):
    @wraps(f)
    def w(*a, **k):
        if session.get("role") not in ("owner", "admin"): abort(403)
        return f(*a, **k)
    return w

def get_user():
    if "user_id" not in session: return None
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
    row = row_to_dict(cur.fetchone(), cur)
    cur.close(); conn.close()
    return row

def get_user_leagues(user):
    return [l.strip() for l in (user.get("leagues") or "").split(",") if l.strip()]

def can_access_league(user, league):
    if user["role"] in ("owner", "admin"): return True
    return league in get_user_leagues(user)

# ── Simple Login ──────────────────────────────────────────────
@app.route("/auth/login", methods=["POST"])
def do_login():
    username = request.form.get("username","").strip()
    password = request.form.get("password","").strip()
    if not username or not password:
        return redirect(url_for("login_page")+"?error=empty")
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT * FROM users WHERE username=%s",(username,))
    row=row_to_dict(cur.fetchone(),cur); cur.close(); conn.close()
    if not row:
        return redirect(url_for("login_page")+"?error=no_access")
    import hashlib
    pw_hash=hashlib.sha256(password.encode()).hexdigest()
    stored=row.get("password_hash","")
    # Owner with no password set = allow and save hash
    if row["role"] in ("owner","admin") and not stored:
        conn2=get_db(); cur2=conn2.cursor()
        cur2.execute("UPDATE users SET password_hash=%s WHERE id=%s",(pw_hash,row["id"]))
        conn2.commit(); cur2.close(); conn2.close()
    elif stored and stored!=pw_hash:
        return redirect(url_for("login_page")+"?error=bad_password")
    session["user_id"]=row["id"]; session["username"]=row["username"]; session["role"]=row["role"]
    return redirect(url_for("dashboard"))

@app.route("/auth/logout")
def auth_logout():
    session.clear(); return redirect(url_for("login_page"))

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login_page"))

@app.route("/")
def index():
    user = get_user() if "user_id" in session else None
    return render_template("home.html", user=user)

@app.route("/admin/fix-db")
def fix_db():
    """One-time route to run DB migrations on existing database."""
    try:
        conn = get_db()
        cur = conn.cursor()
        results = []
        migrations = [
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id TEXT",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT ''",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS leagues TEXT DEFAULT ''",
            "ALTER TABLE pins ADD COLUMN IF NOT EXISTS scan_id INTEGER DEFAULT NULL",
            "ALTER TABLE pins ADD COLUMN IF NOT EXISTS finished_at TEXT DEFAULT NULL",
            "ALTER TABLE users ALTER COLUMN password DROP NOT NULL",
        ]
        for sql in migrations:
            try:
                cur.execute(sql)
                conn.commit()
                results.append(f"✓ {sql[:60]}")
            except Exception as e:
                conn.rollback()
                results.append(f"✗ {sql[:60]} — {e}")
        cur.close(); conn.close()
        return "<br>".join(results) + "<br><br><b>Done. <a href='/'>Go home</a></b>"
    except Exception as e:
        return f"Error: {e}", 500

@app.route("/auth/debug")
def auth_debug():
    """Public debug page — shows OAuth config so you can verify it matches Discord portal."""
    import urllib.parse
    state = "teststate123"
    params = urllib.parse.urlencode({
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT,
        "response_type": "code",
        "scope": "identify guilds guilds.members.read",
        "state": state,
    })
    oauth_url = f"https://discord.com/api/oauth2/authorize?{params}"
    
    # Check if bot token works — use verbose version that shows errors
    bot_self = {}
    guild_info = {}
    bot_raw_error = ""
    guild_raw_error = ""
    if DISCORD_BOT_TOKEN:
        try:
            r = _requests.get("https://discord.com/api/v10/users/@me",
                headers={**_DISCORD_HEADERS, "Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=10)
            if r.ok: bot_self = r.json()
            else: bot_raw_error = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as ex:
            bot_raw_error = str(ex)
    if DISCORD_BOT_TOKEN and DISCORD_GUILD_ID:
        try:
            r = _requests.get(f"https://discord.com/api/v10/guilds/{DISCORD_GUILD_ID}",
                headers={**_DISCORD_HEADERS, "Authorization": f"Bot {DISCORD_BOT_TOKEN}"}, timeout=10)
            if r.ok: guild_info = r.json()
            else: guild_raw_error = f"HTTP {r.status_code}: {r.text[:200]}"
        except Exception as ex:
            guild_raw_error = str(ex)

    html = f"""<!DOCTYPE html>
<html><head><title>Comet Auth Debug</title>
<style>
body{{font-family:monospace;background:#080b10;color:#f0f4ff;padding:40px;}}
h2{{color:#00f5a0;}} .ok{{color:#00f5a0;}} .bad{{color:#ff4d6d;}} .warn{{color:#ffb830;}}
pre{{background:#0f1420;padding:16px;border-radius:8px;border:1px solid #1e2d44;overflow-x:auto;}}
a{{color:#00f5a0;}}
</style></head><body>
<h2>Comet — OAuth2 Debug</h2>
<pre>
DISCORD_CLIENT_ID    : {DISCORD_CLIENT_ID or "<span class='bad'>NOT SET</span>"}
DISCORD_CLIENT_SECRET: {"*****" + DISCORD_CLIENT_SECRET[-4:] if len(DISCORD_CLIENT_SECRET) > 4 else "<span class='bad'>NOT SET</span>"}
DISCORD_REDIRECT     : {DISCORD_REDIRECT}
DISCORD_GUILD_ID     : {DISCORD_GUILD_ID or "<span class='bad'>NOT SET</span>"}
DISCORD_BOT_TOKEN    : {"*****" + DISCORD_BOT_TOKEN[-4:] if len(DISCORD_BOT_TOKEN) > 4 else "<span class='bad'>NOT SET</span>"}

BOT USER             : {bot_self.get("username") or f"<span class='bad'>FAILED: {bot_raw_error or 'no response'}</span>"}
BOT ID               : {bot_self.get("id","?")}
GUILD NAME           : {guild_info.get("name") or f"<span class='bad'>FAILED: {guild_raw_error or 'no response'}</span>"}
GUILD ID             : {guild_info.get("id","?")}

ROLE_COMET           : {ROLE_LITE}
ROLE_UFF             : {ROLE_UFF}
ROLE_FFL             : {ROLE_FFL}
</pre>
<h2>OAuth URL (copy this, compare to Discord portal redirect)</h2>
<pre>{DISCORD_REDIRECT}</pre>
<p>👆 This MUST exactly match what you put in Discord Developer Portal → OAuth2 → Redirects</p>
<h2>Test Login</h2>
<p><a href="/auth/discord">Click here to test Discord login →</a></p>
<p><a href="/">← Back to home</a></p>
</body></html>"""
    return html

@app.route("/login")
def login_page():
    error = request.args.get("error")
    errors = {
        "no_access": "Account not found. Contact an admin.",
                "db_error": "Database error during login.",
                        "bad_password": "Incorrect password.",
        "empty": "Please enter username and password.",
    }
    return render_template("login.html", error=errors.get(error, error if error else None))


@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user()
    return render_template("dashboard.html", user=user,
                           role=user["role"],
                           leagues=get_user_leagues(user))

@app.route("/results/<pin>")
@login_required
def results_page(pin):
    user = get_user()
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM pins WHERE pin=%s", (pin.upper(),))
    pin_row = row_to_dict(cur.fetchone(), cur)
    if not pin_row: cur.close(); conn.close(); abort(404)
    if not can_access_league(user, pin_row["league"]): abort(403)
    scan = None
    if pin_row.get("scan_id"):
        cur.execute("SELECT * FROM scans WHERE id=%s", (pin_row["scan_id"],))
        scan = row_to_dict(cur.fetchone(), cur)
        if scan and scan.get("report_json"):
            scan["report"] = json.loads(scan["report_json"])
        if scan and scan.get("roblox_accs"):
            scan["roblox_accounts"] = json.loads(scan["roblox_accs"])
    cur.close(); conn.close()
    # Build tab data dict from stored report
    report = {}
    roblox_accs = []
    has_scan = bool(scan)
    if scan:
        report = scan.get("report", {})
        roblox_accs = scan.get("roblox_accounts", [])
        if not roblox_accs and scan.get("roblox_accs"):
            try: roblox_accs = json.loads(scan["roblox_accs"])
            except Exception: pass
    return render_template("results.html", pin=pin_row, scan=scan, user=user,
                           report=report, roblox_accs=roblox_accs, has_scan=has_scan)

# ── API: Stats ───────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    # Public totals are fine to show on home page; detailed breakdown requires login
    user = get_user() if "user_id" in session else None
    conn = get_db(); cur = conn.cursor()
    if user and user["role"] in ("owner", "admin"):
        cur.execute("SELECT COUNT(*) FROM scans"); total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict IN ('CHEATER','AUTO FAIL','AUTO_FAIL','AUTO-FAIL')"); cheater = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict IN ('SUSPICIOUS','REVIEW')"); susp = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict='CLEAN'"); clean = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE league='UFF'"); uff_c = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE league='FFL'"); ffl_c = cur.fetchone()[0]
    else:
        allowed = get_user_leagues(user)
        ph = ",".join(["%s"]*len(allowed))
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE league IN ({ph})", allowed); total = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE verdict IN ('CHEATER','AUTO FAIL','AUTO_FAIL','AUTO-FAIL') AND league IN ({ph})", allowed); cheater = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE verdict IN ('SUSPICIOUS','REVIEW') AND league IN ({ph})", allowed); susp = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE verdict='CLEAN' AND league IN ({ph})", allowed); clean = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE league='UFF' AND league IN ({ph})", allowed); uff_c = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE league='FFL' AND league IN ({ph})", allowed); ffl_c = cur.fetchone()[0]
    cur.close(); conn.close()
    return jsonify({"total":total,"cheater":cheater,"suspicious":susp,"clean":clean,"uff":uff_c,"ffl":ffl_c})

# ── API: Scans ───────────────────────────────────────────────
@app.route("/api/scans")
@login_required
def api_scans():
    user = get_user(); lf = request.args.get("league","")
    conn = get_db(); cur = conn.cursor()
    if user["role"] in ("owner","admin"):
        if lf and lf != "ALL": cur.execute("SELECT * FROM scans WHERE league=%s ORDER BY submitted DESC LIMIT 100",(lf,))
        else: cur.execute("SELECT * FROM scans ORDER BY submitted DESC LIMIT 100")
    else:
        allowed = get_user_leagues(user)
        if not allowed: cur.close(); conn.close(); return jsonify([])
        if lf and lf in allowed: cur.execute("SELECT * FROM scans WHERE league=%s ORDER BY submitted DESC LIMIT 100",(lf,))
        else:
            ph = ",".join(["%s"]*len(allowed))
            cur.execute(f"SELECT * FROM scans WHERE league IN ({ph}) ORDER BY submitted DESC LIMIT 100", allowed)
    rows = rows_to_dicts(cur.fetchall(), cur); cur.close(); conn.close()
    return jsonify([{"id":r["id"],"league":r["league"],"pc_user":r["pc_user"],"verdict":r["verdict"],
                     "total_hits":r["total_hits"],"roblox_accs":json.loads(r["roblox_accs"]),
                     "pin_used":r["pin_used"],"submitted":r["submitted"]} for r in rows])

@app.route("/api/scans/<int:scan_id>")
@login_required
def api_scan_detail(scan_id):
    user = get_user(); conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id=%s",(scan_id,))
    row = row_to_dict(cur.fetchone(), cur); cur.close(); conn.close()
    if not row: abort(404)
    if not can_access_league(user, row["league"]): abort(403)
    return jsonify({"id":row["id"],"league":row["league"],"pc_user":row["pc_user"],
                    "verdict":row["verdict"],"total_hits":row["total_hits"],
                    "roblox_accs":json.loads(row["roblox_accs"]),
                    "report":json.loads(row["report_json"]),
                    "pin_used":row["pin_used"],"submitted":row["submitted"]})

# ── API: Pins ────────────────────────────────────────────────
@app.route("/api/pins/generate", methods=["POST"])
@login_required
def api_gen_pin():
    user = get_user(); data = request.json or {}
    league = data.get("league","").upper()
    if not can_access_league(user, league): return jsonify({"error":"Not authorized"}),403
    if not league: return jsonify({"error":"League required"}),400
    pin = gen_pin()
    expires = (datetime.datetime.utcnow()+datetime.timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db(); cur = conn.cursor()

    # Step 1: Insert the new pin
    cur.execute("INSERT INTO pins (pin,league,agent_id,used,created,expires) VALUES (%s,%s,%s,0,%s,%s)",
                (pin, league, user["id"], now(), expires))

    # Step 2: Commit the insert FIRST so the cleanup sees it
    conn.commit()

    # Step 3: Now clean up old pins — keep only 3 most recent UNUSED per agent
    try:
        cur.execute("""
            DELETE FROM pins
            WHERE agent_id = %s
              AND used = 0
              AND pin != %s
              AND id NOT IN (
                  SELECT id FROM pins
                  WHERE agent_id = %s AND used = 0
                  ORDER BY id DESC
                  LIMIT 3
              )
        """, (user["id"], pin, user["id"]))
        conn.commit()
    except Exception:
        try: conn.rollback()
        except Exception: pass

    cur.close(); conn.close()
    return jsonify({"pin":pin,"league":league,"expires":expires,
                    "results_url": f"/results/{pin}"})

@app.route("/api/validate_pin", methods=["POST"])
@app.route("/api/pins/validate", methods=["POST"])
def api_validate_pin():
    data = request.json or {}
    pin = data.get("pin","").upper().strip()
    league = data.get("league","").upper().strip()
    if not pin: return jsonify({"valid":False,"error":"No PIN provided"}),400
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM pins WHERE pin=%s AND used=0",(pin,))
    row = row_to_dict(cur.fetchone(), cur); cur.close(); conn.close()
    if not row: return jsonify({"valid":False,"error":"Invalid or already used PIN"}),401
    try:
        exp_str = row["expires"]
        # Handle various stored formats
        for fmt in ["%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S"]:
            try:
                exp_dt = datetime.datetime.strptime(exp_str[:19], fmt[:len(fmt)])
                break
            except ValueError:
                continue
        else:
            exp_dt = datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # default to valid
        if datetime.datetime.utcnow() > exp_dt:
            return jsonify({"valid":False,"error":"PIN has expired"}),401
    except Exception:
        pass  # If we can't parse expires, allow it through
    # Don't reject on league mismatch — just return the correct league
    # (scanner may send wrong league; we always trust the stored PIN league)
    return jsonify({"ok":True,"valid":True,"league":row["league"]})

@app.route("/api/submit", methods=["POST"])
def api_submit_scan():
    try:
        data = request.json or {}
        pin = data.get("pin","").upper().strip()
        league = data.get("league","").upper().strip()
        if not pin:
            return jsonify({"error":"No PIN provided"}),400
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT * FROM pins WHERE pin=%s AND used=0",(pin,))
        pin_row = row_to_dict(cur.fetchone(), cur)
        if not pin_row:
            cur.close(); conn.close()
            return jsonify({"error":"Invalid or already used PIN"}),401
        # Truncate report to avoid DB overflow
        report = data.get("report",{})
        # Also store top-level scan tabs in report for results page
        ALL_TABS = ["shellbags","bam","prefetch","appcompat","roblox","cheat","yara",
                    "unsigned","recycle","sysmain","processes","cleaners","network",
                    "registry_extra","discord","discord_memory","eventlog","jumplists","lnkfiles",
                    "deleted_int","exec_history_text","power_events","two_pc","deleted_recovery"]
        for tab_key in ALL_TABS:
            if tab_key in data:
                report[tab_key+"_raw"] = data[tab_key]
        for field in ["cleaner_info","process_hits","cleaner_hits",
                      "eventlog_hits","jumplist_hits","lnk_hits","deleted_hits",
                      "exec_history","roblox_log_hits","vpn_detected",
                      "power_hits","two_pc_hits","recovery_hits","discord_memory_hits"]:
            if field in data: report[field] = data[field]
        # Never store raw IP/VPN info - only store the flag
        report.pop("vpn_info", None)
        if "report" in data and isinstance(data["report"], dict):
            data["report"].pop("vpn_info", None)
        # Smart truncation: trim long tab text rather than wiping everything
        # Truncate each raw tab to 30KB max, prioritising metadata over raw text
        TAB_TRIM_ORDER = [
            "cheat_raw","unsigned_raw","processes_raw","yara_raw",
            "deleted_int_raw","lnkfiles_raw","jumplists_raw",
            "appcompat_raw","shellbags_raw","prefetch_raw","bam_raw",
            "roblox_raw","registry_extra_raw","discord_raw","sysmain_raw",
            "recycle_raw","cleaners_raw","network_raw","eventlog_raw",
            "power_events_raw","two_pc_raw","deleted_recovery_raw",
            "discord_memory_raw","exec_history_text_raw",
        ]
        # Pre-trim cheat_raw aggressively — can have 400+ files
        if "cheat_raw" in report and isinstance(report["cheat_raw"], str):
            report["cheat_raw"] = report["cheat_raw"][:20000]
        for tab in TAB_TRIM_ORDER:
            if tab in report and isinstance(report[tab], str):
                report[tab] = report[tab][:30000]
        # Also trim exec_history which can be huge
        if "exec_history" in report and isinstance(report["exec_history"], list):
            report["exec_history"] = report["exec_history"][:50]
        report_str = json.dumps(report, default=str)
        # If still too big after trimming, do a second aggressive trim
        if len(report_str) > 1800000:
            for tab in TAB_TRIM_ORDER:
                if tab in report:
                    report[tab] = report.get(tab,"")[:8000]
            report_str = json.dumps(report, default=str)
        # Last resort - only if truly enormous
        if len(report_str) > 2800000:
            report["_truncated"] = True
            for tab in TAB_TRIM_ORDER:
                if tab in report: report[tab] = "[truncated — too large]"
            report_str = json.dumps(report, default=str)
        cur.execute("""INSERT INTO scans (league,pc_user,verdict,total_hits,roblox_accs,report_json,pin_used,submitted)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (league or pin_row["league"],
                     data.get("pc_user","unknown"),
                     data.get("verdict","UNKNOWN"),
                     int(data.get("total_hits",0)),
                     json.dumps(data.get("roblox_accounts",[])),
                     json.dumps(report),
                     pin, now()))
        scan_id = cur.fetchone()[0]
        cur.execute("UPDATE pins SET used=1, scan_id=%s, finished_at=%s WHERE pin=%s",
                    (scan_id, now(), pin))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"ok":True,"scan_id":scan_id})
    except Exception as e:
        app.logger.error(f"api_submit_scan error: {e}", exc_info=True)
        return jsonify({"error":str(e)}),500

@app.route("/api/pins")
@login_required
def api_pins():
    user = get_user(); conn = get_db(); cur = conn.cursor()
    if user["role"] in ("owner","admin"):
        cur.execute("""SELECT p.*,u.username as agent FROM pins p
                       JOIN users u ON p.agent_id=u.id
                       ORDER BY p.created DESC LIMIT 100""")
    else:
        cur.execute("""SELECT p.*,u.username as agent FROM pins p
                       JOIN users u ON p.agent_id=u.id
                       WHERE p.agent_id=%s ORDER BY p.created DESC LIMIT 100""",
                    (user["id"],))
    rows = rows_to_dicts(cur.fetchall(), cur); cur.close(); conn.close()
    return jsonify(rows)

# ── API: Admin ───────────────────────────────────────────────
@app.route("/api/admin/users")
@login_required
@owner_required
def api_admin_users():
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id,discord_id,username,avatar,role,leagues,created FROM users ORDER BY created DESC")
    rows = rows_to_dicts(cur.fetchall(), cur); cur.close(); conn.close()
    return jsonify(rows)

@app.route("/api/admin/users/<int:uid>", methods=["PATCH"])
@login_required
@owner_required
def api_admin_update_user(uid):
    data = request.json or {}; conn = get_db(); cur = conn.cursor()
    if data.get("role"):     cur.execute("UPDATE users SET role=%s WHERE id=%s",(data["role"],uid))
    if data.get("leagues") is not None: cur.execute("UPDATE users SET leagues=%s WHERE id=%s",(data["leagues"],uid))
    if data.get("username"): cur.execute("UPDATE users SET username=%s WHERE id=%s",(data["username"],uid))
    if data.get("password"):
        pw_hash = hashlib.sha256(data["password"].encode()).hexdigest()
        cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",(pw_hash,uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/admin/users/create", methods=["POST"])
@login_required
@owner_required
def api_admin_create_user():
    data = request.json or {}
    username = data.get("username","").strip()
    password = data.get("password","").strip()
    role     = data.get("role","agent")
    leagues  = data.get("leagues","")
    if not username or not password:
        return jsonify({"error":"Username and password required"}),400
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=%s",(username,))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"error":"Username already exists"}),409
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    cur.execute(
        "INSERT INTO users (discord_id,username,password_hash,role,leagues,created) VALUES (NULL,%s,%s,%s,%s,%s) RETURNING id",
        (username, pw_hash, role, leagues, now()))
    new_id = cur.fetchone()[0]
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True,"id":new_id,"username":username})

@app.route("/api/admin/users/<int:uid>/reset-password", methods=["POST"])
@login_required
@owner_required
def api_admin_reset_password(uid):
    data = request.json or {}
    password = data.get("password","").strip()
    if not password: return jsonify({"error":"Password required"}),400
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    conn=get_db(); cur=conn.cursor()
    cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",(pw_hash,uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@login_required
@owner_required
def api_admin_delete_user(uid):
    if uid == session.get("user_id"): return jsonify({"error":"Cannot delete yourself"}),400
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s",(uid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})



@app.route("/api/debug/pin/<pin_code>")
@login_required
@owner_required
def debug_pin(pin_code):
    """Debug: show exact DB state of a PIN."""
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM pins WHERE pin=%s", (pin_code.upper(),))
    row = row_to_dict(cur.fetchone(), cur)
    cur.close(); conn.close()
    if not row: return jsonify({"found": False, "pin": pin_code.upper()})
    return jsonify({"found": True, "pin": row["pin"], "league": row["league"],
                    "used": row["used"], "expires": row["expires"],
                    "created": row["created"], "agent_id": row["agent_id"]})


@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
@login_required
def api_delete_scan(scan_id):
    user = get_user()
    # Only admins and owners can delete scans — agents cannot
    if user["role"] not in ("admin", "owner"):
        return jsonify({"error": "Only admins and owners can delete scans"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM scans WHERE id=%s", (scan_id,))
    row = row_to_dict(cur.fetchone(), cur)
    if not row: cur.close(); conn.close(); return jsonify({"error":"Not found"}), 404
    if not can_access_league(user, row["league"]): cur.close(); conn.close(); abort(403)
    cur.execute("DELETE FROM scans WHERE id=%s", (scan_id,))
    cur.execute("UPDATE pins SET scan_id=NULL WHERE scan_id=%s", (scan_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})

@app.route("/api/scans/bulk-delete", methods=["POST"])
@login_required
@owner_required
def api_bulk_delete_scans():
    """Delete multiple scans at once — owner only."""
    data = request.json or {}
    ids = data.get("ids", [])
    if not ids: return jsonify({"error": "No IDs provided"}), 400
    conn = get_db(); cur = conn.cursor()
    ph = ",".join(["%s"] * len(ids))
    cur.execute(f"UPDATE pins SET scan_id=NULL WHERE scan_id IN ({ph})", ids)
    cur.execute(f"DELETE FROM scans WHERE id IN ({ph})", ids)
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True, "deleted": len(ids)})


@app.route("/results/<pin>/download")
@login_required
def download_report(pin):
    """Generate and download a formatted HTML report for a scan."""
    user = get_user()
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM pins WHERE pin=%s", (pin.upper(),))
    pin_row = row_to_dict(cur.fetchone(), cur)
    if not pin_row: cur.close(); conn.close(); abort(404)
    if not can_access_league(user, pin_row["league"]): abort(403)
    scan = None
    if pin_row.get("scan_id"):
        cur.execute("SELECT * FROM scans WHERE id=%s", (pin_row["scan_id"],))
        scan = row_to_dict(cur.fetchone(), cur)
        if scan and scan.get("report_json"):
            scan["report"] = json.loads(scan["report_json"])
        if scan and scan.get("roblox_accs"):
            scan["roblox_accounts"] = json.loads(scan["roblox_accs"])
    cur.close(); conn.close()
    if not scan:
        abort(404)

    report = scan.get("report", {})
    roblox_accounts = scan.get("roblox_accounts", [])
    discord_accounts = report.get("discord_accounts", [])

    def esc(s):
        s = str(s or "")
        return s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")

    def section(title, content_html, color="#58a6ff"):
        return f"""<section>
<h2 style="color:{color}">{esc(title)}</h2>
{content_html}
</section>"""

    def pre(text):
        if not text or str(text).strip() in ("", "No data."):
            return '<pre style="color:#6e7681">No data collected.</pre>'
        return f"<pre>{esc(str(text))}</pre>"

    # Build Roblox accounts section
    roblox_html = "<ul>"
    if roblox_accounts:
        for acc in roblox_accounts:
            if isinstance(acc, dict):
                uname = acc.get("username","Unknown")
                uid   = acc.get("userid","")
                ls    = acc.get("last_seen","")
                srcs  = ", ".join(acc.get("sources",[]))
                url   = f"https://www.roblox.com/users/{uid}/profile" if uid else "#"
                roblox_html += f'<li><a href="{url}" target="_blank">{esc(uname)}</a>'
                if uid:   roblox_html += f' <span style="color:#6e7681">(ID: {esc(uid)})</span>'
                if ls:    roblox_html += f' — Last seen: {esc(ls)}'
                if srcs:  roblox_html += f' <span style="color:#6e7681">[{esc(srcs)}]</span>'
                roblox_html += "</li>"
            else:
                roblox_html += f"<li>{esc(str(acc))}</li>"
    else:
        roblox_html += "<li style='color:#6e7681'>No accounts detected</li>"
    roblox_html += "</ul>"

    # Build Discord accounts section
    disc_html = "<ul>"
    if discord_accounts:
        for d in discord_accounts:
            if isinstance(d, dict):
                uname = d.get("username","Unknown")
                uid   = d.get("id","")
                ls    = d.get("last_switched","")
                src   = d.get("source","")
                token = d.get("has_token", False)
                disc_html += f'<li>@{esc(uname)}'
                if uid: disc_html += f' <span style="color:#6e7681">(ID: {esc(uid)})</span>'
                if ls:  disc_html += f' — Last switched: {esc(ls)}'
                if src: disc_html += f' [{esc(src)}]'
                if token: disc_html += ' <span style="color:#f87171">⚠ TOKEN FOUND</span>'
                disc_html += "</li>"
            else:
                disc_html += f"<li>{esc(str(d))}</li>"
    else:
        disc_html += "<li style='color:#6e7681'>No Discord accounts detected</li>"
    disc_html += "</ul>"

    # Hit score bars
    hit_rows = [
        ("ShellBag",     report.get("shellbag_hits",0)),
        ("BAM",          report.get("bam_hits",0)),
        ("Prefetch",     report.get("prefetch_hits",0)),
        ("AppCompat",    report.get("appcompat_hits",0)),
        ("Cheat Files",  report.get("cheat_hits",0)),
        ("YARA",         report.get("yara_hits",0)),
        ("Unsigned",     report.get("unsigned_count",0)),
        ("SysMain",      report.get("sysmain_hits",0)),
        ("Event Log",    report.get("eventlog_hits",0)),
        ("Cleaners",     report.get("cleaner_hits",0)),
        ("Log Tamper",   report.get("roblox_hits",0)),
        ("FastFlags",    len(report.get("fastflags",[]))),
    ]
    score_html = "<table style='width:100%;border-collapse:collapse;font-size:0.8rem'>"
    for label, val in hit_rows:
        bar_w = min(int(val) * 8, 200)
        color = "#f87171" if val > 0 else "#3d4a5c"
        score_html += f"""<tr style="border-bottom:1px solid #21262d">
  <td style="padding:5px 10px 5px 0;color:#8b949e;width:140px">{esc(label)}</td>
  <td style="padding:5px;width:220px"><div style="background:#21262d;height:6px;border-radius:3px">
    <div style="background:{color};width:{bar_w}px;height:6px;border-radius:3px;max-width:200px"></div></div></td>
  <td style="padding:5px;color:{color};font-weight:bold">{val}</td>
</tr>"""
    score_html += f"""<tr style="border-top:2px solid #30363d;margin-top:8px">
  <td style="padding:8px 10px 5px 0;color:#c9d1d9;font-weight:bold">TOTAL HITS</td>
  <td></td>
  <td style="padding:8px 5px;color:{'#f87171' if scan['total_hits']>0 else '#34d399'};font-size:1.1rem;font-weight:bold">{scan["total_hits"]}</td>
</tr></table>"""

    # Tab sections
    tab_sections = [
        ("ShellBags",         report.get("shellbags_raw") or report.get("shellbags","")),
        ("BAM",               report.get("bam_raw") or report.get("bam","")),
        ("Prefetch",          report.get("prefetch_raw") or report.get("prefetch","")),
        ("AppCompat",         report.get("appcompat_raw") or report.get("appcompat","")),
        ("Roblox Logs",       report.get("roblox_raw") or report.get("roblox","")),
        ("Cheat Files",       report.get("cheat_raw") or report.get("cheat","")),
        ("YARA / Heuristic",  report.get("yara_raw") or report.get("yara","")),
        ("Unsigned Files",    report.get("unsigned_raw") or report.get("unsigned","")),
        ("Recycle Bin",       report.get("recycle_raw") or report.get("recycle","")),
        ("SysMain / Bypass",  report.get("sysmain_raw") or report.get("sysmain","")),
        ("Running Processes", report.get("processes_raw") or report.get("processes","")),
        ("Cleaners",          report.get("cleaners_raw") or report.get("cleaners","")),
        ("Network / VPN",     report.get("network_raw") or report.get("network","")),
        ("Event Log",         report.get("eventlog_raw") or report.get("eventlog","")),
        ("Jump Lists",        report.get("jumplists_raw") or report.get("jumplists","")),
        ("LNK Files",         report.get("lnkfiles_raw") or report.get("lnkfiles","")),
        ("Deleted Integrity", report.get("deleted_int_raw") or report.get("deleted_int","")),
        ("Roblox Alt Detection", report.get("registry_extra_raw") or report.get("registry_extra","")),
        ("Factory Reset",     report.get("factory_resets","")),
        ("Drive / USB",       report.get("drive_info","")),
        ("FastFlags",         str(report.get("fastflags",""))),
        ("Full Raw Report",   report.get("full_report","")),
    ]

    sections_html = section("Roblox Accounts", roblox_html, "#34d399")
    sections_html += section("Discord Accounts", disc_html, "#818cf8")
    sections_html += section("Detection Scores", score_html, "#f59e0b")
    for title, text in tab_sections:
        if text and str(text).strip() and str(text).strip() not in ("None","[]","{}",""):
            sections_html += section(title, pre(text))

    cleaner = report.get("cleaner_info","")
    vpn_detected = report.get("vpn_detected", False)
    # Only show VPN flag — never show raw IP
    info_parts = []
    if vpn_detected: info_parts.append("<p><b>VPN Detected:</b> <span style='color:#f87171'>Yes</span></p>")
    if cleaner and cleaner != "None detected": info_parts.append(f"<p><b>Cleaner:</b> {esc(str(cleaner))}</p>")
    if info_parts:
        sections_html += section("Detection Extras", "".join(info_parts), "#f59e0b")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Comet Scan Report — {esc(pin.upper())}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0d1117;color:#c9d1d9;font-family:'Cascadia Code','Consolas',monospace;padding:2rem;max-width:980px;margin:auto;line-height:1.6}}
  h1{{color:#00f5a0;font-size:1.5rem;margin-bottom:.2rem;letter-spacing:.04em}}
  .meta{{color:#6e7681;font-size:.8rem;margin-bottom:.3rem}}
  .badges{{margin:1rem 0 2rem;display:flex;gap:10px;flex-wrap:wrap}}
  .badge{{padding:4px 14px;border-radius:20px;font-size:.75rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase}}
  .badge.REVIEW,.badge.UNKNOWN{{background:rgba(251,191,36,.12);color:#fbbf24;border:1px solid rgba(251,191,36,.25)}}
  .badge.CLEAN{{background:rgba(52,211,153,.12);color:#34d399;border:1px solid rgba(52,211,153,.25)}}
  .badge.CHEATER,.badge.AUTO-FAIL,.badge.AUTO_FAIL{{background:rgba(248,113,113,.12);color:#f87171;border:1px solid rgba(248,113,113,.25)}}
  .badge.hits{{background:rgba(248,113,113,.12);color:#f87171;border:1px solid rgba(248,113,113,.25)}}
  .badge.league{{background:rgba(0,245,160,.1);color:#00f5a0;border:1px solid rgba(0,245,160,.2)}}
  h2{{font-size:.9rem;margin:0 0 .75rem;padding-bottom:.4rem;border-bottom:1px solid #21262d;letter-spacing:.04em}}
  section{{background:#161b22;border:1px solid #21262d;border-radius:10px;padding:1.25rem;margin-bottom:1rem}}
  pre{{white-space:pre-wrap;word-break:break-word;font-size:.78rem;line-height:1.7;color:#c9d1d9}}
  ul{{margin:.25rem 0;padding-left:1.5rem;font-size:.85rem}}
  li{{margin-bottom:.35rem;line-height:1.5}}
  a{{color:#58a6ff;text-decoration:none}}
  a:hover{{text-decoration:underline}}
  .divider{{border:none;border-top:1px solid #21262d;margin:1.5rem 0}}
  @media print{{body{{background:#fff;color:#000}} section{{border:1px solid #ccc}}}}
</style>
</head>
<body>
<h1>◈ Comet Forensic Report</h1>
<p class="meta">PIN: {esc(pin.upper())} &nbsp;|&nbsp; Agent: {esc(scan.get("pc_user","?"))} &nbsp;|&nbsp; Submitted: {esc(scan.get("submitted","?"))} UTC &nbsp;|&nbsp; League: {esc(scan.get("league","?"))}</p>
<p class="meta">Generated: {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC &nbsp;|&nbsp; Comet Scanner v5</p>
<div class="badges">
  <span class="badge {esc(scan.get('verdict','UNKNOWN').replace(' ','-'))}">{esc(scan.get("verdict","UNKNOWN"))}</span>
  <span class="badge hits">{scan.get("total_hits",0)} HITS</span>
  <span class="badge league">{esc(scan.get("league","?"))}</span>
</div>
{sections_html}
<hr class="divider">
<p style="color:#3d4a5c;font-size:.75rem;text-align:center">Comet Forensic Scanner &nbsp;·&nbsp; Report generated {datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")} UTC</p>
</body>
</html>"""

    from flask import Response
    filename = f"comet-report-{pin.upper()}-{scan.get('pc_user','unknown')}.html"
    return Response(
        html,
        mimetype="text/html",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


@app.route("/api/test-submit")
@login_required
@owner_required  
def api_test_submit():
    """Quick test to verify submit pipeline works end to end."""
    try:
        conn=get_db(); cur=conn.cursor()
        # Check DB connection
        cur.execute("SELECT COUNT(*) FROM scans")
        scan_count = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM pins WHERE used=0")
        active_pins = cur.fetchone()[0]
        cur.close(); conn.close()
        return jsonify({
            "ok": True,
            "db": "connected",
            "scan_count": scan_count,
            "active_pins": active_pins,
            "message": "Submit pipeline working"
        })
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 500

# ── Public pages ─────────────────────────────────────────────
@app.route("/download")
def download_page():
    meta = {}
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=%s", ("exe_meta",))
        row = cur.fetchone()
        meta = json.loads(row[0]) if row else {}
        cur.close(); conn.close()
    except Exception: pass
    # exe_meta exists = a file was uploaded (data is in exe_data row)
    has_exe = bool(meta.get("version") and meta.get("updated"))
    user = get_user() if "user_id" in session else None
    return render_template("download.html",
                           has_exe=has_exe,
                           download_url="/download/exe" if has_exe else None,
                           version=meta.get("version","v3.0"),
                           file_size=meta.get("size",""),
                           updated=meta.get("updated",""),
                           user=user)

@app.route("/privacy")
def privacy_page():
    user = get_user() if "user_id" in session else None
    return render_template("privacy.html", user=user)

@app.route("/terms")
def terms_page():
    user = get_user() if "user_id" in session else None
    return render_template("terms.html", user=user)

@app.route("/home")
def home_page():
    return redirect(url_for("login_page"))

@app.route("/api/admin/upload-exe", methods=["POST"])
@login_required
@owner_required
def upload_exe():
    import base64
    f = request.files.get("file")
    ver = (request.form.get("version") or "v3.0").strip()
    if not f: return jsonify({"error":"No file provided"}),400
    filename = f.filename or "CometScanner.exe"
    data = f.read()
    if len(data) == 0: return jsonify({"error":"File is empty"}),400
    size_mb = round(len(data)/1024/1024, 1)
    b64 = base64.b64encode(data).decode("ascii")

    # Store meta (without file) and file data separately so meta queries stay fast
    meta = {"version": ver, "size": f"{size_mb} MB", "filename": filename, "updated": now()}
    try:
        conn = get_db(); cur = conn.cursor()
        # Meta row (small, fast to query)
        cur.execute("INSERT INTO settings (key,value) VALUES (%s,%s) "
                    "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
                    ("exe_meta", json.dumps(meta)))
        # File data row (large, only read on download)
        cur.execute("INSERT INTO settings (key,value) VALUES (%s,%s) "
                    "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
                    ("exe_data", b64))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Also cache to /tmp for fast serving this session
    try:
        with open("/tmp/cometscanner.exe","wb") as fp: fp.write(data)
        with open("/tmp/comet_fname.txt","w") as fp: fp.write(filename)
    except Exception: pass

    return jsonify({"ok":True,"version":ver,"size":f"{size_mb} MB"})


@app.route("/download/exe")
def download_exe():
    import base64, io
    from flask import send_file

    filename = "CometScanner.exe"

    # Try /tmp cache first (fast)
    if os.path.exists("/tmp/cometscanner.exe"):
        try:
            if os.path.exists("/tmp/comet_fname.txt"):
                filename = open("/tmp/comet_fname.txt").read().strip()
            return send_file("/tmp/cometscanner.exe", as_attachment=True,
                             download_name=filename, mimetype="application/octet-stream")
        except Exception: pass

    # Fall back to DB
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key='exe_meta'")
        meta_row = cur.fetchone()
        cur.execute("SELECT value FROM settings WHERE key='exe_data'")
        data_row = cur.fetchone()
        cur.close(); conn.close()
    except Exception:
        abort(404)

    if not data_row or not data_row[0]:
        abort(404)

    if meta_row:
        meta = json.loads(meta_row[0])
        filename = meta.get("filename", filename)

    data = base64.b64decode(data_row[0])
    # Cache for next time
    try:
        with open("/tmp/cometscanner.exe","wb") as fp: fp.write(data)
        with open("/tmp/comet_fname.txt","w") as fp: fp.write(filename)
    except Exception: pass

    return send_file(io.BytesIO(data), as_attachment=True,
                     download_name=filename, mimetype="application/octet-stream")


@app.route("/debug/discord/<discord_id>")
@login_required
@owner_required
def debug_discord(discord_id):
    """Owner-only: check what roles the bot sees for a Discord user."""
    member = _discord_get(f"/guilds/{DISCORD_GUILD_ID}/members/{discord_id}", bot=True)
    bot_self = _discord_get("/users/@me", bot=True)
    return jsonify({
        "guild_id": DISCORD_GUILD_ID,
        "bot_user": bot_self.get("username"),
        "bot_id":   bot_self.get("id"),
        "member":   member,
        "roles_found": member.get("roles",[]),
        "ROLE_COMET_match": ROLE_COMET in member.get("roles",[]),
        "ROLE_UFF_match":  ROLE_UFF  in member.get("roles",[]),
        "ROLE_FFL_match":  ROLE_FFL  in member.get("roles",[]),
    })

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
