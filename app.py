"""
PC Checker - Web Dashboard v2
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
ROLE_LITE = "1475015141882855424"
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

# ── Discord OAuth ─────────────────────────────────────────────
@app.route("/auth/discord")
def discord_auth():
    state = secrets.token_hex(16)
    session["oauth_state"] = state
    params = urllib.parse.urlencode({
        "client_id": DISCORD_CLIENT_ID,
        "redirect_uri": DISCORD_REDIRECT,
        "response_type": "code",
        "scope": "identify guilds guilds.members.read",
        "state": state,
    })
    return redirect(f"https://discord.com/api/oauth2/authorize?{params}")

@app.route("/auth/discord/callback")
def discord_callback():
    code  = request.args.get("code")
    state = request.args.get("state")
    if not code or state != session.get("oauth_state"):
        return redirect(url_for("login_page") + "?error=state_mismatch")

    # Exchange code for token
    status, token_data = _discord_post("/oauth2/token", {
        "client_id": DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": DISCORD_REDIRECT,
    })
    if status != 200 or "access_token" not in token_data:
        err_detail = token_data.get("error_description") or token_data.get("error") or str(token_data)[:100]
        app.logger.error(f"Discord token exchange failed {status}: {err_detail}")
        return redirect(url_for("login_page") + f"?error=token_failed&detail={urllib.parse.quote(err_detail)}")

    access_token = token_data["access_token"]

    # Get Discord user
    discord_user = _discord_get("/users/@me", token=access_token)
    if not discord_user.get("id"):
        return redirect(url_for("login_page") + "?error=user_failed")

    discord_id  = discord_user["id"]
    username    = discord_user.get("username", "Unknown")
    avatar      = discord_user.get("avatar", "")

    # Check guild roles using the USER's own OAuth token (guilds.members.read scope)
    # This avoids needing the bot to make server-side API calls to Discord
    # which can be blocked by Railway's network restrictions
    role         = "pending"
    leagues      = ""

    # First try: use user token to get their member info directly (most reliable)
    member_roles = []
    if DISCORD_GUILD_ID:
        member_data = _discord_get(f"/users/@me/guilds/{DISCORD_GUILD_ID}/member", token=access_token)
        member_roles = member_data.get("roles", [])
        app.logger.info(f"Member data for {discord_id}: code={member_data.get('code')} roles={member_roles}")

    # If user token method failed (scope not granted), fall back to bot
    if not member_roles and DISCORD_BOT_TOKEN:
        member_data = _discord_get(f"/guilds/{DISCORD_GUILD_ID}/members/{discord_id}", bot=True)
        member_roles = member_data.get("roles", [])
        app.logger.info(f"Bot member data for {discord_id}: code={member_data.get('code')} roles={member_roles}")

    # Assign roles based on Discord roles found
    if ROLE_LITE in member_roles:
        role    = "owner"
        leagues = "UFF,FFL"

    if ROLE_UFF in member_roles:
        leagues = (leagues + ",UFF").strip(",")
        if role == "pending": role = "agent"

    if ROLE_FFL in member_roles:
        leagues = (leagues + ",FFL").strip(",")
        if role == "pending": role = "agent"

    # Clean up duplicate leagues
    leagues = ",".join(dict.fromkeys(leagues.split(",")).keys()).strip(",")

    # Hard override: owner Discord ID from env var always gets access
    # Set OWNER_DISCORD_ID in Railway variables to your Discord user ID
    OWNER_DISCORD_ID = os.environ.get("OWNER_DISCORD_ID", "")
    if OWNER_DISCORD_ID and discord_id == OWNER_DISCORD_ID:
        role = "owner"; leagues = "UFF,FFL"

    if role == "pending":
        # Check if user is even in the server
        guilds = _discord_get("/users/@me/guilds", token=access_token)
        in_server = any(str(g.get("id","")) == str(DISCORD_GUILD_ID) for g in (guilds if isinstance(guilds, list) else []))
        if not in_server:
            return redirect(url_for("login_page") + "?error=not_in_server")
        return redirect(url_for("login_page") + "?error=no_access")

    # Upsert user
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE discord_id=%s", (discord_id,))
        existing = cur.fetchone()
        if existing:
            cur.execute("UPDATE users SET username=%s, avatar=%s, role=%s, leagues=%s WHERE discord_id=%s",
                        (username, avatar, role, leagues, discord_id))
            user_id = existing[0]
        else:
            cur.execute("INSERT INTO users (discord_id,username,avatar,role,leagues,created) VALUES (%s,%s,%s,%s,%s,%s) RETURNING id",
                        (discord_id, username, avatar, role, leagues, now()))
            user_id = cur.fetchone()[0]
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        app.logger.error(f"User upsert failed: {e}", exc_info=True)
        return redirect(url_for("login_page") + f"?error=db_error&detail={urllib.parse.quote(str(e)[:100])}")

    session["user_id"] = user_id
    session["username"] = username
    session["role"] = role
    session["leagues"] = leagues
    session["avatar"] = f"https://cdn.discordapp.com/avatars/{discord_id}/{avatar}.png" if avatar else ""
    return redirect(url_for("dashboard"))

# ── Pages ────────────────────────────────────────────────────
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
<html><head><title>Lite Auth Debug</title>
<style>
body{{font-family:monospace;background:#080b10;color:#f0f4ff;padding:40px;}}
h2{{color:#00f5a0;}} .ok{{color:#00f5a0;}} .bad{{color:#ff4d6d;}} .warn{{color:#ffb830;}}
pre{{background:#0f1420;padding:16px;border-radius:8px;border:1px solid #1e2d44;overflow-x:auto;}}
a{{color:#00f5a0;}}
</style></head><body>
<h2>Lite — OAuth2 Debug</h2>
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

ROLE_LITE            : {ROLE_LITE}
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
        "no_access":  "You don't have the required role. You need Lite, UFF Access, or FFL Access in the Lite server.",
        "not_in_server": "You must join the Lite Discord server first before signing in.",
        "db_error": "Database error during login.",
        "token_failed": "Discord login failed. Check your internet and try again.",
        "state_mismatch": "Security check failed. Please try again.",
        "user_failed": "Could not fetch your Discord profile.",
        "bot_error":  "Bot verification failed.",
    }
    detail  = request.args.get("detail", "")
    err_msg = errors.get(error)
    # Show detail message for all error types if available
    if detail and err_msg:
        err_msg = detail
    return render_template("login.html", error=err_msg)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

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
    return render_template("results.html", pin=pin_row, scan=scan, user=user)

# ── API: Stats ───────────────────────────────────────────────
@app.route("/api/stats")
def api_stats():
    # Public totals are fine to show on home page; detailed breakdown requires login
    user = get_user() if "user_id" in session else None
    conn = get_db(); cur = conn.cursor()
    if user and user["role"] in ("owner", "admin"):
        cur.execute("SELECT COUNT(*) FROM scans"); total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict='CHEATER'"); cheater = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict='SUSPICIOUS'"); susp = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict='CLEAN'"); clean = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE league='UFF'"); uff_c = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE league='FFL'"); ffl_c = cur.fetchone()[0]
    else:
        allowed = get_user_leagues(user)
        ph = ",".join(["%s"]*len(allowed))
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE league IN ({ph})", allowed); total = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE verdict='CHEATER' AND league IN ({ph})", allowed); cheater = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE verdict='SUSPICIOUS' AND league IN ({ph})", allowed); susp = cur.fetchone()[0]
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
    cur.execute("INSERT INTO pins (pin,league,agent_id,used,created,expires) VALUES (%s,%s,%s,0,%s,%s)",
                (pin,league,user["id"],now(),expires))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"pin":pin,"league":league,"expires":expires,
                    "results_url": f"/results/{pin}"})

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
    if datetime.datetime.utcnow() > datetime.datetime.strptime(row["expires"],"%Y-%m-%d %H:%M:%S"):
        return jsonify({"valid":False,"error":"PIN has expired"}),401
    if league and row["league"] != league:
        return jsonify({"valid":False,"error":f"PIN is for {row['league']}, not {league}"}),401
    return jsonify({"valid":True,"league":row["league"]})

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
        report_str = json.dumps(report)
        if len(report_str) > 500000:
            report = {"truncated": True, "verdict": data.get("verdict","?")}
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
    if data.get("role"): cur.execute("UPDATE users SET role=%s WHERE id=%s",(data["role"],uid))
    if data.get("leagues") is not None: cur.execute("UPDATE users SET leagues=%s WHERE id=%s",(data["leagues"],uid))
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
    filename = f.filename or "LiteScanner.exe"
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
        with open("/tmp/litescanner.exe","wb") as fp: fp.write(data)
        with open("/tmp/lite_fname.txt","w") as fp: fp.write(filename)
    except Exception: pass

    return jsonify({"ok":True,"version":ver,"size":f"{size_mb} MB"})


@app.route("/download/exe")
def download_exe():
    import base64, io
    from flask import send_file

    filename = "LiteScanner.exe"

    # Try /tmp cache first (fast)
    if os.path.exists("/tmp/litescanner.exe"):
        try:
            if os.path.exists("/tmp/lite_fname.txt"):
                filename = open("/tmp/lite_fname.txt").read().strip()
            return send_file("/tmp/litescanner.exe", as_attachment=True,
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
        with open("/tmp/litescanner.exe","wb") as fp: fp.write(data)
        with open("/tmp/lite_fname.txt","w") as fp: fp.write(filename)
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
        "ROLE_LITE_match": ROLE_LITE in member.get("roles",[]),
        "ROLE_UFF_match":  ROLE_UFF  in member.get("roles",[]),
        "ROLE_FFL_match":  ROLE_FFL  in member.get("roles",[]),
    })

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
