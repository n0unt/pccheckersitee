"""
PC Checker - Web Dashboard v2
Flask + PostgreSQL + Discord OAuth2
"""
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from functools import wraps
import psycopg2, psycopg2.extras
import hashlib, secrets, string, datetime, json, os, urllib.request, urllib.parse, urllib.error, ssl

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

# ── SSL context ──────────────────────────────────────────────
def _ssl_ctx():
    ctx = ssl._create_unverified_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx

def _discord_get(path, token=None, bot=False):
    url = f"https://discord.com/api/v10{path}"
    headers = {"Content-Type": "application/json"}
    if bot:
        headers["Authorization"] = f"Bot {DISCORD_BOT_TOKEN}"
    elif token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=10) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        try: return json.loads(e.read().decode())
        except: return {}
    except Exception:
        return {}

def _discord_post(path, data, token=None, bot=False):
    url = f"https://discord.com/api/v10{path}"
    if bot:
        payload = json.dumps(data).encode()
        headers = {"Authorization": f"Bot {DISCORD_BOT_TOKEN}", "Content-Type": "application/json"}
    else:
        # OAuth2 token exchange must be form-encoded
        payload = urllib.parse.urlencode(data).encode()
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
    req = urllib.request.Request(url, data=payload, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(req, context=_ssl_ctx(), timeout=10) as r:
            return r.status, json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        body = b""
        try: body = e.read()
        except: pass
        try: return e.code, json.loads(body.decode())
        except: return e.code, {"error": body.decode()[:200]}
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
        "scope": "identify guilds",
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

    # Check guild roles via bot
    role         = "pending"
    leagues      = ""
    bot_error    = None
    if DISCORD_GUILD_ID and DISCORD_BOT_TOKEN:
        member = _discord_get(f"/guilds/{DISCORD_GUILD_ID}/members/{discord_id}", bot=True)
        bot_error = member.get("code") or member.get("error")
        member_roles = member.get("roles", [])

        # ROLE_LITE = owner/dev role → full owner access
        if ROLE_LITE in member_roles:
            role    = "owner"
            leagues = "UFF,FFL"

        # UFF or FFL role = regular agent access
        if ROLE_UFF in member_roles:
            leagues += "UFF,"
            if role == "pending": role = "agent"
        if ROLE_FFL in member_roles:
            leagues += "FFL,"
            if role == "pending": role = "agent"

        leagues = leagues.strip(",")

    # If bot failed to reach Discord (bot not in server / missing intent),
    # log the error and allow the login but flag it
    if role == "pending":
        if bot_error:
            app.logger.error(f"Bot member lookup failed for {discord_id}: {bot_error}")
            # Still block — but show a more helpful error
            return redirect(url_for("login_page") + f"?error=no_access&detail={urllib.parse.quote(str(bot_error))}")
        return redirect(url_for("login_page") + "?error=no_access")

    # Upsert user
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

@app.route("/login")
def login_page():
    error = request.args.get("error")
    errors = {
        "no_access": "You don't have the required Discord role to access this.",
        "token_failed": "Discord login failed. Try again.",
        "state_mismatch": "Security error. Please try again.",
        "user_failed": "Could not fetch your Discord profile.",
    }
    detail = request.args.get("detail","")
    err_msg = errors.get(error)
    if err_msg and detail and error == "token_failed":
        err_msg = f"Discord login failed: {detail}"
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
    data = request.json or {}
    pin = data.get("pin","").upper().strip()
    league = data.get("league","").upper().strip()
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM pins WHERE pin=%s AND used=0",(pin,))
    pin_row = row_to_dict(cur.fetchone(), cur)
    if not pin_row: cur.close(); conn.close(); return jsonify({"error":"Invalid PIN"}),401
    cur.execute("""INSERT INTO scans (league,pc_user,verdict,total_hits,roblox_accs,report_json,pin_used,submitted)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (league or pin_row["league"], data.get("pc_user","unknown"),
                 data.get("verdict","UNKNOWN"), data.get("total_hits",0),
                 json.dumps(data.get("roblox_accounts",[])),
                 json.dumps(data.get("report",{})), pin, now()))
    scan_id = cur.fetchone()[0]
    cur.execute("UPDATE pins SET used=1, scan_id=%s, finished_at=%s WHERE pin=%s",
                (scan_id, now(), pin))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True,"scan_id":scan_id})

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
    has_exe = bool(meta.get("b64") or meta.get("url"))
    user = get_user() if "user_id" in session else None
    return render_template("download.html",
                           has_exe=has_exe,
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
    filename = f.filename or "scanner.exe"
    data = f.read()
    if len(data) == 0: return jsonify({"error":"File is empty"}),400
    b64 = base64.b64encode(data).decode()
    size_mb = round(len(data)/1024/1024, 1)
    meta = {"version": ver, "size": f"{size_mb} MB", "filename": filename,
            "updated": now(), "b64": b64}
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("INSERT INTO settings (key,value) VALUES (%s,%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
                    ("exe_meta", json.dumps(meta)))
        conn.commit(); cur.close(); conn.close()
    except Exception as e:
        return jsonify({"error":str(e)}),500
    return jsonify({"ok":True,"version":ver,"size":f"{size_mb} MB"})

@app.route("/download/exe")
def download_exe():
    import base64
    from flask import Response
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key=%s",("exe_meta",))
        row = cur.fetchone()
        cur.close(); conn.close()
    except Exception:
        abort(404)
    if not row: abort(404)
    meta = json.loads(row[0])
    b64  = meta.get("b64","")
    if not b64: abort(404)
    data = base64.b64decode(b64)
    fname = meta.get("filename","LiteScanner.exe")
    return Response(data, mimetype="application/octet-stream",
                    headers={"Content-Disposition":f"attachment; filename={fname}"})


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
