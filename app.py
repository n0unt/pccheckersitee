"""
Zevora — Web Application
Flask + PostgreSQL + Discord OAuth2
"""
from flask import (Flask, render_template, request, jsonify, session,
                   redirect, url_for, abort, Response, send_file)
from functools import wraps
import psycopg2, psycopg2.extras
import hashlib, secrets, string, datetime, json, os, re, base64, io, ssl
import urllib.request, urllib.error, urllib.parse

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
EXE_FILE = os.path.join(UPLOAD_DIR, "ZevoraScanner.exe")

app = Flask(__name__,
            template_folder=BASE_DIR,
            static_folder=os.path.join(BASE_DIR, "static"))
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production")
app.config["MAX_CONTENT_LENGTH"] = 200 * 1024 * 1024

DATABASE_URL       = os.environ.get("DATABASE_URL", "")
DISCORD_CLIENT_ID  = os.environ.get("DISCORD_CLIENT_ID", "")
DISCORD_CLIENT_SECRET = os.environ.get("DISCORD_CLIENT_SECRET", "")
DISCORD_BOT_TOKEN  = os.environ.get("DISCORD_BOT_TOKEN", "")
DISCORD_REDIRECT_URI = os.environ.get("DISCORD_REDIRECT_URI", "")
DISCORD_GUILD_ID   = os.environ.get("DISCORD_GUILD_ID", "1525172045149634790")
DISCORD_INVITE     = os.environ.get("DISCORD_INVITE", "https://discord.gg/zevora")

# Webhook URLs
def _d(s): return base64.b64decode(s).decode()
_WH_KFA = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ3NTM1NTkyNjY1ODU1MTgwOS9Ua09kVEk2QldWQW0tUzBZbEpLTE5TQm9WQkZZRHZMYmlidVlhZWlPYmxIZ2tWZDB6aHJRdHBMUWdpV3VmWjRPVkYwRA=="
_WH_UFF = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ3NTM1NjE3NjE1MjY1ODA0MS85WnlCamgtX1hjZmN3TllXLVBWam9tNC1lVDhFWWRIdHVRQm10NnpxQVN4cDBsREFJY1FJYklMdDhmam9laENmNE9WXw=="
WEBHOOK_KFA = _d(_WH_KFA)
WEBHOOK_UFF = _d(_WH_UFF)

def get_webhook(league):
    return WEBHOOK_KFA if str(league).upper() == "KFA" else WEBHOOK_UFF


# ── DB helpers ────────────────────────────────────────────────
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

def now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def row_to_dict(row, cur):
    if row is None: return None
    return dict(zip([d[0] for d in cur.description], row))

def rows_to_dicts(rows, cur):
    if not rows: return []
    cols = [d[0] for d in cur.description]
    return [dict(zip(cols, r)) for r in rows]

def slugify(name):
    return re.sub(r"[^a-z0-9]", "", name.lower())

def sub_is_active(user):
    if not user: return False
    if user.get("role") in ("owner", "admin"): return True
    exp = user.get("sub_expires")
    if not exp: return False
    try:
        exp_dt = datetime.datetime.strptime(str(exp)[:19], "%Y-%m-%d %H:%M:%S")
        return datetime.datetime.utcnow() <= exp_dt
    except Exception:
        try:
            exp_dt = datetime.datetime.strptime(str(exp)[:10], "%Y-%m-%d")
            return datetime.datetime.utcnow().date() <= exp_dt.date()
        except Exception:
            return False

def days_left(user):
    exp = user.get("sub_expires")
    if not exp: return None
    try:
        exp_dt = datetime.datetime.strptime(str(exp)[:10], "%Y-%m-%d")
        return (exp_dt.date() - datetime.datetime.utcnow().date()).days
    except Exception:
        return None


# ── DB init ───────────────────────────────────────────────────
def init_db():
    conn = get_db(); cur = conn.cursor()
    tables = [
        """CREATE TABLE IF NOT EXISTS leagues (
            id      SERIAL PRIMARY KEY,
            name    TEXT UNIQUE NOT NULL,
            slug    TEXT UNIQUE NOT NULL,
            created TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS users (
            id              SERIAL PRIMARY KEY,
            discord_id      TEXT,
            username        TEXT NOT NULL,
            password_hash   TEXT DEFAULT '',
            role            TEXT NOT NULL DEFAULT 'agent',
            leagues         TEXT NOT NULL DEFAULT '',
            created         TEXT NOT NULL,
            sub_type        TEXT DEFAULT NULL,
            sub_league_slug TEXT DEFAULT NULL,
            sub_expires     TEXT DEFAULT NULL,
            granted_by      TEXT DEFAULT NULL,
            invite_count    INTEGER DEFAULT 0,
            avatar          TEXT DEFAULT ''
        )""",
        """CREATE TABLE IF NOT EXISTS pins (
            id          SERIAL PRIMARY KEY,
            pin         TEXT UNIQUE NOT NULL,
            league      TEXT NOT NULL,
            agent_id    INTEGER NOT NULL,
            used        INTEGER NOT NULL DEFAULT 0,
            created     TEXT NOT NULL,
            expires     TEXT NOT NULL,
            scan_id     INTEGER DEFAULT NULL,
            finished_at TEXT DEFAULT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS scans (
            id          SERIAL PRIMARY KEY,
            league      TEXT NOT NULL,
            pc_user     TEXT NOT NULL,
            verdict     TEXT NOT NULL,
            total_hits  INTEGER NOT NULL DEFAULT 0,
            roblox_accs TEXT NOT NULL DEFAULT '[]',
            report_json TEXT NOT NULL DEFAULT '{}',
            pin_used    TEXT,
            submitted   TEXT NOT NULL
        )""",
        """CREATE TABLE IF NOT EXISTS settings (
            key   TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""",
    ]
    for sql in tables:
        try:
            cur.execute("SAVEPOINT sp"); cur.execute(sql)
            cur.execute("RELEASE SAVEPOINT sp")
        except Exception: cur.execute("ROLLBACK TO SAVEPOINT sp")

    migrations = [
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id TEXT",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT DEFAULT ''",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_type TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_league_slug TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_expires TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS granted_by TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS invite_count INTEGER DEFAULT 0",
        "ALTER TABLE pins ADD COLUMN IF NOT EXISTS scan_id INTEGER DEFAULT NULL",
        "ALTER TABLE pins ADD COLUMN IF NOT EXISTS finished_at TEXT DEFAULT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT DEFAULT ''",
        "ALTER TABLE users ALTER COLUMN leagues SET DEFAULT ''",
    ]
    for sql in migrations:
        try:
            cur.execute("SAVEPOINT sm"); cur.execute(sql)
            cur.execute("RELEASE SAVEPOINT sm")
        except Exception: cur.execute("ROLLBACK TO SAVEPOINT sm")

    # Seed default leagues
    for lname, lslug in [("UFF","uff"),("KFA","kfa")]:
        try:
            cur.execute("SAVEPOINT sl")
            cur.execute("INSERT INTO leagues (name,slug,created) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                        (lname, lslug, now()))
            cur.execute("RELEASE SAVEPOINT sl")
        except Exception: cur.execute("ROLLBACK TO SAVEPOINT sl")

    # Seed owner
    try:
        cur.execute("SAVEPOINT ss")
        cur.execute("SELECT id FROM users WHERE role='owner' LIMIT 1")
        if not cur.fetchone():
            pw = hashlib.sha256(b"admin").hexdigest()
            cur.execute(
                "INSERT INTO users (username,password_hash,role,leagues,created) VALUES ('admin',%s,'owner','UFF,KFA',%s)",
                (pw, now()))
        cur.execute("RELEASE SAVEPOINT ss")
    except Exception: cur.execute("ROLLBACK TO SAVEPOINT ss")

    try:
        cur.execute("SAVEPOINT sc")
        cutoff = (datetime.datetime.utcnow()-datetime.timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("DELETE FROM pins WHERE created<%s AND used=0",(cutoff,))
        cur.execute("RELEASE SAVEPOINT sc")
    except Exception: cur.execute("ROLLBACK TO SAVEPOINT sc")

    conn.commit(); cur.close(); conn.close()


# ── Auth helpers ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def w(*a,**k):
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        return f(*a,**k)
    return w

def owner_required(f):
    @wraps(f)
    def w(*a,**k):
        if session.get("role") not in ("owner","admin"): abort(403)
        return f(*a,**k)
    return w

def get_user():
    if "user_id" not in session: return None
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s",(session["user_id"],))
    row=row_to_dict(cur.fetchone(),cur); cur.close(); conn.close()
    return row

def get_all_leagues():
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT id,name,slug,created FROM leagues ORDER BY name")
    rows=rows_to_dicts(cur.fetchall(),cur); cur.close(); conn.close()
    return rows

def get_user_league_names(user):
    all_lgs=get_all_leagues()
    if user.get("role") in ("owner","admin"): return [lg["name"] for lg in all_lgs]
    slugs=[s.strip().lower() for s in (user.get("leagues") or "").split(",") if s.strip()]
    return [lg["name"] for lg in all_lgs if lg["slug"] in slugs]

def can_access_league(user, league_name):
    if not user: return False
    if user["role"] in ("owner","admin"): return True
    names=get_user_league_names(user)
    return league_name in names


# ── Discord OAuth2 helpers ────────────────────────────────────
def _ssl():
    ctx=ssl._create_unverified_context()
    ctx.check_hostname=False; ctx.verify_mode=ssl.CERT_NONE
    return ctx

def discord_exchange_code(code):
    data=urllib.parse.urlencode({
        "client_id":     DISCORD_CLIENT_ID,
        "client_secret": DISCORD_CLIENT_SECRET,
        "grant_type":    "authorization_code",
        "code":          code,
        "redirect_uri":  DISCORD_REDIRECT_URI,
    }).encode()
    try:
        req=urllib.request.Request("https://discord.com/api/oauth2/token",data=data,
            headers={"Content-Type":"application/x-www-form-urlencoded",
                     "User-Agent":"ZevoraApp/1.0"},method="POST")
        with urllib.request.urlopen(req,context=_ssl(),timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"[Discord] token exchange error: {e}")
        return None

def discord_api(path, token=None, bot=False):
    url=f"https://discord.com/api/v10{path}"
    headers={"User-Agent":"ZevoraApp/1.0"}
    if bot:   headers["Authorization"]=f"Bot {DISCORD_BOT_TOKEN}"
    elif token: headers["Authorization"]=f"Bearer {token}"
    try:
        req=urllib.request.Request(url,headers=headers)
        with urllib.request.urlopen(req,context=_ssl(),timeout=10) as r:
            return json.loads(r.read().decode())
    except Exception as e:
        print(f"[Discord] API error {path}: {e}")
        return None

def discord_in_guild(user_id, access_token):
    """Check if user is in the required Discord server."""
    # Method 1: check via user's guild list
    guilds=discord_api("/users/@me/guilds", token=access_token)
    if guilds and isinstance(guilds,list):
        return any(str(g.get("id"))==str(DISCORD_GUILD_ID) for g in guilds)
    # Method 2: check via bot (fallback)
    if DISCORD_BOT_TOKEN:
        member=discord_api(f"/guilds/{DISCORD_GUILD_ID}/members/{user_id}",bot=True)
        return member is not None and "user" in member
    return False


# ── Auth routes ───────────────────────────────────────────────
@app.route("/login")
def login_page():
    err_map={
        "empty":       "Enter your username and password.",
        "no_access":   "Account not found. Contact an admin to get access.",
        "bad_password":"Incorrect password.",
        "no_sub":      "Your subscription has expired. Contact an admin.",
        "db_error":    "Database error — please try again.",
        "not_in_server": f"You must be in the Zevora Discord server to log in.",
        "discord_error": "Discord login failed — please try again.",
        "discord_cancelled": "Discord login was cancelled.",
        "discord_no_access": "Your Discord account doesn't have Zevora access yet. Contact an admin.",
    }
    err=request.args.get("error")
    return render_template("login.html",
                           error=err_map.get(err,err),
                           discord_login_url=url_for("auth_discord") if DISCORD_CLIENT_ID else None,
                           discord_invite=DISCORD_INVITE)

@app.route("/auth/discord")
def auth_discord():
    if not DISCORD_CLIENT_ID:
        return redirect(url_for("login_page")+"?error=discord_error")
    state=secrets.token_urlsafe(16)
    session["discord_state"]=state
    params=urllib.parse.urlencode({
        "client_id":     DISCORD_CLIENT_ID,
        "redirect_uri":  DISCORD_REDIRECT_URI,
        "response_type": "code",
        "scope":         "identify guilds",
        "state":         state,
    })
    return redirect(f"https://discord.com/api/oauth2/authorize?{params}")

@app.route("/auth/discord/callback")
def auth_discord_callback():
    # Validate state
    state=request.args.get("state","")
    if state != session.pop("discord_state",""):
        return redirect(url_for("login_page")+"?error=discord_error")

    code=request.args.get("code")
    if not code:
        return redirect(url_for("login_page")+"?error=discord_cancelled")

    # Exchange code for token
    token_data=discord_exchange_code(code)
    if not token_data or "access_token" not in token_data:
        return redirect(url_for("login_page")+"?error=discord_error")

    access_token=token_data["access_token"]

    # Get Discord user info
    discord_user=discord_api("/users/@me",token=access_token)
    if not discord_user or "id" not in discord_user:
        return redirect(url_for("login_page")+"?error=discord_error")

    discord_id=discord_user["id"]
    discord_username=discord_user.get("username","Unknown")
    discord_avatar=discord_user.get("avatar","")

    # Check server membership
    if not discord_in_guild(discord_id,access_token):
        return redirect(url_for("login_page")+"?error=not_in_server")

    # Find account in DB
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT * FROM users WHERE discord_id=%s",(discord_id,))
    db_user=row_to_dict(cur.fetchone(),cur)

    if not db_user:
        # Try to find by username match (admin may have created account without Discord ID yet)
        cur.execute("SELECT * FROM users WHERE username ILIKE %s AND (discord_id IS NULL OR discord_id='')",
                    (discord_username,))
        db_user=row_to_dict(cur.fetchone(),cur)
        if db_user:
            # Link Discord ID to account
            cur.execute("UPDATE users SET discord_id=%s,avatar=%s WHERE id=%s",
                        (discord_id,discord_avatar,db_user["id"]))
            conn.commit()
        else:
            cur.close(); conn.close()
            return redirect(url_for("login_page")+"?error=discord_no_access")

    # Update avatar
    cur.execute("UPDATE users SET avatar=%s WHERE id=%s",(discord_avatar,db_user["id"]))
    conn.commit(); cur.close(); conn.close()

    # Subscription check
    if db_user["role"] not in ("owner","admin") and not sub_is_active(db_user):
        return redirect(url_for("login_page")+"?error=no_sub")

    session["user_id"]=db_user["id"]
    session["username"]=db_user["username"]
    session["role"]=db_user["role"]
    return redirect(url_for("dashboard"))

@app.route("/auth/login",methods=["POST"])
def do_login():
    username=request.form.get("username","").strip()
    password=request.form.get("password","").strip()
    if not username or not password:
        return redirect(url_for("login_page")+"?error=empty")
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s",(username,))
        user=row_to_dict(cur.fetchone(),cur); cur.close(); conn.close()
    except Exception:
        return redirect(url_for("login_page")+"?error=db_error")
    if not user:
        return redirect(url_for("login_page")+"?error=no_access")
    pw_hash=hashlib.sha256(password.encode()).hexdigest()
    stored=user.get("password_hash") or ""
    if stored and stored!=pw_hash:
        return redirect(url_for("login_page")+"?error=bad_password")
    if not stored:
        conn2=get_db(); cur2=conn2.cursor()
        cur2.execute("UPDATE users SET password_hash=%s WHERE id=%s",(pw_hash,user["id"]))
        conn2.commit(); cur2.close(); conn2.close()
    if user["role"] not in ("owner","admin") and not sub_is_active(user):
        return redirect(url_for("login_page")+"?error=no_sub")
    session["user_id"]=user["id"]; session["username"]=user["username"]; session["role"]=user["role"]
    return redirect(url_for("dashboard"))

@app.route("/auth/logout")
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


@app.route("/favicon.ico")
def favicon():
    ico = os.path.join(BASE_DIR, "static", "zevora.ico")
    if not os.path.exists(ico):
        ico = os.path.join(BASE_DIR, "zevora.ico")
    if os.path.exists(ico):
        return send_file(ico, mimetype="image/x-icon")
    abort(404)


# ── Public pages ──────────────────────────────────────────────
@app.route("/")
def index():
    return render_template("home.html",user=get_user(),discord_invite=DISCORD_INVITE,
                           discord_login_url=url_for("auth_discord") if DISCORD_CLIENT_ID else None)

@app.route("/privacy")
def privacy(): return render_template("privacy.html",user=get_user())

@app.route("/terms")
def terms(): return render_template("terms.html",user=get_user())

@app.route("/download")
def download_page():
    meta={}
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key='exe_meta'")
        row=cur.fetchone(); meta=json.loads(row[0]) if row else {}
        cur.close(); conn.close()
    except Exception: pass
    return render_template("download.html",user=get_user(),has_exe=bool(meta.get("version")),
                           version=meta.get("version","v5.0"),file_size=meta.get("size",""),
                           updated=meta.get("updated",""))


# ── Dashboard ─────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    user=get_user()
    conn=get_db(); cur=conn.cursor()

    # Pins
    if user["role"] in ("owner","admin"):
        cur.execute("SELECT *,pin AS pin_code,created AS created_at FROM pins ORDER BY id DESC LIMIT 50")
    else:
        cur.execute("SELECT *,pin AS pin_code,created AS created_at FROM pins WHERE agent_id=%s ORDER BY id DESC LIMIT 50",
                    (user["id"],))
    pins=rows_to_dicts(cur.fetchall(),cur)

    # Scans
    accessible_names=get_user_league_names(user)
    if user["role"] in ("owner","admin"):
        cur.execute("""SELECT s.*,u.username as agent_username FROM scans s
                       LEFT JOIN pins p ON p.pin=s.pin_used
                       LEFT JOIN users u ON u.id=p.agent_id
                       ORDER BY s.submitted DESC LIMIT 200""")
    elif accessible_names:
        ph=",".join(["%s"]*len(accessible_names))
        cur.execute(f"""SELECT s.*,u.username as agent_username FROM scans s
                        LEFT JOIN pins p ON p.pin=s.pin_used
                        LEFT JOIN users u ON u.id=p.agent_id
                        WHERE s.league IN ({ph}) ORDER BY s.submitted DESC LIMIT 200""",
                    accessible_names)
    else:
        cur.execute("SELECT * FROM scans WHERE 1=0")
    scans=rows_to_dicts(cur.fetchall(),cur)

    # All leagues for dropdowns
    all_leagues_list=get_all_leagues()

    # All users (admin)
    all_users=[]
    expired_users=[]
    if user["role"] in ("owner","admin"):
        cur.execute("""SELECT u.*,COUNT(DISTINCT p.id) as pin_count
                       FROM users u LEFT JOIN pins p ON p.agent_id=u.id
                       GROUP BY u.id
                       ORDER BY CASE u.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,u.username""")
        all_users=rows_to_dicts(cur.fetchall(),cur)
        for u2 in all_users:
            u2["sub_active"]=sub_is_active(u2)
            u2["days_left"]=days_left(u2)
            u2["subscription_expired"]=(
                u2.get("sub_expires") and not u2["sub_active"] and u2["role"] not in ("owner","admin"))
            u2["league_display"]=u2.get("leagues") or u2.get("sub_league_slug","") or "—"
        expired_users=[u2 for u2 in all_users if u2.get("subscription_expired")]

    # My Team — league → members
    all_leagues_team={}
    team_members=[]
    if user["role"] in ("owner","admin"):
        for lg in all_leagues_list:
            cur.execute("""SELECT u.id,u.username,u.role,u.discord_id,u.sub_type,u.sub_expires,u.leagues,u.avatar,
                                  COUNT(DISTINCT p.id) as pin_count,
                                  COUNT(DISTINCT s.id) as scan_count
                           FROM users u
                           LEFT JOIN pins p ON p.agent_id=u.id
                           LEFT JOIN scans s ON s.league=%s AND s.pin_used=p.pin
                           WHERE u.leagues ILIKE %s OR u.sub_league_slug=%s OR u.role IN ('owner','admin')
                           GROUP BY u.id ORDER BY u.username""",
                        (lg["name"],f"%{lg['slug']}%",lg["slug"]))
            members=rows_to_dicts(cur.fetchall(),cur)
            for m in members:
                m["sub_active"]=sub_is_active(m); m["days_left"]=days_left(m)
            all_leagues_team[lg["name"]]=members
    else:
        user_slugs=[s.strip().lower() for s in (user.get("leagues") or "").split(",") if s.strip()]
        my_leagues=[lg for lg in all_leagues_list if lg["slug"] in user_slugs]
        for lg in my_leagues:
            cur.execute("""SELECT u.id,u.username,u.role,u.sub_type,u.sub_expires,
                                  COUNT(DISTINCT p.id) as pin_count,COUNT(DISTINCT s.id) as scan_count
                           FROM users u LEFT JOIN pins p ON p.agent_id=u.id
                           LEFT JOIN scans s ON s.league=%s AND s.pin_used=p.pin
                           WHERE u.leagues ILIKE %s OR u.sub_league_slug=%s
                           GROUP BY u.id ORDER BY u.username""",
                        (lg["name"],f"%{lg['slug']}%",lg["slug"]))
            members=rows_to_dicts(cur.fetchall(),cur)
            for m in members:
                m["sub_active"]=sub_is_active(m)
            team_members.extend(members)

    cur.close(); conn.close()
    return render_template("dashboard.html",
        user=user, pins=pins, scans=scans,
        all_users=all_users, expired_users=expired_users,
        all_leagues=all_leagues_team, team_members=team_members,
        leagues=all_leagues_list,
        expired_count=len(expired_users))


# ── Results ───────────────────────────────────────────────────
@app.route("/results/<pin>")
@login_required
def results_page(pin):
    user=get_user()
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT * FROM pins WHERE pin=%s",(pin.upper(),))
    pin_row=row_to_dict(cur.fetchone(),cur)
    if not pin_row: cur.close(); conn.close(); abort(404)
    if not can_access_league(user,pin_row["league"]): abort(403)
    scan=None; report={}; roblox_accs=[]
    if pin_row.get("scan_id"):
        cur.execute("SELECT * FROM scans WHERE id=%s",(pin_row["scan_id"],))
        scan=row_to_dict(cur.fetchone(),cur)
        if scan:
            try: report=json.loads(scan.get("report_json","{}"))
            except Exception: report={}
            try: roblox_accs=json.loads(scan.get("roblox_accs","[]"))
            except Exception: roblox_accs=[]
            scan["roblox_accounts"]=roblox_accs
    cur.close(); conn.close()
    return render_template("results.html",pin=pin_row,scan=scan,user=user,
                           report=report,roblox_accs=roblox_accs,has_scan=bool(scan))

@app.route("/results/<pin>/download")
@login_required
def download_report(pin):
    user=get_user()
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT * FROM pins WHERE pin=%s",(pin.upper(),))
    pin_row=row_to_dict(cur.fetchone(),cur)
    if not pin_row: cur.close(); conn.close(); abort(404)
    if not can_access_league(user,pin_row["league"]): abort(403)
    if not pin_row.get("scan_id"): cur.close(); conn.close(); abort(404)
    cur.execute("SELECT * FROM scans WHERE id=%s",(pin_row["scan_id"],))
    scan=row_to_dict(cur.fetchone(),cur); cur.close(); conn.close()
    if not scan: abort(404)
    try: report=json.loads(scan.get("report_json","{}"))
    except Exception: report={}
    def esc(s): return str(s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    sections=[]
    for key,label in [("cheat_raw","Cheat Files"),("bam_raw","BAM"),("prefetch_raw","Prefetch"),
                       ("shellbags_raw","ShellBags"),("appcompat_raw","AppCompat"),
                       ("discord_raw","Discord"),("discord_memory_raw","DC Downloads"),
                       ("network_raw","Network/VPN"),("eventlog_raw","Event Log"),
                       ("power_events_raw","Power Timeline"),("deleted_recovery_raw","Deleted Recovery"),
                       ("deleted_int_raw","Deleted Integrity"),("mft_recovery_raw","Pre-Reset MFT Recovery"),
                       ("cmd_history_raw","CMD History"),("memory_injection_raw","Memory Injection"),
                       ("fastflags_raw","FastFlags"),("factory_reset_raw","Factory Reset"),
                       ("drive_info","USB Drives"),("two_pc_raw","2-PC Bypass"),("cleaners_raw","Cleaners")]:
        val=report.get(key,"")
        if val and str(val).strip() not in ("","None","No data"):
            sections.append(f"<h2>{esc(label)}</h2><pre>{esc(str(val)[:20000])}</pre>")
    html=f"""<!DOCTYPE html><html><head><meta charset="UTF-8"><title>Zevora — {esc(pin.upper())}</title>
<style>body{{background:#0a0a0d;color:#ececf0;font-family:monospace;padding:2rem;max-width:900px;margin:auto}}
h1{{color:#2bba8f}}h2{{color:#8888a0;font-size:.9rem;margin:1.5rem 0 .4rem;text-transform:uppercase;letter-spacing:.06em}}
pre{{background:#18181d;padding:1rem;border-radius:8px;overflow-x:auto;font-size:11px;line-height:1.6;white-space:pre-wrap}}</style>
</head><body><h1>Zevora Forensic Report</h1>
<p style="color:#8888a0">PIN: {esc(pin.upper())} · PC: {esc(scan.get("pc_user","?"))} · League: {esc(scan.get("league","?"))} · {esc(scan.get("submitted","?"))} UTC</p>
<p style="color:#f85149;font-size:1.1rem;font-weight:700">Verdict: {esc(scan.get("verdict","?"))} · {scan.get("total_hits",0)} hits</p>
{"".join(sections)}</body></html>"""
    return Response(html,mimetype="text/html",
                    headers={"Content-Disposition":f"attachment; filename=zevora-{pin.upper()}.html"})


# ── PIN API ───────────────────────────────────────────────────
@app.route("/api/validate_pin",methods=["POST"])
def api_validate_pin():
    data=request.json or {}
    pin=(data.get("pin","") or "").upper().strip()
    if not pin: return jsonify({"valid":False,"error":"No PIN"}),400
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT * FROM pins WHERE pin=%s AND used=0",(pin,))
    row=row_to_dict(cur.fetchone(),cur); cur.close(); conn.close()
    if not row: return jsonify({"valid":False,"error":"Invalid or already used PIN"}),401
    try:
        exp_dt=datetime.datetime.strptime(str(row["expires"])[:19],"%Y-%m-%d %H:%M:%S")
        if datetime.datetime.utcnow()>exp_dt:
            return jsonify({"valid":False,"error":"PIN has expired"}),401
    except Exception: pass
    return jsonify({"ok":True,"valid":True,"league":row["league"],"league_slug":slugify(row["league"])})

@app.route("/api/generate_pin",methods=["POST"])
@app.route("/api/pins/generate",methods=["POST"])
@login_required
def api_generate_pin():
    user=get_user()
    data=request.json or {}
    league_input=(data.get("league","") or "").strip().upper()
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT name FROM leagues WHERE slug=%s OR name=%s",(league_input.lower(),league_input))
    row=cur.fetchone()
    league_name=row[0] if row else league_input
    if not league_name:
        cur.close(); conn.close(); return jsonify({"error":"League required"}),400
    if user["role"] not in ("owner","admin") and not can_access_league(user,league_name):
        cur.close(); conn.close(); return jsonify({"error":"Not authorized for this league"}),403
    pin="".join(secrets.choice(string.ascii_uppercase+string.digits) for _ in range(8))
    expires=(datetime.datetime.utcnow()+datetime.timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("INSERT INTO pins (pin,league,agent_id,used,created,expires) VALUES (%s,%s,%s,0,%s,%s)",
                (pin,league_name,user["id"],now(),expires))
    conn.commit()
    try:
        cur.execute("""DELETE FROM pins WHERE agent_id=%s AND used=0 AND pin!=%s
                       AND id NOT IN (SELECT id FROM pins WHERE agent_id=%s AND used=0 ORDER BY id DESC LIMIT 3)""",
                    (user["id"],pin,user["id"]))
        conn.commit()
    except Exception:
        try: conn.rollback()
        except Exception: pass
    cur.close(); conn.close()
    return jsonify({"pin":pin,"league":league_name,"expires":expires,"results_url":f"/results/{pin}"})

@app.route("/api/submit",methods=["POST"])
def api_submit():
    try:
        data=request.json or {}
        pin=(data.get("pin","") or "").upper().strip()
        if not pin: return jsonify({"error":"No PIN"}),400
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT * FROM pins WHERE pin=%s AND used=0",(pin,))
        pin_row=row_to_dict(cur.fetchone(),cur)
        if not pin_row: cur.close(); conn.close(); return jsonify({"error":"Invalid PIN"}),401
        league=data.get("league","") or pin_row["league"]
        report=data.get("report",{})
        for tab in ["shellbags","bam","prefetch","appcompat","roblox","cheat","yara","unsigned",
                    "recycle","sysmain","processes","cleaners","registry_extra","discord",
                    "discord_memory","eventlog","jumplists","lnkfiles","power_events","two_pc",
                    "deleted_recovery","deleted_int","exec_history_text","network","drive_info",
                    "mft_recovery","cmd_history","memory_injection","fastflags"]:
            if tab in data and data[tab]:
                report[tab+"_raw"]=str(data[tab])[:30000]
        if data.get("factory_reset"):
            report["factory_reset_raw"] = str(data["factory_reset"])[:30000]
        nested = data.get("report") or {}
        if isinstance(nested, dict):
            for k, v in nested.items():
                if k not in report or report[k] in (None, "", {}):
                    report[k] = v
        for field in ["cleaner_info","process_hits","cleaner_hits","eventlog_hits","jumplist_hits",
                      "lnk_hits","deleted_hits","exec_history","roblox_log_hits","vpn_detected",
                      "power_hits","two_pc_hits","recovery_hits","discord_memory_hits","fastflags",
                      "mft_recovery_hits","cmd_history_hits","memory_injection_hits",
                      "shellbag_hits","bam_hits","prefetch_hits","appcompat_hits","cheat_hits",
                      "yara_hits","unsigned_count","sysmain_hits","sysmain_autofail","factory_resets",
                      "drive_info","drive_warn"]:
            if field in data: report[field]=data[field]
        report.pop("vpn_info",None)
        report_str=json.dumps(report,default=str)
        if len(report_str)>2000000:
            for k in ["cheat_raw","unsigned_raw","appcompat_raw","processes_raw"]:
                if k in report: report[k]=report[k][:5000]
            report_str=json.dumps(report,default=str)
        cur.execute("""INSERT INTO scans (league,pc_user,verdict,total_hits,roblox_accs,report_json,pin_used,submitted)
                       VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                    (league,data.get("pc_user","unknown"),data.get("verdict","UNKNOWN"),
                     int(data.get("total_hits",0)),json.dumps(data.get("roblox_accounts",[])),
                     report_str,pin,now()))
        scan_id=cur.fetchone()[0]
        cur.execute("UPDATE pins SET used=1,scan_id=%s,finished_at=%s WHERE pin=%s",(scan_id,now(),pin))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"ok":True,"scan_id":scan_id})
    except Exception as e:
        return jsonify({"error":str(e)}),500

@app.route("/api/scans/<int:scan_id>",methods=["DELETE"])
@login_required
def api_delete_scan(scan_id):
    user=get_user()
    if user["role"] not in ("owner","admin"): return jsonify({"error":"Admins only"}),403
    conn=get_db(); cur=conn.cursor()
    cur.execute("DELETE FROM scans WHERE id=%s",(scan_id,))
    cur.execute("UPDATE pins SET scan_id=NULL WHERE scan_id=%s",(scan_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})


# ── Admin user API ────────────────────────────────────────────
@app.route("/api/admin/users/create",methods=["POST"])
@login_required
@owner_required
def api_create_user():
    data=request.json or {}
    username=(data.get("username","") or "").strip()
    password=(data.get("password","") or "").strip()
    discord_id=(data.get("discord_id","") or "").strip() or None
    role=data.get("role","agent")
    league_val=(data.get("league",data.get("leagues","")) or "").strip().upper()
    months=int(data.get("months",1) or 1)
    sub_type=data.get("sub_type","enterprise" if league_val and league_val!="ALL" else "user")
    if not username: return jsonify({"error":"Username required"}),400
    # Resolve league
    league_name=""
    if league_val and league_val!="ALL":
        conn_t=get_db(); cur_t=conn_t.cursor()
        cur_t.execute("SELECT name FROM leagues WHERE slug=%s OR name=%s",(slugify(league_val),league_val))
        row=cur_t.fetchone(); league_name=row[0] if row else league_val
        cur_t.close(); conn_t.close()
    elif league_val=="ALL":
        league_name=",".join(lg["name"] for lg in get_all_leagues())
    sub_expires=None
    if months>0:
        sub_expires=(datetime.datetime.utcnow()+datetime.timedelta(days=30*months)).strftime("%Y-%m-%d %H:%M:%S")
    pw_hash=hashlib.sha256(password.encode()).hexdigest() if password else ""
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=%s",(username,))
    if cur.fetchone():
        cur.close(); conn.close(); return jsonify({"error":"Username already exists"}),409
    cur.execute("""INSERT INTO users (discord_id,username,password_hash,role,leagues,sub_type,sub_expires,granted_by,created)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id""",
                (discord_id,username,pw_hash,role,league_name,sub_type,sub_expires,get_user()["username"],now()))
    new_id=cur.fetchone()[0]
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True,"id":new_id,"username":username})

@app.route("/api/admin/users/<int:uid>",methods=["PATCH"])
@login_required
@owner_required
def api_update_user(uid):
    data=request.json or {}
    conn=get_db(); cur=conn.cursor()
    if "role" in data: cur.execute("UPDATE users SET role=%s WHERE id=%s",(data["role"],uid))
    if "leagues" in data: cur.execute("UPDATE users SET leagues=%s WHERE id=%s",(data["leagues"],uid))
    if "discord_id" in data: cur.execute("UPDATE users SET discord_id=%s WHERE id=%s",(data["discord_id"],uid))
    if "password" in data and data["password"]:
        cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                    (hashlib.sha256(data["password"].encode()).hexdigest(),uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/admin/users/<int:uid>",methods=["DELETE"])
@login_required
@owner_required
def api_delete_user(uid):
    if uid==session.get("user_id"): return jsonify({"error":"Cannot delete yourself"}),400
    conn=get_db(); cur=conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s",(uid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/admin/users/<int:uid>/extend-sub",methods=["POST"])
@login_required
@owner_required
def api_extend_sub(uid):
    data=request.json or {}
    months=int(data.get("months",1))
    conn=get_db(); cur=conn.cursor()
    cur.execute("SELECT sub_expires FROM users WHERE id=%s",(uid,))
    row=cur.fetchone()
    base=datetime.datetime.utcnow()
    if row and row[0]:
        try:
            p=datetime.datetime.strptime(str(row[0])[:19],"%Y-%m-%d %H:%M:%S")
            if p>base: base=p
        except Exception: pass
    new_exp=(base+datetime.timedelta(days=30*months)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("UPDATE users SET sub_expires=%s WHERE id=%s",(new_exp,uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True,"expires":new_exp})

@app.route("/api/admin/users/<int:uid>/set-sub",methods=["POST"])
@login_required
@owner_required
def api_set_sub(uid):
    data=request.json or {}
    expiry=(data.get("expiry","") or "").strip()
    if not expiry: return jsonify({"error":"Expiry required"}),400
    if len(expiry)==10: expiry+=" 23:59:59"
    conn=get_db(); cur=conn.cursor()
    cur.execute("UPDATE users SET sub_expires=%s WHERE id=%s",(expiry,uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/admin/users/<int:uid>/end-sub",methods=["POST"])
@login_required
@owner_required
def api_end_sub(uid):
    conn=get_db(); cur=conn.cursor()
    cur.execute("UPDATE users SET sub_expires=NULL,sub_type=NULL WHERE id=%s",(uid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/admin/users/<int:uid>/reset-password",methods=["POST"])
@login_required
@owner_required
def api_reset_password(uid):
    data=request.json or {}
    pw=(data.get("password","") or "").strip()
    if not pw: return jsonify({"error":"Password required"}),400
    conn=get_db(); cur=conn.cursor()
    cur.execute("UPDATE users SET password_hash=%s WHERE id=%s",
                (hashlib.sha256(pw.encode()).hexdigest(),uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})


# ── League API ────────────────────────────────────────────────
@app.route("/api/admin/leagues",methods=["GET"])
@login_required
@owner_required
def api_list_leagues(): return jsonify(get_all_leagues())

@app.route("/api/admin/leagues",methods=["POST"])
@login_required
@owner_required
def api_create_league():
    data=request.json or {}
    name=(data.get("name","") or "").strip().upper()
    if not name: return jsonify({"error":"Name required"}),400
    lslug=slugify(name)
    if not lslug: return jsonify({"error":"Invalid name"}),400
    conn=get_db(); cur=conn.cursor()
    try:
        cur.execute("INSERT INTO leagues (name,slug,created) VALUES (%s,%s,%s) RETURNING id",
                    (name,lslug,now()))
        new_id=cur.fetchone()[0]
        conn.commit(); cur.close(); conn.close()
        return jsonify({"ok":True,"id":new_id,"name":name,"slug":lslug})
    except Exception as e:
        conn.rollback(); cur.close(); conn.close()
        return jsonify({"error":str(e)}),409

@app.route("/api/admin/leagues/<int:lid>",methods=["DELETE"])
@login_required
@owner_required
def api_delete_league(lid):
    conn=get_db(); cur=conn.cursor()
    cur.execute("DELETE FROM leagues WHERE id=%s",(lid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})


# ── EXE Upload / Download ─────────────────────────────────────
@app.route("/api/admin/upload-exe",methods=["POST"])
@login_required
@owner_required
def upload_exe():
    f = request.files.get("file")
    ver = (request.form.get("version") or "v5.0").strip()
    if not f:
        return jsonify({"error": "No file"}), 400
    data = f.read()
    if not data:
        return jsonify({"error": "Empty file"}), 400
    if len(data) > 180 * 1024 * 1024:
        return jsonify({"error": "File too large (max 180 MB)"}), 413
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    try:
        with open(EXE_FILE, "wb") as fp:
            fp.write(data)
    except Exception as e:
        return jsonify({"error": f"Could not save file: {e}"}), 500
    size_mb = round(len(data) / 1024 / 1024, 1)
    meta = {
        "version": ver,
        "size": f"{size_mb} MB",
        "filename": f.filename or "ZevoraScanner.exe",
        "updated": now(),
        "storage": "disk",
        "path": EXE_FILE,
    }
    conn = get_db(); cur = conn.cursor()
    cur.execute(
        "INSERT INTO settings (key,value) VALUES ('exe_meta',%s) "
        "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
        (json.dumps(meta),))
    # Drop legacy base64 blob — it breaks large uploads on Postgres
    cur.execute("DELETE FROM settings WHERE key='exe_data'")
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True, "version": ver, "size": f"{size_mb} MB"})


@app.route("/download/exe")
def download_exe():
    filename = "ZevoraScanner.exe"
    meta = {}
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key='exe_meta'")
        row = cur.fetchone()
        if row:
            meta = json.loads(row[0])
            filename = meta.get("filename", filename)
        cur.close(); conn.close()
    except Exception:
        pass
    if os.path.exists(EXE_FILE):
        return send_file(
            EXE_FILE,
            as_attachment=True,
            download_name=filename,
            mimetype="application/octet-stream",
        )
    # Legacy fallback: old DB-stored builds
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key='exe_data'")
        dr = cur.fetchone()
        cur.close(); conn.close()
    except Exception:
        abort(404)
    if not dr:
        abort(404)
    raw = base64.b64decode(dr[0])
    return send_file(
        io.BytesIO(raw),
        as_attachment=True,
        download_name=filename,
        mimetype="application/octet-stream",
    )

@app.route("/api/stats")
def api_stats():
    try:
        conn=get_db(); cur=conn.cursor()
        cur.execute("SELECT COUNT(*) FROM scans"); total=cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict='REVIEW'"); flagged=cur.fetchone()[0]
        cur.close(); conn.close()
        return jsonify({"total":total,"flagged":flagged})
    except Exception: return jsonify({"total":0,"flagged":0})

@app.errorhandler(403)
def forbidden(e): return render_template("login.html",error="Access denied."),403

@app.errorhandler(404)
def not_found(e):
    return """<html><body style="background:#0a0a0d;color:#ececf0;font-family:monospace;display:flex;
    align-items:center;justify-content:center;height:100vh;margin:0;font-size:1.2rem">
    404 — Page not found</body></html>""",404


# ── Start ─────────────────────────────────────────────────────
with app.app_context():
    try: init_db()
    except Exception as e: print(f"[init_db] {e}")

if __name__=="__main__":
    app.run(debug=False,host="0.0.0.0",port=int(os.environ.get("PORT",5000)))
