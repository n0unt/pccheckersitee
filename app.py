"""
Zevora — Web Application
Flask + PostgreSQL
"""
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort, Response
from functools import wraps
import psycopg2, psycopg2.extras
import hashlib, secrets, string, datetime, json, os, re, base64, io, ssl, time
import urllib.request, urllib.error

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production")
app.config["MAX_CONTENT_LENGTH"] = 150 * 1024 * 1024

DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Webhook URLs
def _d(s): return base64.b64decode(s).decode()
_WH_KFA_ENC = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ3NTM1NTkyNjY1ODU1MTgwOS9Ua09kVEk2QldWQW0tUzBZbEpLTE5TQm9WQkZZRHZMYmlidVlhZWlPYmxIZ2tWZDB6aHJRdHBMUWdpV3VmWjRPVkYwRA=="
_WH_UFF_ENC = "aHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvMTQ3NTM1NjE3NjE1MjY1ODA0MS85WnlCamgtX1hjZmN3TllXLVBWam9tNC1lVDhFWWRIdHVRQm10NnpxQVN4cDBsREFJY1FJYklMdDhmam9laENmNE9WXw=="
WEBHOOK_KFA = _d(_WH_KFA_ENC)
WEBHOOK_UFF = _d(_WH_UFF_ENC)

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

def slug(name):
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
        delta = (exp_dt.date() - datetime.datetime.utcnow().date()).days
        return delta
    except Exception:
        return None

# ── DB init ───────────────────────────────────────────────────
def init_db():
    conn = get_db()
    cur = conn.cursor()

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
            cur.execute("SAVEPOINT sp"); cur.execute(sql); cur.execute("RELEASE SAVEPOINT sp")
        except Exception:
            cur.execute("ROLLBACK TO SAVEPOINT sp")

    # Safe column migrations
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
        "ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL",
        "ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT DEFAULT ''",
        # Remove old NOT NULL on legacy columns if they exist
        "ALTER TABLE users ALTER COLUMN leagues SET DEFAULT ''",
    ]
    for sql in migrations:
        try:
            cur.execute("SAVEPOINT sp_m"); cur.execute(sql); cur.execute("RELEASE SAVEPOINT sp_m")
        except Exception:
            cur.execute("ROLLBACK TO SAVEPOINT sp_m")

    # Seed default leagues
    for lname, lslug in [("UFF", "uff"), ("KFA", "kfa")]:
        try:
            cur.execute("SAVEPOINT sp_l")
            cur.execute(
                "INSERT INTO leagues (name, slug, created) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
                (lname, lslug, now()))
            cur.execute("RELEASE SAVEPOINT sp_l")
        except Exception:
            cur.execute("ROLLBACK TO SAVEPOINT sp_l")

    # Seed owner account
    try:
        cur.execute("SAVEPOINT sp_seed")
        cur.execute("SELECT id FROM users WHERE role='owner' LIMIT 1")
        if not cur.fetchone():
            pw = hashlib.sha256(b"admin").hexdigest()
            cur.execute(
                "INSERT INTO users (username,password_hash,role,leagues,created) VALUES ('admin',%s,'owner','UFF,KFA',%s)",
                (pw, now()))
        cur.execute("RELEASE SAVEPOINT sp_seed")
    except Exception:
        cur.execute("ROLLBACK TO SAVEPOINT sp_seed")

    # Clean up old unused pins (>3 days old)
    try:
        cur.execute("SAVEPOINT sp_clean")
        cutoff = (datetime.datetime.utcnow() - datetime.timedelta(days=3)).strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("DELETE FROM pins WHERE created < %s AND used=0", (cutoff,))
        cur.execute("RELEASE SAVEPOINT sp_clean")
    except Exception:
        cur.execute("ROLLBACK TO SAVEPOINT sp_clean")

    conn.commit()
    cur.close(); conn.close()


# ── Auth helpers ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def w(*a, **k):
        if "user_id" not in session:
            return redirect(url_for("login_page"))
        return f(*a, **k)
    return w

def owner_required(f):
    @wraps(f)
    def w(*a, **k):
        if session.get("role") not in ("owner", "admin"):
            abort(403)
        return f(*a, **k)
    return w

def get_user():
    if "user_id" not in session: return None
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
    row = row_to_dict(cur.fetchone(), cur)
    cur.close(); conn.close()
    return row

def get_user_league_slugs(user):
    return [s.strip().lower() for s in (user.get("leagues") or "").split(",") if s.strip()]

def can_access_league(user, league_name):
    if not user: return False
    if user["role"] in ("owner", "admin"): return True
    slugs = get_user_league_slugs(user)
    return slug(league_name) in slugs

def get_all_leagues():
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id, name, slug, created FROM leagues ORDER BY name")
    rows = rows_to_dicts(cur.fetchall(), cur)
    cur.close(); conn.close()
    return rows

def get_user_leagues(user):
    """Return league objects the user can access."""
    all_lg = get_all_leagues()
    if user.get("role") in ("owner", "admin"):
        return all_lg
    slugs = get_user_league_slugs(user)
    return [lg for lg in all_lg if lg["slug"] in slugs]


# ── Login / Logout ────────────────────────────────────────────
@app.route("/login")
def login_page():
    error_map = {
        "empty":       "Enter username and password.",
        "no_access":   "Account not found.",
        "bad_password":"Incorrect password.",
        "no_sub":      "Your subscription has expired. Contact an admin.",
        "db_error":    "Database error — try again.",
    }
    err = request.args.get("error")
    return render_template("login.html", error=error_map.get(err, err))

@app.route("/auth/login", methods=["POST"])
def do_login():
    username = request.form.get("username","").strip()
    password = request.form.get("password","").strip()
    if not username or not password:
        return redirect(url_for("login_page") + "?error=empty")
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        user = row_to_dict(cur.fetchone(), cur)
        cur.close(); conn.close()
    except Exception:
        return redirect(url_for("login_page") + "?error=db_error")
    if not user:
        return redirect(url_for("login_page") + "?error=no_access")
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    stored = user.get("password_hash") or ""
    if stored and stored != pw_hash:
        return redirect(url_for("login_page") + "?error=bad_password")
    # First login — set password
    if not stored:
        conn2 = get_db(); cur2 = conn2.cursor()
        cur2.execute("UPDATE users SET password_hash=%s WHERE id=%s", (pw_hash, user["id"]))
        conn2.commit(); cur2.close(); conn2.close()
    # Subscription check for non-admin users
    if user["role"] not in ("owner", "admin") and not sub_is_active(user):
        return redirect(url_for("login_page") + "?error=no_sub")
    session["user_id"] = user["id"]
    session["username"] = user["username"]
    session["role"] = user["role"]
    return redirect(url_for("dashboard"))

@app.route("/auth/logout")
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))


# ── Public pages ──────────────────────────────────────────────
@app.route("/")
def index():
    user = get_user()
    return render_template("home.html", user=user)

@app.route("/privacy")
def privacy():
    return render_template("privacy.html", user=get_user())

@app.route("/terms")
def terms():
    return render_template("terms.html", user=get_user())

@app.route("/download")
def download_page():
    meta = {}
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key='exe_meta'")
        row = cur.fetchone()
        meta = json.loads(row[0]) if row else {}
        cur.close(); conn.close()
    except Exception: pass
    has_exe = bool(meta.get("version"))
    return render_template("download.html", user=get_user(),
                           has_exe=has_exe, version=meta.get("version","v5.0"),
                           file_size=meta.get("size",""), updated=meta.get("updated",""))


# ── Dashboard ─────────────────────────────────────────────────
@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user()
    conn = get_db(); cur = conn.cursor()

    # ── User's pins ──
    if user["role"] in ("owner","admin"):
        cur.execute("""
            SELECT p.*, p.pin AS pin_code, p.created AS created_at
            FROM pins p ORDER BY p.id DESC LIMIT 50
        """)
    else:
        cur.execute("""
            SELECT p.*, p.pin AS pin_code, p.created AS created_at
            FROM pins p WHERE p.agent_id=%s ORDER BY p.id DESC LIMIT 50
        """, (user["id"],))
    pins = rows_to_dicts(cur.fetchall(), cur)

    # ── Scans ──
    if user["role"] in ("owner","admin"):
        cur.execute("""
            SELECT s.*, u.username as agent_username
            FROM scans s
            LEFT JOIN pins p ON p.pin = s.pin_used
            LEFT JOIN users u ON u.id = p.agent_id
            ORDER BY s.submitted DESC LIMIT 200
        """)
    else:
        user_leagues = get_user_league_slugs(user)
        all_lgs = get_all_leagues()
        accessible_names = [lg["name"] for lg in all_lgs if lg["slug"] in user_leagues]
        if accessible_names:
            ph = ",".join(["%s"]*len(accessible_names))
            cur.execute(f"""
                SELECT s.*, u.username as agent_username
                FROM scans s
                LEFT JOIN pins p ON p.pin = s.pin_used
                LEFT JOIN users u ON u.id = p.agent_id
                WHERE s.league IN ({ph}) ORDER BY s.submitted DESC LIMIT 200
            """, accessible_names)
        else:
            cur.execute("SELECT s.* FROM scans s WHERE 1=0")
    scans = rows_to_dicts(cur.fetchall(), cur)

    # ── All users for admin panel ──
    all_users = []
    if user["role"] in ("owner","admin"):
        cur.execute("""
            SELECT u.id, u.username, u.discord_id, u.role, u.leagues,
                   u.sub_type, u.sub_league_slug, u.sub_expires,
                   u.granted_by, u.invite_count, u.created,
                   COUNT(p.id) as pin_count
            FROM users u
            LEFT JOIN pins p ON p.agent_id = u.id
            GROUP BY u.id ORDER BY
              CASE u.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, u.username
        """)
        all_users = rows_to_dicts(cur.fetchall(), cur)
        for u2 in all_users:
            u2["sub_active"] = sub_is_active(u2)
            u2["subscription_expiry"] = u2.get("sub_expires")
            u2["days_left"] = days_left(u2)
            u2["subscription_expired"] = (
                u2["sub_expires"] is not None and
                not u2["sub_active"] and
                u2["role"] not in ("owner","admin")
            )
            # Build league display
            u2["league"] = u2.get("leagues") or u2.get("sub_league_slug","")

    # ── Leagues for dropdowns ──
    all_leagues_list = get_all_leagues()

    # ── My Team data ──
    # all_leagues_team: dict of {league_name: [members]} for owner
    all_leagues_team = {}
    team_members = []

    if user["role"] in ("owner","admin"):
        for lg in all_leagues_list:
            cur.execute("""
                SELECT u.id, u.username, u.role, u.sub_type, u.sub_expires, u.leagues,
                       COUNT(DISTINCT p.id) as pin_count,
                       COUNT(DISTINCT s.id) as scan_count
                FROM users u
                LEFT JOIN pins p ON p.agent_id = u.id
                LEFT JOIN scans s ON s.league = %s AND s.pin_used = p.pin
                WHERE u.leagues ILIKE %s OR u.sub_league_slug=%s
                   OR u.role IN ('owner','admin')
                GROUP BY u.id ORDER BY u.username
            """, (lg["name"], f"%{lg['slug']}%", lg["slug"]))
            members = rows_to_dicts(cur.fetchall(), cur)
            for m in members:
                m["sub_active"] = sub_is_active(m)
                m["days_left"] = days_left(m)
            all_leagues_team[lg["name"]] = members
    else:
        user_slugs = get_user_league_slugs(user)
        accessible = [lg for lg in all_leagues_list if lg["slug"] in user_slugs]
        for lg in accessible:
            cur.execute("""
                SELECT u.id, u.username, u.role, u.sub_type, u.sub_expires,
                       COUNT(DISTINCT p.id) as pin_count,
                       COUNT(DISTINCT s.id) as scan_count
                FROM users u
                LEFT JOIN pins p ON p.agent_id = u.id
                LEFT JOIN scans s ON s.league = %s AND s.pin_used = p.pin
                WHERE u.leagues ILIKE %s OR u.sub_league_slug=%s
                GROUP BY u.id ORDER BY u.username
            """, (lg["name"], f"%{lg['slug']}%", lg["slug"]))
            members = rows_to_dicts(cur.fetchall(), cur)
            for m in members:
                m["sub_active"] = sub_is_active(m)
            team_members.extend(members)

    cur.close(); conn.close()

    return render_template("dashboard.html",
        user=user,
        pins=pins,
        scans=scans,
        all_users=all_users,
        all_leagues=all_leagues_team,  # dict {league_name: [members]}
        team_members=team_members,     # list for non-admins
        leagues=all_leagues_list,      # list of {id,name,slug} for dropdowns
        pending_count=sum(1 for u2 in all_users if u2.get("subscription_expired")),
    )


# ── Results ───────────────────────────────────────────────────
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
    report = {}; roblox_accs = []
    if pin_row.get("scan_id"):
        cur.execute("SELECT * FROM scans WHERE id=%s", (pin_row["scan_id"],))
        scan = row_to_dict(cur.fetchone(), cur)
        if scan:
            if scan.get("report_json"):
                try: report = json.loads(scan["report_json"])
                except Exception: report = {}
            if scan.get("roblox_accs"):
                try: roblox_accs = json.loads(scan["roblox_accs"])
                except Exception: roblox_accs = []
            scan["roblox_accounts"] = roblox_accs
    cur.close(); conn.close()
    return render_template("results.html",
        pin=pin_row, scan=scan, user=user,
        report=report, roblox_accs=roblox_accs,
        has_scan=bool(scan))

@app.route("/results/<pin>/download")
@login_required
def download_report(pin):
    user = get_user()
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM pins WHERE pin=%s", (pin.upper(),))
    pin_row = row_to_dict(cur.fetchone(), cur)
    if not pin_row: cur.close(); conn.close(); abort(404)
    if not can_access_league(user, pin_row["league"]): abort(403)
    if not pin_row.get("scan_id"): cur.close(); conn.close(); abort(404)
    cur.execute("SELECT * FROM scans WHERE id=%s", (pin_row["scan_id"],))
    scan = row_to_dict(cur.fetchone(), cur)
    cur.close(); conn.close()
    if not scan: abort(404)
    try: report = json.loads(scan.get("report_json","{}"))
    except Exception: report = {}
    # Build minimal HTML report
    def esc(s): return str(s or "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    sections = []
    for key, label in [
        ("cheat_raw","Cheat Files"),("bam_raw","BAM"),("prefetch_raw","Prefetch"),
        ("shellbags_raw","ShellBags"),("appcompat_raw","AppCompat"),
        ("discord_raw","Discord"),("discord_memory_raw","DC Downloads"),
        ("network_raw","Network/VPN"),("eventlog_raw","Event Log"),
        ("power_events_raw","Power Timeline"),("two_pc_raw","2-PC Bypass"),
        ("cleaners_raw","Cleaners"),("deleted_recovery_raw","Deleted Recovery"),
        ("drive_info","USB/Drives"),
    ]:
        val = report.get(key, "")
        if val and str(val).strip() not in ("","None","No data"):
            sections.append(f"<h2>{esc(label)}</h2><pre>{esc(str(val)[:20000])}</pre>")
    html = f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<title>Zevora Report — {esc(pin.upper())}</title>
<style>body{{background:#0a0a0d;color:#ececf0;font-family:monospace;padding:2rem;max-width:900px;margin:auto}}
h1{{color:#2bba8f}}h2{{color:#8888a0;font-size:.9rem;margin:1.5rem 0 .4rem;text-transform:uppercase;letter-spacing:.06em}}
pre{{background:#18181d;padding:1rem;border-radius:8px;overflow-x:auto;font-size:11px;line-height:1.6;white-space:pre-wrap}}</style>
</head><body>
<h1>Zevora Forensic Report</h1>
<p style="color:#8888a0">PIN: {esc(pin.upper())} · PC: {esc(scan.get("pc_user","?"))} · League: {esc(scan.get("league","?"))} · {esc(scan.get("submitted","?"))} UTC</p>
<p style="color:#f85149;font-size:1.1rem;font-weight:700;margin:.5rem 0">Verdict: {esc(scan.get("verdict","?"))} · {scan.get("total_hits",0)} hits</p>
{"".join(sections)}
</body></html>"""
    filename = f"zevora-{pin.upper()}-{scan.get('pc_user','unknown')}.html"
    return Response(html, mimetype="text/html",
                    headers={"Content-Disposition": f"attachment; filename={filename}"})


# ── PIN API ───────────────────────────────────────────────────
@app.route("/api/validate_pin", methods=["POST"])
def api_validate_pin():
    data = request.json or {}
    pin = data.get("pin","").upper().strip()
    if not pin:
        return jsonify({"valid": False, "error": "No PIN provided"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM pins WHERE pin=%s AND used=0", (pin,))
    row = row_to_dict(cur.fetchone(), cur)
    cur.close(); conn.close()
    if not row:
        return jsonify({"valid": False, "error": "Invalid or already used PIN"}), 401
    try:
        exp_dt = datetime.datetime.strptime(str(row["expires"])[:19], "%Y-%m-%d %H:%M:%S")
        if datetime.datetime.utcnow() > exp_dt:
            return jsonify({"valid": False, "error": "PIN has expired"}), 401
    except Exception:
        pass
    return jsonify({"ok": True, "valid": True, "league": row["league"],
                    "league_slug": slug(row["league"])})


@app.route("/api/generate_pin", methods=["POST"])
@app.route("/api/pins/generate", methods=["POST"])
@login_required
def api_generate_pin():
    user = get_user()
    data = request.json or {}
    league_input = (data.get("league","") or "").strip().upper()

    # Resolve league from DB
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT name FROM leagues WHERE slug=%s OR name=%s",
                (league_input.lower(), league_input))
    row = cur.fetchone()
    league_name = row[0] if row else league_input
    if not league_name:
        cur.close(); conn.close()
        return jsonify({"error": "League required"}), 400

    # Access check
    if user["role"] not in ("owner","admin"):
        if not can_access_league(user, league_name):
            cur.close(); conn.close()
            return jsonify({"error": "Not authorized for this league"}), 403

    pin = "".join(secrets.choice(string.ascii_uppercase + string.digits) for _ in range(8))
    expires = (datetime.datetime.utcnow() + datetime.timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S")

    cur.execute(
        "INSERT INTO pins (pin,league,agent_id,used,created,expires) VALUES (%s,%s,%s,0,%s,%s)",
        (pin, league_name, user["id"], now(), expires))
    conn.commit()

    # Keep only 3 most recent unused pins per agent
    try:
        cur.execute("""
            DELETE FROM pins WHERE agent_id=%s AND used=0 AND pin!=%s
            AND id NOT IN (SELECT id FROM pins WHERE agent_id=%s AND used=0 ORDER BY id DESC LIMIT 3)
        """, (user["id"], pin, user["id"]))
        conn.commit()
    except Exception:
        try: conn.rollback()
        except Exception: pass

    cur.close(); conn.close()
    return jsonify({"pin": pin, "league": league_name, "expires": expires,
                    "results_url": f"/results/{pin}"})


@app.route("/api/submit", methods=["POST"])
def api_submit():
    try:
        data = request.json or {}
        pin = (data.get("pin","") or "").upper().strip()
        if not pin:
            return jsonify({"error": "No PIN"}), 400
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT * FROM pins WHERE pin=%s AND used=0", (pin,))
        pin_row = row_to_dict(cur.fetchone(), cur)
        if not pin_row:
            cur.close(); conn.close()
            return jsonify({"error": "Invalid or already used PIN"}), 401

        league = data.get("league","") or pin_row["league"]
        report = data.get("report", {})

        # Merge tab data into report
        for tab in ["shellbags","bam","prefetch","appcompat","roblox","cheat","yara",
                    "unsigned","recycle","sysmain","processes","cleaners","registry_extra",
                    "discord","discord_memory","eventlog","jumplists","lnkfiles",
                    "power_events","two_pc","deleted_recovery","deleted_int","exec_history_text",
                    "network","drive_info"]:
            if tab in data and data[tab]:
                report[tab+"_raw"] = str(data[tab])[:30000]

        for field in ["cleaner_info","process_hits","cleaner_hits","eventlog_hits",
                      "jumplist_hits","lnk_hits","deleted_hits","exec_history",
                      "roblox_log_hits","vpn_detected","power_hits","two_pc_hits",
                      "recovery_hits","discord_memory_hits","fastflags"]:
            if field in data:
                report[field] = data[field]

        report.pop("vpn_info", None)

        report_str = json.dumps(report, default=str)
        if len(report_str) > 2000000:
            for k in ["cheat_raw","unsigned_raw","appcompat_raw","processes_raw"]:
                if k in report: report[k] = report[k][:5000]
            report_str = json.dumps(report, default=str)

        cur.execute("""
            INSERT INTO scans (league,pc_user,verdict,total_hits,roblox_accs,report_json,pin_used,submitted)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
        """, (league, data.get("pc_user","unknown"), data.get("verdict","UNKNOWN"),
              int(data.get("total_hits",0)),
              json.dumps(data.get("roblox_accounts",[])),
              report_str, pin, now()))
        scan_id = cur.fetchone()[0]
        cur.execute("UPDATE pins SET used=1, scan_id=%s, finished_at=%s WHERE pin=%s",
                    (scan_id, now(), pin))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"ok": True, "scan_id": scan_id})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scans")
@login_required
def api_scans():
    user = get_user()
    conn = get_db(); cur = conn.cursor()
    if user["role"] in ("owner","admin"):
        cur.execute("SELECT * FROM scans ORDER BY submitted DESC LIMIT 100")
    else:
        slugs = get_user_league_slugs(user)
        all_lgs = get_all_leagues()
        names = [lg["name"] for lg in all_lgs if lg["slug"] in slugs]
        if not names: cur.close(); conn.close(); return jsonify([])
        ph = ",".join(["%s"]*len(names))
        cur.execute(f"SELECT * FROM scans WHERE league IN ({ph}) ORDER BY submitted DESC LIMIT 100", names)
    rows = rows_to_dicts(cur.fetchall(), cur)
    cur.close(); conn.close()
    return jsonify(rows)


@app.route("/api/scans/<int:scan_id>", methods=["DELETE"])
@login_required
def api_delete_scan(scan_id):
    user = get_user()
    if user["role"] not in ("owner","admin"):
        return jsonify({"error": "Admins only"}), 403
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM scans WHERE id=%s", (scan_id,))
    cur.execute("UPDATE pins SET scan_id=NULL WHERE scan_id=%s", (scan_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


# ── Admin User API ────────────────────────────────────────────
@app.route("/api/admin/users")
@login_required
@owner_required
def api_admin_users():
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users ORDER BY username")
    rows = rows_to_dicts(cur.fetchall(), cur)
    cur.close(); conn.close()
    for r in rows:
        r["sub_active"] = sub_is_active(r)
        r["days_left"] = days_left(r)
    return jsonify(rows)


@app.route("/api/admin/users/create", methods=["POST"])
@login_required
@owner_required
def api_create_user():
    data = request.json or {}
    username = (data.get("username","") or "").strip()
    password = (data.get("password","") or "").strip()
    role     = data.get("role","agent")
    leagues_val = data.get("league", data.get("leagues","")) or ""
    sub_months  = int(data.get("sub_months", data.get("months", 1)) or 1)

    if not username or not password:
        return jsonify({"error": "Username and password required"}), 400

    # Resolve league name
    league_name = ""
    if leagues_val and leagues_val != "ALL":
        conn_tmp = get_db(); cur_tmp = conn_tmp.cursor()
        cur_tmp.execute("SELECT name FROM leagues WHERE slug=%s OR name=%s",
                        (slug(leagues_val), leagues_val.upper()))
        row = cur_tmp.fetchone()
        league_name = row[0] if row else leagues_val.upper()
        cur_tmp.close(); conn_tmp.close()
    elif leagues_val == "ALL":
        all_lgs = get_all_leagues()
        league_name = ",".join(lg["name"] for lg in all_lgs)

    sub_expires = None
    if sub_months and sub_months > 0:
        sub_expires = (datetime.datetime.utcnow() + datetime.timedelta(days=30*sub_months)).strftime("%Y-%m-%d %H:%M:%S")

    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id FROM users WHERE username=%s", (username,))
    if cur.fetchone():
        cur.close(); conn.close()
        return jsonify({"error": "Username already exists"}), 409
    cur.execute("""
        INSERT INTO users (username,password_hash,role,leagues,sub_type,sub_expires,granted_by,created)
        VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
    """, (username, pw_hash, role, league_name,
          "enterprise" if league_name else "user",
          sub_expires, get_user()["username"], now()))
    new_id = cur.fetchone()[0]
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True, "id": new_id, "username": username})


@app.route("/api/admin/users/<int:uid>", methods=["PATCH"])
@login_required
@owner_required
def api_update_user(uid):
    data = request.json or {}
    conn = get_db(); cur = conn.cursor()
    if "role" in data:
        cur.execute("UPDATE users SET role=%s WHERE id=%s", (data["role"], uid))
    if "leagues" in data:
        cur.execute("UPDATE users SET leagues=%s WHERE id=%s", (data["leagues"], uid))
    if "password" in data and data["password"]:
        pw_hash = hashlib.sha256(data["password"].encode()).hexdigest()
        cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (pw_hash, uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@login_required
@owner_required
def api_delete_user(uid):
    if uid == session.get("user_id"):
        return jsonify({"error": "Cannot delete yourself"}), 400
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM users WHERE id=%s", (uid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:uid>/extend-sub", methods=["POST"])
@login_required
@owner_required
def api_extend_sub(uid):
    data = request.json or {}
    months = int(data.get("months", 1))
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT sub_expires FROM users WHERE id=%s", (uid,))
    row = cur.fetchone()
    base = datetime.datetime.utcnow()
    if row and row[0]:
        try:
            parsed = datetime.datetime.strptime(str(row[0])[:19], "%Y-%m-%d %H:%M:%S")
            if parsed > base: base = parsed
        except Exception: pass
    new_exp = (base + datetime.timedelta(days=30*months)).strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("UPDATE users SET sub_expires=%s WHERE id=%s", (new_exp, uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True, "expires": new_exp})


@app.route("/api/admin/users/<int:uid>/end-sub", methods=["POST"])
@login_required
@owner_required
def api_end_sub(uid):
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE users SET sub_expires=NULL, sub_type=NULL WHERE id=%s", (uid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:uid>/set-sub", methods=["POST"])
@login_required
@owner_required
def api_set_sub(uid):
    data = request.json or {}
    expiry = (data.get("expiry","") or "").strip()
    if not expiry: return jsonify({"error": "Expiry date required"}), 400
    # Normalize to datetime string
    if len(expiry) == 10: expiry += " 23:59:59"
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE users SET sub_expires=%s WHERE id=%s", (expiry, uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


@app.route("/api/admin/users/<int:uid>/reset-password", methods=["POST"])
@login_required
@owner_required
def api_reset_password(uid):
    data = request.json or {}
    password = (data.get("password","") or "").strip()
    if not password: return jsonify({"error": "Password required"}), 400
    pw_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = get_db(); cur = conn.cursor()
    cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (pw_hash, uid))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


# ── League API ────────────────────────────────────────────────
@app.route("/api/admin/leagues", methods=["GET"])
@login_required
@owner_required
def api_list_leagues():
    return jsonify(get_all_leagues())


@app.route("/api/admin/leagues", methods=["POST"])
@login_required
@owner_required
def api_create_league():
    data = request.json or {}
    name = (data.get("name","") or "").strip().upper()
    if not name: return jsonify({"error": "Name required"}), 400
    lslug = slug(name)
    if not lslug: return jsonify({"error": "Invalid name"}), 400
    conn = get_db(); cur = conn.cursor()
    try:
        cur.execute("INSERT INTO leagues (name,slug,created) VALUES (%s,%s,%s) RETURNING id",
                    (name, lslug, now()))
        new_id = cur.fetchone()[0]
        conn.commit(); cur.close(); conn.close()
        return jsonify({"ok": True, "id": new_id, "name": name, "slug": lslug})
    except Exception as e:
        conn.rollback(); cur.close(); conn.close()
        return jsonify({"error": f"League already exists: {e}"}), 409


@app.route("/api/admin/leagues/<int:league_id>", methods=["DELETE"])
@login_required
@owner_required
def api_delete_league(league_id):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM leagues WHERE id=%s", (league_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


# ── EXE Upload / Download ─────────────────────────────────────
@app.route("/api/admin/upload-exe", methods=["POST"])
@login_required
@owner_required
def upload_exe():
    f = request.files.get("file")
    ver = (request.form.get("version") or "v5.0").strip()
    if not f: return jsonify({"error": "No file"}), 400
    data = f.read()
    if not data: return jsonify({"error": "Empty file"}), 400
    size_mb = round(len(data)/1024/1024, 1)
    b64 = base64.b64encode(data).decode("ascii")
    meta = {"version": ver, "size": f"{size_mb} MB",
            "filename": f.filename or "ZevoraScanner.exe", "updated": now()}
    conn = get_db(); cur = conn.cursor()
    cur.execute("INSERT INTO settings (key,value) VALUES ('exe_meta',%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
                (json.dumps(meta),))
    cur.execute("INSERT INTO settings (key,value) VALUES ('exe_data',%s) ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
                (b64,))
    conn.commit(); cur.close(); conn.close()
    try:
        with open("/tmp/zevora.exe","wb") as fp: fp.write(data)
        with open("/tmp/zevora_fname.txt","w") as fp: fp.write(f.filename or "ZevoraScanner.exe")
    except Exception: pass
    return jsonify({"ok": True, "version": ver, "size": f"{size_mb} MB"})


@app.route("/download/exe")
def download_exe():
    from flask import send_file
    filename = "ZevoraScanner.exe"
    if os.path.exists("/tmp/zevora.exe"):
        try:
            if os.path.exists("/tmp/zevora_fname.txt"):
                filename = open("/tmp/zevora_fname.txt").read().strip()
            return send_file("/tmp/zevora.exe", as_attachment=True,
                             download_name=filename, mimetype="application/octet-stream")
        except Exception: pass
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT value FROM settings WHERE key='exe_meta'")
        meta_row = cur.fetchone()
        cur.execute("SELECT value FROM settings WHERE key='exe_data'")
        data_row = cur.fetchone()
        cur.close(); conn.close()
    except Exception:
        abort(404)
    if not data_row: abort(404)
    if meta_row:
        try: filename = json.loads(meta_row[0]).get("filename", filename)
        except Exception: pass
    raw = base64.b64decode(data_row[0])
    return send_file(io.BytesIO(raw), as_attachment=True,
                     download_name=filename, mimetype="application/octet-stream")


# ── Stats API (for home page) ─────────────────────────────────
@app.route("/api/stats")
def api_stats():
    try:
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM scans"); total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict='REVIEW'"); flagged = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM users"); users_count = cur.fetchone()[0]
        cur.close(); conn.close()
        return jsonify({"total": total, "flagged": flagged, "users": users_count})
    except Exception:
        return jsonify({"total": 0, "flagged": 0, "users": 0})


# ── Error pages ───────────────────────────────────────────────
@app.errorhandler(403)
def forbidden(e):
    return render_template("login.html", error="You don't have permission to access that page."), 403

@app.errorhandler(404)
def not_found(e):
    return "<h1 style='font-family:monospace;color:#ececf0;background:#0a0a0d;height:100vh;display:flex;align-items:center;justify-content:center;margin:0'>404 — Not Found</h1>", 404


# ── Startup ───────────────────────────────────────────────────
with app.app_context():
    try:
        init_db()
    except Exception as e:
        print(f"[init_db error] {e}")

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
