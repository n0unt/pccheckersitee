"""
PC Checker - Web Dashboard
Flask backend for OFL/FFL forensic scan results
Deploy on Railway/Render: set SECRET_KEY env var
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from functools import wraps
import sqlite3, hashlib, secrets, string, datetime, json, os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production-plz")

DB = os.environ.get("DATABASE_URL", "/tmp/pcchecker.db")

# ── DB Setup ─────────────────────────────────────────────────
def get_db():
    db = sqlite3.connect(DB)
    db.row_factory = sqlite3.Row
    return db

def init_db():
    db = get_db()
    db.executescript("""
    CREATE TABLE IF NOT EXISTS users (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        username  TEXT UNIQUE NOT NULL,
        password  TEXT NOT NULL,
        role      TEXT NOT NULL DEFAULT 'pending',
        leagues   TEXT NOT NULL DEFAULT '',
        created   TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS pins (
        id        INTEGER PRIMARY KEY AUTOINCREMENT,
        pin       TEXT UNIQUE NOT NULL,
        league    TEXT NOT NULL,
        agent_id  INTEGER NOT NULL,
        used      INTEGER NOT NULL DEFAULT 0,
        created   TEXT NOT NULL,
        expires   TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS scans (
        id           INTEGER PRIMARY KEY AUTOINCREMENT,
        league       TEXT NOT NULL,
        pc_user      TEXT NOT NULL,
        verdict      TEXT NOT NULL,
        total_hits   INTEGER NOT NULL DEFAULT 0,
        roblox_accs  TEXT NOT NULL DEFAULT '[]',
        report_json  TEXT NOT NULL DEFAULT '{}',
        pin_used     TEXT,
        submitted    TEXT NOT NULL
    );
    """)
    # Seed owner account
    pw = hashlib.sha256("123456".encode()).hexdigest()
    try:
        db.execute("""
            INSERT INTO users (username, password, role, leagues, created)
            VALUES (?, ?, 'owner', 'UFF,FFL', ?)
        """, ("ars", pw, now()))
        db.commit()
    except Exception:
        pass
    db.close()

def now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def gen_pin():
    chars = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(8))

# ── Auth helpers ──────────────────────────────────────────────
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def owner_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "owner":
            abort(403)
        return f(*args, **kwargs)
    return wrapper

def get_user():
    if "user_id" not in session:
        return None
    db = get_db()
    u = db.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    db.close()
    return u

# ── Routes ────────────────────────────────────────────────────

@app.route("/")
def index():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username=? AND password=?",
            (username, hash_pw(password))
        ).fetchone()
        db.close()
        if user:
            if user["role"] == "pending":
                error = "Your account is pending approval."
            else:
                session["user_id"] = user["id"]
                session["username"] = user["username"]
                session["role"] = user["role"]
                session["leagues"] = user["leagues"]
                return redirect(url_for("dashboard"))
        else:
            error = "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    success = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        league   = request.form.get("league", "").strip()
        if not username or not password or not league:
            error = "All fields required."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        else:
            db = get_db()
            try:
                db.execute(
                    "INSERT INTO users (username, password, role, leagues, created) VALUES (?,?,?,?,?)",
                    (username, hash_pw(password), "pending", league, now())
                )
                db.commit()
                success = "Account created! Wait for owner approval."
            except sqlite3.IntegrityError:
                error = "Username already taken."
            finally:
                db.close()
    return render_template("register.html", error=error, success=success)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user()
    role = user["role"]
    leagues = [l.strip() for l in user["leagues"].split(",") if l.strip()]
    return render_template("dashboard.html", user=user, role=role, leagues=leagues)

# ── API: Scans ────────────────────────────────────────────────

@app.route("/api/scans")
@login_required
def api_scans():
    user = get_user()
    league_filter = request.args.get("league", "")
    db = get_db()

    if user["role"] == "owner":
        if league_filter and league_filter != "ALL":
            rows = db.execute(
                "SELECT * FROM scans WHERE league=? ORDER BY submitted DESC LIMIT 100",
                (league_filter,)
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT * FROM scans ORDER BY submitted DESC LIMIT 100"
            ).fetchall()
    else:
        allowed = [l.strip() for l in user["leagues"].split(",")]
        if league_filter and league_filter in allowed:
            rows = db.execute(
                "SELECT * FROM scans WHERE league=? ORDER BY submitted DESC LIMIT 100",
                (league_filter,)
            ).fetchall()
        elif not league_filter:
            placeholders = ",".join("?" * len(allowed))
            rows = db.execute(
                f"SELECT * FROM scans WHERE league IN ({placeholders}) ORDER BY submitted DESC LIMIT 100",
                allowed
            ).fetchall()
        else:
            rows = []
    db.close()

    scans = []
    for r in rows:
        scans.append({
            "id": r["id"], "league": r["league"], "pc_user": r["pc_user"],
            "verdict": r["verdict"], "total_hits": r["total_hits"],
            "roblox_accs": json.loads(r["roblox_accs"]),
            "pin_used": r["pin_used"], "submitted": r["submitted"],
        })
    return jsonify(scans)

@app.route("/api/scans/<int:scan_id>")
@login_required
def api_scan_detail(scan_id):
    user = get_user()
    db = get_db()
    row = db.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    db.close()
    if not row:
        abort(404)
    allowed = [l.strip() for l in user["leagues"].split(",")]
    if user["role"] != "owner" and row["league"] not in allowed:
        abort(403)
    return jsonify({
        "id": row["id"], "league": row["league"], "pc_user": row["pc_user"],
        "verdict": row["verdict"], "total_hits": row["total_hits"],
        "roblox_accs": json.loads(row["roblox_accs"]),
        "report": json.loads(row["report_json"]),
        "pin_used": row["pin_used"], "submitted": row["submitted"],
    })

@app.route("/api/stats")
@login_required
def api_stats():
    user = get_user()
    db = get_db()
    if user["role"] == "owner":
        total   = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        cheater = db.execute("SELECT COUNT(*) FROM scans WHERE verdict='CHEATER'").fetchone()[0]
        susp    = db.execute("SELECT COUNT(*) FROM scans WHERE verdict='SUSPICIOUS'").fetchone()[0]
        clean   = db.execute("SELECT COUNT(*) FROM scans WHERE verdict='CLEAN'").fetchone()[0]
        uff_c   = db.execute("SELECT COUNT(*) FROM scans WHERE league='UFF'").fetchone()[0]
        ffl_c   = db.execute("SELECT COUNT(*) FROM scans WHERE league='FFL'").fetchone()[0]
    else:
        allowed = [l.strip() for l in user["leagues"].split(",")]
        ph = ",".join("?" * len(allowed))
        total   = db.execute(f"SELECT COUNT(*) FROM scans WHERE league IN ({ph})", allowed).fetchone()[0]
        cheater = db.execute(f"SELECT COUNT(*) FROM scans WHERE verdict='CHEATER' AND league IN ({ph})", allowed).fetchone()[0]
        susp    = db.execute(f"SELECT COUNT(*) FROM scans WHERE verdict='SUSPICIOUS' AND league IN ({ph})", allowed).fetchone()[0]
        clean   = db.execute(f"SELECT COUNT(*) FROM scans WHERE verdict='CLEAN' AND league IN ({ph})", allowed).fetchone()[0]
        uff_c   = db.execute(f"SELECT COUNT(*) FROM scans WHERE league='UFF' AND league IN ({ph})", allowed).fetchone()[0]
        ffl_c   = db.execute(f"SELECT COUNT(*) FROM scans WHERE league='FFL' AND league IN ({ph})", allowed).fetchone()[0]
    db.close()
    return jsonify({"total": total, "cheater": cheater, "suspicious": susp,
                    "clean": clean, "uff": uff_c, "ffl": ffl_c})

# ── API: PINs ─────────────────────────────────────────────────

@app.route("/api/pins/generate", methods=["POST"])
@login_required
def api_gen_pin():
    user = get_user()
    data   = request.json or {}
    league = data.get("league", "").upper()
    allowed = [l.strip() for l in user["leagues"].split(",")]
    if league not in allowed and user["role"] != "owner":
        return jsonify({"error": "Not authorized for this league"}), 403
    if not league:
        return jsonify({"error": "League required"}), 400

    pin = gen_pin()
    expires = (datetime.datetime.utcnow() + datetime.timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S")
    db = get_db()
    db.execute(
        "INSERT INTO pins (pin, league, agent_id, used, created, expires) VALUES (?,?,?,0,?,?)",
        (pin, league, user["id"], now(), expires)
    )
    db.commit()
    db.close()
    return jsonify({"pin": pin, "league": league, "expires": expires})

@app.route("/api/pins/validate", methods=["POST"])
def api_validate_pin():
    """Called by the scanner app to validate a PIN before scanning."""
    data   = request.json or {}
    pin    = data.get("pin", "").upper().strip()
    league = data.get("league", "").upper().strip()
    if not pin:
        return jsonify({"valid": False, "error": "No PIN provided"}), 400

    db = get_db()
    row = db.execute(
        "SELECT * FROM pins WHERE pin=? AND used=0",
        (pin,)
    ).fetchone()

    if not row:
        db.close()
        return jsonify({"valid": False, "error": "Invalid or already used PIN"}), 401

    # Check expiry
    expires = datetime.datetime.strptime(row["expires"], "%Y-%m-%d %H:%M:%S")
    if datetime.datetime.utcnow() > expires:
        db.close()
        return jsonify({"valid": False, "error": "PIN has expired"}), 401

    # Check league matches
    if league and row["league"] != league:
        db.close()
        return jsonify({"valid": False, "error": f"PIN is for {row['league']}, not {league}"}), 401

    db.close()
    return jsonify({"valid": True, "league": row["league"]})

@app.route("/api/submit", methods=["POST"])
def api_submit_scan():
    """Called by the scanner app to submit results."""
    data = request.json or {}
    pin    = data.get("pin", "").upper().strip()
    league = data.get("league", "").upper().strip()

    db = get_db()
    pin_row = db.execute(
        "SELECT * FROM pins WHERE pin=? AND used=0", (pin,)
    ).fetchone()

    if not pin_row:
        db.close()
        return jsonify({"error": "Invalid PIN"}), 401

    # Mark PIN as used
    db.execute("UPDATE pins SET used=1 WHERE pin=?", (pin,))

    # Store scan
    db.execute("""
        INSERT INTO scans (league, pc_user, verdict, total_hits, roblox_accs, report_json, pin_used, submitted)
        VALUES (?,?,?,?,?,?,?,?)
    """, (
        league or pin_row["league"],
        data.get("pc_user", "unknown"),
        data.get("verdict", "UNKNOWN"),
        data.get("total_hits", 0),
        json.dumps(data.get("roblox_accounts", [])),
        json.dumps(data.get("report", {})),
        pin,
        now(),
    ))
    db.commit()
    db.close()
    return jsonify({"ok": True})

# ── API: Admin ────────────────────────────────────────────────

@app.route("/api/admin/users")
@login_required
@owner_required
def api_admin_users():
    db = get_db()
    rows = db.execute("SELECT id, username, role, leagues, created FROM users ORDER BY created DESC").fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/admin/users/<int:uid>", methods=["PATCH"])
@login_required
@owner_required
def api_admin_update_user(uid):
    data   = request.json or {}
    role   = data.get("role")
    leagues = data.get("leagues")
    db = get_db()
    if role:
        db.execute("UPDATE users SET role=? WHERE id=?", (role, uid))
    if leagues is not None:
        db.execute("UPDATE users SET leagues=? WHERE id=?", (leagues, uid))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.route("/api/admin/users/<int:uid>", methods=["DELETE"])
@login_required
@owner_required
def api_admin_delete_user(uid):
    if uid == session.get("user_id"):
        return jsonify({"error": "Cannot delete yourself"}), 400
    db = get_db()
    db.execute("DELETE FROM users WHERE id=?", (uid,))
    db.commit()
    db.close()
    return jsonify({"ok": True})

@app.route("/api/pins")
@login_required
def api_pins():
    user = get_user()
    db = get_db()
    if user["role"] == "owner":
        rows = db.execute(
            "SELECT p.*, u.username as agent FROM pins p JOIN users u ON p.agent_id=u.id ORDER BY p.created DESC LIMIT 50"
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT p.*, u.username as agent FROM pins p JOIN users u ON p.agent_id=u.id WHERE p.agent_id=? ORDER BY p.created DESC LIMIT 50",
            (user["id"],)
        ).fetchall()
    db.close()
    return jsonify([dict(r) for r in rows])

if __name__ == "__main__":
    init_db()
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
