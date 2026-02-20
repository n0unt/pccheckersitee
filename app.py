"""
PC Checker - Web Dashboard
Flask + PostgreSQL backend for OFL/FFL forensic scan results
"""

from flask import Flask, render_template, request, jsonify, session, redirect, url_for, abort
from functools import wraps
import psycopg2, psycopg2.extras
import hashlib, secrets, string, datetime, json, os

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "change-this-in-production-plz")

DATABASE_URL = os.environ.get("DATABASE_URL", "")

def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    conn.autocommit = False
    return conn

def now():
    return datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def hash_pw(pw):
    return hashlib.sha256(pw.encode()).hexdigest()

def gen_pin():
    chars = string.ascii_uppercase + string.digits
    return "".join(secrets.choice(chars) for _ in range(8))

def row_to_dict(row, cur):
    if row is None: return None
    cols = [desc[0] for desc in cur.description]
    return dict(zip(cols, row))

def rows_to_dicts(rows, cur):
    cols = [desc[0] for desc in cur.description]
    return [dict(zip(cols, row)) for row in rows]

def init_db():
    conn = get_db(); cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'pending',
        leagues TEXT NOT NULL DEFAULT '', created TEXT NOT NULL)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS pins (
        id SERIAL PRIMARY KEY, pin TEXT UNIQUE NOT NULL,
        league TEXT NOT NULL, agent_id INTEGER NOT NULL,
        used INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL, expires TEXT NOT NULL)""")
    cur.execute("""CREATE TABLE IF NOT EXISTS scans (
        id SERIAL PRIMARY KEY, league TEXT NOT NULL, pc_user TEXT NOT NULL,
        verdict TEXT NOT NULL, total_hits INTEGER NOT NULL DEFAULT 0,
        roblox_accs TEXT NOT NULL DEFAULT '[]', report_json TEXT NOT NULL DEFAULT '{}',
        pin_used TEXT, submitted TEXT NOT NULL)""")
    pw = hash_pw("123456")
    cur.execute("SELECT id FROM users WHERE username=%s", ("ars",))
    if not cur.fetchone():
        cur.execute("INSERT INTO users (username,password,role,leagues,created) VALUES (%s,%s,'owner','UFF,FFL',%s)",
                    ("ars", pw, now()))
    conn.commit(); cur.close(); conn.close()

def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if "user_id" not in session: return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper

def owner_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get("role") != "owner": abort(403)
        return f(*args, **kwargs)
    return wrapper

def get_user():
    if "user_id" not in session: return None
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id=%s", (session["user_id"],))
    row = row_to_dict(cur.fetchone(), cur)
    cur.close(); conn.close()
    return row

@app.route("/")
def index():
    return redirect(url_for("dashboard") if "user_id" in session else url_for("login"))

@app.route("/login", methods=["GET","POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","").strip()
        conn = get_db(); cur = conn.cursor()
        cur.execute("SELECT * FROM users WHERE username=%s AND password=%s", (u, hash_pw(p)))
        user = row_to_dict(cur.fetchone(), cur)
        cur.close(); conn.close()
        if user:
            if user["role"] == "pending": error = "Your account is pending approval."
            else:
                session["user_id"] = user["id"]; session["username"] = user["username"]
                session["role"] = user["role"]; session["leagues"] = user["leagues"]
                return redirect(url_for("dashboard"))
        else: error = "Invalid username or password."
    return render_template("login.html", error=error)

@app.route("/register", methods=["GET","POST"])
def register():
    error = None; success = None
    if request.method == "POST":
        u = request.form.get("username","").strip()
        p = request.form.get("password","").strip()
        l = request.form.get("league","").strip()
        if not u or not p or not l: error = "All fields required."
        elif len(p) < 6: error = "Password must be at least 6 characters."
        else:
            conn = get_db(); cur = conn.cursor()
            try:
                cur.execute("INSERT INTO users (username,password,role,leagues,created) VALUES (%s,%s,%s,%s,%s)",
                            (u, hash_pw(p), "pending", l, now()))
                conn.commit(); success = "Account created! Wait for owner approval."
            except psycopg2.IntegrityError: conn.rollback(); error = "Username already taken."
            finally: cur.close(); conn.close()
    return render_template("register.html", error=error, success=success)

@app.route("/logout")
def logout():
    session.clear(); return redirect(url_for("login"))

@app.route("/dashboard")
@login_required
def dashboard():
    user = get_user()
    return render_template("dashboard.html", user=user, role=user["role"],
                           leagues=[l.strip() for l in user["leagues"].split(",") if l.strip()])

@app.route("/api/scans")
@login_required
def api_scans():
    user = get_user(); lf = request.args.get("league","")
    conn = get_db(); cur = conn.cursor()
    if user["role"] == "owner":
        if lf and lf != "ALL": cur.execute("SELECT * FROM scans WHERE league=%s ORDER BY submitted DESC LIMIT 100",(lf,))
        else: cur.execute("SELECT * FROM scans ORDER BY submitted DESC LIMIT 100")
    else:
        allowed = [l.strip() for l in user["leagues"].split(",")]
        if lf and lf in allowed: cur.execute("SELECT * FROM scans WHERE league=%s ORDER BY submitted DESC LIMIT 100",(lf,))
        elif not lf:
            ph = ",".join(["%s"]*len(allowed))
            cur.execute(f"SELECT * FROM scans WHERE league IN ({ph}) ORDER BY submitted DESC LIMIT 100", allowed)
        else: cur.close(); conn.close(); return jsonify([])
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
    allowed = [l.strip() for l in user["leagues"].split(",")]
    if user["role"] != "owner" and row["league"] not in allowed: abort(403)
    return jsonify({"id":row["id"],"league":row["league"],"pc_user":row["pc_user"],
                    "verdict":row["verdict"],"total_hits":row["total_hits"],
                    "roblox_accs":json.loads(row["roblox_accs"]),
                    "report":json.loads(row["report_json"]),
                    "pin_used":row["pin_used"],"submitted":row["submitted"]})

@app.route("/api/stats")
@login_required
def api_stats():
    user = get_user(); conn = get_db(); cur = conn.cursor()
    if user["role"] == "owner":
        cur.execute("SELECT COUNT(*) FROM scans"); total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict='CHEATER'"); cheater = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict='SUSPICIOUS'"); susp = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE verdict='CLEAN'"); clean = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE league='UFF'"); uff_c = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM scans WHERE league='FFL'"); ffl_c = cur.fetchone()[0]
    else:
        allowed = [l.strip() for l in user["leagues"].split(",")]
        ph = ",".join(["%s"]*len(allowed))
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE league IN ({ph})",allowed); total = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE verdict='CHEATER' AND league IN ({ph})",allowed); cheater = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE verdict='SUSPICIOUS' AND league IN ({ph})",allowed); susp = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE verdict='CLEAN' AND league IN ({ph})",allowed); clean = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE league='UFF' AND league IN ({ph})",allowed); uff_c = cur.fetchone()[0]
        cur.execute(f"SELECT COUNT(*) FROM scans WHERE league='FFL' AND league IN ({ph})",allowed); ffl_c = cur.fetchone()[0]
    cur.close(); conn.close()
    return jsonify({"total":total,"cheater":cheater,"suspicious":susp,"clean":clean,"uff":uff_c,"ffl":ffl_c})

@app.route("/api/pins/generate", methods=["POST"])
@login_required
def api_gen_pin():
    user = get_user(); data = request.json or {}
    league = data.get("league","").upper()
    allowed = [l.strip() for l in user["leagues"].split(",")]
    if league not in allowed and user["role"] != "owner": return jsonify({"error":"Not authorized"}),403
    if not league: return jsonify({"error":"League required"}),400
    pin = gen_pin()
    expires = (datetime.datetime.utcnow()+datetime.timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db(); cur = conn.cursor()
    cur.execute("INSERT INTO pins (pin,league,agent_id,used,created,expires) VALUES (%s,%s,%s,0,%s,%s)",
                (pin,league,user["id"],now(),expires))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"pin":pin,"league":league,"expires":expires})

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
    cur.execute("UPDATE pins SET used=1 WHERE pin=%s",(pin,))
    cur.execute("""INSERT INTO scans (league,pc_user,verdict,total_hits,roblox_accs,report_json,pin_used,submitted)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s)""",
                (league or pin_row["league"], data.get("pc_user","unknown"), data.get("verdict","UNKNOWN"),
                 data.get("total_hits",0), json.dumps(data.get("roblox_accounts",[])),
                 json.dumps(data.get("report",{})), pin, now()))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok":True})

@app.route("/api/admin/users")
@login_required
@owner_required
def api_admin_users():
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT id,username,role,leagues,created FROM users ORDER BY created DESC")
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

@app.route("/api/pins")
@login_required
def api_pins():
    user = get_user(); conn = get_db(); cur = conn.cursor()
    if user["role"] == "owner":
        cur.execute("SELECT p.*,u.username as agent FROM pins p JOIN users u ON p.agent_id=u.id ORDER BY p.created DESC LIMIT 50")
    else:
        cur.execute("SELECT p.*,u.username as agent FROM pins p JOIN users u ON p.agent_id=u.id WHERE p.agent_id=%s ORDER BY p.created DESC LIMIT 50",
                    (user["id"],))
    rows = rows_to_dicts(cur.fetchall(), cur); cur.close(); conn.close()
    return jsonify(rows)

with app.app_context():
    init_db()

if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=int(os.environ.get("PORT",5000)))
