"""
=================================================================
  Zevora — app.py SUBSCRIPTION + DYNAMIC LEAGUES PATCH
=================================================================
HOW TO APPLY:
  1. Add the DB migration block to your existing init_db() function
  2. Add the helper functions (get_user_leagues_full, sub_is_active)
  3. Add all the routes below to your app.py
  4. Add the /team route and render the team.html template
  5. Update existing PIN generate routes to use dynamic leagues

All existing routes (scan submit, validate pin, webhook, etc.) stay
the same — this is additive only.
=================================================================
"""

# ─────────────────────────────────────────────────────────────
# STEP 1: Add to your init_db() — inside the migrations list
# ─────────────────────────────────────────────────────────────
SUBSCRIPTION_MIGRATIONS = [
    # Dynamic leagues table — add any league here from admin panel
    """CREATE TABLE IF NOT EXISTS leagues (
        id   SERIAL PRIMARY KEY,
        name TEXT UNIQUE NOT NULL,
        slug TEXT UNIQUE NOT NULL,
        created TEXT NOT NULL
    )""",
    # Subscription fields on users
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_type TEXT DEFAULT NULL",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_league_slug TEXT DEFAULT NULL",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS sub_expires TEXT DEFAULT NULL",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS granted_by TEXT DEFAULT NULL",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS invite_count INTEGER DEFAULT 0",
    "ALTER TABLE users ADD COLUMN IF NOT EXISTS discord_id_external TEXT DEFAULT NULL",
    # Update leagues column to be a comma-separated list of slugs
    # (already exists on users — just ensure it can hold multiple)
]

# Seed default leagues if not already there — run this inside init_db() after migrations
SEED_LEAGUES = [
    ("UFF",  "uff"),
    ("KFA",  "kfa"),
]


# ─────────────────────────────────────────────────────────────
# STEP 2: Helper functions — add to your app.py
# ─────────────────────────────────────────────────────────────
import datetime as _dt

def sub_is_active(user):
    """Returns True if user's subscription is currently valid."""
    if user.get("role") in ("owner", "admin"):
        return True  # admins/owners always have access
    exp = user.get("sub_expires")
    if not exp:
        return False
    try:
        exp_dt = _dt.datetime.strptime(str(exp)[:19], "%Y-%m-%d %H:%M:%S")
        return _dt.datetime.utcnow() <= exp_dt
    except Exception:
        try:
            exp_dt = _dt.datetime.strptime(str(exp)[:10], "%Y-%m-%d")
            return _dt.datetime.utcnow().date() <= exp_dt.date()
        except Exception:
            return False

def get_all_leagues(conn=None):
    """Return all leagues from the leagues table."""
    close = False
    if conn is None:
        conn = get_db(); close = True
    cur = conn.cursor()
    cur.execute("SELECT id, name, slug, created FROM leagues ORDER BY name")
    rows = rows_to_dicts(cur.fetchall(), cur)
    cur.close()
    if close: conn.close()
    return rows

def get_user_leagues_full(user, conn=None):
    """
    Return the full league objects for the leagues this user can access.
    Owners/admins get all leagues. Others get only their assigned leagues.
    """
    all_leagues = get_all_leagues(conn)
    if user.get("role") in ("owner", "admin"):
        return all_leagues
    slugs = [s.strip().lower() for s in (user.get("leagues") or "").split(",") if s.strip()]
    return [lg for lg in all_leagues if lg["slug"].lower() in slugs]

def can_access_league_slug(user, slug):
    """Check if user can access a league by slug."""
    if user.get("role") in ("owner", "admin"):
        return True
    slugs = [s.strip().lower() for s in (user.get("leagues") or "").split(",") if s.strip()]
    return slug.lower() in slugs


# ─────────────────────────────────────────────────────────────
# STEP 3: New routes — add to your app.py
# ─────────────────────────────────────────────────────────────

# ── Team page ─────────────────────────────────────────────────
@app.route("/team")
@login_required
def team_page():
    user = get_user()
    conn = get_db(); cur = conn.cursor()

    user_leagues_full = get_user_leagues_full(user, conn)

    # Build per-league member lists
    for league in user_leagues_full:
        slug = league["slug"]
        # Members = users whose leagues field contains this slug
        cur.execute("""
            SELECT u.id, u.username, u.role, u.sub_type, u.sub_expires, u.created,
                   COUNT(s.id) as scan_count
            FROM users u
            LEFT JOIN scans s ON s.league = %s
            WHERE u.leagues ILIKE %s
               OR u.sub_league_slug = %s
               OR u.role IN ('owner','admin')
            GROUP BY u.id, u.username, u.role, u.sub_type, u.sub_expires, u.created
            ORDER BY u.username
        """, (league["name"], f"%{slug}%", slug))
        members = rows_to_dicts(cur.fetchall(), cur)
        for m in members:
            m["sub_active"] = sub_is_active(m)
        league["members"] = members
        league["member_count"] = len(members)

        # Total scans for this league
        cur.execute("SELECT COUNT(*) FROM scans WHERE league=%s", (league["name"],))
        league["scan_count"] = (cur.fetchone() or [0])[0]

    # All members for owner/admin "All" tab
    all_members = []
    if user["role"] in ("owner", "admin"):
        cur.execute("""
            SELECT id, username, role, sub_type, sub_expires, leagues, created
            FROM users ORDER BY username
        """)
        all_members = rows_to_dicts(cur.fetchall(), cur)
        for m in all_members:
            m["sub_active"] = sub_is_active(m)

    cur.execute("SELECT COUNT(*) FROM scans")
    all_scans_count = (cur.fetchone() or [0])[0]

    cur.close(); conn.close()
    return render_template("team.html",
                           user=user,
                           user_leagues=user_leagues_full,
                           all_members=all_members,
                           all_scans_count=all_scans_count)


# ── Dynamic leagues API ───────────────────────────────────────
@app.route("/api/admin/leagues", methods=["GET"])
@login_required
@owner_required
def api_list_leagues():
    leagues = get_all_leagues()
    return jsonify(leagues)


@app.route("/api/admin/leagues", methods=["POST"])
@login_required
@owner_required
def api_create_league():
    """Create a new league. Body: { name: "ACFL" }"""
    data = request.json or {}
    name = data.get("name", "").strip().upper()
    if not name:
        return jsonify({"error": "League name required"}), 400
    # Auto-generate slug from name
    slug = re.sub(r"[^a-z0-9]", "", name.lower())
    if not slug:
        return jsonify({"error": "Invalid league name"}), 400
    conn = get_db(); cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO leagues (name, slug, created) VALUES (%s, %s, %s) RETURNING id",
            (name, slug, now()))
        new_id = cur.fetchone()[0]
        conn.commit()
        cur.close(); conn.close()
        return jsonify({"ok": True, "id": new_id, "name": name, "slug": slug})
    except Exception as e:
        conn.rollback(); cur.close(); conn.close()
        return jsonify({"error": f"League already exists or DB error: {e}"}), 409


@app.route("/api/admin/leagues/<int:league_id>", methods=["DELETE"])
@login_required
@owner_required
def api_delete_league(league_id):
    conn = get_db(); cur = conn.cursor()
    cur.execute("DELETE FROM leagues WHERE id=%s", (league_id,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


# ── Subscription management ───────────────────────────────────
@app.route("/api/admin/grant", methods=["POST"])
@login_required
@owner_required
def api_grant_access():
    """
    Grant or update access for a user by Discord ID or username.
    Body: {
      discord_id: "123456789",   -- Discord user ID (optional)
      username: "playerName",    -- display name / username
      role: "agent",             -- agent | admin
      sub_type: "enterprise",    -- enterprise | user | null
      league_slug: "uff",        -- which league (enterprise only)
      months: 1                  -- how many months of sub to grant
    }
    """
    data = request.json or {}
    discord_id = data.get("discord_id", "").strip() or None
    username   = data.get("username",   "").strip()
    role       = data.get("role",       "agent")
    sub_type   = data.get("sub_type",   None)
    league_slug = data.get("league_slug", "").strip().lower() or None
    months     = int(data.get("months", 1))

    if not username:
        return jsonify({"error": "Username required"}), 400

    # Calculate expiry
    expires = (_dt.datetime.utcnow() + _dt.timedelta(days=30*months)).strftime("%Y-%m-%d %H:%M:%S")

    # Resolve league name from slug
    leagues_str = ""
    if league_slug:
        conn_tmp = get_db(); cur_tmp = conn_tmp.cursor()
        cur_tmp.execute("SELECT name FROM leagues WHERE slug=%s", (league_slug,))
        row = cur_tmp.fetchone()
        cur_tmp.close(); conn_tmp.close()
        if row:
            leagues_str = row[0]

    conn = get_db(); cur = conn.cursor()

    # Check if user already exists by Discord ID or username
    existing = None
    if discord_id:
        cur.execute("SELECT * FROM users WHERE discord_id=%s OR discord_id_external=%s", (discord_id, discord_id))
        existing = row_to_dict(cur.fetchone(), cur) if cur.description else None
    if not existing:
        cur.execute("SELECT * FROM users WHERE username=%s", (username,))
        existing = row_to_dict(cur.fetchone(), cur) if cur.description else None

    if existing:
        # Update existing user's subscription
        cur.execute("""
            UPDATE users SET
                role=%s, sub_type=%s, sub_league_slug=%s, sub_expires=%s,
                granted_by=%s, leagues=%s
            WHERE id=%s
        """, (role, sub_type, league_slug, expires,
              get_user()["username"], leagues_str or existing.get("leagues",""),
              existing["id"]))
        conn.commit(); cur.close(); conn.close()
        return jsonify({"ok": True, "action": "updated", "id": existing["id"],
                        "username": existing["username"], "expires": expires})
    else:
        # Create new user — generate a temp password they'll need to reset
        import secrets as _sec
        tmp_pw = _sec.token_hex(8)
        import hashlib as _hl
        pw_hash = _hl.sha256(tmp_pw.encode()).hexdigest()
        cur.execute("""
            INSERT INTO users
              (discord_id_external, username, password_hash, role, leagues,
               sub_type, sub_league_slug, sub_expires, granted_by, created)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id
        """, (discord_id, username, pw_hash, role, leagues_str,
              sub_type, league_slug, expires, get_user()["username"], now()))
        new_id = cur.fetchone()[0]
        conn.commit(); cur.close(); conn.close()
        return jsonify({"ok": True, "action": "created", "id": new_id,
                        "username": username, "expires": expires,
                        "temp_password": tmp_pw,
                        "note": "Share this temp password with the user — they should reset it."})


@app.route("/api/admin/users/<int:uid>/subscription", methods=["PATCH"])
@login_required
@owner_required
def api_update_subscription(uid):
    """
    Update a user's subscription.
    Body: {
      sub_type: "enterprise" | "user" | null,
      league_slug: "uff",
      months: 1,        -- add this many months
      set_expires: "2026-06-01"  -- OR set exact date
    }
    """
    data = request.json or {}
    conn = get_db(); cur = conn.cursor()

    cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
    user = row_to_dict(cur.fetchone(), cur)
    if not user:
        cur.close(); conn.close()
        return jsonify({"error": "User not found"}), 404

    updates = {}

    if "sub_type" in data:
        updates["sub_type"] = data["sub_type"]

    if "league_slug" in data:
        slug = (data["league_slug"] or "").strip().lower()
        updates["sub_league_slug"] = slug or None
        if slug:
            cur.execute("SELECT name FROM leagues WHERE slug=%s", (slug,))
            row = cur.fetchone()
            if row:
                updates["leagues"] = row[0]

    # Calculate new expiry
    if "set_expires" in data and data["set_expires"]:
        try:
            updates["sub_expires"] = data["set_expires"][:10] + " 23:59:59"
        except Exception:
            pass
    elif "months" in data and int(data.get("months", 0)) > 0:
        months = int(data["months"])
        # Extend from current expiry if still active, else from now
        current_exp = user.get("sub_expires")
        base_dt = _dt.datetime.utcnow()
        if current_exp:
            try:
                parsed = _dt.datetime.strptime(str(current_exp)[:19], "%Y-%m-%d %H:%M:%S")
                if parsed > _dt.datetime.utcnow():
                    base_dt = parsed
            except Exception:
                pass
        updates["sub_expires"] = (base_dt + _dt.timedelta(days=30*months)).strftime("%Y-%m-%d %H:%M:%S")

    if not updates:
        cur.close(); conn.close()
        return jsonify({"error": "Nothing to update"}), 400

    set_clause = ", ".join(f"{k}=%s" for k in updates)
    values = list(updates.values()) + [uid]
    cur.execute(f"UPDATE users SET {set_clause} WHERE id=%s", values)
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True, "updated": updates})


@app.route("/api/admin/users/<int:uid>/revoke", methods=["POST"])
@login_required
@owner_required
def api_revoke_access(uid):
    """Immediately expire a user's subscription."""
    conn = get_db(); cur = conn.cursor()
    cur.execute("""
        UPDATE users SET sub_type=NULL, sub_expires=NULL, sub_league_slug=NULL
        WHERE id=%s
    """, (uid,))
    conn.commit(); cur.close(); conn.close()
    return jsonify({"ok": True})


# ── Admin page (renders admin tab within dashboard or standalone) ──
@app.route("/admin")
@login_required
@owner_required
def admin_page():
    user = get_user()
    conn = get_db(); cur = conn.cursor()

    # All users with subscription info
    cur.execute("""
        SELECT u.id, u.username, u.role, u.leagues, u.sub_type,
               u.sub_league_slug, u.sub_expires, u.granted_by,
               u.invite_count, u.created, u.discord_id_external,
               COUNT(s.id) as scan_count
        FROM users u
        LEFT JOIN scans s ON TRUE
        GROUP BY u.id
        ORDER BY
          CASE u.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END,
          u.username
    """)
    all_users = rows_to_dicts(cur.fetchall(), cur)
    for u in all_users:
        u["sub_active"] = sub_is_active(u)

    # Expired subscriptions
    now_str_val = _dt.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    expired = [u for u in all_users if u.get("sub_expires") and u["sub_expires"] < now_str_val]

    # All leagues
    leagues = get_all_leagues(conn)

    # All results (scans)
    cur.execute("SELECT s.*, u.username as agent FROM scans s LEFT JOIN pins p ON p.pin=s.pin_used LEFT JOIN users u ON u.id=p.agent_id ORDER BY s.submitted DESC LIMIT 100")
    all_results = rows_to_dicts(cur.fetchall(), cur)

    cur.close(); conn.close()
    return render_template("admin.html",
                           user=user,
                           all_users=all_users,
                           expired_users=expired,
                           leagues=leagues,
                           all_results=all_results)


# ── Updated /api/validate_pin — checks league by slug or name ──
# Replace your existing validate_pin route with this version:
@app.route("/api/validate_pin_v2", methods=["POST"])
@app.route("/api/validate_pin", methods=["POST"])
def api_validate_pin_v2():
    """Validate a PIN. Returns league name AND slug."""
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
        exp = str(row["expires"])[:19]
        exp_dt = _dt.datetime.strptime(exp, "%Y-%m-%d %H:%M:%S")
        if _dt.datetime.utcnow() > exp_dt:
            return jsonify({"valid": False, "error": "PIN has expired"}), 401
    except Exception:
        pass
    return jsonify({
        "ok": True, "valid": True,
        "league": row["league"],
        "league_slug": re.sub(r"[^a-z0-9]", "", row["league"].lower()),
    })


# ── Updated PIN generation — uses dynamic league from DB ──────
@app.route("/api/generate_pin", methods=["POST"])
@app.route("/api/pins/generate", methods=["POST"])
@login_required
def api_gen_pin_v2():
    """
    Generate a PIN. League can now be any slug or name stored in the leagues table.
    Body: { league: "UFF" | "KFA" | any-league-name }
    """
    user = get_user()
    data = request.json or {}
    league_input = data.get("league","").strip().upper()

    # Resolve league from DB
    conn = get_db(); cur = conn.cursor()
    cur.execute("SELECT * FROM leagues WHERE slug=%s OR name=%s",
                (league_input.lower(), league_input))
    league_row = row_to_dict(cur.fetchone(), cur)

    if not league_row and league_input:
        # Fallback: treat the input itself as the league name (backward compat)
        league_name = league_input
    elif league_row:
        league_name = league_row["name"]
    else:
        cur.close(); conn.close()
        return jsonify({"error": "League required"}), 400

    # Access check
    if user["role"] not in ("owner", "admin"):
        user_slugs = [s.strip().lower() for s in (user.get("leagues") or "").split(",") if s.strip()]
        league_slug = re.sub(r"[^a-z0-9]", "", league_name.lower())
        if league_slug not in user_slugs:
            cur.close(); conn.close()
            return jsonify({"error": "Not authorized for this league"}), 403

    import secrets as _sec, string as _str
    pin = "".join(_sec.choice(_str.ascii_uppercase + _str.digits) for _ in range(8))
    expires = (_dt.datetime.utcnow() + _dt.timedelta(hours=4)).strftime("%Y-%m-%d %H:%M:%S")

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


# ─────────────────────────────────────────────────────────────
# STEP 4: Seed leagues in init_db()
#
# Inside your existing init_db(), after the migrations block,
# add this to seed the default leagues if they don't exist yet:
#
#   for (lname, lslug) in [("UFF","uff"),("KFA","kfa")]:
#       try:
#           cur.execute("SAVEPOINT sp_league")
#           cur.execute(
#               "INSERT INTO leagues (name,slug,created) VALUES (%s,%s,%s) ON CONFLICT DO NOTHING",
#               (lname, lslug, now()))
#           cur.execute("RELEASE SAVEPOINT sp_league")
#       except Exception:
#           cur.execute("ROLLBACK TO SAVEPOINT sp_league")
# ─────────────────────────────────────────────────────────────
