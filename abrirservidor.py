import os
import json
import sqlite3
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional, Tuple

from flask import Flask, request, jsonify


# =============== Constants & Paths ===============
# Use current directory for Railway (Linux) compatibility
BASE_DIR = os.getcwd()
DB_PATH = os.path.join(BASE_DIR, "steamvalidator.db")
TOKENS_PATH = os.path.join(BASE_DIR, "server_tokens.json")
SERVER_LOG_PATH = os.path.join(BASE_DIR, "server_logs.txt")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")


# =============== Utilities ===============
def ensure_base_dir() -> None:
    if not os.path.isdir(BASE_DIR):
        os.makedirs(BASE_DIR, exist_ok=True)


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def db_connect() -> sqlite3.Connection:
    try:
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        # Try to create directory if it doesn't exist
        os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
        conn = sqlite3.connect(DB_PATH, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn


def init_db(conn: sqlite3.Connection) -> None:
    cur = conn.cursor()
    # users(id, username, hwid, created_at, updated_at)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            hwid TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );
        """
    )

    # keys(id, key, user_id, created_at, expires_at)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            key TEXT UNIQUE NOT NULL,
            user_id INTEGER NOT NULL,
            created_at TEXT NOT NULL,
            expires_at TEXT,
            FOREIGN KEY(user_id) REFERENCES users(id)
        );
        """
    )

    # hwid_bans(id, hwid, reason, banned_at)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS hwid_bans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hwid TEXT UNIQUE NOT NULL,
            reason TEXT,
            banned_at TEXT NOT NULL
        );
        """
    )

    # logs(id, timestamp, endpoint, ip, status, details)
    cur.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            endpoint TEXT NOT NULL,
            ip TEXT NOT NULL,
            status INTEGER NOT NULL,
            details TEXT
        );
        """
    )
    conn.commit()


def read_or_create_tokens() -> Dict[str, str]:
    # server_api_key for /api/validate and admin_token for /api/admin/*
    default = {
        "server_api_key": os.urandom(16).hex(),
        "admin_token": os.urandom(16).hex(),
        "rate_limit_per_min": 60
    }
    if not os.path.isfile(TOKENS_PATH):
        with open(TOKENS_PATH, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)
        return default
    try:
        with open(TOKENS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        # Ensure keys exist
        changed = False
        for k in ("server_api_key", "admin_token", "rate_limit_per_min"):
            if k not in data:
                data[k] = default[k]
                changed = True
        if changed:
            with open(TOKENS_PATH, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        return data
    except Exception:
        with open(TOKENS_PATH, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)
        return default


def read_or_create_config() -> Dict[str, Any]:
    default_cfg = {
        "host": "0.0.0.0",  # Listen on all interfaces for remote access
        "port": 5000
    }
    if not os.path.isfile(CONFIG_PATH):
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(default_cfg, f, indent=2)
        return default_cfg
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        for k in ("host", "port"):
            if k not in cfg:
                cfg[k] = default_cfg[k]
        return cfg
    except Exception:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(default_cfg, f, indent=2)
        return default_cfg


def write_log_to_file(line: str) -> None:
    try:
        with open(SERVER_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass


def insert_log(conn: sqlite3.Connection, endpoint: str, ip: str, status: int, details: str) -> None:
    ts = utcnow_iso()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO logs(timestamp, endpoint, ip, status, details) VALUES(?,?,?,?,?)",
        (ts, endpoint, ip, status, details),
    )
    conn.commit()
    write_log_to_file(f"{ts} | {ip} | {endpoint} | {status} | {details}")


def get_client_ip() -> str:
    # Trust direct remote addr; can be extended for proxies
    return request.headers.get("X-Forwarded-For", request.remote_addr or "?")


# =============== Rate Limiter (simple per-IP) ===============
class RateLimiter:
    def __init__(self, limit_per_minute: int):
        self.limit_per_minute = limit_per_minute
        self.lock = threading.Lock()
        self.ip_to_hits: Dict[str, list] = {}

    def allow(self, ip: str) -> bool:
        now = time.time()
        one_min_ago = now - 60.0
        with self.lock:
            hits = self.ip_to_hits.get(ip, [])
            # Drop old hits
            hits = [t for t in hits if t >= one_min_ago]
            if len(hits) >= self.limit_per_minute:
                self.ip_to_hits[ip] = hits
                return False
            hits.append(now)
            self.ip_to_hits[ip] = hits
            return True


# =============== Application Setup ===============
ensure_base_dir()
conn = db_connect()
init_db(conn)
tokens = read_or_create_tokens()
config = read_or_create_config()
rate_limiter = RateLimiter(limit_per_minute=int(tokens.get("rate_limit_per_min", 60)))

app = Flask(__name__)


# =============== DB Helpers ===============
def get_user_by_username(username: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cur.fetchone()


def get_user_by_id(user_id: int) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cur.fetchone()


def create_or_get_user(username: str) -> sqlite3.Row:
    existing = get_user_by_username(username)
    if existing:
        return existing
    now = utcnow_iso()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users(username, hwid, created_at, updated_at) VALUES(?,?,?,?)",
            (username, None, now, now),
        )
        conn.commit()
        return get_user_by_username(username)
    except sqlite3.IntegrityError:
        # Username already exists (race condition)
        existing = get_user_by_username(username)
        if existing:
            return existing
        raise


def insert_key(user_id: int, key_value: str, expires_at: Optional[str]) -> None:
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO keys(key, user_id, created_at, expires_at) VALUES(?,?,?,?)",
        (key_value, user_id, utcnow_iso(), expires_at),
    )
    conn.commit()


def get_key_record(key_value: str) -> Optional[sqlite3.Row]:
    cur = conn.cursor()
    cur.execute("SELECT * FROM keys WHERE key = ?", (key_value,))
    return cur.fetchone()


def is_hwid_banned(hwid: str) -> Tuple[bool, Optional[str]]:
    if not hwid:
        return False, None
    cur = conn.cursor()
    cur.execute("SELECT reason FROM hwid_bans WHERE hwid = ?", (hwid,))
    row = cur.fetchone()
    if row:
        return True, row["reason"]
    return False, None


def bind_hwid_to_user(user_id: int, hwid: str) -> None:
    now = utcnow_iso()
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET hwid = ?, updated_at = ? WHERE id = ?",
        (hwid, now, user_id),
    )
    conn.commit()


def reset_user_hwid(username: str) -> bool:
    user = get_user_by_username(username)
    if not user:
        return False
    cur = conn.cursor()
    cur.execute(
        "UPDATE users SET hwid = NULL, updated_at = ? WHERE id = ?",
        (utcnow_iso(), user["id"]),
    )
    conn.commit()
    return True


def validate_username_key_hwid(username: str, token_value: str, hwid: str) -> Tuple[Dict[str, Any], int]:
    banned, ban_reason = is_hwid_banned(hwid)
    if banned:
        return {
            "valid": False,
            "reason": f"hwid_banned: {ban_reason}",
            "user": None,
            "expires_at": None,
            "bound_hwid": hwid,
        }, 403

    key_rec = get_key_record(token_value)
    if not key_rec:
        return {"valid": False, "reason": "invalid_token", "user": None, "expires_at": None, "bound_hwid": None}, 404

    user = get_user_by_id(int(key_rec["user_id"]))
    if not user:
        return {"valid": False, "reason": "user_not_found_for_key", "user": None, "expires_at": None, "bound_hwid": None}, 404

    if user["username"] != str(username):
        return {"valid": False, "reason": "username_key_mismatch", "user": user["username"], "expires_at": key_rec["expires_at"], "bound_hwid": user["hwid"]}, 403

    expires_at = key_rec["expires_at"]
    if expires_at:
        try:
            exp_dt = datetime.strptime(expires_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_dt:
                return {"valid": False, "reason": "token_expired", "user": user["username"], "expires_at": expires_at, "bound_hwid": user["hwid"]}, 403
        except Exception:
            return {"valid": False, "reason": "token_expiration_invalid", "user": user["username"], "expires_at": expires_at, "bound_hwid": user["hwid"]}, 500

    bound_hwid = user["hwid"]
    if bound_hwid is None:
        bind_hwid_to_user(int(user["id"]), hwid)
        bound_hwid = hwid
    else:
        if bound_hwid != hwid:
            return {"valid": False, "reason": "hwid_mismatch", "user": user["username"], "expires_at": expires_at, "bound_hwid": bound_hwid}, 403

    return {"valid": True, "reason": "ok", "user": user["username"], "expires_at": expires_at, "bound_hwid": bound_hwid}, 200


# =============== Auth Decorators (simple) ===============
def require_server_api_key() -> Optional[Tuple[Dict[str, Any], int]]:
    ip = get_client_ip()
    if not rate_limiter.allow(ip):
        return {"error": "rate_limited"}, 429
    api_key = request.headers.get("X-Api-Key")
    if not api_key or api_key != tokens.get("server_api_key"):
        return {"error": "unauthorized"}, 401
    return None


def require_admin() -> Optional[Tuple[Dict[str, Any], int]]:
    ip = get_client_ip()
    if not rate_limiter.allow(ip):
        return {"error": "rate_limited"}, 429
    admin = request.headers.get("X-Admin-Token")
    if not admin or admin != tokens.get("admin_token"):
        return {"error": "unauthorized"}, 401
    return None


# =============== Routes ===============
@app.route("/api/public/server_api_key", methods=["GET"])
def public_server_api_key():
    # No auth: used by clients to bootstrap client_api_key.txt
    endpoint = "/api/public/server_api_key"
    ip = get_client_ip()
    result = {"server_api_key": tokens.get("server_api_key"), "rate_limit_per_min": tokens.get("rate_limit_per_min", 60)}
    insert_log(conn, endpoint, ip, 200, json.dumps({"provided": True}))
    return jsonify(result), 200


@app.route("/api/public/admin_token", methods=["GET"])
def public_admin_token():
    # No auth: used by admin panel to get admin token
    endpoint = "/api/public/admin_token"
    ip = get_client_ip()
    result = {"admin_token": tokens.get("admin_token")}
    insert_log(conn, endpoint, ip, 200, json.dumps({"provided": True}))
    return jsonify(result), 200
@app.route("/api/register", methods=["POST"])
def api_register():
    auth_err = require_server_api_key()
    endpoint = "/api/register"
    ip = get_client_ip()
    if auth_err:
        insert_log(conn, endpoint, ip, auth_err[1], json.dumps(auth_err[0]))
        return jsonify(auth_err[0]), auth_err[1]

    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    license_key = data.get("license_key")
    hwid = data.get("hwid")
    if not username or not license_key or not hwid:
        msg = {"ok": False, "reason": "missing_username_or_license_key_or_hwid"}
        insert_log(conn, endpoint, ip, 400, json.dumps(msg))
        return jsonify(msg), 400

    # Validate combination and bind HWID if first time
    result, code = validate_username_key_hwid(username, license_key, hwid)
    if not result.get("valid"):
        msg = {"ok": False, "reason": result.get("reason")}
        insert_log(conn, endpoint, ip, code, json.dumps(msg))
        return jsonify(msg), code

    # If valid, consider it "registered"
    msg = {"ok": True, "user": username, "expires_at": result.get("expires_at"), "bound_hwid": result.get("bound_hwid")}
    insert_log(conn, endpoint, ip, 200, json.dumps(msg))
    return jsonify(msg), 200


@app.route("/api/login", methods=["POST"])
def api_login():
    auth_err = require_server_api_key()
    endpoint = "/api/login"
    ip = get_client_ip()
    if auth_err:
        insert_log(conn, endpoint, ip, auth_err[1], json.dumps(auth_err[0]))
        return jsonify(auth_err[0]), auth_err[1]

    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    license_key = data.get("license_key")
    hwid = data.get("hwid")
    if not username or not license_key or not hwid:
        msg = {"ok": False, "reason": "missing_username_or_license_key_or_hwid"}
        insert_log(conn, endpoint, ip, 400, json.dumps(msg))
        return jsonify(msg), 400

    result, code = validate_username_key_hwid(username, license_key, hwid)
    msg = {"ok": bool(result.get("valid")), "reason": result.get("reason"), "expires_at": result.get("expires_at"), "bound_hwid": result.get("bound_hwid")}
    insert_log(conn, endpoint, ip, code, json.dumps(msg))
    return jsonify(msg), code
@app.route("/api/validate", methods=["POST"])
def api_validate():
    auth_err = require_server_api_key()
    endpoint = "/api/validate"
    ip = get_client_ip()
    if auth_err:
        insert_log(conn, endpoint, ip, auth_err[1], json.dumps(auth_err[0]))
        return jsonify(auth_err[0]), auth_err[1]

    try:
        payload = request.get_json(force=True, silent=True) or {}
    except Exception:
        payload = {}

    token_value = payload.get("token")  # license key
    hwid = payload.get("hwid")
    username = payload.get("username")
    steam_token = payload.get("steam_token")  # optional for logging
    if not token_value or not hwid or not username:
        msg = {"valid": False, "reason": "missing_license_or_hwid_or_username"}
        insert_log(conn, endpoint, ip, 400, json.dumps(msg))
        return jsonify(msg), 400

    result, code = validate_username_key_hwid(username, token_value, hwid)
    # attach reference steam_token hash if provided
    result = dict(result)
    result["steam_token_hash"] = (hash(steam_token) if steam_token else None)
    insert_log(conn, endpoint, ip, code, json.dumps(result))
    return jsonify(result), code


@app.route("/api/admin/generate_key", methods=["POST"])
def admin_generate_key():
    auth_err = require_admin()
    endpoint = "/api/admin/generate_key"
    ip = get_client_ip()
    if auth_err:
        insert_log(conn, endpoint, ip, auth_err[1], json.dumps(auth_err[0]))
        return jsonify(auth_err[0]), auth_err[1]

    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    duration_days = data.get("duration_days")  # can be None or 0 or negative for lifetime
    key_value = data.get("key")  # optional custom key; otherwise generate

    if not username:
        msg = {"error": "missing_username"}
        insert_log(conn, endpoint, ip, 400, json.dumps(msg))
        return jsonify(msg), 400

    try:
        user = create_or_get_user(username)
    except sqlite3.IntegrityError:
        msg = {"error": "username_already_exists", "username": username}
        insert_log(conn, endpoint, ip, 409, json.dumps(msg))
        return jsonify(msg), 409

    if not key_value or not isinstance(key_value, str) or len(key_value) < 8:
        key_value = os.urandom(24).hex()

    expires_at: Optional[str] = None
    if duration_days is not None:
        try:
            days = int(duration_days)
            if days > 0:
                exp = datetime.now(timezone.utc) + timedelta(days=days)
                expires_at = exp.strftime("%Y-%m-%dT%H:%M:%SZ")
            else:
                expires_at = None  # lifetime
        except Exception:
            expires_at = None

    try:
        insert_key(int(user["id"]), key_value, expires_at)
    except sqlite3.IntegrityError:
        # Retry with a different random key if conflict
        key_value = os.urandom(24).hex()
        insert_key(int(user["id"]), key_value, expires_at)

    result = {
        "username": user["username"],
        "key": key_value,
        "expires_at": expires_at,
    }
    insert_log(conn, endpoint, ip, 200, json.dumps(result))
    return jsonify(result), 200


@app.route("/api/admin/reset_hwid", methods=["POST"])
def admin_reset_hwid():
    auth_err = require_admin()
    endpoint = "/api/admin/reset_hwid"
    ip = get_client_ip()
    if auth_err:
        insert_log(conn, endpoint, ip, auth_err[1], json.dumps(auth_err[0]))
        return jsonify(auth_err[0]), auth_err[1]

    data = request.get_json(force=True, silent=True) or {}
    username = data.get("username")
    if not username:
        msg = {"error": "missing_username"}
        insert_log(conn, endpoint, ip, 400, json.dumps(msg))
        return jsonify(msg), 400

    ok = reset_user_hwid(username)
    status = 200 if ok else 404
    result = {"ok": ok, "username": username}
    insert_log(conn, endpoint, ip, status, json.dumps(result))
    return jsonify(result), status


@app.route("/api/admin/ban_hwid", methods=["POST"])
def admin_ban_hwid():
    auth_err = require_admin()
    endpoint = "/api/admin/ban_hwid"
    ip = get_client_ip()
    if auth_err:
        insert_log(conn, endpoint, ip, auth_err[1], json.dumps(auth_err[0]))
        return jsonify(auth_err[0]), auth_err[1]

    data = request.get_json(force=True, silent=True) or {}
    hwid = data.get("hwid")
    reason = data.get("reason", "")
    if not hwid:
        msg = {"error": "missing_hwid"}
        insert_log(conn, endpoint, ip, 400, json.dumps(msg))
        return jsonify(msg), 400

    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO hwid_bans(hwid, reason, banned_at) VALUES(?,?,?)",
            (hwid, reason, utcnow_iso()),
        )
        conn.commit()
        result = {"ok": True, "hwid": hwid}
        insert_log(conn, endpoint, ip, 200, json.dumps(result))
        return jsonify(result), 200
    except sqlite3.IntegrityError:
        result = {"ok": False, "error": "already_banned", "hwid": hwid}
        insert_log(conn, endpoint, ip, 409, json.dumps(result))
        return jsonify(result), 409


@app.route("/api/admin/logs", methods=["GET"])
def admin_get_logs():
    auth_err = require_admin()
    endpoint = "/api/admin/logs"
    ip = get_client_ip()
    if auth_err:
        insert_log(conn, endpoint, ip, auth_err[1], json.dumps(auth_err[0]))
        return jsonify(auth_err[0]), auth_err[1]

    limit = request.args.get("limit", default="200")
    try:
        n = max(1, min(1000, int(limit)))
    except Exception:
        n = 200
    cur = conn.cursor()
    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT ?", (n,))
    rows = [dict(r) for r in cur.fetchall()]
    insert_log(conn, endpoint, ip, 200, json.dumps({"count": len(rows)}))
    return jsonify({"logs": rows}), 200


@app.route("/api/admin/export_data", methods=["GET"])
def admin_export_data():
    auth_err = require_admin()
    endpoint = "/api/admin/export_data"
    ip = get_client_ip()
    if auth_err:
        insert_log(conn, endpoint, ip, auth_err[1], json.dumps(auth_err[0]))
        return jsonify(auth_err[0]), auth_err[1]

    cur = conn.cursor()
    
    # Export all tables
    data = {}
    
    # Users
    cur.execute("SELECT * FROM users")
    data["users"] = [dict(r) for r in cur.fetchall()]
    
    # Keys
    cur.execute("SELECT * FROM keys")
    data["keys"] = [dict(r) for r in cur.fetchall()]
    
    # HWID Bans
    cur.execute("SELECT * FROM hwid_bans")
    data["hwid_bans"] = [dict(r) for r in cur.fetchall()]
    
    # Logs (last 1000)
    cur.execute("SELECT * FROM logs ORDER BY id DESC LIMIT 1000")
    data["logs"] = [dict(r) for r in cur.fetchall()]
    
    insert_log(conn, endpoint, ip, 200, json.dumps({"exported": True, "counts": {k: len(v) for k, v in data.items()}}))
    return jsonify(data), 200


def main() -> None:
    # Run Flask server
    host = str(config.get("host", "0.0.0.0"))
    port = int(os.environ.get("PORT", config.get("port", 5000)))
    print(f"SteamValidator server starting on {host}:{port}")
    print(f"Current directory: {os.getcwd()}")
    print(f"DB: {DB_PATH}")
    print(f"Tokens: {TOKENS_PATH}")
    print(f"Logs: {SERVER_LOG_PATH}")
    print(f"Base dir exists: {os.path.exists(BASE_DIR)}")
    print(f"Base dir: {BASE_DIR}")
    app.run(host=host, port=port)


if __name__ == "__main__":
    main()


