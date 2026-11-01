from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from datetime import datetime, timezone, timedelta
from contextlib import contextmanager
from http.cookies import SimpleCookie, CookieError
from urllib.parse import urlparse, parse_qs, quote, urlencode
import argparse, base64, getpass, hashlib, hmac, json, math, os, re, secrets, sqlite3, urllib.error, urllib.request

ROOT = Path(__file__).resolve().parent
MAX_BODY = 16_384
MAX_DRIVER_UPLOAD_BYTES = 5 * 1024 * 1024
MAX_DRIVER_APPLICATION_BODY = 14 * 1024 * 1024
SESSION_DAYS = 14
PBKDF2_ROUNDS = 310_000
COOKIE_NAME = "quickride_session"
VEHICLES = {
    "bike": {"label": "Bike", "icon": "🏍️", "base_fare": 20, "per_km": 8, "per_minute": 0.35, "minimum_fare": 30, "campus_cap": 180, "availability_weight": 1.0},
    "scooty": {"label": "Scooty", "icon": "🛵", "base_fare": 18, "per_km": 7, "per_minute": 0.3, "minimum_fare": 28, "campus_cap": 160, "availability_weight": 0.9},
    "auto": {"label": "Auto", "icon": "🛺", "base_fare": 30, "per_km": 12, "per_minute": 0.5, "minimum_fare": 45, "campus_cap": 300, "availability_weight": 0.7},
    "car": {"label": "Car", "icon": "🚗", "base_fare": 60, "per_km": 18, "per_minute": 0.75, "minimum_fare": 80, "campus_cap": 600, "availability_weight": 0.5},
}
PRICING = {"demand_multiplier_min": 1.0, "demand_multiplier_max": 1.3,
           "moderate_demand_ratio": 1.0, "high_demand_ratio": 2.0,
           "moderate_multiplier": 1.1, "high_multiplier": 1.3}
RIDE_PIN_PEPPER = os.environ.get("CAMPUSLIFT_PIN_SECRET", "local-prototype-pin-key").encode("utf-8")
STATUSES = ("unverified", "pending", "verified", "rejected", "suspended")


def now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def campus_day_start_utc():
    offset = os.environ.get("CAMPUS_UTC_OFFSET_MINUTES", "").strip()
    try:
        minutes = int(offset) if offset else None
        zone = timezone(timedelta(minutes=minutes)) if minutes is not None and -840 <= minutes <= 840 else None
    except ValueError:
        zone = None
    local = (datetime.now(zone) if zone else datetime.now().astimezone()).replace(hour=0, minute=0, second=0, microsecond=0)
    return local.astimezone(timezone.utc).isoformat(timespec="seconds")


def password_hash(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return f"pbkdf2_sha256${PBKDF2_ROUNDS}${base64.urlsafe_b64encode(salt).decode()}${base64.urlsafe_b64encode(digest).decode()}"


def password_matches(password, stored):
    try:
        scheme, rounds, salt, expected = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), base64.urlsafe_b64decode(salt), int(rounds))
        return hmac.compare_digest(actual, base64.urlsafe_b64decode(expected))
    except (ValueError, TypeError):
        return False


def decode_driver_upload(upload, label, allowed_types):
    if not isinstance(upload, dict):
        raise ValueError(f"Upload your {label}.")
    mime_type = str(upload.get("mime_type", "")).lower()
    encoded = upload.get("data")
    if mime_type not in allowed_types or not isinstance(encoded, str) or len(encoded) > MAX_DRIVER_UPLOAD_BYTES * 4 // 3 + 8:
        raise ValueError(f"Choose a supported {label} file no larger than 5 MB.")
    try:
        content = base64.b64decode(encoded, validate=True)
    except (ValueError, base64.binascii.Error):
        raise ValueError(f"The {label} upload could not be read. Choose the file again.")
    if not content or len(content) > MAX_DRIVER_UPLOAD_BYTES:
        raise ValueError(f"Choose a {label} file no larger than 5 MB.")
    signatures = {
        "application/pdf": content.startswith(b"%PDF-"),
        "image/jpeg": content.startswith(b"\xff\xd8\xff"),
        "image/png": content.startswith(b"\x89PNG\r\n\x1a\n"),
        "image/webp": len(content) >= 12 and content[:4] == b"RIFF" and content[8:12] == b"WEBP",
    }
    if not signatures.get(mime_type, False):
        raise ValueError(f"The {label} file does not match its selected file type.")
    return content, mime_type


def create_schema(con):
    con.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL, role TEXT NOT NULL CHECK(role IN ('rider','driver')),
        vehicle_type TEXT, vehicle_number TEXT, is_online INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS sessions (
        token_hash TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS rides (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rider_id INTEGER REFERENCES users(id), driver_id INTEGER REFERENCES users(id),
        pickup TEXT NOT NULL, destination TEXT NOT NULL,
        vehicle_type TEXT NOT NULL DEFAULT 'bike', distance_km REAL, estimated_minutes INTEGER,
        estimated_fare REAL, status TEXT NOT NULL CHECK(status IN ('searching','driver_assigned','in_progress','completed','declined','cancelled')),
        created_at TEXT NOT NULL, updated_at TEXT NOT NULL)""")
    con.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
    con.execute("""CREATE TABLE IF NOT EXISTS admins (
        id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, email TEXT NOT NULL UNIQUE,
        password_hash TEXT NOT NULL, created_at TEXT NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS admin_sessions (
        token_hash TEXT PRIMARY KEY, admin_id INTEGER NOT NULL REFERENCES admins(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL, expires_at TEXT NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS ratings (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ride_id INTEGER NOT NULL REFERENCES rides(id) ON DELETE CASCADE,
        rater_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        rated_user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        score INTEGER NOT NULL CHECK(score BETWEEN 1 AND 5), note TEXT,
        created_at TEXT NOT NULL, UNIQUE(ride_id,rater_id))""")
    con.execute("""CREATE TABLE IF NOT EXISTS incident_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT, ride_id INTEGER NOT NULL REFERENCES rides(id) ON DELETE CASCADE,
        reporter_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        category TEXT NOT NULL, description TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'open',
        created_at TEXT NOT NULL)""")
    con.execute("""CREATE TABLE IF NOT EXISTS ride_declines (
        ride_id INTEGER NOT NULL REFERENCES rides(id) ON DELETE CASCADE,
        driver_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TEXT NOT NULL, PRIMARY KEY(ride_id, driver_id))""")
    con.execute("CREATE INDEX IF NOT EXISTS idx_rides_status_created ON rides(status, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_rides_rider_created ON rides(rider_id, created_at)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_rides_driver_status ON rides(driver_id, status)")
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS uq_driver_one_active_ride ON rides(driver_id) WHERE driver_id IS NOT NULL AND status IN ('driver_assigned','in_progress')")
    user_columns = {row[1] for row in con.execute("PRAGMA table_info(users)")}
    user_migrations = (("college_status", "TEXT NOT NULL DEFAULT 'unverified'"),
        ("driver_verification_status", "TEXT NOT NULL DEFAULT 'unverified'"),
        ("licence_status", "TEXT NOT NULL DEFAULT 'pending'"),
        ("vehicle_document_status", "TEXT NOT NULL DEFAULT 'pending'"),
        ("insurance_status", "TEXT NOT NULL DEFAULT 'pending'"),
        ("profile_photo_url", "TEXT"), ("vehicle_photo_url", "TEXT"),
        ("college_id_status", "TEXT NOT NULL DEFAULT 'pending'"),
        ("driver_license_data", "BLOB"), ("driver_license_mime", "TEXT"),
        ("driver_selfie_data", "BLOB"), ("driver_selfie_mime", "TEXT"))
    for name, sql_type in user_migrations:
        if name not in user_columns:
            con.execute(f"ALTER TABLE users ADD COLUMN {name} {sql_type}")
    con.execute("UPDATE users SET driver_verification_status='pending',is_online=0 WHERE role='driver' AND driver_verification_status='unverified'")
    ride_columns = {row[1] for row in con.execute("PRAGMA table_info(rides)")}
    for name, sql_type in (("driver_latitude", "REAL"), ("driver_longitude", "REAL"),
                           ("driver_accuracy", "REAL"), ("driver_location_updated_at", "TEXT"),
                           ("ride_pin", "TEXT"), ("pricing_multiplier", "REAL")):
        if name not in ride_columns:
            con.execute(f"ALTER TABLE rides ADD COLUMN {name} {sql_type}")
    con.execute("CREATE INDEX IF NOT EXISTS idx_ratings_rated_user ON ratings(rated_user_id)")
    con.execute("CREATE INDEX IF NOT EXISTS idx_incident_reports_status ON incident_reports(status,created_at)")
    con.commit()


def initialize_db(db_path):
    db_path = Path(db_path).resolve()
    db_path.parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(db_path, timeout=20)
    try:
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        marker = con.execute("SELECT 1 FROM settings WHERE key='campuslift_iteration1' LIMIT 1").fetchone() if "settings" in tables else None
        if "users" in tables and not marker:
            backup = db_path.with_name(f"{db_path.stem}-pre-campuslift-iteration1.sqlite3")
            if not backup.exists():
                with sqlite3.connect(backup) as backup_con:
                    con.backup(backup_con)
        con.execute("PRAGMA journal_mode=WAL")
        tables = {row[0] for row in con.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        if "rides" in tables:
            columns = {row[1] for row in con.execute("PRAGMA table_info(rides)")}
            if "rider_id" not in columns:
                backup = db_path.with_name("quickride-pre-auth-backup.sqlite3")
                if not backup.exists():
                    with sqlite3.connect(backup) as backup_con:
                        con.backup(backup_con)
                con.execute("ALTER TABLE rides RENAME TO rides_legacy")
                create_schema(con)
                con.execute("""INSERT INTO rides(id,pickup,destination,vehicle_type,status,created_at,updated_at)
                    SELECT id,pickup,destination,'bike',
                    CASE status WHEN 'requested' THEN 'searching' WHEN 'accepted' THEN 'driver_assigned'
                    ELSE status END,created_at,updated_at FROM rides_legacy""")
                con.execute("DROP TABLE rides_legacy")
                con.commit()
        create_schema(con)
        con.execute("INSERT OR REPLACE INTO settings(key,value) VALUES('campuslift_iteration1',?)", (now(),))
        con.commit()
    finally:
        con.close()


def public_user(row):
    if not row:
        return None
    return {"id": row["id"], "name": row["name"], "email": row["email"], "role": row["role"],
            "vehicle_type": row["vehicle_type"], "vehicle_number": row["vehicle_number"],
            "is_online": bool(row["is_online"]), "created_at": row["created_at"],
            "college_status": row["college_status"],
            "driver_verification_status": row["driver_verification_status"],
            "rating": None}


def driver_is_eligible(row):
    """Only admin-verified drivers with complete onboarding can operate."""
    return bool(row and row["role"] == "driver"
                and row["driver_verification_status"] == "verified"
                and row["vehicle_type"] in VEHICLES
                and row["has_driver_license"] and row["has_driver_selfie"])


class QuickRideHandler(SimpleHTTPRequestHandler):
    def __init__(self, *args, directory=None, db_path=None, **kwargs):
        self.db_path = Path(db_path or ROOT / "quickride.db")
        super().__init__(*args, directory=str(ROOT), **kwargs)

    @contextmanager
    def db_session(self):
        con = sqlite3.connect(self.db_path, timeout=20)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        try:
            yield con
            con.commit()
        except Exception:
            con.rollback()
            raise
        finally:
            con.close()

    def send_json(self, status, data, cookie=None):
        raw = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(raw)

    def read_json(self, max_bytes=MAX_BODY):
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            raise ValueError("Invalid request size")
        if length <= 0 or length > max_bytes:
            raise ValueError("Request body is empty or larger than the allowed size.")
        try:
            data = json.loads(self.rfile.read(length))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Send a valid JSON request")
        if not isinstance(data, dict):
            raise ValueError("Send a JSON object")
        return data

    def request_user(self, con):
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie[COOKIE_NAME].value
        except (KeyError, CookieError):
            return None
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        row = con.execute("""SELECT u.id,u.name,u.email,u.password_hash,u.role,u.vehicle_type,u.vehicle_number,u.is_online,u.created_at,
            u.college_status,u.driver_verification_status,u.licence_status,u.vehicle_document_status,u.insurance_status,
            u.profile_photo_url,u.vehicle_photo_url,u.college_id_status,u.driver_license_mime,u.driver_selfie_mime,
            u.driver_license_data IS NOT NULL AS has_driver_license,
            u.driver_selfie_data IS NOT NULL AS has_driver_selfie
            FROM sessions s JOIN users u ON u.id=s.user_id
            WHERE s.token_hash=? AND s.expires_at>?""", (token_hash, now())).fetchone()
        return row

    def request_admin(self, con):
        try:
            cookie = SimpleCookie(self.headers.get("Cookie", ""))
            token = cookie["campuslift_admin_session"].value
        except (KeyError, CookieError):
            return None
        return con.execute("""SELECT a.* FROM admin_sessions s JOIN admins a ON a.id=s.admin_id
            WHERE s.token_hash=? AND s.expires_at>?""",
            (hashlib.sha256(token.encode()).hexdigest(), now())).fetchone()

    def require_admin(self, con):
        admin = self.request_admin(con)
        if not admin:
            self.send_json(401, {"error": "An administrator must sign in."})
        return admin

    def create_admin_session(self, con, admin_id):
        token = secrets.token_urlsafe(32)
        expires = (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(timespec="seconds")
        con.execute("DELETE FROM admin_sessions WHERE expires_at<=?", (now(),))
        con.execute("INSERT INTO admin_sessions(token_hash,admin_id,created_at,expires_at) VALUES(?,?,?,?)",
            (hashlib.sha256(token.encode()).hexdigest(), admin_id, now(), expires))
        secure = "; Secure" if os.environ.get("QUICKRIDE_COOKIE_SECURE", "").lower() in ("1", "true", "yes") else ""
        return f"campuslift_admin_session={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=86400{secure}"

    def require_user(self, con, role=None):
        user = self.request_user(con)
        if not user:
            self.send_json(401, {"error": "Please sign in to continue."})
            return None
        if role and user["role"] != role:
            self.send_json(403, {"error": f"This action is for {role}s only."})
            return None
        return user

    def session_cookie(self, token, expires):
        secure = "; Secure" if os.environ.get("QUICKRIDE_COOKIE_SECURE", "").lower() in ("1", "true", "yes") else ""
        return f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_DAYS*86400}{secure}"

    def make_session(self, con, user_id):
        token = secrets.token_urlsafe(32)
        expiry = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
        con.execute("DELETE FROM sessions WHERE expires_at<=?", (now(),))
        con.execute("INSERT INTO sessions(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)",
                    (hashlib.sha256(token.encode()).hexdigest(), user_id, now(), expiry))
        return token, expiry

    def check_origin(self):
        origin = self.headers.get("Origin")
        if not origin:
            return True
        parsed = urlparse(origin)
        return parsed.netloc.lower() == self.headers.get("Host", "").lower()

    def ride(self, con, row):
        if not row:
            return None
        data = dict(row)
        data["rider_name"] = data.pop("rider_name", None)
        data["driver_name"] = data.pop("driver_name", None)
        data["driver_vehicle_type"] = data.pop("driver_vehicle_type", None)
        data["driver_vehicle_number"] = data.pop("driver_vehicle_number", None)
        data.pop("ride_pin", None)
        if data.get("driver_id"):
            avg = con.execute("SELECT AVG(score),COUNT(*) FROM ratings WHERE rated_user_id=?", (data["driver_id"],)).fetchone()
            driver = con.execute("SELECT college_status,driver_verification_status FROM users WHERE id=?", (data["driver_id"],)).fetchone()
            data["driver_rating"] = round(avg[0], 1) if avg and avg[0] is not None else None
            data["driver_rating_count"] = avg[1] if avg else 0
            data["driver_college_status"] = driver["college_status"] if driver else "unverified"
            data["driver_verification_status"] = driver["driver_verification_status"] if driver else "unverified"
        else:
            data["driver_rating"] = None
            data["driver_rating_count"] = 0
        rider_status = con.execute("SELECT college_status FROM users WHERE id=?", (data.get("rider_id"),)).fetchone() if data.get("rider_id") else None
        data["rider_college_status"] = rider_status[0] if rider_status else "unverified"
        viewer = self.request_user(con)
        if viewer and viewer["role"] == "rider" and viewer["id"] == data.get("rider_id") and data.get("status") in ("driver_assigned", "in_progress"):
            pin_row = con.execute("SELECT ride_pin FROM rides WHERE id=?", (data["id"],)).fetchone()
            data["ride_pin"] = pin_row["ride_pin"] if pin_row else None
        rating = con.execute("SELECT score FROM ratings WHERE ride_id=? AND rater_id=?", (data["id"], viewer["id"])).fetchone() if viewer else None
        data["rated_by_me"] = bool(rating)
        data["my_rating"] = rating["score"] if rating and viewer["role"] == "rider" and viewer["id"] == data.get("rider_id") else None
        return data

    def ride_query(self, con, where, params=()):
        return con.execute(f"""SELECT r.*,ru.name AS rider_name,du.name AS driver_name,
            du.vehicle_type AS driver_vehicle_type,du.vehicle_number AS driver_vehicle_number
            FROM rides r LEFT JOIN users ru ON ru.id=r.rider_id
            LEFT JOIN users du ON du.id=r.driver_id WHERE {where} ORDER BY r.id DESC""", params)

    def fare_quote(self, con, vehicle_type, distance, minutes):
        vehicle = VEHICLES[vehicle_type]
        available = con.execute("""SELECT COUNT(*) FROM users u WHERE u.role='driver' AND u.is_online=1
            AND u.driver_verification_status='verified'
            AND u.driver_license_data IS NOT NULL AND u.driver_selfie_data IS NOT NULL AND u.vehicle_type=?
            AND NOT EXISTS(SELECT 1 FROM rides r WHERE r.driver_id=u.id AND r.status IN ('driver_assigned','in_progress'))""", (vehicle_type,)).fetchone()[0]
        demand = con.execute("SELECT COUNT(*) FROM rides WHERE vehicle_type=? AND status='searching'", (vehicle_type,)).fetchone()[0]
        effective_supply = max(available * vehicle["availability_weight"], 1)
        ratio = demand / effective_supply
        if ratio >= PRICING["high_demand_ratio"]:
            multiplier = min(PRICING["high_multiplier"], PRICING["demand_multiplier_max"])
        elif ratio >= PRICING["moderate_demand_ratio"]:
            multiplier = min(PRICING["moderate_multiplier"], PRICING["demand_multiplier_max"])
        else:
            multiplier = PRICING["demand_multiplier_min"]
        raw = max(vehicle["minimum_fare"], vehicle["base_fare"] + distance * vehicle["per_km"] + minutes * vehicle["per_minute"])
        fare = min(vehicle["campus_cap"], round(raw * multiplier))
        return {"estimated_fare": fare, "currency": "INR", "surge_multiplier": multiplier,
                "distance_km": round(distance, 1), "estimated_minutes": minutes,
                "availability": available, "available": available > 0}

    def map_request(self, url, body, field_mask):
        key = os.environ.get("GOOGLE_MAPS_API_KEY", "").strip()
        if not key:
            self.send_json(503, {"error": "Maps estimates are not configured. Set GOOGLE_MAPS_API_KEY on the server; you can still book without an estimate."})
            return None
        req = urllib.request.Request(url, data=json.dumps(body).encode(), method="POST", headers={
            "Content-Type": "application/json", "X-Goog-Api-Key": key, "X-Goog-FieldMask": field_mask})
        try:
            with urllib.request.urlopen(req, timeout=12) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            self.send_json(502, {"error": "Google Maps could not calculate this route. Check the key, enabled APIs, billing and locations."})
            return None

    def map_get_request(self, url, field_mask):
        key = os.environ.get("GOOGLE_MAPS_API_KEY", "").strip()
        if not key:
            self.send_json(503, {"error": "Maps search is not configured. Set GOOGLE_MAPS_API_KEY on the server."})
            return None
        req = urllib.request.Request(url, headers={"X-Goog-Api-Key": key, "X-Goog-FieldMask": field_mask})
        try:
            with urllib.request.urlopen(req, timeout=12) as response:
                return json.loads(response.read())
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError):
            self.send_json(502, {"error": "Google Places could not load this location. Check the key, enabled APIs and billing."})
            return None

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path
        if not path.startswith("/api/"):
            static_path = Path(self.translate_path(self.path)).resolve()
            if static_path.suffix.lower() in (".db", ".sqlite", ".sqlite3") or static_path.name.lower().endswith(("-wal", "-shm")):
                return self.send_error(404)
            return super().do_GET()
        if path == "/api/config":
            vehicles = {key: {"label": val["label"], "icon": val["icon"]} for key, val in VEHICLES.items()}
            return self.send_json(200, {"vehicles": vehicles, "maps_enabled": bool(os.environ.get("GOOGLE_MAPS_API_KEY", "").strip()),
                "maps_embed_enabled": bool(os.environ.get("GOOGLE_MAPS_EMBED_API_KEY", "").strip()),
                "demo_pricing": True})
        if path == "/api/maps/autocomplete":
            with self.db_session() as con:
                if not self.require_user(con, "rider"):
                    return
            query = parse_qs(parsed.query).get("q", [""])[0].strip()
            if len(query) < 2:
                return self.send_json(200, {"suggestions": []})
            token = parse_qs(parsed.query).get("session_token", [""])[0]
            request_body = {"input": query}
            if token:
                request_body["sessionToken"] = token
            result = self.map_request("https://places.googleapis.com/v1/places:autocomplete",
                request_body, "suggestions.placePrediction.placeId,suggestions.placePrediction.text.text,suggestions.placePrediction.structuredFormat.mainText.text")
            if result is None:
                return
            picks = []
            for item in result.get("suggestions", []):
                place = item.get("placePrediction", {})
                if place.get("placeId"):
                    picks.append({"place_id": place["placeId"], "text": place.get("text", {}).get("text", "")})
            return self.send_json(200, {"suggestions": picks})
        if path == "/api/maps/place":
            with self.db_session() as con:
                if not self.require_user(con, "rider"):
                    return
            args = parse_qs(parsed.query)
            place_id = args.get("place_id", [""])[0]
            session_token = args.get("session_token", [""])[0]
            if not place_id or len(place_id) > 256:
                return self.send_json(400, {"error": "Select a valid suggested location."})
            query_args = urlencode({"sessionToken": session_token}) if session_token else ""
            url = f"https://places.googleapis.com/v1/places/{quote(place_id, safe='')}" + (f"?{query_args}" if query_args else "")
            result = self.map_get_request(url, "id,formattedAddress,location")
            if result is None:
                return
            return self.send_json(200, {"place_id": result.get("id"), "formatted_address": result.get("formattedAddress")})
        if path == "/api/health":
            return self.send_json(200, {"ok": True, "service": "CampusLift demo API"})
        if path == "/api/admin/me":
            with self.db_session() as con:
                admin = self.request_admin(con)
                return self.send_json(200, {"admin": {"id": admin["id"], "name": admin["name"], "email": admin["email"]} if admin else None})
        document_path = re.fullmatch(r"/api/admin/drivers/(\d+)/documents/(licence|selfie)", path)
        if document_path:
            with self.db_session() as con:
                if not self.require_admin(con):
                    return
                driver_id, kind = int(document_path.group(1)), document_path.group(2)
                column = "driver_license" if kind == "licence" else "driver_selfie"
                row = con.execute(f"SELECT {column}_data AS data,{column}_mime AS mime FROM users WHERE id=? AND role='driver'", (driver_id,)).fetchone()
                if not row or not row["data"]:
                    return self.send_json(404, {"error": "This document is not available."})
                raw = bytes(row["data"])
                self.send_response(200)
                self.send_header("Content-Type", "application/octet-stream")
                ext = {"application/pdf": "pdf", "image/jpeg": "jpg", "image/png": "png", "image/webp": "webp"}.get(row["mime"], "bin")
                self.send_header("Content-Disposition", f'attachment; filename="driver-{driver_id}-{kind}.{ext}"')
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Cache-Control", "private, no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                self.wfile.write(raw)
                return
        if path == "/api/admin/overview":
            with self.db_session() as con:
                if not self.require_admin(con):
                    return
                drivers = con.execute("""SELECT id,name,email,vehicle_type,driver_verification_status,created_at,
                    driver_license_data IS NOT NULL AS has_driver_license,
                    driver_selfie_data IS NOT NULL AS has_driver_selfie
                    FROM users WHERE role='driver' ORDER BY CASE driver_verification_status WHEN 'pending' THEN 0 ELSE 1 END,created_at DESC""").fetchall()
                reports = con.execute("""SELECT i.id,i.ride_id,i.category,i.description,i.status,i.created_at,
                    u.name AS reporter_name,r.pickup,r.destination FROM incident_reports i
                    JOIN users u ON u.id=i.reporter_id JOIN rides r ON r.id=i.ride_id
                    ORDER BY i.created_at DESC LIMIT 100""").fetchall()
                college_users = con.execute("SELECT id,name,email,role,college_status FROM users WHERE college_status IN ('pending','unverified') ORDER BY created_at DESC").fetchall()
                return self.send_json(200, {"drivers": [dict(row) for row in drivers], "reports": [dict(row) for row in reports],
                    "college_users": [dict(row) for row in college_users]})
        with self.db_session() as con:
            if path == "/api/market/summary":
                user = self.require_user(con, "rider")
                if not user:
                    return
                available = con.execute("""SELECT COUNT(*) FROM users u
                    WHERE u.role='driver' AND u.is_online=1 AND u.driver_verification_status='verified'
                    AND u.vehicle_type IN ('bike','scooty','car','auto')
                    AND u.driver_license_data IS NOT NULL AND u.driver_selfie_data IS NOT NULL
                    AND NOT EXISTS(SELECT 1 FROM rides r WHERE r.driver_id=u.id
                        AND r.status IN ('driver_assigned','in_progress'))""").fetchone()[0]
                by_vehicle = {}
                for row in con.execute("""SELECT u.vehicle_type,COUNT(*) AS count FROM users u WHERE u.role='driver'
                    AND u.is_online=1 AND u.driver_verification_status='verified'
                    AND u.vehicle_type IN ('bike','scooty','car','auto')
                    AND u.driver_license_data IS NOT NULL AND u.driver_selfie_data IS NOT NULL
                    AND NOT EXISTS(SELECT 1 FROM rides r WHERE r.driver_id=u.id AND r.status IN ('driver_assigned','in_progress'))
                    GROUP BY u.vehicle_type"""):
                    by_vehicle[row["vehicle_type"]] = row["count"]
                return self.send_json(200, {"available_drivers": available, "by_vehicle": by_vehicle})
            if path == "/api/auth/me":
                user = self.request_user(con)
                return self.send_json(200, {"user": public_user(user)})
            if path == "/api/rides":
                user = self.require_user(con)
                if not user:
                    return
                if user["role"] == "rider":
                    rows = self.ride_query(con, "r.rider_id=?", (user["id"],)).fetchall()
                else:
                    if user["is_online"]:
                        rows = self.ride_query(con, "(r.status='searching' AND NOT EXISTS(SELECT 1 FROM ride_declines d WHERE d.ride_id=r.id AND d.driver_id=?)) OR r.driver_id=?", (user["id"], user["id"])).fetchall()
                    else:
                        rows = self.ride_query(con, "r.driver_id=?", (user["id"],)).fetchall()
                return self.send_json(200, {"rides": [self.ride(con, r) for r in rows[:50]]})
            parts = path.strip("/").split("/")
            if len(parts) == 4 and parts[:2] == ["api", "rides"] and parts[2].isdigit() and parts[3] == "location":
                user = self.require_user(con)
                if not user:
                    return
                row = con.execute("SELECT * FROM rides WHERE id=? AND (rider_id=? OR driver_id=?)",
                                  (int(parts[2]), user["id"], user["id"])).fetchone()
                if not row:
                    return self.send_json(404, {"error": "Ride not found"})
                if user["role"] == "rider" and row["rider_id"] != user["id"]:
                    return self.send_json(403, {"error": "This ride is not yours."})
                if user["role"] == "driver" and row["driver_id"] != user["id"]:
                    return self.send_json(403, {"error": "This ride is not assigned to you."})
                is_active = row["status"] in ("driver_assigned", "in_progress")
                location = None
                stale = False
                if is_active and row["driver_latitude"] is not None and row["driver_location_updated_at"]:
                    age = datetime.now(timezone.utc) - datetime.fromisoformat(row["driver_location_updated_at"])
                    if age <= timedelta(seconds=60):
                        location = {"latitude": row["driver_latitude"], "longitude": row["driver_longitude"],
                                    "accuracy": row["driver_accuracy"], "updated_at": row["driver_location_updated_at"]}
                    else:
                        stale = True
                return self.send_json(200, {"location": location, "sharing": bool(location), "stale": stale, "status": row["status"]})
            if path == "/api/driver/summary":
                user = self.require_user(con, "driver")
                if not user:
                    return
                eligible = driver_is_eligible(user)
                online = bool(user["is_online"] and eligible)
                if not eligible and user["is_online"]:
                    con.execute("UPDATE users SET is_online=0 WHERE id=?", (user["id"],))
                pending = self.ride_query(con, "r.status='searching' AND NOT EXISTS(SELECT 1 FROM ride_declines d WHERE d.ride_id=r.id AND d.driver_id=?)", (user["id"],)).fetchall() if online else []
                active = self.ride_query(con, "r.driver_id=? AND r.status IN ('driver_assigned','in_progress')", (user["id"],)).fetchone()
                day_start = campus_day_start_utc()
                completed = con.execute("SELECT COUNT(*) FROM rides WHERE driver_id=? AND status='completed' AND updated_at>=?", (user["id"],day_start)).fetchone()[0]
                earnings = con.execute("SELECT SUM(estimated_fare) FROM rides WHERE driver_id=? AND status='completed' AND updated_at>=?", (user["id"],day_start)).fetchone()[0]
                rating = con.execute("SELECT AVG(score),COUNT(*) FROM ratings WHERE rated_user_id=?", (user["id"],)).fetchone()
                return self.send_json(200, {"online": online, "eligible": eligible, "pending": [self.ride(con, r) for r in pending], "active": self.ride(con, active), "completed_count": completed,
                    "today_earnings": round(earnings, 2) if earnings is not None else None,
                    "rating": round(rating[0], 1) if rating and rating[0] is not None else None,
                    "rating_count": rating[1] if rating else 0, "verification_status": user["driver_verification_status"],
                    "college_status": user["college_status"], "licence_status": user["licence_status"],
                    "vehicle_document_status": user["vehicle_document_status"], "insurance_status": user["insurance_status"],
                    "has_driver_license": bool(user["has_driver_license"]), "has_driver_selfie": bool(user["has_driver_selfie"]),
                    "vehicle_type": user["vehicle_type"], "vehicle_number": user["vehicle_number"]})
            parts = path.strip("/").split("/")
            if len(parts) == 3 and parts[:2] == ["api", "rides"] and parts[2].isdigit():
                user = self.require_user(con)
                if not user:
                    return
                row = self.ride_query(con, "r.id=? AND (r.rider_id=? OR r.driver_id=?)", (int(parts[2]), user["id"], user["id"])).fetchone()
                if not row:
                    return self.send_json(404, {"error": "Ride not found"})
                return self.send_json(200, {"ride": self.ride(con, row)})
        return self.send_json(404, {"error": "Endpoint not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        if not self.check_origin():
            return self.send_json(403, {"error": "Cross-origin requests are not allowed."})
        try:
            body_limit = MAX_DRIVER_APPLICATION_BODY if path in ("/api/auth/register", "/api/driver/application") else MAX_BODY
            body = self.read_json(body_limit)
            with self.db_session() as con:
                if path == "/api/admin/login":
                    email = str(body.get("email", "")).strip().lower()
                    password = str(body.get("password", ""))
                    admin = con.execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone()
                    if not admin or not password_matches(password, admin["password_hash"]):
                        return self.send_json(401, {"error": "Administrator email or password is incorrect."})
                    cookie = self.create_admin_session(con, admin["id"])
                    return self.send_json(200, {"admin": {"id": admin["id"], "name": admin["name"], "email": admin["email"]}}, cookie)
                if path == "/api/admin/logout":
                    try:
                        token = SimpleCookie(self.headers.get("Cookie", ""))["campuslift_admin_session"].value
                        con.execute("DELETE FROM admin_sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
                    except (KeyError, CookieError):
                        pass
                    return self.send_json(200, {"ok": True}, "campuslift_admin_session=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0")
                if path.startswith("/api/admin/drivers/") and path.endswith("/verification"):
                    if not self.require_admin(con):
                        return
                    parts = path.strip("/").split("/")
                    if len(parts) != 5 or not parts[3].isdigit():
                        return self.send_json(404, {"error": "Driver not found."})
                    driver_id = int(parts[3])
                    status = str(body.get("status", ""))
                    # Older admin screens submit "reviewed" for the approval action.
                    # Keep one canonical database status so driver eligibility continues
                    # to depend on the existing "verified" value.
                    if status == "reviewed":
                        status = "verified"
                    if status not in STATUSES:
                        return self.send_json(400, {"error": "Choose approve or reject for this driver."})
                    if status == "verified":
                        docs = con.execute("SELECT driver_license_data,driver_selfie_data FROM users WHERE id=? AND role='driver'", (driver_id,)).fetchone()
                        if not docs:
                            return self.send_json(404, {"error": "Driver not found."})
                        if not docs["driver_license_data"] or not docs["driver_selfie_data"]:
                            return self.send_json(409, {"error": "A driving licence and selfie are required before approval."})
                    cur = con.execute("UPDATE users SET driver_verification_status=?,is_online=0 WHERE id=? AND role='driver'", (status, driver_id))
                    if not cur.rowcount:
                        return self.send_json(404, {"error": "Driver not found."})
                    return self.send_json(200, {"ok": True, "driver_id": driver_id, "status": status})
                if path.startswith("/api/admin/reports/") and path.endswith("/resolve"):
                    if not self.require_admin(con):
                        return
                    parts = path.strip("/").split("/")
                    if len(parts) != 5 or not parts[3].isdigit():
                        return self.send_json(404, {"error": "Report not found."})
                    cur = con.execute("UPDATE incident_reports SET status='reviewed' WHERE id=?", (int(parts[3]),))
                    return self.send_json(200 if cur.rowcount else 404, {"ok": bool(cur.rowcount)})
                if path.startswith("/api/admin/users/") and path.endswith("/college-verification"):
                    if not self.require_admin(con):
                        return
                    parts = path.strip("/").split("/")
                    if len(parts) != 5 or not parts[3].isdigit():
                        return self.send_json(404, {"error": "User not found."})
                    status = str(body.get("status", ""))
                    if status not in STATUSES:
                        return self.send_json(400, {"error": "Choose a valid college verification status."})
                    cur = con.execute("UPDATE users SET college_status=?,college_id_status=? WHERE id=?", (status, status, int(parts[3])))
                    return self.send_json(200 if cur.rowcount else 404, {"ok": bool(cur.rowcount)})
                if path == "/api/auth/register":
                    name = str(body.get("name", "")).strip()
                    email = str(body.get("email", "")).strip().lower()
                    password = str(body.get("password", ""))
                    role = body.get("role")
                    vehicle_type = str(body.get("vehicle_type", "bike")).lower()
                    vehicle_number = str(body.get("vehicle_number", "")).strip().upper()
                    licence_upload = selfie_upload = (None, None)
                    if len(name) < 2 or len(name) > 100:
                        return self.send_json(400, {"error": "Name must be between 2 and 100 characters."})
                    if len(email) > 254 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
                        return self.send_json(400, {"error": "Enter a valid email address."})
                    if len(password) < 10 or len(password) > 200:
                        return self.send_json(400, {"error": "Use a password with at least 10 characters."})
                    if role not in ("rider", "driver"):
                        return self.send_json(400, {"error": "Choose Rider or Driver."})
                    if role == "driver" and vehicle_type not in VEHICLES:
                        return self.send_json(400, {"error": "Choose a supported driver vehicle type."})
                    if role == "driver":
                        licence_upload = decode_driver_upload(body.get("driver_license"), "driving licence", {"application/pdf", "image/jpeg", "image/png", "image/webp"})
                        selfie_upload = decode_driver_upload(body.get("driver_selfie"), "selfie", {"image/jpeg", "image/png", "image/webp"})
                    domains = {x.strip().lower().lstrip("@") for x in os.environ.get("CAMPUS_EMAIL_DOMAINS", "").split(",") if x.strip()}
                    domain = email.rsplit("@", 1)[-1].lower()
                    college_status = "pending" if domain in domains else "unverified"
                    try:
                        cur = con.execute("""INSERT INTO users(name,email,password_hash,role,vehicle_type,vehicle_number,created_at,
                            college_status,driver_verification_status,driver_license_data,driver_license_mime,driver_selfie_data,driver_selfie_mime)
                            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (name,email,password_hash(password),role,vehicle_type if role == "driver" else None,vehicle_number if role == "driver" and vehicle_number else None,
                            now(),college_status,"pending" if role == "driver" else "unverified",
                             licence_upload[0],licence_upload[1],selfie_upload[0],selfie_upload[1]))
                    except sqlite3.IntegrityError:
                        return self.send_json(409, {"error": "An account with that email already exists. Sign in instead."})
                    user = con.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
                    token, expiry = self.make_session(con, cur.lastrowid)
                    return self.send_json(201, {"user": public_user(user)}, self.session_cookie(token, expiry))
                if path == "/api/auth/login":
                    email = str(body.get("email", "")).strip().lower()
                    password = str(body.get("password", ""))
                    row = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
                    if row and password_matches(password, row["password_hash"]):
                        token, expiry = self.make_session(con, row["id"])
                        return self.send_json(200, {"user": public_user(row)}, self.session_cookie(token, expiry))
                    admin = con.execute("SELECT * FROM admins WHERE email=?", (email,)).fetchone()
                    if admin and password_matches(password, admin["password_hash"]):
                        cookie = self.create_admin_session(con, admin["id"])
                        return self.send_json(200, {"user": {"id": admin["id"], "name": admin["name"],
                            "email": admin["email"], "role": "admin"}}, cookie)
                    return self.send_json(401, {"error": "Email or password is incorrect."})
                if path == "/api/auth/logout":
                    try:
                        cookie = SimpleCookie(self.headers.get("Cookie", ""))
                        token = cookie[COOKIE_NAME].value
                        con.execute("DELETE FROM sessions WHERE token_hash=?", (hashlib.sha256(token.encode()).hexdigest(),))
                    except (KeyError, CookieError):
                        pass
                    return self.send_json(200, {"ok": True}, f"{COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0")
                if path == "/api/maps/route":
                    if not self.require_user(con, "rider"):
                        return
                    start = body.get("pickup_place_id")
                    end = body.get("destination_place_id")
                    selected = str(body.get("vehicle_type", "")).lower()
                    vehicles = body.get("vehicle_types") or [selected]
                    if not isinstance(vehicles, list):
                        return self.send_json(400, {"error": "Choose valid vehicle types."})
                    vehicles = list(dict.fromkeys(str(x).lower() for x in vehicles))
                    vehicle = selected if selected in VEHICLES else (vehicles[0] if vehicles else "")
                    if not start or not end or not vehicles or any(x not in VEHICLES for x in vehicles) or vehicle not in VEHICLES:
                        return self.send_json(400, {"error": "Select pickup, destination and a vehicle to estimate the fare."})
                    result = self.map_request("https://routes.googleapis.com/directions/v2:computeRoutes",
                        {"origin": {"placeId": start}, "destination": {"placeId": end}, "travelMode": "DRIVE", "routingPreference": "TRAFFIC_UNAWARE"},
                        "routes.distanceMeters,routes.duration")
                    if result is None:
                        return
                    routes = result.get("routes", [])
                    if not routes:
                        return self.send_json(422, {"error": "No route was found for those locations."})
                    distance = routes[0].get("distanceMeters", 0) / 1000
                    duration = int(math.ceil(float(routes[0].get("duration", "0s").removesuffix("s")) / 60))
                    quotes = {key: self.fare_quote(con, key, distance, duration) for key in vehicles}
                    quote = quotes[vehicle]
                    embed_key = os.environ.get("GOOGLE_MAPS_EMBED_API_KEY", "").strip()
                    return self.send_json(200, {**quote, "vehicle": {"label": VEHICLES[vehicle]["label"], "icon": VEHICLES[vehicle]["icon"]},
                        "vehicle_type": vehicle, "quotes": quotes, "map_embed_key": embed_key})
                if path == "/api/rides":
                    user = self.require_user(con, "rider")
                    if not user:
                        return
                    pickup = str(body.get("pickup", "")).strip()
                    destination = str(body.get("destination", "")).strip()
                    vehicle_type = str(body.get("vehicle_type", "bike")).lower()
                    if not pickup or not destination or len(pickup) > 180 or len(destination) > 180:
                        return self.send_json(400, {"error": "Enter pickup and destination (180 characters maximum)."})
                    if pickup.casefold() == destination.casefold():
                        return self.send_json(400, {"error": "Pickup and destination must be different."})
                    if vehicle_type not in VEHICLES:
                        return self.send_json(400, {"error": "Choose a valid vehicle type."})
                    distance = duration = fare = multiplier = None
                    pickup_place_id = body.get("pickup_place_id")
                    destination_place_id = body.get("destination_place_id")
                    if pickup_place_id and destination_place_id and os.environ.get("GOOGLE_MAPS_API_KEY", "").strip():
                        route_data = self.map_request("https://routes.googleapis.com/directions/v2:computeRoutes",
                            {"origin": {"placeId": str(pickup_place_id)}, "destination": {"placeId": str(destination_place_id)},
                             "travelMode": "DRIVE", "routingPreference": "TRAFFIC_UNAWARE"},
                            "routes.distanceMeters,routes.duration")
                        if route_data is None:
                            return
                        routes = route_data.get("routes", [])
                        if not routes:
                            return self.send_json(422, {"error": "No route was found for those locations."})
                        distance = routes[0].get("distanceMeters", 0) / 1000
                        duration = int(math.ceil(float(routes[0].get("duration", "0s").removesuffix("s")) / 60))
                        if not 0 < distance < 1000 or not 0 < duration < 1440:
                            return self.send_json(422, {"error": "The route estimate is outside the supported range."})
                        quote = self.fare_quote(con, vehicle_type, distance, duration)
                        fare, multiplier = quote["estimated_fare"], quote["surge_multiplier"]
                    stamp = now()
                    cur = con.execute("""INSERT INTO rides(rider_id,pickup,destination,vehicle_type,distance_km,estimated_minutes,estimated_fare,pricing_multiplier,status,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,'searching',?,?)""", (user["id"],pickup,destination,vehicle_type,distance,duration,fare,multiplier,stamp,stamp))
                    row = self.ride_query(con, "r.id=?", (cur.lastrowid,)).fetchone()
                    return self.send_json(201, {"ride": self.ride(con, row)})
                if path == "/api/driver/application":
                    user = self.require_user(con, "driver")
                    if not user:
                        return
                    if user["driver_verification_status"] == "verified":
                        return self.send_json(409, {"error": "Your driver profile is already approved."})
                    if user["driver_verification_status"] == "suspended":
                        return self.send_json(403, {"error": "Your driver profile is suspended. Contact a campus administrator."})
                    if user["driver_verification_status"] == "rejected":
                        return self.send_json(403, {"error": "Your driver application was rejected. Contact a campus administrator."})
                    vehicle_type = str(body.get("vehicle_type", "")).lower()
                    if vehicle_type not in VEHICLES:
                        return self.send_json(400, {"error": "Choose a supported vehicle type."})
                    licence_upload = decode_driver_upload(body.get("driver_license"), "driving licence", {"application/pdf", "image/jpeg", "image/png", "image/webp"})
                    selfie_upload = decode_driver_upload(body.get("driver_selfie"), "selfie", {"image/jpeg", "image/png", "image/webp"})
                    con.execute("""UPDATE users SET vehicle_type=?,driver_license_data=?,driver_license_mime=?,
                        driver_selfie_data=?,driver_selfie_mime=?,driver_verification_status='pending',is_online=0 WHERE id=?""",
                        (vehicle_type,licence_upload[0],licence_upload[1],selfie_upload[0],selfie_upload[1],user["id"]))
                    return self.send_json(200, {"ok": True, "status": "pending", "eligible": False})
                if path == "/api/driver/availability":
                    user = self.require_user(con, "driver")
                    if not user:
                        return
                    online = body.get("online")
                    if not isinstance(online, bool):
                        return self.send_json(400, {"error": "online must be true or false."})
                    if online and not driver_is_eligible(user):
                        return self.send_json(403, {"error": "A complete driver profile and campus admin verification are required before going online. Restricted profiles must contact a campus administrator."})
                    con.execute("UPDATE users SET is_online=? WHERE id=?", (int(online), user["id"]))
                    return self.send_json(200, {"online": online})
                parts = path.strip("/").split("/")
                if len(parts) == 4 and parts[:2] == ["api", "rides"] and parts[2].isdigit():
                    ride_id, action = int(parts[2]), parts[3]
                    if action == "rating":
                        user = self.require_user(con)
                        if not user:
                            return
                        ride = con.execute("SELECT rider_id,driver_id,status FROM rides WHERE id=?", (ride_id,)).fetchone()
                        if not ride:
                            return self.send_json(404, {"error": "Ride not found."})
                        if user["role"] != "rider" or user["id"] != ride["rider_id"]:
                            return self.send_json(403, {"error": "Only the rider can rate the driver for this ride."})
                        if ride["status"] != "completed":
                            return self.send_json(409, {"error": "Ratings are available after ride completion."})
                        target_id = ride["driver_id"]
                        score = body.get("score")
                        if isinstance(score, bool) or not isinstance(score, int) or not 1 <= score <= 5:
                            return self.send_json(400, {"error": "Choose a rating from 1 to 5 stars."})
                        note = str(body.get("note", "")).strip()[:500]
                        try:
                            con.execute("INSERT INTO ratings(ride_id,rater_id,rated_user_id,score,note,created_at) VALUES(?,?,?,?,?,?)",
                                (ride_id, user["id"], target_id, score, note or None, now()))
                        except sqlite3.IntegrityError:
                            return self.send_json(409, {"error": "You already rated this ride."})
                        avg = con.execute("SELECT AVG(score),COUNT(*) FROM ratings WHERE rated_user_id=?", (target_id,)).fetchone()
                        return self.send_json(201, {"ok": True, "rating": round(avg[0], 1), "rating_count": avg[1]})
                    if action == "report":
                        user = self.require_user(con)
                        if not user:
                            return
                        ride = con.execute("SELECT rider_id,driver_id FROM rides WHERE id=?", (ride_id,)).fetchone()
                        if not ride:
                            return self.send_json(404, {"error": "Ride not found."})
                        if user["id"] not in (ride["rider_id"], ride["driver_id"]):
                            return self.send_json(403, {"error": "Only ride participants can report a ride."})
                        category = str(body.get("category", "ride_issue"))
                        description = str(body.get("description", "")).strip()
                        if category not in ("safety", "conduct", "ride_issue") or not 5 <= len(description) <= 2000:
                            return self.send_json(400, {"error": "Choose a report type and enter 5–2000 characters."})
                        cur = con.execute("INSERT INTO incident_reports(ride_id,reporter_id,category,description,created_at) VALUES(?,?,?,?,?)",
                            (ride_id, user["id"], category, description, now()))
                        return self.send_json(201, {"ok": True, "report_id": cur.lastrowid, "status": "open"})
                    if action == "location":
                        user = self.require_user(con, "driver")
                        if not user:
                            return
                        coords = body.get("coords", body)
                        try:
                            latitude = float(coords.get("latitude"))
                            longitude = float(coords.get("longitude"))
                            accuracy = float(coords.get("accuracy", 0))
                        except (TypeError, ValueError):
                            return self.send_json(400, {"error": "Send numeric latitude, longitude and accuracy."})
                        if not (math.isfinite(latitude) and math.isfinite(longitude) and math.isfinite(accuracy)
                                and -90 <= latitude <= 90 and -180 <= longitude <= 180 and 0 <= accuracy <= 10000):
                            return self.send_json(400, {"error": "The location coordinates are outside valid ranges."})
                        stamp = now()
                        cur = con.execute("""UPDATE rides SET driver_latitude=?,driver_longitude=?,driver_accuracy=?,
                            driver_location_updated_at=?,updated_at=? WHERE id=? AND driver_id=?
                            AND status IN ('driver_assigned','in_progress')""",
                            (latitude, longitude, accuracy, stamp, stamp, ride_id, user["id"]))
                        if not cur.rowcount:
                            return self.send_json(409, {"error": "Live sharing is available only for your assigned active ride."})
                        return self.send_json(200, {"ok": True, "updated_at": stamp})
                    if action == "location-stop":
                        user = self.require_user(con, "driver")
                        if not user:
                            return
                        cur = con.execute("""UPDATE rides SET driver_latitude=NULL,driver_longitude=NULL,driver_accuracy=NULL,
                            driver_location_updated_at=NULL,updated_at=? WHERE id=? AND driver_id=?
                            AND status IN ('driver_assigned','in_progress')""", (now(), ride_id, user["id"]))
                        if not cur.rowcount:
                            return self.send_json(409, {"error": "This is not your assigned active ride."})
                        return self.send_json(200, {"ok": True, "sharing": False})
                    if action == "cancel":
                        user = self.require_user(con, "rider")
                        old, new = "searching", "cancelled"
                    else:
                        user = self.require_user(con, "driver")
                        transition = {"accept": ("searching", "driver_assigned"), "decline": ("searching", "searching"),
                                      "start": ("driver_assigned", "in_progress"), "complete": ("in_progress", "completed")}
                        if action not in transition:
                            return self.send_json(404, {"error": "Action not found"})
                        old, new = transition[action]
                    if not user:
                        return
                    stamp = now()
                    if action == "accept":
                        if not user["is_online"]:
                            return self.send_json(409, {"error": "Set your driver availability online before accepting."})
                        if not driver_is_eligible(user):
                            return self.send_json(403, {"error": "A complete, eligible driver profile is required to accept rides."})
                        active = con.execute("SELECT 1 FROM rides WHERE driver_id=? AND status IN ('driver_assigned','in_progress')", (user["id"],)).fetchone()
                        if active:
                            return self.send_json(409, {"error": "Complete your active ride before accepting another request."})
                        pin = f"{secrets.randbelow(10000):04d}"
                        cur = con.execute("UPDATE rides SET status='driver_assigned',driver_id=?,ride_pin=?,updated_at=? WHERE id=? AND status='searching' AND NOT EXISTS(SELECT 1 FROM ride_declines WHERE ride_id=? AND driver_id=?)",
                            (user["id"],pin,stamp,ride_id,ride_id,user["id"]))
                    elif action == "decline":
                        con.execute("INSERT OR IGNORE INTO ride_declines(ride_id,driver_id,created_at) SELECT id,?,? FROM rides WHERE id=? AND status='searching'", (user["id"],stamp,ride_id))
                        row = self.ride_query(con, "r.id=? AND r.status='searching'", (ride_id,)).fetchone()
                        if not row:
                            return self.send_json(409, {"error": "This request has already changed state."})
                        return self.send_json(200, {"ride": self.ride(con, row)})
                    elif action == "cancel":
                        cur = con.execute("UPDATE rides SET status=?,updated_at=? WHERE id=? AND rider_id=? AND status=?", (new,stamp,ride_id,user["id"],old))
                    else:
                        if action == "start":
                            pin_row = con.execute("SELECT ride_pin FROM rides WHERE id=? AND driver_id=? AND status='driver_assigned'", (ride_id,user["id"])).fetchone()
                            if not pin_row:
                                return self.send_json(409, {"error": "This ride is not ready to start."})
                            if pin_row["ride_pin"] and not hmac.compare_digest(str(body.get("pin", "")), pin_row["ride_pin"]):
                                return self.send_json(403, {"error": "Ride PIN is incorrect."})
                        cur = con.execute("""UPDATE rides SET status=?,updated_at=?,
                            ride_pin=CASE WHEN ?='completed' THEN NULL ELSE ride_pin END,
                            driver_latitude=CASE WHEN ?='completed' THEN NULL ELSE driver_latitude END,
                            driver_longitude=CASE WHEN ?='completed' THEN NULL ELSE driver_longitude END,
                            driver_accuracy=CASE WHEN ?='completed' THEN NULL ELSE driver_accuracy END,
                            driver_location_updated_at=CASE WHEN ?='completed' THEN NULL ELSE driver_location_updated_at END
                            WHERE id=? AND driver_id=? AND status=?""",
                            (new,stamp,new,new,new,new,new,ride_id,user["id"],old))
                    if not cur.rowcount:
                        row = con.execute("SELECT id FROM rides WHERE id=?", (ride_id,)).fetchone()
                        if not row:
                            return self.send_json(404, {"error": "Ride not found"})
                        return self.send_json(409, {"error": "This ride has already changed or is assigned to another user."})
                    row = self.ride_query(con, "r.id=?", (ride_id,)).fetchone()
                    return self.send_json(200, {"ride": self.ride(con, row)})
            return self.send_json(404, {"error": "Endpoint not found"})
        except ValueError as error:
            return self.send_json(400, {"error": str(error)})
        except (BrokenPipeError, ConnectionResetError):
            return

    def log_message(self, fmt, *args):
        print("%s - %s" % (self.log_date_time_string(), fmt % args))


def create_demo_accounts(db_path):
    initialize_db(db_path)
    with sqlite3.connect(db_path) as con:
        con.row_factory = sqlite3.Row
        for role, email, name in (("rider", "rider@quickride.demo", "Demo Rider"), ("driver", "driver@quickride.demo", "Demo Driver")):
            existing = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()
            if existing:
                print(f"{role.title()} demo account already exists: {email} (use its current password)")
                continue
            password = secrets.token_urlsafe(12)
            con.execute("INSERT INTO users(name,email,password_hash,role,vehicle_type,vehicle_number,created_at) VALUES(?,?,?,?,?,?,?)",
                (name,email,password_hash(password),role,"bike" if role == "driver" else None,"DEMO-2042" if role == "driver" else None,now()))
            print(f"Created {role}: {email}  one-time password: {password}")


def create_admin_account(db_path):
    email = input("CampusLift admin email: ").strip().lower()
    name = input("Admin display name: ").strip()
    if len(name) < 2 or not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email):
        raise SystemExit("Enter a valid name and email.")
    password = getpass.getpass("Choose an admin password (10+ characters): ")
    confirm = getpass.getpass("Confirm password: ")
    if len(password) < 10 or password != confirm:
        raise SystemExit("Passwords must match and contain at least 10 characters.")
    with sqlite3.connect(db_path) as con:
        try:
            con.execute("INSERT INTO admins(name,email,password_hash,created_at) VALUES(?,?,?,?)",
                (name,email,password_hash(password),now()))
        except sqlite3.IntegrityError:
            raise SystemExit("An admin account with this email already exists.")
    print("Admin account created. Keep its password private.")


def main():
    parser = argparse.ArgumentParser(description="CampusLift campus ride service")
    parser.add_argument("--host", default="127.0.0.1", help="Use 0.0.0.0 for same-Wi-Fi access")
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--db-path", default=str(ROOT / "quickride.db"))
    parser.add_argument("--create-demo-accounts", action="store_true", help="Create demo accounts and print generated passwords once")
    parser.add_argument("--create-admin", action="store_true", help="Interactively create an admin account for verification review")
    args = parser.parse_args()
    db_path = Path(args.db_path).resolve()
    initialize_db(db_path)
    if args.create_demo_accounts:
        create_demo_accounts(db_path)
        return
    if args.create_admin:
        create_admin_account(db_path)
        return
    handler = lambda *a, **kw: QuickRideHandler(*a, db_path=db_path, **kw)
    server = ThreadingHTTPServer((args.host, args.port), handler)
    print(f"CampusLift is running at http://{args.host}:{args.port}")
    print(f"Shared SQLite database: {db_path}")
    print("Authentication enabled. Maps: " + ("configured" if os.environ.get("GOOGLE_MAPS_API_KEY") else "not configured; manual booking remains available"))
    print("Use HTTPS and a campus security review before public deployment.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nCampusLift server stopped.")
    finally:
        server.server_close()

if __name__ == "__main__":
    main()

