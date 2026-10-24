import hashlib
import hmac
import os
import re
import secrets
import sqlite3
import zipfile
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from flask import Flask, g, jsonify, request, send_from_directory
from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename


ROOT = Path(__file__).resolve().parent
INSTANCE_DIR = ROOT / "instance"
UPLOAD_DIR = INSTANCE_DIR / "uploads"
DATABASE_PATH = INSTANCE_DIR / "trustvault.sqlite3"
ALLOWED_EXTENSIONS = {"pdf", "docx", "xlsx", "png", "jpg", "jpeg"}
FRONTEND_EXTENSIONS = {".html", ".css", ".js", ".ico", ".svg", ".png", ".jpg", ".jpeg"}
MAX_UPLOAD_BYTES = 10 * 1024 * 1024
SESSION_LIFETIME = timedelta(days=7)
EMAIL_PATTERN = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")

app = Flask(__name__, static_folder=None)
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES + (1024 * 1024)
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("TRUSTVAULT_COOKIE_SECURE") == "true"


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE_PATH)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(_error):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def initialize_database():
    INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(DATABASE_PATH)
    try:
        db.execute("PRAGMA foreign_keys = ON")
        db.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                csrf_hash TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS documents (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                original_name TEXT NOT NULL,
                stored_name TEXT NOT NULL UNIQUE,
                file_type TEXT NOT NULL,
                file_size INTEGER NOT NULL,
                uploaded_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS permissions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
                recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                permission TEXT NOT NULL CHECK(permission IN ('View', 'Download')),
                status TEXT NOT NULL DEFAULT 'Active' CHECK(status IN ('Active', 'Revoked')),
                created_at TEXT NOT NULL,
                revoked_at TEXT,
                UNIQUE(document_id, recipient_id)
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
                document_id INTEGER REFERENCES documents(id) ON DELETE SET NULL,
                action TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
            CREATE INDEX IF NOT EXISTS idx_permissions_recipient ON permissions(recipient_id, status);
            CREATE INDEX IF NOT EXISTS idx_audit_document ON audit_events(document_id, created_at);
            """
        )
    finally:
        db.close()


def now_iso():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def json_error(message, status):
    return jsonify({"error": message}), status


def json_object():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else None


def user_payload(row):
    return {"id": row["id"], "full_name": row["full_name"], "email": row["email"]}


def get_session_user():
    token = request.cookies.get("tv_session")
    if not token:
        return None

    row = get_db().execute(
        """
        SELECT users.id, users.full_name, users.email, sessions.csrf_hash
        FROM sessions JOIN users ON users.id = sessions.user_id
        WHERE sessions.token_hash = ? AND sessions.expires_at > ?
        """,
        (digest(token), now_iso()),
    ).fetchone()
    if row:
        g.session_csrf_hash = row["csrf_hash"]
    return row


def login_required(route):
    @wraps(route)
    def wrapped(*args, **kwargs):
        user = get_session_user()
        if not user:
            return json_error("Please log in to continue.", 401)
        g.user = user
        return route(*args, **kwargs)

    return wrapped


def csrf_required(route):
    @wraps(route)
    def wrapped(*args, **kwargs):
        user = get_session_user()
        if not user:
            return json_error("Please log in to continue.", 401)
        g.user = user
        cookie_token = request.cookies.get("tv_csrf", "")
        header_token = request.headers.get("X-CSRF-Token", "")
        if (
            not cookie_token
            or not header_token
            or not hmac.compare_digest(cookie_token, header_token)
            or not hmac.compare_digest(digest(cookie_token), g.session_csrf_hash)
        ):
            return json_error("The security token is invalid. Refresh the page and try again.", 403)
        return route(*args, **kwargs)

    return wrapped


def set_session_cookies(response, token, csrf_token):
    secure = app.config["SESSION_COOKIE_SECURE"]
    response.set_cookie(
        "tv_session",
        token,
        httponly=True,
        secure=secure,
        samesite="Lax",
        max_age=int(SESSION_LIFETIME.total_seconds()),
        path="/",
    )
    response.set_cookie(
        "tv_csrf",
        csrf_token,
        httponly=False,
        secure=secure,
        samesite="Lax",
        max_age=int(SESSION_LIFETIME.total_seconds()),
        path="/",
    )
    return response


def clear_session_cookies(response):
    response.delete_cookie("tv_session", path="/", samesite="Lax")
    response.delete_cookie("tv_csrf", path="/", samesite="Lax")
    return response


def log_event(actor_id, document_id, action):
    # Audit events are append-only through the API; no user-facing edit endpoint exists.
    get_db().execute(
        "INSERT INTO audit_events (actor_id, document_id, action, created_at) VALUES (?, ?, ?, ?)",
        (actor_id, document_id, action, now_iso()),
    )


def document_for_user(document_id, user_id):
    return get_db().execute(
        """
        SELECT documents.*, users.full_name AS owner_name
        FROM documents JOIN users ON users.id = documents.owner_id
        WHERE documents.id = ? AND documents.owner_id = ?
        """,
        (document_id, user_id),
    ).fetchone()


def readable_document(document_id, user_id):
    return get_db().execute(
        """
        SELECT documents.*, users.full_name AS owner_name, permissions.permission AS granted_permission
        FROM documents
        JOIN users ON users.id = documents.owner_id
        LEFT JOIN permissions
          ON permissions.document_id = documents.id
         AND permissions.recipient_id = ?
         AND permissions.status = 'Active'
        WHERE documents.id = ? AND (documents.owner_id = ? OR permissions.id IS NOT NULL)
        """,
        (user_id, document_id, user_id),
    ).fetchone()


def document_payload(row, status="Active"):
    return {
        "id": row["id"],
        "name": row["original_name"],
        "type": row["file_type"],
        "uploaded": row["uploaded_at"],
        "size": row["file_size"],
        "status": status,
    }


def file_content_matches(path, extension):
    try:
        with path.open("rb") as uploaded_file:
            signature = uploaded_file.read(8)
        if extension == "pdf":
            return signature.startswith(b"%PDF-")
        if extension == "png":
            return signature.startswith(b"\x89PNG\r\n\x1a\n")
        if extension in {"jpg", "jpeg"}:
            return signature.startswith(b"\xff\xd8\xff")
        if extension in {"docx", "xlsx"}:
            if not zipfile.is_zipfile(path):
                return False
            with zipfile.ZipFile(path) as archive:
                names = set(archive.namelist())
            if extension == "docx":
                return "[Content_Types].xml" in names and "word/document.xml" in names
            return "[Content_Types].xml" in names and "xl/workbook.xml" in names
    except (OSError, zipfile.BadZipFile):
        return False
    return False


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "same-origin"
    if request.path.startswith("/api/"):
        response.headers["Cache-Control"] = "no-store"
    return response


@app.before_request
def reject_cross_origin_mutations():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return None
    origin = request.headers.get("Origin")
    if not origin:
        return None
    supplied = urlsplit(origin)
    expected = urlsplit(request.host_url)
    if supplied.scheme != expected.scheme or supplied.netloc != expected.netloc:
        return json_error("Cross-origin requests are not allowed.", 403)
    return None


@app.errorhandler(413)
def request_too_large(_error):
    return json_error("The request exceeds the 10 MB file limit.", 413)


@app.get("/")
def home():
    return send_from_directory(ROOT, "index.html")


@app.get("/<path:filename>")
def frontend_file(filename):
    if any(part.startswith(".") for part in Path(filename).parts):
        return json_error("Not found.", 404)
    candidate = (ROOT / filename).resolve()
    if (
        ROOT not in candidate.parents
        or candidate.suffix.lower() not in FRONTEND_EXTENSIONS
        or not candidate.is_file()
    ):
        return json_error("Not found.", 404)
    return send_from_directory(ROOT, filename)


@app.get("/api/health")
def health():
    return jsonify({"status": "ok", "service": "TrustVault API"})


@app.post("/api/auth/register")
def register():
    data = json_object()
    if data is None:
        return json_error("Send registration details as a JSON object.", 400)
    full_name_value = data.get("full_name", "")
    email_value = data.get("email", "")
    password = data.get("password", "")
    if not isinstance(full_name_value, str) or not full_name_value.strip() or len(full_name_value.strip()) > 120:
        return json_error("Enter a name between 1 and 120 characters.", 400)
    if not isinstance(email_value, str):
        return json_error("Enter a valid email address.", 400)
    full_name = full_name_value.strip()
    email = email_value.strip().lower()
    if not EMAIL_PATTERN.fullmatch(email) or len(email) > 254:
        return json_error("Enter a valid email address.", 400)
    if not isinstance(password, str) or len(password) < 8 or len(password) > 256:
        return json_error("Password must be between 8 and 256 characters.", 400)

    db = get_db()
    try:
        cursor = db.execute(
            "INSERT INTO users (full_name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (full_name, email, generate_password_hash(password), now_iso()),
        )
        db.commit()
    except sqlite3.IntegrityError:
        return json_error("An account with this email already exists.", 409)

    return jsonify(
        {"message": "Account created. You can now log in.", "user": {"id": cursor.lastrowid, "full_name": full_name, "email": email}}
    ), 201


@app.post("/api/auth/login")
def login():
    data = json_object()
    if data is None:
        return json_error("Send login details as a JSON object.", 400)
    email_value = data.get("email", "")
    password = data.get("password", "")
    if not isinstance(email_value, str) or not isinstance(password, str):
        return json_error("Enter your email and password.", 400)
    email = email_value.strip().lower()
    if not email:
        return json_error("Enter your email and password.", 400)

    db = get_db()
    db.execute("DELETE FROM sessions WHERE expires_at <= ?", (now_iso(),))
    user = db.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
    if not user or not check_password_hash(user["password_hash"], password):
        return json_error("Email or password is incorrect.", 401)

    token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    db.execute(
        "INSERT INTO sessions (token_hash, user_id, csrf_hash, expires_at, created_at) VALUES (?, ?, ?, ?, ?)",
        (
            digest(token),
            user["id"],
            digest(csrf_token),
            (datetime.now(timezone.utc) + SESSION_LIFETIME).isoformat(timespec="seconds"),
            now_iso(),
        ),
    )
    db.commit()
    response = jsonify({"message": "Logged in.", "user": user_payload(user)})
    return set_session_cookies(response, token, csrf_token)


@app.get("/api/auth/me")
@login_required
def current_user():
    return jsonify({"user": user_payload(g.user)})


@app.post("/api/auth/logout")
@csrf_required
def logout():
    token = request.cookies.get("tv_session", "")
    get_db().execute("DELETE FROM sessions WHERE token_hash = ?", (digest(token),))
    get_db().commit()
    return clear_session_cookies(jsonify({"message": "Logged out."}))


@app.get("/api/dashboard")
@login_required
def dashboard():
    db = get_db()
    user_id = g.user["id"]
    total = db.execute("SELECT COUNT(*) FROM documents WHERE owner_id = ?", (user_id,)).fetchone()[0]
    shared = db.execute(
        "SELECT COUNT(*) FROM permissions WHERE recipient_id = ? AND status = 'Active'",
        (user_id,),
    ).fetchone()[0]
    events = db.execute(
        """
        SELECT audit_events.action, audit_events.created_at, documents.original_name,
               actor.full_name AS actor_name, actor.email AS actor_email
        FROM audit_events
        LEFT JOIN documents ON documents.id = audit_events.document_id
        LEFT JOIN users AS actor ON actor.id = audit_events.actor_id
        WHERE audit_events.actor_id = ? OR documents.owner_id = ?
        ORDER BY audit_events.created_at DESC LIMIT 5
        """,
        (user_id, user_id),
    ).fetchall()
    recent = [
        {
            "action": row["action"],
            "document": row["original_name"] or "Document",
            "actor": row["actor_name"] or row["actor_email"] or "Former user",
            "created_at": row["created_at"],
        }
        for row in events
    ]
    return jsonify(
        {
            "total_documents": total,
            "shared_documents": shared,
            "audit_events": db.execute(
                "SELECT COUNT(*) FROM audit_events WHERE actor_id = ?",
                (user_id,),
            ).fetchone()[0],
            "recent_activity": recent,
        }
    )


@app.get("/api/documents")
@login_required
def list_documents():
    rows = get_db().execute(
        "SELECT * FROM documents WHERE owner_id = ? ORDER BY uploaded_at DESC",
        (g.user["id"],),
    ).fetchall()
    result = []
    for row in rows:
        has_shares = get_db().execute(
            "SELECT 1 FROM permissions WHERE document_id = ? AND status = 'Active' LIMIT 1",
            (row["id"],),
        ).fetchone()
        result.append(document_payload(row, "Shared" if has_shares else "Active"))
    return jsonify({"documents": result})


@app.post("/api/documents/upload")
@csrf_required
def upload_document():
    uploaded = request.files.get("file")
    if not uploaded or not uploaded.filename:
        return json_error("Choose a file to upload.", 400)
    original_name = secure_filename(uploaded.filename)
    if not original_name:
        return json_error("The filename is invalid.", 400)
    extension = original_name.rsplit(".", 1)[-1].lower() if "." in original_name else ""
    if extension not in ALLOWED_EXTENSIONS:
        return json_error("Unsupported file type. Allowed types: PDF, DOCX, XLSX, PNG, JPG.", 400)

    stored_name = f"{uuid4().hex}.{extension}"
    target = UPLOAD_DIR / stored_name
    uploaded.save(target)
    file_size = target.stat().st_size
    if file_size > MAX_UPLOAD_BYTES:
        target.unlink(missing_ok=True)
        return json_error("The selected file exceeds the 10 MB limit.", 413)
    if file_size == 0 or not file_content_matches(target, extension):
        target.unlink(missing_ok=True)
        return json_error("File contents do not match the selected file type.", 400)

    db = get_db()
    created_at = now_iso()
    cursor = db.execute(
        """
        INSERT INTO documents (owner_id, original_name, stored_name, file_type, file_size, uploaded_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (g.user["id"], original_name, stored_name, extension.upper(), file_size, created_at),
    )
    document_id = cursor.lastrowid
    log_event(g.user["id"], document_id, "Upload")
    db.commit()
    return jsonify(
        {
            "message": "Document uploaded.",
            "document": {
                "id": document_id,
                "name": original_name,
                "type": extension.upper(),
                "uploaded": created_at,
                "size": file_size,
                "status": "Active",
            },
        }
    ), 201


@app.post("/api/documents/<int:document_id>/view")
@csrf_required
def view_document(document_id):
    row = readable_document(document_id, g.user["id"])
    if not row:
        return json_error("Document not found or you do not have access.", 404)
    log_event(g.user["id"], document_id, "View")
    get_db().commit()
    return jsonify(
        {
            "document": document_payload(row),
            "owner": row["owner_name"],
            "permission": row["granted_permission"] or "Owner",
        }
    )


@app.post("/api/documents/<int:document_id>/download")
@csrf_required
def download_document(document_id):
    row = readable_document(document_id, g.user["id"])
    if not row:
        return json_error("Document not found or you do not have access.", 404)
    if row["owner_id"] != g.user["id"] and row["granted_permission"] != "Download":
        return json_error("This share only allows viewing.", 403)

    file_path = UPLOAD_DIR / row["stored_name"]
    if not file_path.is_file():
        return json_error("The stored file is unavailable.", 404)
    log_event(g.user["id"], document_id, "Download")
    get_db().commit()
    return send_from_directory(
        UPLOAD_DIR,
        row["stored_name"],
        as_attachment=True,
        download_name=row["original_name"],
    )


@app.get("/api/shared")
@login_required
def shared_documents():
    rows = get_db().execute(
        """
        SELECT documents.id, documents.original_name, documents.file_type, documents.uploaded_at,
               permissions.permission, permissions.created_at AS shared_at,
               users.full_name AS shared_by
        FROM permissions
        JOIN documents ON documents.id = permissions.document_id
        JOIN users ON users.id = documents.owner_id
        WHERE permissions.recipient_id = ? AND permissions.status = 'Active'
        ORDER BY permissions.created_at DESC
        """,
        (g.user["id"],),
    ).fetchall()
    return jsonify(
        {
            "documents": [
                {
                    "id": row["id"],
                    "name": row["original_name"],
                    "type": row["file_type"],
                    "sharedBy": row["shared_by"],
                    "date": row["shared_at"],
                    "permission": row["permission"],
                }
                for row in rows
            ]
        }
    )


@app.get("/api/permissions")
@login_required
def list_permissions():
    rows = get_db().execute(
        """
        SELECT permissions.id, permissions.permission, permissions.status, permissions.created_at,
               documents.id AS document_id, documents.original_name, users.email AS recipient_email
        FROM permissions
        JOIN documents ON documents.id = permissions.document_id
        JOIN users ON users.id = permissions.recipient_id
        WHERE documents.owner_id = ? AND permissions.status = 'Active'
        ORDER BY permissions.created_at DESC
        """,
        (g.user["id"],),
    ).fetchall()
    return jsonify(
        {
            "permissions": [
                {
                    "id": row["id"],
                    "document_id": row["document_id"],
                    "document": row["original_name"],
                    "recipient": row["recipient_email"],
                    "permission": row["permission"],
                    "status": row["status"],
                    "created_at": row["created_at"],
                }
                for row in rows
            ]
        }
    )


@app.post("/api/permissions")
@csrf_required
def create_permission():
    data = json_object()
    if data is None:
        return json_error("Send sharing details as a JSON object.", 400)
    try:
        document_id = int(data.get("document_id"))
    except (TypeError, ValueError):
        return json_error("Choose a valid document.", 400)
    recipient_value = data.get("recipient_email", "")
    permission = data.get("permission")
    if not isinstance(recipient_value, str):
        return json_error("Enter a valid recipient email.", 400)
    recipient_email = recipient_value.strip().lower()
    if not EMAIL_PATTERN.fullmatch(recipient_email):
        return json_error("Enter a valid recipient email.", 400)
    if permission not in ("View", "Download"):
        return json_error("Choose View or Download permission.", 400)

    db = get_db()
    document = document_for_user(document_id, g.user["id"])
    if not document:
        return json_error("You can only share documents in your own vault.", 404)
    recipient = db.execute("SELECT id FROM users WHERE email = ?", (recipient_email,)).fetchone()
    if not recipient:
        return json_error("No TrustVault account exists for that email yet.", 404)
    if recipient["id"] == g.user["id"]:
        return json_error("You cannot share a document with yourself.", 400)

    existing = db.execute(
        "SELECT id FROM permissions WHERE document_id = ? AND recipient_id = ?",
        (document_id, recipient["id"]),
    ).fetchone()
    created_at = now_iso()
    if existing:
        db.execute(
            """
            UPDATE permissions SET permission = ?, status = 'Active', created_at = ?, revoked_at = NULL
            WHERE id = ?
            """,
            (permission, created_at, existing["id"]),
        )
    else:
        db.execute(
            """
            INSERT INTO permissions (document_id, recipient_id, permission, status, created_at)
            VALUES (?, ?, ?, 'Active', ?)
            """,
            (document_id, recipient["id"], permission, created_at),
        )
    log_event(g.user["id"], document_id, "Share")
    db.commit()
    return jsonify({"message": f"Document shared with {recipient_email}."}), 201


@app.delete("/api/permissions/<int:permission_id>")
@csrf_required
def revoke_permission(permission_id):
    db = get_db()
    row = db.execute(
        """
        SELECT permissions.id, permissions.document_id
        FROM permissions JOIN documents ON documents.id = permissions.document_id
        WHERE permissions.id = ? AND documents.owner_id = ? AND permissions.status = 'Active'
        """,
        (permission_id, g.user["id"]),
    ).fetchone()
    if not row:
        return json_error("Active permission not found.", 404)

    db.execute(
        "UPDATE permissions SET status = 'Revoked', revoked_at = ? WHERE id = ?",
        (now_iso(), permission_id),
    )
    log_event(g.user["id"], row["document_id"], "Revoke")
    db.commit()
    return jsonify({"message": "Access revoked."})


@app.get("/api/audit")
@login_required
def audit_history():
    action = request.args.get("action", "").strip()
    search = request.args.get("search", "").strip().lower()
    allowed_actions = {"Upload", "Download", "Share", "View", "Revoke"}
    if action and action not in allowed_actions:
        return json_error("Unknown audit action.", 400)

    rows = get_db().execute(
        """
        SELECT audit_events.action, audit_events.created_at, documents.original_name,
               users.full_name AS actor_name, users.email AS actor_email
        FROM audit_events
        LEFT JOIN documents ON documents.id = audit_events.document_id
        LEFT JOIN users ON users.id = audit_events.actor_id
        WHERE (audit_events.actor_id = ? OR documents.owner_id = ?)
        ORDER BY audit_events.created_at DESC LIMIT 500
        """,
        (g.user["id"], g.user["id"]),
    ).fetchall()
    records = []
    for row in rows:
        if action and row["action"] != action:
            continue
        record = {
            "action": row["action"],
            "actor": row["actor_name"] or row["actor_email"] or "Former user",
            "document": row["original_name"] or "Deleted document",
            "date": row["created_at"],
        }
        if search and search not in " ".join(record.values()).lower():
            continue
        records.append(record)
    return jsonify({"events": records})


initialize_database()


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=os.environ.get("TRUSTVAULT_DEBUG") == "true")
