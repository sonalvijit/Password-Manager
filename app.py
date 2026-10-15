"""A small, local password manager built with Flask and SQLite."""

import base64
import csv
import hashlib
import hmac
import io
import json
import os
import secrets
import sqlite3
import threading
import time
import webbrowser
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, Response, abort, flash, redirect, render_template, request, session, url_for


BASE_DIR = Path(__file__).resolve().parent
DB_PATH = Path(os.environ.get("PASSWORD_MANAGER_DB", BASE_DIR / "passwords.sqlite3"))
PBKDF2_ITERATIONS = 600_000
UNLOCKED_VAULTS = {}
UNLOCK_LOCK = threading.Lock()

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY") or secrets.token_hex(32)
app.config.update(SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax", MAX_CONTENT_LENGTH=10 * 1024 * 1024)


def connect_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with connect_db() as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)")
        conn.execute(
            """CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                encrypted_data BLOB NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )"""
        )


def get_setting(key):
    with connect_db() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row["value"] if row else None


def derive(password, salt, purpose):
    material = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt + purpose, PBKDF2_ITERATIONS, dklen=32)
    return base64.urlsafe_b64encode(material)


def current_fernet():
    token = session.get("vault_token")
    if not token:
        return None
    with UNLOCK_LOCK:
        return UNLOCKED_VAULTS.get(token)


def require_vault():
    fernet = current_fernet()
    if not fernet:
        session.clear()
        return None
    return fernet


def get_existing_tags(fernet):
    with connect_db() as conn:
        rows = conn.execute("SELECT encrypted_data FROM entries").fetchall()
    tags_by_key = {}
    for row in rows:
        try:
            item = json.loads(fernet.decrypt(row["encrypted_data"]).decode("utf-8"))
        except (InvalidToken, ValueError, UnicodeDecodeError):
            continue
        tags = item.get("tags", [])
        if isinstance(tags, list):
            for tag in tags:
                if isinstance(tag, str) and tag.strip():
                    tags_by_key.setdefault(tag.strip().casefold(), tag.strip())
    return sorted(tags_by_key.values(), key=str.casefold)


def get_existing_values(fernet, key):
    with connect_db() as conn:
        rows = conn.execute("SELECT encrypted_data FROM entries").fetchall()
    values_by_key = {}
    for row in rows:
        try:
            item = json.loads(fernet.decrypt(row["encrypted_data"]).decode("utf-8"))
        except (InvalidToken, ValueError, UnicodeDecodeError):
            continue
        candidates = [item.get(key, "")]
        if key == "username":
            candidates.extend(
                identifier.get("value", "") for identifier in item.get("login_ids", [])
                if isinstance(identifier, dict)
            )
        for value in candidates:
            if isinstance(value, str) and value.strip():
                values_by_key.setdefault(value.strip().casefold(), value.strip())
    return sorted(values_by_key.values(), key=str.casefold)


def get_form_custom_fields(form):
    names = form.getlist("custom_field_name")
    values = form.getlist("custom_field_value")
    hidden_values = form.getlist("custom_field_hidden")
    fields = []
    for index, (name, value) in enumerate(zip(names, values)):
        name = name.strip()
        if name:
            hidden = hidden_values[index] != "0" if index < len(hidden_values) else True
            fields.append({"name": name, "value": value, "hidden": hidden})
    return fields


def get_form_login_ids(form):
    types = form.getlist("login_id_type")
    values = form.getlist("login_id_value")
    identifiers = []
    for kind, value in zip(types, values):
        value = value.strip()
        if value:
            identifiers.append({"type": kind.strip() or "Login ID", "value": value})
    return identifiers


def safe_http_url(value):
    if not isinstance(value, str) or not value.strip():
        return ""
    try:
        parsed = urlsplit(value.strip())
        if parsed.scheme.lower() in ("http", "https") and parsed.hostname:
            return value.strip()
    except ValueError:
        pass
    return ""


def import_file_records(upload):
    filename = (upload.filename or "").lower()
    content = upload.read().decode("utf-8-sig")
    if filename.endswith(".json"):
        data = json.loads(content)
        if isinstance(data, dict):
            data = data.get("entries", data.get("passwords", data.get("credentials", [data])))
    elif filename.endswith(".csv"):
        data = list(csv.DictReader(io.StringIO(content)))
    else:
        raise ValueError("Choose a JSON or CSV file.")
    if not isinstance(data, list) or any(not isinstance(row, dict) for row in data):
        raise ValueError("The file must contain a list of password entries.")
    return data


def import_text(value):
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False)
    return str(value)


def flatten_import_fields(value, prefix=""):
    fields = []
    if isinstance(value, dict):
        for key, child in value.items():
            label = f"{prefix} / {key}" if prefix else str(key)
            fields.extend(flatten_import_fields(child, label))
    elif isinstance(value, list):
        for index, child in enumerate(value, start=1):
            label = f"{prefix} / {index}" if prefix else str(index)
            fields.extend(flatten_import_fields(child, label))
    elif prefix:
        fields.append({"name": prefix, "value": import_text(value), "hidden": True})
    return fields


def normalize_import_record(record):
    normalized = {str(key).strip().casefold().replace(" ", "_"): value for key, value in record.items() if key is not None}

    def first(*keys):
        for key in keys:
            value = normalized.get(key)
            if value is not None and value != "":
                return value
        return ""

    site = import_text(first("website", "website_name", "site", "title", "platform", "pltform", "service", "name")).strip()
    password = import_text(first("password", "pwd", "pass"))
    if not site or not password.strip():
        return None

    login_ids = []
    raw_ids = first("login_ids", "identifiers")
    if isinstance(raw_ids, str):
        try:
            raw_ids = json.loads(raw_ids)
        except ValueError:
            raw_ids = [raw_ids]
    if isinstance(raw_ids, dict):
        raw_ids = [{"type": kind, "value": value} for kind, value in raw_ids.items()]
    if not isinstance(raw_ids, list):
        raw_ids = []
    for identifier in raw_ids:
        if isinstance(identifier, dict):
            kind = import_text(identifier.get("type", "Login ID")).strip() or "Login ID"
            value = import_text(identifier.get("value", identifier.get("id", ""))).strip()
        else:
            kind, value = "Login ID", import_text(identifier).strip()
        if value:
            login_ids.append({"type": kind, "value": value})
    for kind, keys in (("Username", ("username", "user", "login")), ("Email", ("email",)), ("Phone", ("phone", "mobile")), ("ID", ("id", "account_id", "login_id"))):
        value = import_text(first(*keys)).strip()
        if value and value.casefold() not in {item["value"].casefold() for item in login_ids}:
            login_ids.append({"type": kind, "value": value})

    raw_tags = first("tags", "tag")
    if isinstance(raw_tags, str):
        try:
            parsed_tags = json.loads(raw_tags)
            raw_tags = parsed_tags if isinstance(parsed_tags, list) else raw_tags.split(",")
        except ValueError:
            raw_tags = raw_tags.split(",")
    tags = list(dict.fromkeys(import_text(tag).strip() for tag in raw_tags if import_text(tag).strip())) if isinstance(raw_tags, list) else []

    raw_custom = first("custom_fields", "additional_fields")
    if isinstance(raw_custom, str):
        try:
            raw_custom = json.loads(raw_custom)
        except ValueError:
            raw_custom = []
    custom_fields = []
    if isinstance(raw_custom, list):
        for field in raw_custom:
            if isinstance(field, dict) and field.get("name"):
                custom_fields.append({
                    "name": import_text(field["name"]),
                    "value": import_text(field.get("value", "")),
                    "hidden": field.get("hidden", True) is not False,
                })
    elif isinstance(raw_custom, dict):
        custom_fields.extend(flatten_import_fields(raw_custom))

    known = {
        "website", "website_name", "site", "title", "platform", "pltform", "service", "name",
        "website_url", "site_url", "url", "uri", "login_ids", "identifiers", "username", "user", "login",
        "email", "phone", "mobile", "id", "account_id", "login_id", "password", "pwd", "pass",
        "tags", "tag", "notes", "note", "custom_fields", "additional_fields", "verified", "verification_status",
        "created_at", "updated_at",
    }
    for key, value in record.items():
        normalized_key = str(key).strip().casefold().replace(" ", "_")
        if normalized_key not in known and value not in (None, ""):
            custom_fields.extend(flatten_import_fields(value, str(key)))

    verified = first("verified", "verification_status")
    is_verified = verified is True or (isinstance(verified, str) and verified.casefold() == "verified")
    return {
        "site": site,
        "site_url": import_text(first("website_url", "site_url", "url", "uri")).strip(),
        "login_ids": login_ids,
        "username": login_ids[0]["value"] if login_ids else "",
        "password": password,
        "tags": tags,
        "notes": import_text(first("notes", "note")),
        "custom_fields": custom_fields,
        "verified": is_verified,
    }


@app.before_request
def csrf_guard():
    if request.method == "POST" and request.endpoint not in ("setup", "login"):
        if not session.get("csrf_token") or not hmac.compare_digest(
            request.form.get("csrf_token", ""), session["csrf_token"]
        ):
            abort(400, "Invalid form token. Reload the page and try again.")


@app.context_processor
def inject_csrf():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return {"csrf_token": session["csrf_token"]}


@app.route("/", methods=["GET"])
def index():
    if not get_setting("salt"):
        return redirect(url_for("setup"))
    fernet = require_vault()
    if not fernet:
        return redirect(url_for("login"))

    query = request.args.get("q", "").strip().casefold()
    selected_tag = request.args.get("tag", "").strip().casefold()
    selected_status = request.args.get("status", "").strip().casefold()
    with connect_db() as conn:
        rows = conn.execute("SELECT id, encrypted_data, updated_at FROM entries ORDER BY updated_at DESC, id DESC").fetchall()
    entries = []
    all_tags = set()
    verified_count = 0
    for row in rows:
        try:
            fields = row["encrypted_data"]
            import json
            item = json.loads(fernet.decrypt(fields).decode("utf-8"))
        except (InvalidToken, ValueError, UnicodeDecodeError):
            continue
        if item.get("verified") is True:
            verified_count += 1
        item_tags = item.get("tags", [])
        if not isinstance(item_tags, list):
            item_tags = []
        all_tags.update(tag.strip() for tag in item_tags if isinstance(tag, str) and tag.strip())
        searchable = [item.get(k, "").casefold() for k in ("site", "username", "notes")]
        searchable.append(item.get("site_url", "").casefold())
        searchable.extend(
            identifier.get("value", "").casefold()
            for identifier in item.get("login_ids", [])
            if isinstance(identifier, dict) and isinstance(identifier.get("value", ""), str)
        )
        searchable.extend(
            identifier.get("type", "").casefold()
            for identifier in item.get("login_ids", [])
            if isinstance(identifier, dict) and isinstance(identifier.get("type", ""), str)
        )
        searchable.extend(tag.casefold() for tag in item_tags if isinstance(tag, str))
        for custom_field in item.get("custom_fields", []):
            if isinstance(custom_field, dict):
                searchable.extend(
                    value.casefold() for value in (custom_field.get("name", ""), custom_field.get("value", ""))
                    if isinstance(value, str)
                )
        query_matches = not query or any(query in field for field in searchable)
        tag_matches = not selected_tag or any(
            isinstance(tag, str) and tag.casefold() == selected_tag for tag in item_tags
        )
        verified = item.get("verified") is True
        status_matches = not selected_status or (selected_status == "verified" and verified) or (
            selected_status == "unverified" and not verified
        )
        if query_matches and tag_matches and status_matches:
            entries.append({
                "id": row["id"], **item,
                "verified": item.get("verified") is True,
                "site_href": safe_http_url(item.get("site_url", "")),
                "updated_at": row["updated_at"],
            })
    return render_template(
        "index.html",
        entries=entries,
        total_count=len(rows),
        verified_count=verified_count,
        unverified_count=max(0, len(rows) - verified_count),
        query=request.args.get("q", ""),
        tags=sorted(all_tags, key=str.casefold),
        selected_tag=request.args.get("tag", ""),
        selected_status=selected_status,
    )


@app.route("/setup", methods=["GET", "POST"])
def setup():
    if get_setting("salt"):
        return redirect(url_for("login"))
    if request.method == "POST":
        password = request.form.get("master_password", "")
        confirm = request.form.get("confirm_password", "")
        if len(password) < 4:
            flash("Choose a master password with at least 4 characters.", "error")
        elif password != confirm:
            flash("The passwords do not match.", "error")
        else:
            salt = secrets.token_bytes(16)
            verifier = derive(password, salt, b"password-manager-verifier").decode("ascii")
            with connect_db() as conn:
                conn.executemany("INSERT INTO settings(key, value) VALUES(?, ?)", [
                    ("salt", base64.b64encode(salt).decode("ascii")), ("verifier", verifier)
                ])
            unlock(password, salt)
            return redirect(url_for("index"))
    return render_template("setup.html")


def unlock(password, salt):
    token = secrets.token_urlsafe(32)
    fernet = Fernet(derive(password, salt, b"password-manager-encryption"))
    with UNLOCK_LOCK:
        UNLOCKED_VAULTS[token] = fernet
    session.clear()
    session["vault_token"] = token
    session["csrf_token"] = secrets.token_urlsafe(32)


@app.route("/login", methods=["GET", "POST"])
def login():
    salt_setting = get_setting("salt")
    if not salt_setting:
        return redirect(url_for("setup"))
    if current_fernet():
        return redirect(url_for("index"))
    if request.method == "POST":
        password = request.form.get("master_password", "")
        salt = base64.b64decode(salt_setting)
        verifier = derive(password, salt, b"password-manager-verifier").decode("ascii")
        if hmac.compare_digest(verifier, get_setting("verifier") or ""):
            unlock(password, salt)
            return redirect(url_for("index"))
        flash("Incorrect master password.", "error")
    return render_template("login.html")


@app.post("/logout")
def logout():
    token = session.get("vault_token")
    with UNLOCK_LOCK:
        if token:
            UNLOCKED_VAULTS.pop(token, None)
    session.clear()
    return redirect(url_for("login"))


def save_entry(fernet, values, entry_id=None):
    import json
    payload = {key: values.get(key, "").strip() for key in ("site", "site_url", "username", "notes")}
    payload["password"] = values.get("password", "")
    payload["verified"] = entry_id is not None and values.get("verification_status") == "verified"
    payload["login_ids"] = get_form_login_ids(values)
    payload["username"] = payload["login_ids"][0]["value"] if payload["login_ids"] else ""
    payload["tags"] = list(dict.fromkeys(
        tag.strip() for tag in values.get("tags", "").split(",") if tag.strip()
    ))
    payload["custom_fields"] = get_form_custom_fields(values)
    if not payload["site"] or not payload["password"].strip():
        return False
    encrypted = fernet.encrypt(json.dumps(payload, ensure_ascii=False).encode("utf-8"))
    with connect_db() as conn:
        if entry_id is None:
            conn.execute("INSERT INTO entries(encrypted_data) VALUES(?)", (encrypted,))
        else:
            result = conn.execute(
                "UPDATE entries SET encrypted_data = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?",
                (encrypted, entry_id),
            )
            if result.rowcount == 0:
                abort(404)
    return True


@app.route("/add", methods=["GET", "POST"])
def add_entry():
    fernet = require_vault()
    if not fernet:
        return redirect(url_for("login"))
    if request.method == "POST":
        if save_entry(fernet, request.form):
            flash("Password saved.", "success")
            return redirect(url_for("index"))
        flash("Website and password are required.", "error")
        entry = dict(request.form)
        entry["custom_fields"] = get_form_custom_fields(request.form)
        entry["tags"] = request.form.get("tags", "").split(",")
        entry["login_ids"] = get_form_login_ids(request.form)
    else:
        entry = None
    return render_template(
        "entry_form.html", entry=entry, heading="Add password", is_edit=False,
        existing_tags=get_existing_tags(fernet),
        existing_sites=get_existing_values(fernet, "site"),
      existing_urls=get_existing_values(fernet, "site_url"),
        existing_usernames=get_existing_values(fernet, "username"),
    )


@app.route("/edit/<int:entry_id>", methods=["GET", "POST"])
def edit_entry(entry_id):
    fernet = require_vault()
    if not fernet:
        return redirect(url_for("login"))
    import json
    with connect_db() as conn:
        row = conn.execute("SELECT encrypted_data FROM entries WHERE id = ?", (entry_id,)).fetchone()
    if not row:
        abort(404)
    try:
        entry = json.loads(fernet.decrypt(row["encrypted_data"]).decode("utf-8"))
    except InvalidToken:
        abort(500, "Could not decrypt this vault entry.")
    if not entry.get("login_ids") and entry.get("username"):
        entry["login_ids"] = [{"type": "Login ID", "value": entry["username"]}]
    elif not entry.get("login_ids"):
        entry["login_ids"] = []
    if request.method == "POST":
        if save_entry(fernet, request.form, entry_id):
            flash("Password updated.", "success")
            return redirect(url_for("index"))
        flash("Website and password are required.", "error")
        entry = dict(request.form)
        entry["custom_fields"] = get_form_custom_fields(request.form)
        entry["tags"] = request.form.get("tags", "").split(",")
        entry["login_ids"] = get_form_login_ids(request.form)
    return render_template(
        "entry_form.html", entry=entry, heading="Update password", is_edit=True,
        existing_tags=get_existing_tags(fernet),
        existing_sites=get_existing_values(fernet, "site"),
      existing_urls=get_existing_values(fernet, "site_url"),
        existing_usernames=get_existing_values(fernet, "username"),
    )


@app.post("/delete/<int:entry_id>")
def delete_entry(entry_id):
    if not require_vault():
        return redirect(url_for("login"))
    with connect_db() as conn:
        conn.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
    flash("Password deleted.", "success")
    return redirect(url_for("index"))


def decrypted_export_rows(fernet):
    with connect_db() as conn:
        rows = conn.execute(
            "SELECT id, encrypted_data, created_at, updated_at FROM entries ORDER BY id"
        ).fetchall()
    entries = []
    for row in rows:
        try:
            item = json.loads(fernet.decrypt(row["encrypted_data"]).decode("utf-8"))
        except (InvalidToken, ValueError, UnicodeDecodeError):
            abort(500, "Could not export the vault because an entry could not be decrypted.")
        entries.append({
            "website": item.get("site", ""),
            "website_url": item.get("site_url", ""),
            "login_ids": item.get("login_ids", []),
            "username": item.get("username", ""),
            "password": item.get("password", ""),
            "tags": item.get("tags", []),
            "notes": item.get("notes", ""),
            "custom_fields": item.get("custom_fields", []),
            "verification_status": "verified" if item.get("verified") is True else "unverified",
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
        })
    return entries


@app.get("/export/json")
def export_json():
    fernet = require_vault()
    if not fernet:
        return redirect(url_for("login"))
    content = json.dumps({"entries": decrypted_export_rows(fernet)}, ensure_ascii=False, indent=2)
    response = Response(content, content_type="application/json; charset=utf-8")
    response.headers["Content-Disposition"] = 'attachment; filename="keybox-passwords.json"'
    response.headers["Cache-Control"] = "no-store"
    return response


@app.get("/export/csv")
def export_csv():
    fernet = require_vault()
    if not fernet:
        return redirect(url_for("login"))
    entries = decrypted_export_rows(fernet)
    columns = [
        "website", "website_url", "login_ids", "username", "password", "tags",
        "notes", "custom_fields", "verification_status", "created_at", "updated_at",
    ]
    buffer = io.StringIO(newline="")
    writer = csv.DictWriter(buffer, fieldnames=columns, lineterminator="\r\n")
    writer.writeheader()
    for entry in entries:
        row = dict(entry)
        for column in ("login_ids", "tags", "custom_fields"):
            row[column] = json.dumps(row[column], ensure_ascii=False)
        writer.writerow(row)
    response = Response(buffer.getvalue(), content_type="text/csv; charset=utf-8")
    response.headers["Content-Disposition"] = 'attachment; filename="keybox-passwords.csv"'
    response.headers["Cache-Control"] = "no-store"
    return response


@app.post("/import")
def import_vault():
    fernet = require_vault()
    if not fernet:
        return redirect(url_for("login"))
    upload = request.files.get("file")
    if not upload or not upload.filename:
        flash("Choose a JSON or CSV file to import.", "error")
        return redirect(url_for("index"))
    try:
        source_records = import_file_records(upload)
    except (UnicodeDecodeError, json.JSONDecodeError, csv.Error, ValueError):
        flash("Could not read that file. Choose a valid JSON or CSV password export.", "error")
        return redirect(url_for("index"))
    normalized_records = [normalize_import_record(record) for record in source_records]
    valid_records = [record for record in normalized_records if record is not None]
    skipped = len(source_records) - len(valid_records)
    if not valid_records:
        flash("No valid password entries were found in that file.", "error")
        return redirect(url_for("index"))
    encrypted_records = [
        (fernet.encrypt(json.dumps(record, ensure_ascii=False).encode("utf-8")),)
        for record in valid_records
    ]
    with connect_db() as conn:
        conn.executemany("INSERT INTO entries(encrypted_data) VALUES(?)", encrypted_records)
    message = f"Imported {len(valid_records)} {('entry' if len(valid_records) == 1 else 'entries')}."
    if skipped:
        message += f" Skipped {skipped} invalid row(s)."
    flash(message, "success")
    return redirect(url_for("index"))


init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", "54327"))
    url = f"http://127.0.0.1:{port}"
    # Give Flask's development server a moment to bind before opening the page.
    threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    app.run(host="127.0.0.1", port=port, debug=True, use_reloader=False)
