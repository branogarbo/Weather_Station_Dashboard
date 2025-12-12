"""
app.py

RDS-backed auth with admin vs standard users, per-user/global theme persistence,
signup with password confirmation, admin activation workflow, DynamoDB dashboard,
MQTT publishing, and custom error pages (401/404/405).

Replace your broken file with this corrected version.
"""
import os
import json
from datetime import datetime
from functools import wraps
from urllib.parse import urlencode

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    session,
    abort,
    jsonify,
)
from dotenv import load_dotenv
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import pytz

# SQLAlchemy
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    func,
    Boolean,
    Text,
)
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import create_engine

# password hashing
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

# ---------------------
# Config
# ---------------------
AWS_REGION = os.getenv("WS_REGION", "us-east-1")
DDB_TABLE = os.getenv("DDB_TABLE", "weather_station_thing_readings")
FLASK_SECRET = os.getenv("FLASK_SECRET")
DEVICE_ID = os.getenv("DEVICE_ID")
PORT = int(os.getenv("PORT", "5000"))
DATABASE_URL = os.getenv("DATABASE_URL")

if not FLASK_SECRET:
    raise RuntimeError("FLASK_SECRET is required")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL is required")

app = Flask(__name__)
app.secret_key = FLASK_SECRET
app.config.setdefault("PERMANENT_SESSION_LIFETIME", 7 * 24 * 3600)

# ---------------------
# DB setup
# ---------------------
Base = declarative_base()
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(
    bind=engine, autoflush=False, autocommit=False, future=True)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=False, nullable=False)
    is_admin = Column(Boolean, default=False, nullable=False)
    theme = Column(String(64), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    activated_at = Column(DateTime(timezone=True), nullable=True)
    activated_by = Column(Integer, nullable=True)

    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


class Setting(Base):
    __tablename__ = "settings"
    key = Column(String(128), primary_key=True)
    value = Column(Text, nullable=True)


# create tables if needed
Base.metadata.create_all(bind=engine)

# ---------------------
# AWS resources
# ---------------------
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(DDB_TABLE)
_iot_data_client = None


def get_iot_data_client():
    global _iot_data_client
    if _iot_data_client:
        return _iot_data_client
    iot = boto3.client("iot", region_name=AWS_REGION)
    ep = iot.describe_endpoint(endpointType="iot:Data-ATS")["endpointAddress"]
    _iot_data_client = boto3.client(
        "iot-data", region_name=AWS_REGION, endpoint_url=f"https://{ep}")
    return _iot_data_client


def parse_payload_item(item):
    payload_raw = item.get("payload")
    if payload_raw is None:
        return None
    try:
        if isinstance(payload_raw, (bytes, bytearray)):
            data = json.loads(payload_raw.decode("utf-8"))
        elif isinstance(payload_raw, str):
            data = json.loads(payload_raw)
        elif isinstance(payload_raw, dict):
            data = payload_raw
        else:
            data = json.loads(str(payload_raw))
    except Exception:
        return None

    ts = data.get("timestamp")
    if ts:
        try:
            dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            data["_ts_dt"] = dt.astimezone(pytz.UTC)
        except Exception:
            data["_ts_dt"] = None
    else:
        data["_ts_dt"] = None
    return data


# ---------------------
# Helper functions
# ---------------------
def get_setting(key: str):
    db = SessionLocal()
    try:
        s = db.query(Setting).filter(Setting.key == key).first()
        return s.value if s else None
    finally:
        db.close()


def set_setting(key: str, value: str):
    db = SessionLocal()
    try:
        existing = db.query(Setting).filter(Setting.key == key).first()
        if existing:
            existing.value = value
            db.add(existing)
        else:
            s = Setting(key=key, value=value)
            db.add(s)
        db.commit()
        return True
    except SQLAlchemyError:
        db.rollback()
        return False
    finally:
        db.close()


def count_users():
    db = SessionLocal()
    try:
        return db.query(User).count()
    finally:
        db.close()


def create_user(email: str, password: str, is_admin: bool = False, is_active: bool = False, activated_by: int = None):
    hashed = generate_password_hash(
        password, method="pbkdf2:sha256", salt_length=16)
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            return None, "A user with that email already exists."
        user = User(email=email, password_hash=hashed,
                    is_admin=is_admin, is_active=is_active)
        if is_active:
            user.activated_at = datetime.utcnow()
            user.activated_by = activated_by
        db.add(user)
        db.commit()
        db.refresh(user)
        return user, None
    except SQLAlchemyError as e:
        db.rollback()
        return None, str(e)
    finally:
        db.close()


def authenticate_user(email: str, password: str):
    db = SessionLocal()
    try:
        user = db.query(User).filter(User.email == email).first()
        if user and user.verify_password(password):
            return user
        return None
    finally:
        db.close()


# ---------------------
# Decorators
# ---------------------
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("unauthorized"))
        db = SessionLocal()
        try:
            user = db.query(User).get(user_id)
            if not user or not user.is_active:
                session.clear()
                return redirect(url_for("unauthorized"))
        finally:
            db.close()
        return f(*args, **kwargs)
    return decorated


def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user_id = session.get("user_id")
        if not user_id:
            return redirect(url_for("unauthorized"))
        db = SessionLocal()
        try:
            user = db.query(User).get(user_id)
            if not user or not user.is_active or not user.is_admin:
                return redirect(url_for("unauthorized"))
        finally:
            db.close()
        return f(*args, **kwargs)
    return decorated


# ---------------------
# Context processor
# ---------------------
@app.context_processor
def inject_globals():
    device = DEVICE_ID or "—"
    server_theme = None
    user_theme = None
    uid = session.get("user_id")
    if uid:
        db = SessionLocal()
        try:
            u = db.query(User).get(uid)
            if u:
                user_theme = u.theme
        finally:
            db.close()
    if user_theme:
        server_theme = user_theme
    else:
        global_theme = get_setting("global_theme")
        if global_theme:
            server_theme = global_theme
    return dict(device_id=device, server_theme=server_theme)


# ---------------------
# Auth routes
# ---------------------
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        if password != confirm:
            flash("Passwords do not match.", "warning")
            return redirect(url_for("signup"))

        if not email or not password:
            flash("Provide an email and password.", "warning")
            return redirect(url_for("signup"))

        total = count_users()
        if total == 0:
            user, err = create_user(
                email, password, is_admin=True, is_active=True)
            if user:
                session["user_id"] = user.id
                session["user_email"] = user.email
                session["is_admin"] = True
                session.permanent = True
                flash(
                    "First user created and granted admin privileges. You're logged in.", "success")
                return redirect(url_for("dashboard"))
            else:
                flash(f"Signup failed: {err}", "danger")
                return redirect(url_for("signup"))
        else:
            user, err = create_user(
                email, password, is_admin=False, is_active=False)
            if user:
                flash(
                    "Signup successful. Your account is pending activation by an administrator.", "info")
                return redirect(url_for("login"))
            else:
                flash(f"Signup failed: {err}", "danger")
                return redirect(url_for("signup"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not email or not password:
            flash("Provide email and password.", "warning")
            return redirect(url_for("login"))
        user = authenticate_user(email, password)
        if not user:
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))
        if not user.is_active:
            flash(
                "Your account is not active. An administrator must activate your account.", "warning")
            return redirect(url_for("unauthorized"))
        session["user_id"] = user.id
        session["user_email"] = user.email
        session["is_admin"] = bool(user.is_admin)
        session.permanent = True
        flash("Logged in.", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/401")
def unauthorized():
    return render_template("401.html"), 401


@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return render_template("405.html"), 405


# ---------------------
# Admin routes
# ---------------------
@app.route("/admin/users", methods=["GET"])
@admin_required
def admin_list_users():
    db = SessionLocal()
    try:
        users = db.query(User).order_by(User.created_at.desc()).all()
        global_theme = get_setting("global_theme")
        return render_template("admin_users.html", users=users, current_user_id=session.get("user_id"), global_theme=global_theme)
    finally:
        db.close()


@app.route("/admin/users/<int:user_id>/toggle", methods=["POST"])
@admin_required
def admin_toggle_user(user_id):
    admin_id = session.get("user_id")
    if admin_id == user_id:
        flash("You cannot change your own activation status.", "warning")
        return redirect(url_for("admin_list_users"))
    db = SessionLocal()
    try:
        user = db.query(User).get(user_id)
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("admin_list_users"))
        user.is_active = not user.is_active
        user.activated_by = admin_id
        user.activated_at = datetime.utcnow() if user.is_active else None
        db.add(user)
        db.commit()
        flash(
            f"User {user.email} is now {'active' if user.is_active else 'inactive'}.", "success")
    except SQLAlchemyError as e:
        db.rollback()
        flash(f"Failed to update user: {e}", "danger")
    finally:
        db.close()
    return redirect(url_for("admin_list_users"))


@app.route("/admin/users/<int:user_id>/set_theme", methods=["POST"])
@admin_required
def admin_set_user_theme(user_id):
    theme = request.form.get("theme") or ""
    db = SessionLocal()
    try:
        user = db.query(User).get(user_id)
        if not user:
            flash("User not found.", "danger")
            return redirect(url_for("admin_list_users"))
        user.theme = theme or None
        db.add(user)
        db.commit()
        flash(
            f"Set theme for {user.email} to '{theme or 'default'}'.", "success")
    except SQLAlchemyError as e:
        db.rollback()
        flash(f"Failed to set theme: {e}", "danger")
    finally:
        db.close()
    return redirect(url_for("admin_list_users"))


@app.route("/admin/global_theme", methods=["POST"])
@admin_required
def admin_set_global_theme():
    theme = request.form.get("global_theme") or ""
    ok = set_setting("global_theme", theme or "")
    if ok:
        flash(f"Global theme set to '{theme or 'default'}'.", "success")
    else:
        flash("Failed to set global theme.", "danger")
    return redirect(url_for("admin_list_users"))


# ---------------------
# User theme API
# ---------------------
@app.route("/me/theme", methods=["POST"])
@login_required
def set_my_theme():
    theme = request.form.get("theme")
    if theme is None:
        return jsonify({"ok": False, "error": "missing theme"}), 400
    uid = session.get("user_id")
    db = SessionLocal()
    try:
        user = db.query(User).get(uid)
        if not user:
            return jsonify({"ok": False, "error": "user not found"}), 404
        user.theme = theme or None
        db.add(user)
        db.commit()
        return jsonify({"ok": True, "theme": theme}), 200
    except SQLAlchemyError as e:
        db.rollback()
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        db.close()


# ---------------------
# App routes
# ---------------------
@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET"])
@login_required
def dashboard():
    page = request.args.get("page", type=int) or 1
    per_page = request.args.get("per_page", type=int) or 10
    per_page = max(1, min(per_page, 200))
    if page < 1:
        page = 1

    if not DEVICE_ID:
        flash("DEVICE_ID missing in configuration.", "danger")
        return render_template("dashboard.html", readings=[], device_id=None)

    results = []
    last_key = None

    try:
        while True:
            params = {"Limit": 1000}
            if last_key:
                params["ExclusiveStartKey"] = last_key
            try:
                resp = table.scan(**params, ProjectionExpression="payload")
            except Exception:
                resp = table.scan(**params)

            for item in resp.get("Items", []):
                parsed = parse_payload_item(item)
                if parsed and parsed.get("thing_id") == DEVICE_ID:
                    results.append(parsed)

            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break
    except (BotoCoreError, ClientError) as e:
        flash(f"Error reading from DynamoDB: {e}", "danger")
        return render_template("dashboard.html", readings=[], device_id=DEVICE_ID)

    results.sort(key=lambda r: (r.get("_ts_dt") is None,
                 r.get("_ts_dt")), reverse=True)
    total_items = len(results)
    total_pages = max(1, (total_items + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages

    start_idx = (page - 1) * per_page
    end_idx = start_idx + per_page
    page_items = results[start_idx:end_idx]

    for r in page_items:
        dt = r.get("_ts_dt")
        r["_ts_display"] = dt.isoformat() if dt else r.get("timestamp", "—")

    return render_template(
        "dashboard.html",
        readings=page_items,
        device_id=DEVICE_ID,
        page=page,
        per_page=per_page,
        start_idx=start_idx + 1 if page_items else 0,
        end_idx=start_idx + len(page_items),
        has_prev=(page > 1),
        has_next=(page < total_pages),
        total_pages=total_pages,
        user_email=session.get("user_email"),
        is_admin=session.get("is_admin", False),
    )


@app.route("/publish", methods=["POST"])
@login_required
def publish_command():
    topic = request.form.get("topic") or "mesa/weather/readings"
    payload_text = request.form.get("payload", "").strip()
    command_text = request.form.get("command", "").strip()
    if not payload_text and not command_text:
        flash("Provide a command or JSON payload.", "warning")
        return redirect(url_for("dashboard"))

    try:
        publish_payload = json.dumps(json.loads(
            payload_text)) if payload_text else json.dumps({"command": command_text})
    except Exception:
        publish_payload = payload_text

    try:
        client = get_iot_data_client()
        client.publish(topic=topic, qos=0,
                       payload=publish_payload.encode("utf-8"))
        flash(f"Published to {topic}", "success")
    except Exception as e:
        flash(f"Publish failed: {e}", "danger")

    return redirect(url_for("dashboard"))


# ---------------------
# Run
# ---------------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
