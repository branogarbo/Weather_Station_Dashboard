"""
app.py

RDS-backed auth + protected routes.
Unauthenticated access to protected routes -> redirect to 401 page.
Unknown routes -> 404 page.

Requires environment variables in .env:
- WS_REGION, DDB_TABLE, FLASK_SECRET, DEVICE_ID, PORT
- DATABASE_URL (SQLAlchemy URL for your RDS)
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
)
from dotenv import load_dotenv
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import pytz

# SQLAlchemy
from sqlalchemy import Column, Integer, String, DateTime, func
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import declarative_base, sessionmaker
from sqlalchemy import create_engine

# password hashing
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

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

# SQLAlchemy
Base = declarative_base()
engine = create_engine(DATABASE_URL, pool_pre_ping=True, future=True)
SessionLocal = sessionmaker(
    bind=engine, autoflush=False, autocommit=False, future=True)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String(255), unique=True, index=True)
    password_hash = Column(String(255), nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    def verify_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)


Base.metadata.create_all(bind=engine)

# AWS / DynamoDB / IoT
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


# Authentication helpers
def create_user(email: str, password: str):
    hashed = generate_password_hash(
        password, method="pbkdf2:sha256", salt_length=16)
    db = SessionLocal()
    try:
        existing = db.query(User).filter(User.email == email).first()
        if existing:
            return None, "User already exists."
        user = User(email=email, password_hash=hashed)
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


# NOTE: Protected routes now redirect to the 401 page for unauthenticated access.
def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if "user_id" not in session:
            # redirect to 401 page (not to login) per your requirement
            return redirect(url_for("unauthorized"))
        return f(*args, **kwargs)
    return decorated


# Auth routes (signup, login)
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not email or not password:
            flash("Provide email and password.", "warning")
            return redirect(url_for("signup"))
        user, err = create_user(email, password)
        if user:
            session["user_id"] = user.id
            session["user_email"] = user.email
            session.permanent = True
            flash("Signup successful. You are now logged in.", "success")
            return redirect(url_for("dashboard"))
        else:
            flash(f"Signup failed: {err}", "danger")
            return redirect(url_for("signup"))
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    # GET shows login form; POST attempts authentication
    if request.method == "POST":
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        if not email or not password:
            flash("Provide email and password.", "warning")
            return redirect(url_for("login"))
        user = authenticate_user(email, password)
        if user:
            session["user_id"] = user.id
            session["user_email"] = user.email
            session.permanent = True
            flash("Logged in.", "success")
            # After login, go to dashboard
            return redirect(url_for("dashboard"))
        else:
            flash("Invalid email or password.", "danger")
            return redirect(url_for("login"))
    return render_template("login.html")


# Explicit 401 page route
@app.route("/401")
def unauthorized():
    # Use 401 status for the response
    return render_template("401.html"), 401


# 404 handler: custom page
@app.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"), 404


# Logout route (you allowed adding it)
@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# App routes (protected)
@app.route("/")
def index():
    if session.get("user_id"):
        return redirect(url_for("dashboard"))
    return render_template("login.html")


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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
