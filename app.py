import os
import json
import base64
import requests
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
)
from dotenv import load_dotenv
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import pytz

# Load .env
load_dotenv()

# Config from environment
AWS_REGION = os.getenv("WS_REGION", "us-east-1")
DDB_TABLE = os.getenv("DDB_TABLE", "weather_station_thing_readings")
FLASK_SECRET = os.getenv("FLASK_SECRET")
DEVICE_ID = os.getenv("DEVICE_ID")
PORT = int(os.getenv("PORT", "5000"))

# Cognito config (Hosted UI)
# e.g. https://your-domain.auth.us-east-1.amazoncognito.com
COGNITO_DOMAIN = os.getenv("COGNITO_DOMAIN")
COGNITO_CLIENT_ID = os.getenv("COGNITO_CLIENT_ID")
COGNITO_CLIENT_SECRET = os.getenv("COGNITO_CLIENT_SECRET")
# must match configured redirect in Cognito
COGNITO_REDIRECT_URI = os.getenv("COGNITO_REDIRECT_URI")

if FLASK_SECRET is None:
    raise RuntimeError("FLASK_SECRET env var is required")

app = Flask(__name__)
app.secret_key = FLASK_SECRET
app.config.setdefault("PERMANENT_SESSION_LIFETIME", 7 * 24 * 3600)  # 7 days

# AWS resources
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(DDB_TABLE)

_iot_data_client = None


def get_iot_data_client():
    global _iot_data_client
    if _iot_data_client:
        return _iot_data_client

    iot = boto3.client("iot", region_name=AWS_REGION)
    resp = iot.describe_endpoint(endpointType="iot:Data-ATS")
    endpoint_addr = resp.get("endpointAddress")
    if not endpoint_addr:
        raise RuntimeError("Unable to determine IoT data endpoint")
    _iot_data_client = boto3.client(
        "iot-data", region_name=AWS_REGION, endpoint_url=f"https://{endpoint_addr}")
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


def login_required(f):
    """Decorator to require a logged-in user (session['user']). Redirects to /login with next param."""
    @wraps(f)
    def decorated(*args, **kwargs):
        if not session.get("user"):
            # preserve the original URL so user returns after login
            next_url = request.url
            return redirect(url_for("login") + "?" + urlencode({"next": next_url}))
        return f(*args, **kwargs)
    return decorated


@app.route("/")
def index():
    # If logged in, go to dashboard; otherwise redirect to login
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login")
def login():
    """
    Redirect user to Cognito Hosted UI.
    Accepts optional ?next=<url> to return the user after login.
    """
    if not all([COGNITO_DOMAIN, COGNITO_CLIENT_ID, COGNITO_REDIRECT_URI]):
        return "Cognito not configured. Set COGNITO_DOMAIN, COGNITO_CLIENT_ID, and COGNITO_REDIRECT_URI.", 500

    next_url = request.args.get("next") or url_for("dashboard", _external=True)

    params = {
        "response_type": "code",
        "client_id": COGNITO_CLIENT_ID,
        "redirect_uri": COGNITO_REDIRECT_URI,
        "scope": "openid email profile",
        # Put the next_url into state so we can redirect there after callback
        "state": next_url,
    }
    login_url = f"{COGNITO_DOMAIN}/login?{urlencode(params)}"
    return redirect(login_url)


@app.route("/callback")
def callback():
    """
    Cognito redirects back here with ?code=...&state=...
    Exchange the code for tokens and store user info in session.
    """
    code = request.args.get("code")
    state = request.args.get("state")  # our next URL
    if not code:
        flash("Missing authorization code from Cognito.", "danger")
        return redirect(url_for("index"))

    token_url = f"{COGNITO_DOMAIN}/oauth2/token"
    client_id = COGNITO_CLIENT_ID
    client_secret = COGNITO_CLIENT_SECRET
    redirect_uri = COGNITO_REDIRECT_URI

    # Basic auth header for client credentials
    auth_str = f"{client_id}:{client_secret or ''}"
    b64 = base64.b64encode(auth_str.encode()).decode()
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "Authorization": f"Basic {b64}",
    }

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
    }

    try:
        resp = requests.post(token_url, headers=headers, data=data, timeout=10)
    except Exception as e:
        flash(f"Token exchange request failed: {e}", "danger")
        return redirect(url_for("index"))

    if resp.status_code != 200:
        flash(
            f"Token exchange failed: {resp.status_code} {resp.text}", "danger")
        return redirect(url_for("index"))

    tokens = resp.json()
    id_token = tokens.get("id_token")
    if not id_token:
        flash("No id_token returned from Cognito.", "danger")
        return redirect(url_for("index"))

    # Decode JWT payload (no signature verification) to get user claims
    try:
        parts = id_token.split(".")
        if len(parts) < 2:
            raise ValueError("Invalid id_token format")
        payload_b64 = parts[1]
        # add padding if necessary
        rem = len(payload_b64) % 4
        if rem:
            payload_b64 += "=" * (4 - rem)
        payload_bytes = base64.urlsafe_b64decode(payload_b64)
        user_claims = json.loads(payload_bytes)
    except Exception as e:
        flash(f"Failed to decode id_token: {e}", "danger")
        return redirect(url_for("index"))

    # Store user info in session
    session["user"] = user_claims
    session.permanent = True

    # Redirect to original next URL if present
    next_url = state or url_for("dashboard")
    return redirect(next_url)


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
        return render_template(
            "dashboard.html",
            readings=[],
            device_id=None,
            page=1,
            per_page=per_page,
            start_idx=0,
            end_idx=0,
            has_next=False,
            has_prev=False,
            total_pages=1,
        )

    # FULL SCAN — collects all entries with matching thing_id
    results = []
    last_key = None

    try:
        while True:
            kwargs = {"Limit": 1000}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key
            # Try to project only payload for efficiency; fall back if fails
            try:
                resp = table.scan(**kwargs, ProjectionExpression="payload")
            except Exception:
                resp = table.scan(**kwargs)

            for item in resp.get("Items", []):
                parsed = parse_payload_item(item)
                if parsed and parsed.get("thing_id") == DEVICE_ID:
                    results.append(parsed)

            last_key = resp.get("LastEvaluatedKey")
            if not last_key:
                break

    except (BotoCoreError, ClientError) as e:
        flash(f"Error scanning DynamoDB: {e}", "danger")
        return render_template(
            "dashboard.html",
            readings=[],
            device_id=DEVICE_ID,
            page=1,
            per_page=per_page,
            start_idx=0,
            end_idx=0,
            has_next=False,
            has_prev=False,
            total_pages=1,
        )

    # Sort newest first
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

    has_prev = page > 1
    has_next = page < total_pages

    # Optionally pass current user's email/name to template for display
    user = session.get("user", {})
    return render_template(
        "dashboard.html",
        readings=page_items,
        device_id=DEVICE_ID,
        page=page,
        per_page=per_page,
        start_idx=start_idx + 1 if page_items else 0,
        end_idx=start_idx + len(page_items),
        has_prev=has_prev,
        has_next=has_next,
        total_pages=total_pages,
        user=user,
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
