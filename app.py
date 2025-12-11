from boto3.dynamodb.conditions import Attr
import boto3
from flask import Flask, render_template, request, jsonify, flash, redirect, url_for, session

import os
import uuid
import decimal
import json
import base64
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser
from authlib.integrations.flask_client import OAuth


from dotenv import load_dotenv
load_dotenv()


# ---------- Configuration ----------
DYNAMODB_TABLE = os.environ.get("DDB_TABLE", "weather_station_thing_readings")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
# still available if you want to restrict UI
DEVICE_ID = os.environ.get("DEVICE_ID", None)
FLASK_SECRET = os.environ.get("FLASK_SECRET", "dev-secret")


# ---------- Flask app ----------
app = Flask(__name__)
app.secret_key = FLASK_SECRET
app.config["DDB_TABLE"] = DYNAMODB_TABLE
app.config["DEVICE_ID"] = DEVICE_ID

# ---------- DynamoDB init ----------
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(DYNAMODB_TABLE)

# -------------------------------

oauth = OAuth(app)


oauth.register(
    name='oidc',
    authority='https://cognito-idp.us-east-1.amazonaws.com/us-east-1_aCQtIuz03',
    client_id='73thd11qu94teddjel6l97g48j',
    client_secret='ojisjsmnkih0msihecveelgv1lf7ei5rbpim8fi2s39hl20v06n',
    server_metadata_url='https://cognito-idp.us-east-1.amazonaws.com/us-east-1_aCQtIuz03/.well-known/openid-configuration',
    client_kwargs={'scope': 'phone openid email'}
)


# ---------- Helpers ----------


def to_datetime(ts):
    """Return aware UTC datetime or None. Accept ISO strings or epoch numbers."""
    if ts is None:
        return None
    if isinstance(ts, (int, float, decimal.Decimal)):
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except Exception:
            return None
    if isinstance(ts, str):
        # try ISO parse then numeric fallback
        try:
            dt = dateutil_parser.isoparse(ts)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            try:
                return datetime.fromtimestamp(float(ts), tz=timezone.utc)
            except Exception:
                return None
    return None


def decimal_to_native(o):
    """Convert Decimal recursively to int/float for JSON/templates."""
    if isinstance(o, dict):
        return {k: decimal_to_native(v) for k, v in o.items()}
    if isinstance(o, list):
        return [decimal_to_native(v) for v in o]
    if isinstance(o, decimal.Decimal):
        if o % 1 == 0:
            return int(o)
        return float(o)
    return o


def unwrap_attrvalue(av):
    """Convert DynamoDB AttributeValue to native Python types (recursive)."""
    if not isinstance(av, dict):
        return av
    if len(av) == 1:
        k = next(iter(av.keys()))
        v = av[k]
        if k == "N":
            try:
                if '.' in str(v) or 'e' in str(v).lower():
                    return float(v)
                return int(v)
            except Exception:
                try:
                    return float(v)
                except Exception:
                    return v
        if k == "S":
            return v
        if k == "BOOL":
            return bool(v)
        if k == "NULL":
            return None
        if k == "M":
            return {kk: unwrap_attrvalue(vv) for kk, vv in v.items()}
        if k == "L":
            return [unwrap_attrvalue(x) for x in v]
        return v
    # If a dict with multiple keys, try to unwrap each inner value
    return {kk: unwrap_attrvalue(vv) for kk, vv in av.items()}


def normalize_item(item):
    """
    Normalize a DynamoDB item into a dict with top-level fields:
    temperature, humidity, pressure, battery, thing_id, timestamp, id.
    Handles 'payload' that may be a DynamoDB AttributeValue map or a JSON string.
    """
    out = dict(item) if isinstance(item, dict) else {}
    out = decimal_to_native(out)

    payload = out.get("payload")
    if payload is not None:
        payload_parsed = None
        if isinstance(payload, str):
            try:
                payload_parsed = json.loads(payload)
            except Exception:
                payload_parsed = None
        else:
            payload_parsed = payload

        extracted = {}
        if isinstance(payload_parsed, dict):
            is_av_map = any(isinstance(v, dict) and any(k in v for k in (
                "N", "S", "M", "L", "BOOL", "NULL")) for v in payload_parsed.values())
            if is_av_map:
                for k, v in payload_parsed.items():
                    extracted[k] = unwrap_attrvalue(v)
            else:
                for k, v in payload_parsed.items():
                    extracted[k] = v
        for k, v in extracted.items():
            out[k] = v

    # Unwrap top-level AttributeValue-shaped fields if present
    for k in ["temperature", "humidity", "pressure", "battery", "thing_id", "timestamp"]:
        if k in out and isinstance(out[k], dict):
            out[k] = unwrap_attrvalue(out[k])

    # Aliases
    if "thing_id" not in out:
        for alt in ("ThingName", "thing", "device_id", "deviceId"):
            if alt in out:
                out["thing_id"] = out.get(alt)
                break
    if "timestamp" not in out:
        for alt in ("ts", "time", "timestamp_iso"):
            if alt in out:
                out["timestamp"] = out.get(alt)
                break

    return out


def encode_key(key):
    """Encode DynamoDB LastEvaluatedKey into a URL-safe base64 token."""
    if key is None:
        return None
    raw = json.dumps(key, default=str, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).decode("utf-8")


def decode_key(token):
    """Decode a URL-safe base64 token back into a dict usable as ExclusiveStartKey."""
    if not token:
        return None
    try:
        raw = base64.urlsafe_b64decode(token.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return None


def fetch_readings_page(limit=50, last_key_token=None):
    """
    Fetch a single page of items using DynamoDB Scan with Limit and ExclusiveStartKey.
    Returns: (normalized_items_list, next_key_token_or_None)
    """
    items = []
    try:
        exclusive_start_key = decode_key(last_key_token)
        # perform scan with Limit to page through the table
        scan_args = {"Limit": int(limit)} if limit else {}
        if exclusive_start_key:
            scan_args["ExclusiveStartKey"] = exclusive_start_key

        resp = table.scan(**scan_args)
        items.extend(resp.get("Items", []))
        last_evaluated = resp.get("LastEvaluatedKey")
    except Exception as e:
        raise

    normalized = []
    for it in items:
        nit = normalize_item(it)
        dt = to_datetime(nit.get("timestamp"))
        nit["_ts_dt"] = dt
        nit["_ts_iso"] = dt.isoformat() if dt else None
        normalized.append(nit)

    # sort page by timestamp descending (so newest first within page)
    normalized.sort(key=lambda x: (
        x["_ts_dt"] is not None, x["_ts_dt"]), reverse=True)

    next_token = encode_key(last_evaluated) if last_evaluated else None
    return normalized, next_token

# ---------- Routes ----------


@app.route('/')
def index():
    user = session.get('user')
    if user:
        return f'Hello, {user["email"]}. <a href="/logout">Logout</a>'
    else:
        return f'Welcome! Please <a href="/login">Login</a>.'


@app.route('/login')
def login():
    # Alternate option to redirect to /authorize
    # redirect_uri = url_for('authorize', _external=True)
    # return oauth.oidc.authorize_redirect(redirect_uri)
    return oauth.oidc.authorize_redirect('https://weather.brano.dev')


@app.route('/authorize')
def authorize():
    token = oauth.oidc.authorize_access_token()
    user = token['userinfo']
    session['user'] = user
    return redirect(url_for('index'))


@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect(url_for('index'))


# ------------------------------------


@app.route("/dashboard")
def dashboard():
    # Leave device_id available in template; UI can filter client-side if desired
    device_id = app.config.get("DEVICE_ID")

    # We'll not fetch server-side here; front-end will call /api/readings for pages
    # but keep initial small page to render server-side table if you prefer:
    # We'll fetch first page server-side for initial render to avoid blank page.
    page_size = int(request.args.get("page_size", 50))
    try:
        readings, next_token = fetch_readings_page(
            limit=page_size, last_key_token=None)
    except Exception as e:
        flash(f"Error reading from DynamoDB: {e}", "danger")
        readings, next_token = [], None

    possible_attrs = ["temperature", "humidity", "pressure", "battery"]
    selected_attr = request.args.get("attr")
    if not selected_attr:
        selected_attr = next((a for a in possible_attrs if any(
            r.get(a) is not None for r in readings)), "temperature")

    return render_template("dashboard.html",
                           readings=readings,
                           device_id=device_id,
                           possible_attrs=possible_attrs,
                           selected_attr=selected_attr,
                           limit=len(readings),
                           next_token=next_token,
                           page_size=page_size)


@app.route("/api/readings", methods=["GET"])
def api_readings():
    """
    API returns one page of readings.
    Query params:
      - limit: number of items per page (default 50)
      - last_key: opaque token returned from previous call to fetch next page
    Response:
      { readings: [...], next_key: "token" | null }
    """
    limit = int(request.args.get("limit", 50))
    last_key = request.args.get("last_key")  # opaque token

    try:
        items, next_token = fetch_readings_page(
            limit=limit, last_key_token=last_key)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    out = []
    for it in items:
        out.append({
            "id": it.get("id"),
            "thing_id": it.get("thing_id"),
            "timestamp": it.get("_ts_iso"),
            "temperature": it.get("temperature"),
            "humidity": it.get("humidity"),
            "pressure": it.get("pressure"),
            "battery": it.get("battery"),
        })
    return jsonify({"readings": out, "next_key": next_token})


@app.route("/api/readings", methods=["POST"])
def ingest_reading():
    """
    Accepts JSON in native or AttributeValue shape. Writes normalized top-level item to table.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON"}), 400

    data_norm = normalize_item(data)

    thing_id = str(data_norm.get(
        "thing_id", data_norm.get("device_id", "unknown")))
    temperature = data_norm.get("temperature")
    humidity = data_norm.get("humidity")
    pressure = data_norm.get("pressure")
    battery = data_norm.get("battery")
    timestamp = data_norm.get("timestamp")

    item = {
        "id": str(uuid.uuid4()),
        "thing_id": thing_id,
        "timestamp": timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat()
    }

    try:
        if temperature is not None:
            item["temperature"] = decimal.Decimal(str(temperature))
        if humidity is not None:
            item["humidity"] = decimal.Decimal(str(humidity))
        if pressure is not None:
            item["pressure"] = decimal.Decimal(str(pressure))
        if battery is not None:
            item["battery"] = decimal.Decimal(str(battery))
        table.put_item(Item=item)
    except Exception as e:
        return jsonify({"error": f"Failed to write to DynamoDB: {e}"}), 500

    return jsonify({"status": "ok", "id": item["id"]}), 201


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
