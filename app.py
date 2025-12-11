from boto3.dynamodb.conditions import Attr
import boto3
from flask import Flask, render_template, request, jsonify, flash
import os
import uuid
import decimal
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser

from dotenv import load_dotenv
load_dotenv()  # loads .env into environment


# ---------- Configuration ----------
DYNAMODB_TABLE = os.environ.get("DDB_TABLE", "weather_station_thing_readings")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
# REQUIRED: restrict dashboard to this device
DEVICE_ID = os.environ.get("DEVICE_ID", None)
if DEVICE_ID is None:
    # allow local dev but warn
    print("WARNING: DEVICE_ID not set in environment. The app will still run but won't be restricted to a device.")
FLASK_SECRET = os.environ.get("FLASK_SECRET", "dev-secret")

# ---------- Flask app ----------
app = Flask(__name__)
app.secret_key = FLASK_SECRET
app.config["DDB_TABLE"] = DYNAMODB_TABLE
app.config["DEVICE_ID"] = DEVICE_ID

# ---------- AWS DynamoDB init ----------
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(DYNAMODB_TABLE)

# ---------- Helpers ----------


def to_datetime(ts):
    """
    Accept ISO8601 string or epoch (int/float/Decimal). Return aware datetime in UTC.
    """
    if ts is None:
        return None
    if isinstance(ts, (int, float, decimal.Decimal)):
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except Exception:
            return None
    if isinstance(ts, str):
        try:
            dt = dateutil_parser.isoparse(ts)
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            # fallback: numeric string
            try:
                return datetime.fromtimestamp(float(ts), tz=timezone.utc)
            except Exception:
                return None
    return None


def decimal_to_native(obj):
    """Convert Decimal recursively to int/float for JSON/templates."""
    if isinstance(obj, dict):
        return {k: decimal_to_native(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decimal_to_native(v) for v in obj]
    if isinstance(obj, decimal.Decimal):
        # prefer int if no fractional part
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    return obj


def fetch_readings_for_device(device_id, limit=500):
    """
    Scan the table filtered by thing_id == device_id.
    Returns list of items converted to native python types.
    NOTE: For large tables, implement a Query on a GSI instead.
    """
    items = []
    try:
        resp = table.scan(
            FilterExpression=Attr("thing_id").eq(device_id),
            ProjectionExpression="#id, thing_id, #ts, temperature, humidity, pressure, battery",
            ExpressionAttributeNames={"#id": "id", "#ts": "timestamp"},
            Limit=1000
        )
        items.extend(resp.get("Items", []))
        # continue scanning until done or limit reached
        while "LastEvaluatedKey" in resp and len(items) < limit:
            resp = table.scan(
                FilterExpression=Attr("thing_id").eq(device_id),
                ProjectionExpression="#id, thing_id, #ts, temperature, humidity, pressure, battery",
                ExpressionAttributeNames={"#id": "id", "#ts": "timestamp"},
                ExclusiveStartKey=resp["LastEvaluatedKey"],
                Limit=1000
            )
            items.extend(resp.get("Items", []))
    except Exception as e:
        # bubble up as None and caller will handle
        raise

    # convert decimals and compute parsed timestamp
    items = [decimal_to_native(it) for it in items]
    for it in items:
        ts_val = it.get("timestamp") or it.get("ts") or it.get("time")
        dt = to_datetime(ts_val)
        it["_ts_dt"] = dt
        it["_ts_iso"] = dt.isoformat() if dt else None

    # sort by timestamp desc, missing timestamps last
    items_with_ts = [it for it in items if it["_ts_dt"] is not None]
    items_no_ts = [it for it in items if it["_ts_dt"] is None]
    items_with_ts.sort(key=lambda x: x["_ts_dt"], reverse=True)
    items_sorted = items_with_ts + items_no_ts
    return items_sorted[:limit]

# ---------- Routes ----------


@app.route("/")
def dashboard():
    device_id = app.config.get("DEVICE_ID")
    if not device_id:
        flash("DEVICE_ID is not configured. Set DEVICE_ID in your environment/.env to restrict to a single device.", "warning")
        # When DEVICE_ID not set, show message but continue with empty list
        readings = []
    else:
        try:
            limit = int(request.args.get("limit", 200))
            readings = fetch_readings_for_device(device_id, limit=limit)
        except Exception as e:
            flash(f"Error reading from DynamoDB: {e}", "danger")
            readings = []

    # attributes available for plotting (filter by numeric presence)
    possible_attrs = ["temperature", "humidity", "pressure", "battery"]
    # default attribute to show (choose the first that appears in readings with non-null numeric)
    default_attr = request.args.get("attr", None)
    if default_attr is None:
        # pick best available
        found = None
        for a in possible_attrs:
            if any((r.get(a) is not None) for r in readings):
                found = a
                break
        default_attr = found or "temperature"

    return render_template("dashboard.html",
                           readings=readings,
                           device_id=device_id,
                           possible_attrs=possible_attrs,
                           selected_attr=default_attr,
                           limit=len(readings))


@app.route("/api/readings", methods=["GET"])
def api_readings():
    """
    Return JSON list of readings for DEVICE_ID.
    Query params:
      - attr: optional attribute (temperature, humidity, etc.) - not required for response
      - limit: max number of items to return
    """
    device_id = app.config.get("DEVICE_ID")
    if not device_id:
        return jsonify({"error": "DEVICE_ID not configured on server"}), 400

    limit = int(request.args.get("limit", 500))
    try:
        items = fetch_readings_for_device(device_id, limit=limit)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # keep only useful fields and ensure types are JSON serializable
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
    return jsonify({"readings": out})


@app.route("/api/readings", methods=["POST"])
def ingest_reading():
    """
    Ingest endpoint for devices (optional). Accepts JSON and writes to DynamoDB.
    Uses the same assumptions as earlier: id, thing_id, timestamp, numeric fields.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON"}), 400

    thing_id = str(data.get("thing_id", data.get("device_id", "unknown")))
    temperature = data.get("temperature")
    humidity = data.get("humidity")
    pressure = data.get("pressure")
    battery = data.get("battery")
    timestamp = data.get("timestamp")

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
    # development server
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
