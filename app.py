import os
import uuid
import decimal
from datetime import datetime, timezone
from dateutil import parser as dateutil_parser

from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
import boto3
from boto3.dynamodb.conditions import Attr

# ---------- Configuration ----------
DYNAMODB_TABLE = os.environ.get("DDB_TABLE", "weather_station_thing_readings")
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")  # change as needed

# AWS credentials are picked up from environment, ~/.aws/credentials, or IAM role.
# e.g. export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_REGION=...

# ---------- Utilities ----------


def to_datetime(ts):
    """
    Accept either ISO8601 string or numeric epoch (seconds). Return timezone-aware datetime in UTC.
    """
    if ts is None:
        return None
    # numeric (int/float/Decimal)
    if isinstance(ts, (int, float, decimal.Decimal)):
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except Exception:
            pass
    if isinstance(ts, str):
        try:
            dt = dateutil_parser.isoparse(ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            else:
                dt = dt.astimezone(timezone.utc)
            return dt
        except Exception:
            # try parse as numeric string
            try:
                return datetime.fromtimestamp(float(ts), tz=timezone.utc)
            except Exception:
                return None
    return None


def decimal_to_native(obj):
    """Recursively convert Decimal to float/int for JSON/template usage."""
    if isinstance(obj, dict):
        return {k: decimal_to_native(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [decimal_to_native(v) for v in obj]
    if isinstance(obj, decimal.Decimal):
        # convert to int if no fractional part
        if obj % 1 == 0:
            return int(obj)
        return float(obj)
    return obj


# ---------- Flask app ----------
app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET", "dev-secret")

# Initialize DynamoDB resource
dynamodb = boto3.resource("dynamodb", region_name=AWS_REGION)
table = dynamodb.Table(DYNAMODB_TABLE)

# ---------- Routes ----------


@app.route("/")
def dashboard():
    """
    Show recent sensor readings. We'll scan the table (for small datasets).
    If your table is large, adapt to use a Query on a GSI keyed by thing_id or timestamp.
    """
    max_items = int(request.args.get("limit", 100))

    try:
        # Simple scan to retrieve items. Adjust pagination / filtering for production.
        resp = table.scan(Limit=1000)  # read up to 1000 then sort locally
        items = resp.get("Items", [])

        # handle pagination (LastEvaluatedKey) for larger tables - keep scanning until done or cap
        while "LastEvaluatedKey" in resp and len(items) < 2000:
            resp = table.scan(
                ExclusiveStartKey=resp["LastEvaluatedKey"], Limit=1000)
            items.extend(resp.get("Items", []))
    except Exception as e:
        flash(f"Error reading from DynamoDB: {e}", "danger")
        items = []

    # Convert Decimal types -> native types
    items = [decimal_to_native(it) for it in items]

    # Parse timestamps and sort by timestamp descending
    for it in items:
        it_ts = it.get("timestamp") or it.get("ts") or it.get("time")
        dt = to_datetime(it_ts)
        it["_ts_dt"] = dt

    # Filter out items with no timestamp and sort. Items with missing timestamp will appear last.
    items_with_ts = [it for it in items if it["_ts_dt"] is not None]
    items_no_ts = [it for it in items if it["_ts_dt"] is None]

    items_with_ts.sort(key=lambda x: x["_ts_dt"], reverse=True)
    items_sorted = items_with_ts + items_no_ts

    # Trim to max_items
    items_sorted = items_sorted[:max_items]

    # Format timestamp readable string
    for it in items_sorted:
        dt = it.get("_ts_dt")
        it["ts_human"] = dt.isoformat() if dt else "N/A"

    return render_template("dashboard.html", readings=items_sorted, limit=max_items)


@app.route("/api/readings", methods=["POST"])
def ingest_reading():
    """
    Accept JSON payload from device and write to DynamoDB.
    Expected JSON keys: thing_id, temperature, humidity, pressure (optional), battery (optional), timestamp (optional)
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON payload"}), 400

    # Basic validation and extraction
    thing_id = str(data.get("thing_id", data.get("device_id", "unknown")))
    temperature = data.get("temperature")
    humidity = data.get("humidity")
    pressure = data.get("pressure")
    battery = data.get("battery")
    timestamp = data.get("timestamp")  # Accept ISO or epoch

    # Create item
    item = {
        "id": str(uuid.uuid4()),
        "thing_id": thing_id,
        "timestamp": timestamp if timestamp is not None else datetime.now(timezone.utc).isoformat(),
    }

    # Only include numeric fields if present
    if temperature is not None:
        item["temperature"] = decimal.Decimal(str(temperature))
    if humidity is not None:
        item["humidity"] = decimal.Decimal(str(humidity))
    if pressure is not None:
        item["pressure"] = decimal.Decimal(str(pressure))
    if battery is not None:
        item["battery"] = decimal.Decimal(str(battery))

    try:
        table.put_item(Item=item)
    except Exception as e:
        return jsonify({"error": f"Failed to write to DynamoDB: {str(e)}"}), 500

    return jsonify({"status": "ok", "id": item["id"]}), 201


@app.route("/example-post", methods=["GET"])
def example_post_page():
    """Simple page with curl example and link back to dashboard"""
    return render_template("example_post.html")

# Optional route to redirect to dashboard


@app.route("/dashboard")
def redirect_dashboard():
    return redirect(url_for("dashboard"))


# Run
if __name__ == "__main__":
    # For development only. In production use gunicorn/uwsgi and set FLASK_ENV appropriately.
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 3000)), debug=True)
