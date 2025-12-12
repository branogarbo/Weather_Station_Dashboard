import os
import json
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from dotenv import load_dotenv
import boto3
from botocore.exceptions import BotoCoreError, ClientError
import pytz

# Load .env
load_dotenv()

AWS_REGION = os.getenv("WS_REGION", "us-east-1")
DDB_TABLE = os.getenv("DDB_TABLE", "weather_station_thing_readings")
FLASK_SECRET = os.getenv("FLASK_SECRET")
DEVICE_ID = os.getenv("DEVICE_ID")
PORT = int(os.getenv("PORT", "5000"))

if FLASK_SECRET is None:
    raise RuntimeError("FLASK_SECRET is required")

app = Flask(__name__)
app.secret_key = FLASK_SECRET

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

    return data


@app.route("/", methods=["GET"])
def index():
    page = request.args.get("page", type=int) or 1
    per_page = request.args.get("per_page", type=int) or 10
    per_page = max(1, min(per_page, 200))
    if page < 1:
        page = 1

    if not DEVICE_ID:
        flash("DEVICE_ID missing in configuration.", "danger")
        return render_template("index.html",
                               readings=[], device_id=None, page=1,
                               per_page=per_page, start_idx=0, end_idx=0,
                               has_next=False, has_prev=False, total_pages=1)

    # FULL SCAN — collects all entries with matching thing_id
    results = []
    last_key = None

    try:
        while True:
            kwargs = {"Limit": 1000}
            if last_key:
                kwargs["ExclusiveStartKey"] = last_key

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

    except Exception as e:
        flash(f"Error scanning DynamoDB: {e}", "danger")
        return render_template("index.html",
                               readings=[], device_id=DEVICE_ID, page=1,
                               per_page=per_page, start_idx=0, end_idx=0,
                               has_next=False, has_prev=False, total_pages=1)

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

    return render_template(
        "index.html",
        readings=page_items,
        device_id=DEVICE_ID,
        page=page,
        per_page=per_page,
        start_idx=start_idx + 1 if page_items else 0,
        end_idx=start_idx + len(page_items),
        has_prev=has_prev,
        has_next=has_next,
        total_pages=total_pages
    )


@app.route("/publish", methods=["POST"])
def publish_command():
    # DEFAULT TOPIC UPDATED HERE
    topic = request.form.get("topic") or "mesa/weather/readings"

    payload_text = request.form.get("payload", "").strip()
    command_text = request.form.get("command", "").strip()

    if not payload_text and not command_text:
        flash("Provide a command or JSON payload.", "warning")
        return redirect(url_for("index"))

    try:
        publish_payload = (
            json.dumps(json.loads(payload_text))
            if payload_text else json.dumps({"command": command_text})
        )
    except Exception:
        publish_payload = payload_text

    try:
        client = get_iot_data_client()
        client.publish(topic=topic, qos=0,
                       payload=publish_payload.encode("utf-8"))
        flash(f"Published to {topic}", "success")
    except Exception as e:
        flash(f"Publish failed: {e}", "danger")

    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=True)
