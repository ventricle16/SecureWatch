import os
import sys
from collections import Counter

from flask import Flask, render_template, request, redirect, url_for

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    from backend.database import db
    from backend.models import Event, Alert
    from backend.log_parser import parse_auth_log
    from backend.detection_engine import detect_bruteforce
except ImportError:
    from database import db
    from models import Event, Alert
    from log_parser import parse_auth_log
    from detection_engine import detect_bruteforce


app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static",
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///securewatch.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db.init_app(app)


@app.route("/")
def dashboard():

    total_events = Event.query.count()
    total_alerts = Alert.query.count()

    alerts = Alert.query.order_by(Alert.id.desc()).all()

    # -------------------------
    # Top Attacking IPs
    # -------------------------

    ip_counter = Counter()

    for alert in alerts:
        if hasattr(alert, "source_ip") and alert.source_ip:
            ip_counter[alert.source_ip] += 1

    top_ips = dict(ip_counter.most_common(5))

    # -------------------------
    # Alerts Over Time
    # -------------------------

    alert_ids = []
    alert_counts = []

    for alert in alerts[-10:]:

        alert_ids.append(f"Alert {alert.id}")
        alert_counts.append(1)

    return render_template(
        "dashboard.html",
        total_events=total_events,
        total_alerts=total_alerts,
        alerts=alerts,
        top_ips=top_ips,
        alert_ids=alert_ids,
        alert_counts=alert_counts
    )


@app.route("/upload", methods=["GET", "POST"])
def upload_log():

    if request.method == "POST":

        uploaded_file = request.files.get("file")

        if uploaded_file is None or uploaded_file.filename == "":
            return "No file selected"

        os.makedirs("sample_logs", exist_ok=True)

        filepath = os.path.join(
            "sample_logs",
            uploaded_file.filename
        )

        uploaded_file.save(filepath)

        failed_ips = parse_auth_log(filepath)

        if failed_ips is None:
            failed_ips = {}

        print("DEBUG failed_ips =", failed_ips)

        alerts_found = detect_bruteforce(failed_ips)

        for ip, count in failed_ips.items():

            event = Event(
                timestamp="NOW",
                source_ip=ip,
                username="Unknown",
                event_type="Failed Login",
                status="Failed",
                raw_log=f"{count} failed login attempts"
            )

            db.session.add(event)

        db.session.commit()

        for alert in alerts_found:

          new_alert = Alert(
            event_id=0,
            severity=alert["severity"],
            alert_type=alert["type"],
            source_ip=alert["ip"],
            description=f"Detected {alert['count']} failed login attempts from {alert['ip']}"
          )

          db.session.add(new_alert)

        db.session.commit()

        return redirect(url_for("dashboard"))

    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Upload Log File</title>
        <style>
            body{
                background:#071426;
                color:white;
                font-family:Arial;
                padding:40px;
            }

            form{
                background:#13233f;
                padding:25px;
                border-radius:10px;
                width:400px;
            }

            button{
                padding:10px 20px;
                background:#16c784;
                border:none;
                color:white;
                border-radius:5px;
                cursor:pointer;
            }

            a{
                color:#3ea6ff;
            }
        </style>
    </head>
    <body>

        <h2>Upload Linux auth.log</h2>

        <form method="POST" enctype="multipart/form-data">

            <input type="file" name="file">

            <br><br>

            <button type="submit">
                Upload & Analyze
            </button>

        </form>

        <br>

        <a href="/">← Back to Dashboard</a>

    </body>
    </html>
    """


if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(
        host="0.0.0.0",
        port=5001,
        debug=True
    )