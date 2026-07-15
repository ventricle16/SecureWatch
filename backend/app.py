
import os
import sqlite3
import sys
from datetime import datetime

from flask import (
    Flask,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import LoginManager, current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash


def hash_password(password: str) -> str:
    return generate_password_hash(password, method="pbkdf2:sha256")

ROOT_DIR = os.path.dirname(
    os.path.dirname(
        os.path.abspath(__file__)
    )
)

if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

# ==========================================
# Imports
# ==========================================

try:
    from backend.database import db

    from backend.models import (
        Alert,
        Event,
        IncidentNote,
        MITRETechnique,
        ThreatIntel,
        User,
    )

    from backend.log_parser import (
        parse_auth_log
    )

    from backend.detection_engine import (
        run_all_detections,
    )

    from backend.incident import (
        incident_bp
    )

    from backend.reports import (
        report_bp
    )

except ImportError:

    from database import db

    from models import (
        Alert,
        Event,
        IncidentNote,
        MITRETechnique,
        ThreatIntel,
        User,
    )

    from log_parser import (
        parse_auth_log
    )

    from detection_engine import (
        run_all_detections,
    )

    from incident import (
        incident_bp
    )

    from reports import (
        report_bp
    )

# ==========================================
# Flask App
# ==========================================

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)

app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get("DATABASE_URL", "sqlite:///securewatch.db")
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "securewatch-demo-secret"

login_manager = LoginManager(app)
login_manager.login_view = "login"
db.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


def initialize_database():
    with app.app_context():
        db.create_all()

        db_path = os.environ.get("DATABASE_URL", "securewatch.db")
        if db_path.startswith("sqlite:///" ):
            db_path = db_path.replace("sqlite:///", "", 1)
        if db_path and os.path.exists(db_path):
            connection = sqlite3.connect(db_path)
            cursor = connection.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts'")
            if cursor.fetchone():
                cursor.execute("PRAGMA table_info(alerts)")
                columns = [row[1] for row in cursor.fetchall()]
                if "mitre_tactic" not in columns:
                    cursor.execute("ALTER TABLE alerts ADD COLUMN mitre_tactic VARCHAR(100)")
                if "confidence_score" not in columns:
                    cursor.execute("ALTER TABLE alerts ADD COLUMN confidence_score FLOAT")
                if "created_at" not in columns:
                    cursor.execute("ALTER TABLE alerts ADD COLUMN created_at DATETIME")
            connection.commit()
            connection.close()

        if not User.query.filter_by(username="admin").first():
            db.session.add(User(username="admin", password=hash_password("admin123"), role="admin"))
        if not User.query.filter_by(username="analyst").first():
            db.session.add(User(username="analyst", password=hash_password("analyst123"), role="analyst"))
        if not MITRETechnique.query.count():
            seed_techniques = [
                MITRETechnique(technique_id="T1110", name="Brute Force", tactic="Credential Access", detection_count=3),
                MITRETechnique(technique_id="T1078", name="Valid Accounts", tactic="Initial Access", detection_count=2),
                MITRETechnique(technique_id="T1046", name="Network Service Discovery", tactic="Discovery", detection_count=1),
            ]
            db.session.add_all(seed_techniques)
        if not ThreatIntel.query.count():
            db.session.add_all([
                ThreatIntel(source="AbuseIPDB", indicator="198.51.100.10", severity="High", score=92, details="Repeated password spray attempts"),
                ThreatIntel(source="VirusTotal", indicator="203.0.113.20", severity="Medium", score=74, details="Observed in malicious campaigns"),
            ])
        db.session.commit()


initialize_database()

# ==========================================
# Register Blueprints
# ==========================================

app.register_blueprint(
    incident_bp
)

app.register_blueprint(
    report_bp
)

# ==========================================
# Helpers
# ==========================================

def build_dashboard_context():
    alerts = Alert.query.order_by(Alert.id.desc()).all()
    events = Event.query.order_by(Event.id.desc()).all()

    total_events = Event.query.count()
    total_alerts = Alert.query.count()
    high_alerts = Alert.query.filter_by(severity="High").count()
    medium_alerts = Alert.query.filter_by(severity="Medium").count()
    low_alerts = Alert.query.filter_by(severity="Low").count()
    active_incidents = Alert.query.filter(Alert.status.in_(["OPEN", "INVESTIGATING"])).count()
    contained_incidents = Alert.query.filter_by(status="CONTAINED").count()
    closed_incidents = Alert.query.filter_by(status="CLOSED").count()

    recent_alerts = alerts[:10]
    alert_ids = [f"Alert {alert.id}" for alert in reversed(recent_alerts)]
    alert_counts = list(range(1, len(alert_ids) + 1))

    severity_counts = {
        "High": Alert.query.filter_by(severity="High").count(),
        "Medium": Alert.query.filter_by(severity="Medium").count(),
        "Low": Alert.query.filter_by(severity="Low").count(),
    }

    mitre_counts = {}
    for alert in alerts:
        technique = alert.mitre_technique or "T1110 - Brute Force"
        mitre_counts[technique] = mitre_counts.get(technique, 0) + 1

    ip_counter = {}
    for alert in alerts:
        ip = alert.source_ip or "Unknown"
        ip_counter[ip] = ip_counter.get(ip, 0) + 1

    sorted_ips = sorted(ip_counter.items(), key=lambda item: item[1], reverse=True)[:6]
    ip_labels = [item[0] for item in sorted_ips]
    ip_values = [item[1] for item in sorted_ips]

    return {
        "alerts": alerts,
        "events": events,
        "total_events": total_events,
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "medium_alerts": medium_alerts,
        "low_alerts": low_alerts,
        "active_incidents": active_incidents,
        "contained_incidents": contained_incidents,
        "closed_incidents": closed_incidents,
        "alert_ids": alert_ids,
        "alert_counts": alert_counts,
        "severity_counts": severity_counts,
        "mitre_counts": mitre_counts,
        "ip_labels": ip_labels,
        "ip_values": ip_values,
    }


# ==========================================
# Dashboard
# ==========================================

@app.route("/")
@login_required
def dashboard():
    context = build_dashboard_context()
    context["current_user"] = current_user
    return render_template("dashboard.html", **context)


@app.route("/login", methods=["GET", "POST"])
def login():
    if User.query.count() == 0:
        db.session.add(User(username="admin", password=hash_password("admin123"), role="admin"))
        db.session.commit()

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for("dashboard"))
        return render_template("login.html", error="Invalid credentials")
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/users")
@login_required
def users_page():
    if not current_user.is_admin():
        return redirect(url_for("dashboard"))
    users = User.query.order_by(User.id.asc()).all()
    return render_template("users.html", users=users, current_user=current_user)


@app.route("/users/create", methods=["POST"])
@login_required
def create_user():
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    username = request.form.get("username", "").strip()
    role = request.form.get("role", "analyst")
    password = request.form.get("password", "")
    if not username or not password:
        return redirect(url_for("users_page"))
    if User.query.filter_by(username=username).first():
        return redirect(url_for("users_page"))
    user = User(username=username, password=hash_password(password), role=role)
    db.session.add(user)
    db.session.commit()
    return redirect(url_for("users_page"))


@app.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
def delete_user(user_id):
    if not current_user.is_admin():
        return jsonify({"error": "Unauthorized"}), 403
    user = User.query.get_or_404(user_id)
    if user.id == current_user.id:
        return redirect(url_for("users_page"))
    db.session.delete(user)
    db.session.commit()
    return redirect(url_for("users_page"))

# ==========================================
# Upload Log File
# ==========================================

@app.route("/upload", methods=["POST"])
@login_required
def upload_log():
    uploaded_file = request.files.get("file")
    if uploaded_file is None or uploaded_file.filename == "":
        return redirect(url_for("dashboard"))

    os.makedirs("sample_logs", exist_ok=True)
    filepath = os.path.join("sample_logs", uploaded_file.filename)
    uploaded_file.save(filepath)

    failed_ips = parse_auth_log(filepath) or {}
    alerts_found = run_all_detections(failed_ips)

    for ip, count in failed_ips.items():
        event = Event(
            timestamp=datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"),
            source_ip=ip,
            username="Unknown",
            event_type="Failed Login",
            status="Failed",
            raw_log=f"{count} failed login attempts",
        )
        db.session.add(event)

    for alert in alerts_found:
        new_alert = Alert(
            event_id=0,
            severity=alert["severity"],
            alert_type=alert["type"],
            source_ip=alert["ip"],
            description=(
                f"Detected {alert['count']} suspicious authentication events from {alert['ip']}"
            ),
            status="OPEN",
            mitre_technique=alert.get("mitre", "T1110 - Brute Force"),
            mitre_tactic=alert.get("tactic", "Initial Access"),
            confidence_score=alert.get("confidence", 0.7),
        )
        db.session.add(new_alert)

    db.session.commit()
    return redirect(url_for("dashboard"))

# ==========================================
# Reports Page
# ==========================================

@app.route("/reports")
@login_required
def reports_page():
    return render_template("report.html", current_user=current_user)


@app.route("/mitre")
@login_required
def mitre_page():
    techniques = MITRETechnique.query.order_by(MITRETechnique.detection_count.desc()).all()
    return render_template("mitre.html", techniques=techniques, current_user=current_user)


@app.route("/threat-intel")
@login_required
def threat_intel_page():
    intel_items = ThreatIntel.query.order_by(ThreatIntel.id.desc()).all()
    return render_template("threat_intel.html", threat_intel=intel_items, current_user=current_user)


@app.route("/api/dashboard")
def api_dashboard():
    return jsonify(build_dashboard_context())


@app.route("/api/alerts")
def api_alerts():
    alerts = Alert.query.order_by(Alert.id.desc()).all()
    return jsonify([
        {
            "id": alert.id,
            "severity": alert.severity,
            "alert_type": alert.alert_type,
            "source_ip": alert.source_ip,
            "description": alert.description,
            "status": alert.status,
            "mitre_technique": alert.mitre_technique,
            "confidence_score": alert.confidence_score,
        }
        for alert in alerts
    ])


@app.route("/api/incidents")
def api_incidents():
    alerts = Alert.query.order_by(Alert.id.desc()).all()
    return jsonify([
        {
            "id": alert.id,
            "severity": alert.severity,
            "status": alert.status,
            "source_ip": alert.source_ip,
            "description": alert.description,
            "alert_type": alert.alert_type,
        }
        for alert in alerts
    ])


@app.route("/api/stats")
def api_stats():
    context = build_dashboard_context()
    return jsonify({
        "total_events": context["total_events"],
        "total_alerts": context["total_alerts"],
        "high_alerts": context["high_alerts"],
        "active_incidents": context["active_incidents"],
        "contained_incidents": context["contained_incidents"],
        "closed_incidents": context["closed_incidents"],
    })


@app.route("/api/mitre")
def api_mitre():
    techniques = MITRETechnique.query.order_by(MITRETechnique.detection_count.desc()).all()
    return jsonify([
        {
            "technique_id": technique.technique_id,
            "name": technique.name,
            "tactic": technique.tactic,
            "detection_count": technique.detection_count,
        }
        for technique in techniques
    ])


@app.route("/api/threat-intel")
def api_threat_intel():
    intel_items = ThreatIntel.query.order_by(ThreatIntel.id.desc()).all()
    return jsonify([
        {
            "id": item.id,
            "source": item.source,
            "indicator": item.indicator,
            "severity": item.severity,
            "score": item.score,
            "details": item.details,
        }
        for item in intel_items
    ])


@app.route("/api/incident/update", methods=["POST"])
@login_required
def update_incident():
    payload = request.get_json(silent=True) or {}
    alert_id = payload.get("alert_id")
    new_status = payload.get("status")
    note = payload.get("note")
    if not alert_id or not new_status:
        return jsonify({"error": "Missing incident data"}), 400
    alert = db.session.get(Alert, alert_id)
    if not alert:
        return jsonify({"error": "Incident not found"}), 404
    alert.status = new_status
    if note:
        db.session.add(IncidentNote(alert_id=alert.id, user_id=current_user.id, content=note))
    db.session.commit()
    return jsonify({"status": "updated"})

# ==========================================
# Health Check
# ==========================================

@app.route("/health")
def health():
    return {
        "status": "healthy",
        "service": "SecureWatch",
        "alerts": Alert.query.count(),
        "events": Event.query.count(),
    }

# ==========================================
# Main
# ==========================================

if __name__ == "__main__":
    initialize_database()
    app.run(host="0.0.0.0", port=5001, debug=True)


