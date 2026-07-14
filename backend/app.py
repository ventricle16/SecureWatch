import os
import sys

from flask import Flask, render_template

ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

try:
    from backend.database import db
    from backend.models import Event, Alert
except ImportError:
    from database import db
    from models import Event, Alert

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static",
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///securewatch.db"

db.init_app(app)

@app.route("/")
def dashboard():

    total_events = Event.query.count()

    total_alerts = Alert.query.count()

    alerts = Alert.query.all()

    return render_template(
        "dashboard.html",
        total_events=total_events,
        total_alerts=total_alerts,
        alerts=alerts
    )

if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True)