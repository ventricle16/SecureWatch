import os
import sys

from flask import Flask, render_template, request, redirect

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


# NEW ROUTE
@app.route("/upload", methods=["GET", "POST"])
def upload_log():

    if request.method == "POST":

        log_file = request.files.get("file")

        if log_file:

            os.makedirs("sample_logs", exist_ok=True)

            filepath = os.path.join(
                "sample_logs",
                log_file.filename
            )

            log_file.save(filepath)

            return redirect("/")

    return """
    <h2>SecureWatch Log Upload</h2>

    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file">
        <button type="submit">Upload</button>
    </form>
    """


if __name__ == "__main__":

    with app.app_context():
        db.create_all()

    app.run(debug=True, port=5001)