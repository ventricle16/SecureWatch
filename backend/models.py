try:
    from backend.database import db
except ImportError:
    from database import db

class Event(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.String(50))
    source_ip = db.Column(db.String(50))
    username = db.Column(db.String(100))

    event_type = db.Column(db.String(100))
    status = db.Column(db.String(50))

    raw_log = db.Column(db.Text)


class Alert(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    event_id = db.Column(db.Integer)

    severity = db.Column(db.String(20))

    alert_type = db.Column(db.String(100))

    description = db.Column(db.Text)