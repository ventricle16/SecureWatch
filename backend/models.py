try:
    from backend.database import db
except ImportError:
    from database import db


class Event(db.Model):
    __tablename__ = "events"

    id = db.Column(db.Integer, primary_key=True)

    timestamp = db.Column(db.String(50))
    source_ip = db.Column(db.String(50))
    username = db.Column(db.String(100))

    event_type = db.Column(db.String(100))
    status = db.Column(db.String(50))

    raw_log = db.Column(db.Text)

    def __repr__(self):
        return f"<Event {self.id} {self.source_ip}>"



class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)

    event_id = db.Column(db.Integer)

    severity = db.Column(db.String(20))

    alert_type = db.Column(db.String(100))

    source_ip = db.Column(db.String(50))   # NEW COLUMN

    description = db.Column(db.Text)

    def __repr__(self):
        return f"<Alert {self.id} {self.alert_type}>"