
from datetime import datetime

from flask_login import UserMixin

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return f"<Event {self.id} {self.event_type}>"


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    event_id = db.Column(db.Integer, db.ForeignKey("events.id"), nullable=True)
    severity = db.Column(db.String(20))
    alert_type = db.Column(db.String(100))
    source_ip = db.Column(db.String(50))
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default="OPEN")
    mitre_technique = db.Column(db.String(100), default="T1110 - Brute Force")
    mitre_tactic = db.Column(db.String(100), default="Initial Access")
    confidence_score = db.Column(db.Float, default=0.0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    event = db.relationship("Event", backref="alerts", lazy=True)
    notes = db.relationship("IncidentNote", backref="alert", cascade="all, delete-orphan", lazy=True)

    def __repr__(self):
        return f"<Alert {self.id} {self.alert_type}>"


class User(db.Model, UserMixin):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(50), default="analyst")
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def is_admin(self):
        return self.role == "admin"

    def is_analyst(self):
        return self.role in {"admin", "analyst"}

    def __repr__(self):
        return f"<User {self.username}>"


class IncidentNote(db.Model):
    __tablename__ = "incident_notes"

    id = db.Column(db.Integer, primary_key=True)
    alert_id = db.Column(db.Integer, db.ForeignKey("alerts.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    author = db.relationship("User", backref="notes", lazy=True)


class MITRETechnique(db.Model):
    __tablename__ = "mitre_techniques"

    id = db.Column(db.Integer, primary_key=True)
    technique_id = db.Column(db.String(20), unique=True, nullable=False)
    name = db.Column(db.String(200), nullable=False)
    tactic = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    detection_count = db.Column(db.Integer, default=0)


class ThreatIntel(db.Model):
    __tablename__ = "threat_intel"

    id = db.Column(db.Integer, primary_key=True)
    source = db.Column(db.String(100), nullable=False)
    indicator = db.Column(db.String(200), nullable=False)
    severity = db.Column(db.String(50), default="Medium")
    score = db.Column(db.Integer, default=0)
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)


class GeoLocation(db.Model):
    __tablename__ = "geo_locations"

    id = db.Column(db.Integer, primary_key=True)
    ip = db.Column(db.String(50), unique=True, nullable=False)
    country = db.Column(db.String(100))
    city = db.Column(db.String(100))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)


