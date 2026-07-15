from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import login_required

try:
    from backend.database import db
    from backend.models import Alert, IncidentNote
except ImportError:
    from database import db
    from models import Alert, IncidentNote


incident_bp = Blueprint(
    "incident",
    __name__
)


@incident_bp.route("/incidents")
@login_required
def incidents():
    """
    Incident Response Dashboard
    """

    alerts = Alert.query.order_by(
        Alert.id.desc()
    ).all()

    return render_template(
        "incidents.html",
        alerts=alerts
    )


@incident_bp.route("/incident/<int:alert_id>")
@login_required
def view_incident(alert_id):
    """
    View Single Incident
    """

    alert = Alert.query.get_or_404(
        alert_id
    )

    return render_template(
        "incident_details.html",
        alert=alert
    )


@incident_bp.route("/incident/<int:alert_id>/investigate")
@login_required
def investigate_incident(alert_id):
    """
    Change status to INVESTIGATING
    """

    alert = Alert.query.get_or_404(
        alert_id
    )

    alert.status = "INVESTIGATING"

    db.session.commit()

    return redirect(
        url_for("incident.incidents")
    )


@incident_bp.route("/incident/<int:alert_id>/contain")
@login_required
def contain_incident(alert_id):
    """
    Change status to CONTAINED
    """

    alert = Alert.query.get_or_404(
        alert_id
    )

    alert.status = "CONTAINED"

    db.session.commit()

    return redirect(
        url_for("incident.incidents")
    )


@incident_bp.route("/incident/<int:alert_id>/close")
@login_required
def close_incident(alert_id):
    """
    Change status to CLOSED
    """

    alert = Alert.query.get_or_404(
        alert_id
    )

    alert.status = "CLOSED"

    db.session.commit()

    return redirect(
        url_for("incident.incidents")
    )


@incident_bp.route("/incident/<int:alert_id>/reopen")
@login_required
def reopen_incident(alert_id):
    """
    Reopen closed incident
    """

    alert = Alert.query.get_or_404(
        alert_id
    )

    alert.status = "OPEN"

    db.session.commit()

    return redirect(
        url_for("incident.incidents")
    )


@incident_bp.route("/incident/delete/<int:alert_id>")
@login_required
def delete_incident(alert_id):
    """
    Delete incident
    """

    alert = Alert.query.get_or_404(
        alert_id
    )

    db.session.delete(alert)

    db.session.commit()

    return redirect(
        url_for("incident.incidents")
    )


@incident_bp.route("/incident/clear")
@login_required
def clear_all_incidents():
    """
    Remove all incidents
    """

    Alert.query.delete()

    db.session.commit()

    return redirect(
        url_for("incident.incidents")
    )


@incident_bp.route("/incident/<int:alert_id>/notes", methods=["POST"])
@login_required
def add_note(alert_id):
    alert = Alert.query.get_or_404(alert_id)
    note_text = request.form.get("note", "").strip()
    if note_text:
        db.session.add(IncidentNote(alert_id=alert.id, user_id=None, content=note_text))
        db.session.commit()
    return redirect(url_for("incident.view_incident", alert_id=alert.id))