from io import BytesIO
from datetime import datetime

from flask import Blueprint, send_file

try:
    from backend.models import Event, Alert
except ImportError:
    from models import Event, Alert

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    PageBreak
)

from reportlab.lib.styles import getSampleStyleSheet


report_bp = Blueprint(
    "report",
    __name__
)


@report_bp.route("/generate-report")
def generate_report():

    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    elements = []

    total_events = Event.query.count()

    total_alerts = Alert.query.count()

    high_alerts = Alert.query.filter_by(
        severity="High"
    ).count()

    medium_alerts = Alert.query.filter_by(
        severity="Medium"
    ).count()

    low_alerts = Alert.query.filter_by(
        severity="Low"
    ).count()

    # ==================================
    # Title
    # ==================================

    elements.append(
        Paragraph(
            "SecureWatch SIEM Security Report",
            styles["Title"]
        )
    )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            f"Generated: {datetime.now()}",
            styles["Normal"]
        )
    )

    elements.append(Spacer(1, 20))

    # ==================================
    # Executive Summary
    # ==================================

    elements.append(
        Paragraph(
            "Executive Summary",
            styles["Heading1"]
        )
    )

    elements.append(
        Paragraph(
            """
            This report summarizes detected security events,
            alerts, attack activity, and incident statistics
            observed by SecureWatch SIEM.
            """,
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 15))

    # ==================================
    # Statistics
    # ==================================

    elements.append(
        Paragraph(
            "Security Statistics",
            styles["Heading1"]
        )
    )

    elements.append(
        Paragraph(
            f"Total Events Processed: {total_events}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Total Alerts Generated: {total_alerts}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"High Severity Alerts: {high_alerts}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Medium Severity Alerts: {medium_alerts}",
            styles["BodyText"]
        )
    )

    elements.append(
        Paragraph(
            f"Low Severity Alerts: {low_alerts}",
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 15))

    # ==================================
    # Threat Assessment
    # ==================================

    elements.append(
        Paragraph(
            "Threat Assessment",
            styles["Heading1"]
        )
    )

    if total_alerts == 0:

        threat_level = "LOW"

    elif total_alerts < 10:

        threat_level = "MEDIUM"

    else:

        threat_level = "HIGH"

    elements.append(
        Paragraph(
            f"Current Threat Level: {threat_level}",
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 15))

    # ==================================
    # Alert Details
    # ==================================

    elements.append(
        Paragraph(
            "Detected Security Alerts",
            styles["Heading1"]
        )
    )

    alerts = Alert.query.order_by(
        Alert.id.desc()
    ).all()

    if alerts:

        for alert in alerts:

            elements.append(
                Paragraph(
                    f"""
                    Alert ID: {alert.id}<br/>
                    Severity: {alert.severity}<br/>
                    Type: {alert.alert_type}<br/>
                    Source IP: {alert.source_ip}<br/>
                    Description: {alert.description}
                    """,
                    styles["BodyText"]
                )
            )

            elements.append(
                Spacer(1, 10)
            )

    else:

        elements.append(
            Paragraph(
                "No security alerts detected.",
                styles["BodyText"]
            )
        )

    elements.append(PageBreak())

    # ==================================
    # Recommendations
    # ==================================

    elements.append(
        Paragraph(
            "Security Recommendations",
            styles["Heading1"]
        )
    )

    elements.append(
        Paragraph(
            """
            • Enable Multi-Factor Authentication (MFA)<br/>
            • Enforce strong password policies<br/>
            • Monitor authentication logs continuously<br/>
            • Block repeated brute-force sources<br/>
            • Review privileged accounts regularly<br/>
            • Apply operating system updates promptly
            """,
            styles["BodyText"]
        )
    )

    elements.append(Spacer(1, 20))

    elements.append(
        Paragraph(
            "End of Report",
            styles["Heading2"]
        )
    )

    doc.build(elements)

    buffer.seek(0)

    return send_file(
        buffer,
        as_attachment=True,
        download_name="SecureWatch_Report.pdf",
        mimetype="application/pdf"
    )