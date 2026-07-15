
# ==========================================
# SecureWatch Detection Engine
# ==========================================

def detect_bruteforce(failed_ips):
    alerts = []
    if not failed_ips:
        return alerts

    for ip, count in failed_ips.items():
        if count >= 10:
            alerts.append({
                "ip": ip,
                "count": count,
                "severity": "High",
                "type": "Brute Force Attack",
                "mitre": "T1110 - Brute Force",
                "tactic": "Credential Access",
                "confidence": 0.95,
            })
        elif count >= 5:
            alerts.append({
                "ip": ip,
                "count": count,
                "severity": "Medium",
                "type": "Multiple Failed Logins",
                "mitre": "T1110 - Brute Force",
                "tactic": "Credential Access",
                "confidence": 0.82,
            })
        elif count >= 3:
            alerts.append({
                "ip": ip,
                "count": count,
                "severity": "Low",
                "type": "Suspicious Login Activity",
                "mitre": "T1110 - Brute Force",
                "tactic": "Credential Access",
                "confidence": 0.7,
            })
    return alerts


def detect_password_spraying(failed_ips):
    alerts = []
    for ip, count in failed_ips.items():
        if count >= 20:
            alerts.append({
                "ip": ip,
                "count": count,
                "severity": "High",
                "type": "Password Spraying",
                "mitre": "T1110.003 - Password Spraying",
                "tactic": "Credential Access",
                "confidence": 0.91,
            })
    return alerts


def detect_credential_stuffing(failed_ips):
    alerts = []
    for ip, count in failed_ips.items():
        if count >= 30:
            alerts.append({
                "ip": ip,
                "count": count,
                "severity": "Critical",
                "type": "Credential Stuffing",
                "mitre": "T1110.004 - Credential Stuffing",
                "tactic": "Credential Access",
                "confidence": 0.97,
            })
    return alerts


def detect_account_enumeration(failed_ips):
    alerts = []
    for ip, count in failed_ips.items():
        if count >= 7:
            alerts.append({
                "ip": ip,
                "count": count,
                "severity": "Medium",
                "type": "Account Enumeration",
                "mitre": "T1087 - Account Discovery",
                "tactic": "Discovery",
                "confidence": 0.76,
            })
    return alerts


def detect_reconnaissance(failed_ips):
    alerts = []
    for ip, count in failed_ips.items():
        if count >= 4:
            alerts.append({
                "ip": ip,
                "count": count,
                "severity": "Medium",
                "type": "Reconnaissance Activity",
                "mitre": "T1046 - Network Service Discovery",
                "tactic": "Discovery",
                "confidence": 0.72,
            })
    return alerts


def run_all_detections(failed_ips):
    all_alerts = []
    all_alerts.extend(detect_bruteforce(failed_ips))
    all_alerts.extend(detect_password_spraying(failed_ips))
    all_alerts.extend(detect_credential_stuffing(failed_ips))
    all_alerts.extend(detect_account_enumeration(failed_ips))
    all_alerts.extend(detect_reconnaissance(failed_ips))
    return all_alerts

