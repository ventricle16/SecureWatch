def detect_bruteforce(failed_ips):

    alerts = []

    if not failed_ips:
        return alerts

    for ip, count in failed_ips.items():

        if count >= 5:

            alerts.append({
                "ip": ip,
                "count": count,
                "severity": "High",
                "type": "Brute Force Attack"
            })

    return alerts