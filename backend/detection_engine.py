from collections import defaultdict

def detect_bruteforce(events):

    ip_count = defaultdict(int)

    alerts = []

    for event in events:

        ip_count[event["ip"]] += 1

        if ip_count[event["ip"]] >= 5:

            alerts.append({
                "ip": event["ip"],
                "severity": "HIGH",
                "type": "BRUTE_FORCE"
            })

    return alerts