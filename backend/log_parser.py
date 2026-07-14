import re

def parse_auth_log(log_line):

    pattern = r"Failed password for (\w+) from ([0-9.]+)"

    match = re.search(pattern, log_line)

    if match:

        return {
            "username": match.group(1),
            "ip": match.group(2),
            "event_type": "FAILED_LOGIN"
        }

    return None