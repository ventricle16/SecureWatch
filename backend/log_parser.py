import re

def parse_auth_log(filepath):

    failed_ips = {}

    with open(filepath, "r", errors="ignore") as logfile:

        for line in logfile:

            if "Failed password" in line:

                match = re.search(
                    r"from (\d+\.\d+\.\d+\.\d+)",
                    line
                )

                if match:

                    ip = match.group(1)

                    failed_ips[ip] = (
                        failed_ips.get(ip, 0) + 1
                    )

    return failed_ips