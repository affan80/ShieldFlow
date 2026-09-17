import time
import json
import re
import glob
import os
from collections import defaultdict, deque
from datetime import datetime


LOG_DIR = "./logs"
OUTPUT_FILE = "./ddosguard_events.jsonl"

# DDoS detection settings
WINDOW_SECONDS = 10
REQUEST_LIMIT = 50

# Nginx access-log pattern
log_pattern = re.compile(
    r'(\S+) \S+ \S+ \[(.*?)\] '
    r'"(\S+) (\S+) \S+" '
    r'(\d+) (\d+)'
)


print("======================================")
print("          DDoSGuard Started")
print("======================================")
print(f"Monitoring : {LOG_DIR}")
print(f"Output     : {OUTPUT_FILE}")
print(f"Window     : {WINDOW_SECONDS} seconds")
print(f"Limit      : {REQUEST_LIMIT} requests")
print("Waiting for requests...")
print("")


# Store request timestamps for every IP
ip_requests = defaultdict(deque)

# Remember which IPs have already triggered an alert
alerted_ips = set()


def get_latest_log():

    files = glob.glob(
        os.path.join(LOG_DIR, "access_*.log")
    )

    if not files:
        return None

    return max(files, key=os.path.getmtime)


def process_log_line(line):

    line = line.strip()

    match = log_pattern.match(line)

    if not match:
        print(f"[RAW] {line}")
        return

    ip = match.group(1)
    timestamp = match.group(2)
    method = match.group(3)
    path = match.group(4)
    status = int(match.group(5))
    bytes_sent = int(match.group(6))

    # Current time used for detection
    now = time.time()

    # Add current request
    ip_requests[ip].append(now)

    # Remove requests older than our detection window
    while (
        ip_requests[ip]
        and now - ip_requests[ip][0] > WINDOW_SECONDS
    ):
        ip_requests[ip].popleft()

    request_count = len(ip_requests[ip])

    event = {
        "timestamp": timestamp,
        "source_ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "bytes_sent": bytes_sent,
        "requests_in_window": request_count
    }

    # Display request
    print(
        f"[REQUEST] "
        f"{ip} "
        f"{method} "
        f"{path} "
        f"status={status} "
        f"rate={request_count}/{WINDOW_SECONDS}s"
    )

    # Save normal event
    with open(OUTPUT_FILE, "a") as output:

        output.write(
            json.dumps(event) + "\n"
        )

    # DDoS detection
    if request_count >= REQUEST_LIMIT:

        if ip not in alerted_ips:

            alerted_ips.add(ip)

            alert = {
                "timestamp": datetime.now().isoformat(),
                "type": "DDOS_ALERT",
                "source_ip": ip,
                "requests": request_count,
                "window_seconds": WINDOW_SECONDS,
                "reason": (
                    f"{request_count} requests "
                    f"within {WINDOW_SECONDS} seconds"
                )
            }

            print("")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("           ⚠ DDOS ALERT ⚠")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print(f"Source IP : {ip}")
            print(f"Requests  : {request_count}")
            print(f"Window    : {WINDOW_SECONDS} seconds")
            print("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            print("")

            with open(OUTPUT_FILE, "a") as output:

                output.write(
                    json.dumps(alert) + "\n"
                )


def monitor_file(log_file):

    print(f"[+] Monitoring file: {log_file}")

    with open(log_file, "r") as log:

        # Start from current end of file
        log.seek(0, 2)

        while True:

            line = log.readline()

            if line:

                process_log_line(line)

            else:

                # Check whether Bash created a newer log file
                latest = get_latest_log()

                if latest and latest != log_file:

                    print("")
                    print(
                        f"[+] New log detected: {latest}"
                    )
                    print("")

                    return latest

                time.sleep(0.1)


while True:

    latest_log = get_latest_log()

    if latest_log is None:

        print("[WAITING] No access log found...")
        time.sleep(1)
        continue

    latest_log = monitor_file(latest_log)
