import time
import json
import re
import glob
import os
import sys
from collections import defaultdict, deque
from datetime import datetime

DEFAULT_LOG_FILE = "/var/log/nginx/access.log"
LOG_DIR = "./logs"
OUTPUT_FILE = "./ddosguard_events.jsonl"

WINDOW_SECONDS = 10
REQUEST_LIMIT = 50

# Regex pattern for standard Nginx access logs:
# e.g. 127.0.0.1 - - [17/Sep/2026:18:19:22 +0530] "GET / HTTP/1.1" 200 615
log_pattern = re.compile(
    r'(\S+) \S+ \S+ \[(.*?)\] '
    r'"(\S+) (\S+) \S+" '
    r'(\d+) (\d+)'
)

# Recent requests in the last WINDOW_SECONDS:
# stores tuples of (time, ip, status, bytes)
recent_requests = deque()

# Total statistics
total_requests = 0
total_bytes = 0
status_counts = defaultdict(int)

# Timestamps of recent requests for each IP (for DDoS rate tracking)
ip_requests = defaultdict(deque)

# IPs that have triggered a DDoS alert in this run
alerted_ips = set()

# Live terminal console messages
console_messages = deque(maxlen=15)


def log_message(msg):
    console_messages.append(msg)


def get_latest_log():
    files = glob.glob(os.path.join(LOG_DIR, "access_*.log"))
    if not files:
        return None
    return max(files, key=os.path.getmtime)


def add_request(ip, status, bytes_sent):
    global total_requests
    global total_bytes

    now = time.time()
    recent_requests.append((now, ip, status, bytes_sent))

    total_requests += 1
    total_bytes += bytes_sent
    status_counts[status] += 1


def remove_old_requests():
    cutoff = time.time() - WINDOW_SECONDS
    while recent_requests:
        request_time = recent_requests[0][0]
        if request_time >= cutoff:
            break
        recent_requests.popleft()


def calculate_metrics():
    remove_old_requests()
    request_count = len(recent_requests)

    if request_count == 0:
        return {
            "rps": 0.0,
            "rpm": 0.0,
            "unique_ips": 0,
            "bytes_per_second": 0.0,
            "2xx": 0,
            "4xx": 0,
            "5xx": 0,
        }

    unique_ips = set()
    bytes_total = 0
    count_2xx = 0
    count_4xx = 0
    count_5xx = 0

    for _, ip, status, bytes_sent in recent_requests:
        unique_ips.add(ip)
        bytes_total += bytes_sent

        if 200 <= status < 300:
            count_2xx += 1
        elif 400 <= status < 500:
            count_4xx += 1
        elif 500 <= status < 600:
            count_5xx += 1

    rps = request_count / WINDOW_SECONDS
    rpm = rps * 60
    bytes_per_second = bytes_total / WINDOW_SECONDS

    return {
        "rps": rps,
        "rpm": rpm,
        "unique_ips": len(unique_ips),
        "bytes_per_second": bytes_per_second,
        "2xx": count_2xx,
        "4xx": count_4xx,
        "5xx": count_5xx,
    }


def display_metrics(log_file):
    metrics = calculate_metrics()

    print("\033[2J\033[H", end="")
    print("╔══════════════════════════════════════╗")
    print("║          DDoSGuard v0.2              ║")
    print("╠══════════════════════════════════════╣")
    print(f"║ Requests/sec    : {metrics['rps']:>8.2f}          ║")
    print(f"║ Requests/min    : {metrics['rpm']:>8.2f}          ║")
    print(f"║ Unique IPs      : {metrics['unique_ips']:>8}          ║")
    print(f"║ 2xx responses   : {metrics['2xx']:>8}          ║")
    print(f"║ 4xx responses   : {metrics['4xx']:>8}          ║")
    print(f"║ 5xx responses   : {metrics['5xx']:>8}          ║")
    print(f"║ Bandwidth       : {metrics['bytes_per_second']:>8.2f} B/s    ║")
    print("╚══════════════════════════════════════╝")
    print(f"Monitoring log: {log_file}")
    print("-" * 40)
    print("Live activity:")
    for msg in console_messages:
        print(msg)


def display_waiting_screen():
    print("\033[2J\033[H", end="")
    print("╔══════════════════════════════════════╗")
    print("║          DDoSGuard v0.2              ║")
    print("╠══════════════════════════════════════╣")
    print("║ Status: Waiting for access log...    ║")
    print("║                                      ║")
    print("║ Searched paths:                      ║")
    print(f"║  - {DEFAULT_LOG_FILE:<33} ║")
    print(f"║  - {os.path.join(LOG_DIR, 'access_*.log'):<33} ║")
    print("║                                      ║")
    print("║ Hint: Run ./example_collect_log.sh   ║")
    print("║ to start collecting remote logs.     ║")
    print("╚══════════════════════════════════════╝")


def process_log_line(line):
    line = line.strip()
    if not line:
        return

    match = log_pattern.match(line)
    if not match:
        log_message(f"[RAW] {line}")
        return

    ip = match.group(1)
    timestamp = match.group(2)
    method = match.group(3)
    path = match.group(4)
    status = int(match.group(5))
    bytes_sent = int(match.group(6))

    now = time.time()

    # Add to general statistics
    add_request(ip, status, bytes_sent)

    # Add request to DDoS tracking
    ip_requests[ip].append(now)

    # Evict request timestamps outside the time window for this IP
    while ip_requests[ip] and now - ip_requests[ip][0] > WINDOW_SECONDS:
        ip_requests[ip].popleft()

    request_count = len(ip_requests[ip])

    # Log request to terminal messages list
    log_message(
        f"[REQUEST] {ip} {method} {path} "
        f"status={status} rate={request_count}/{WINDOW_SECONDS}s"
    )

    # Save to JSON log file
    event = {
        "timestamp": timestamp,
        "source_ip": ip,
        "method": method,
        "path": path,
        "status": status,
        "bytes_sent": bytes_sent,
        "requests_in_window": request_count,
    }

    try:
        with open(OUTPUT_FILE, "a") as output:
            output.write(json.dumps(event) + "\n")
    except Exception as e:
        log_message(f"[ERROR] Could not write event: {e}")

    # Check for DDoS rate limits
    if request_count >= REQUEST_LIMIT:
        if ip not in alerted_ips:
            alerted_ips.add(ip)

            alert = {
                "timestamp": datetime.now().isoformat(),
                "type": "DDOS_ALERT",
                "source_ip": ip,
                "requests": request_count,
                "window_seconds": WINDOW_SECONDS,
                "reason": f"{request_count} requests within {WINDOW_SECONDS} seconds",
            }

            log_message("")
            log_message("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            log_message("           ⚠ DDOS ALERT ⚠             ")
            log_message("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            log_message(f"Source IP : {ip}")
            log_message(f"Requests  : {request_count}")
            log_message(f"Window    : {WINDOW_SECONDS} seconds")
            log_message("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
            log_message("")

            try:
                with open(OUTPUT_FILE, "a") as output:
                    output.write(json.dumps(alert) + "\n")
            except Exception as e:
                log_message(f"[ERROR] Could not write alert: {e}")


def monitor_file(log_file):
    log_message(f"[+] Monitoring file: {log_file}")

    try:
        with open(log_file, "r") as log:
            # Seek to end of file to ignore past events
            log.seek(0, 2)

            last_display = 0.0

            while True:
                # Check for newer logs if we are not using a manually specified file
                if len(sys.argv) == 1:
                    latest = get_latest_log()
                    if latest and latest != log_file:
                        log_message(f"[+] New log detected: {latest}")
                        return

                line = log.readline()

                if line:
                    process_log_line(line)
                else:
                    time.sleep(0.1)

                # Periodically update dashboard
                current_time = time.time()
                if current_time - last_display >= 1:
                    display_metrics(log_file)
                    last_display = current_time

    except FileNotFoundError:
        log_message(f"[ERROR] File not found: {log_file}")
        time.sleep(1)


def main():
    while True:
        log_file = None
        if len(sys.argv) > 1:
            log_file = sys.argv[1]
            if not os.path.exists(log_file):
                display_waiting_screen()
                time.sleep(1)
                continue
        else:
            # Check default nginx log first
            if os.path.exists(DEFAULT_LOG_FILE):
                log_file = DEFAULT_LOG_FILE
            else:
                log_file = get_latest_log()

            if log_file is None:
                display_waiting_screen()
                time.sleep(1)
                continue

        monitor_file(log_file)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\033[2J\033[H", end="")
        print("======================================")
        print("          DDoSGuard Stopped           ")
        print("======================================")
        print("[+] Gracefully exiting. Goodbye!")
        print("")
        sys.exit(0)
