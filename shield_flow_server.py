#!/usr/bin/env python3

import argparse
import glob
import math
import os
import platform
import re
import sys
import time
from collections import deque


# ============================================================
# CONFIGURATION
# ============================================================

WINDOW_SECONDS = 10

# How long we observe traffic before detection starts
WARMUP_SECONDS = 30

# Number of previous RPS samples used for baseline
BASELINE_SAMPLES = 30

# Statistical threshold
Z_SCORE_THRESHOLD = 3.0

# Minimum increase required before calling something anomalous
# This prevents tiny traffic changes from triggering alerts.
MIN_MULTIPLIER = 2.0

DISPLAY_INTERVAL = 1.0


def get_latest_log_in_dir(directory):
    files = glob.glob(os.path.join(directory, "access_*.log"))
    if not files:
        return None
    return max(files, key=os.path.getmtime)


# ============================================================
# FIND NGINX ACCESS LOG
# ============================================================

def get_default_log_file():
    # Only check ./logs
    latest_log = get_latest_log_in_dir("./logs")
    if latest_log:
        return latest_log

    return None


# ============================================================
# NGINX LOG FORMAT
# ============================================================

LOG_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+'
    r'-\s+-\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<path>\S+)\s+'
    r'(?P<protocol>\S+)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)\s+'
    r'"(?P<referrer>[^"]*)"\s+'
    r'"(?P<user_agent>[^"]*)"'
)


# ============================================================
# PARSE NGINX LOG
# ============================================================

def parse_log_line(line):

    match = LOG_PATTERN.search(line)

    if not match:
        return None

    bytes_value = match.group("bytes")

    if bytes_value == "-":
        bytes_value = 0
    else:
        bytes_value = int(bytes_value)

    return {
        "ip": match.group("ip"),
        "timestamp": match.group("timestamp"),
        "method": match.group("method"),
        "path": match.group("path"),
        "protocol": match.group("protocol"),
        "status": int(match.group("status")),
        "bytes": bytes_value,
    }


# ============================================================
# REQUEST STORAGE
# ============================================================

# Each entry:
#
# (
#     local_time,
#     ip,
#     status,
#     bytes
# )

recent_requests = deque()

# Each entry for display:
# {ip, method, path, user_agent, status}
recent_activity = deque(maxlen=10)


# ============================================================
# BASELINE STORAGE
# ============================================================

# Stores RPS observations.
#
# Example:
#
# 8.2
# 9.1
# 10.4
# 8.8
# ...

rps_samples = deque(maxlen=BASELINE_SAMPLES)


# ============================================================
# ADD REQUEST
# ============================================================

def add_request(request):

    received_time = time.time()

    recent_requests.append(
        (
            received_time,
            request["ip"],
            request["status"],
            request["bytes"],
        )
    )

    recent_activity.append({
        "ip": request["ip"],
        "method": request["method"],
        "path": request["path"],
        "status": request["status"],
        "user_agent": request.get("user_agent", "-")
    })


# ============================================================
# REMOVE OLD REQUESTS
# ============================================================

def remove_old_requests():

    cutoff = time.time() - WINDOW_SECONDS

    while recent_requests:

        request_time = recent_requests[0][0]

        if request_time >= cutoff:
            break

        recent_requests.popleft()


# ============================================================
# CALCULATE CURRENT METRICS
# ============================================================

def calculate_metrics():

    remove_old_requests()

    request_count = len(recent_requests)

    if request_count == 0:

        return {
            "rps": 0.0,
            "rpm": 0.0,
            "unique_ips": 0,
            "bandwidth": 0.0,
            "2xx": 0,
            "3xx": 0,
            "4xx": 0,
            "5xx": 0,
        }

    unique_ips = set()

    total_bytes = 0

    count_2xx = 0
    count_3xx = 0
    count_4xx = 0
    count_5xx = 0

    for _, ip, status, bytes_sent in recent_requests:

        unique_ips.add(ip)

        total_bytes += bytes_sent

        if 200 <= status < 300:

            count_2xx += 1

        elif 300 <= status < 400:

            count_3xx += 1

        elif 400 <= status < 500:

            count_4xx += 1

        elif 500 <= status < 600:

            count_5xx += 1

    # The window is fixed at WINDOW_SECONDS.
    # Therefore:
    #
    # RPS = requests in window / window size

    rps = request_count / WINDOW_SECONDS

    rpm = rps * 60

    bandwidth = total_bytes / WINDOW_SECONDS

    return {
        "rps": rps,
        "rpm": rpm,
        "unique_ips": len(unique_ips),
        "bandwidth": bandwidth,
        "2xx": count_2xx,
        "3xx": count_3xx,
        "4xx": count_4xx,
        "5xx": count_5xx,
    }


# ============================================================
# BASELINE CALCULATION
# ============================================================

def calculate_baseline():

    if len(rps_samples) < 2:

        return {
            "mean": 0.0,
            "stddev": 0.0,
        }

    values = list(rps_samples)

    mean = sum(values) / len(values)

    variance = sum(
        (value - mean) ** 2
        for value in values
    ) / len(values)

    stddev = math.sqrt(variance)

    return {
        "mean": mean,
        "stddev": stddev,
    }


# ============================================================
# ANOMALY DETECTION
# ============================================================

def detect_anomaly(current_rps, baseline):

    mean = baseline["mean"]
    stddev = baseline["stddev"]

    # Not enough baseline information yet.
    if len(rps_samples) < BASELINE_SAMPLES:

        return {
            "status": "WARMUP",
            "z_score": 0.0,
            "baseline": mean,
        }

    # Avoid division by zero when traffic is extremely stable.
    safe_stddev = max(stddev, 0.1)

    z_score = (current_rps - mean) / safe_stddev

    # Two conditions must be satisfied:
    #
    # 1. RPS is statistically unusual
    # 2. RPS is at least 2x the baseline

    statistical_anomaly = (
        z_score >= Z_SCORE_THRESHOLD
    )

    traffic_jump = (
        mean > 0
        and current_rps >= mean * MIN_MULTIPLIER
    )

    if statistical_anomaly and traffic_jump:

        return {
            "status": "ANOMALY CANDIDATE",
            "z_score": z_score,
            "baseline": mean,
        }

    return {
        "status": "NORMAL",
        "z_score": z_score,
        "baseline": mean,
    }


# ============================================================
# CLEAR TERMINAL
# ============================================================

def clear_terminal():

    print("\033[2J\033[H", end="")


# ============================================================
# DISPLAY DASHBOARD
# ============================================================

def display_recent_requests():
    print("Recent Activity:")
    print(f"{'IP':<15} | {'Method':<6} | {'Path':<20} | {'Status':<6} | {'User Agent'}")
    print("-" * 80)
    for req in recent_activity:
        print(f"{req['ip']:<15} | {req['method']:<6} | {req['path']:<20} | {req['status']:<6} | {req['user_agent']}")


def display_dashboard(log_file, uptime):

    metrics = calculate_metrics()

    baseline = calculate_baseline()

    detection = detect_anomaly(
        metrics["rps"],
        baseline,
    )

    clear_terminal()

    print("╔════════════════════════════════════════════╗")
    print("║             SHIELD FLOW v0.3              ║")
    print("║        Baseline + Anomaly Engine          ║")
    print("╠════════════════════════════════════════════╣")

    print(
        f"║ Current RPS      : {metrics['rps']:>10.2f}        ║"
    )

    print(
        f"║ Requests/min     : {metrics['rpm']:>10.2f}        ║"
    )

    print(
        f"║ Unique IPs       : {metrics['unique_ips']:>10}        ║"
    )

    print(
        f"║ Bandwidth        : {metrics['bandwidth']:>10.2f} B/s ║"
    )

    print("╠════════════════════════════════════════════╣")

    print(
        f"║ HTTP 2xx         : {metrics['2xx']:>10}        ║"
    )

    print(
        f"║ HTTP 3xx         : {metrics['3xx']:>10}        ║"
    )

    print(
        f"║ HTTP 4xx         : {metrics['4xx']:>10}        ║"
    )

    print(
        f"║ HTTP 5xx         : {metrics['5xx']:>10}        ║"
    )

    print("╠════════════════════════════════════════════╣")

    print(
        f"║ Baseline RPS     : {baseline['mean']:>10.2f}        ║"
    )

    print(
        f"║ Std deviation    : {baseline['stddev']:>10.2f}        ║"
    )

    print(
        f"║ Z-score          : {detection['z_score']:>10.2f}        ║"
    )

    print(
        f"║ Baseline samples : {len(rps_samples):>10}        ║"
    )

    print("╠════════════════════════════════════════════╣")

    print(
        f"║ STATUS           : {detection['status']:<18} ║"
    )

    print("╚════════════════════════════════════════════╝")

    print()
    display_recent_requests()
    print()

    print(f"Log: {log_file}")
    print(f"Uptime: {uptime:.0f}s")


# ============================================================
# MAIN
# ============================================================

def main():

    parser = argparse.ArgumentParser(
        description="Shield Flow traffic monitoring and anomaly detection"
    )

    parser.add_argument(
        "--log",
        default=None,
        help="Path to Nginx access.log",
    )

    args = parser.parse_args()

    # --------------------------------------------------------
    # Determine log path
    # --------------------------------------------------------

    if args.log:

        log_file = os.path.abspath(args.log)

    else:

        log_file = get_default_log_file()

    if not log_file:

        print()
        print("ERROR: No access logs found in the './logs' directory.")
        print()
        print("Please ensure your log collector is writing files to './logs/'")
        print()

        sys.exit(1)

    # --------------------------------------------------------
    # Validate file
    # --------------------------------------------------------

    if not os.path.isfile(log_file):

        print()
        print("ERROR: Log file does not exist:")
        print(log_file)
        print()

        sys.exit(1)

    if not os.access(log_file, os.R_OK):

        print()
        print("ERROR: Log file cannot be read:")
        print(log_file)
        print()
        print("Try running with sudo.")
        print()

        sys.exit(1)

    # --------------------------------------------------------
    # Start
    # --------------------------------------------------------

    print("============================================")
    print("          SHIELD FLOW v0.3")
    print("      Baseline Anomaly Detection")
    print("============================================")
    print()
    print(f"Monitoring: {log_file}")
    print()
    print(
        f"Warm-up period: {WARMUP_SECONDS} seconds"
    )
    print(
        f"Detection window: {WINDOW_SECONDS} seconds"
    )
    print()

    start_time = time.time()

    # --------------------------------------------------------
    # Open Nginx log
    # --------------------------------------------------------

    try:

        with open(
            log_file,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as log:

            # Ignore old log entries.
            log.seek(0, os.SEEK_END)

            last_display = 0
            last_sample = 0

            while True:

                # ============================================
                # READ LOG
                # ============================================

                line = log.readline()

                if line:

                    request = parse_log_line(line)

                    if request:

                        add_request(request)

                else:

                    time.sleep(0.05)

                now = time.time()

                # ============================================
                # TAKE ONE RPS SAMPLE EVERY SECOND
                # ============================================

                if now - last_sample >= 1:

                    metrics = calculate_metrics()

                    # Only start learning after the warm-up period.
                    if now - start_time >= WARMUP_SECONDS:

                        rps_samples.append(
                            metrics["rps"]
                        )

                    last_sample = now

                # ============================================
                # UPDATE DISPLAY
                # ============================================

                if now - last_display >= DISPLAY_INTERVAL:

                    display_dashboard(
                        log_file,
                        now - start_time,
                    )

                    last_display = now

    except KeyboardInterrupt:

        print()
        print()
        print("Shield Flow stopped.")

    except PermissionError:

        print()
        print("ERROR: Permission denied.")

        print(
            f"sudo python3 shield_flow_server.py "
            f"--log {log_file}"
        )

    except FileNotFoundError:

        print()
        print("ERROR: Nginx log file disappeared.")
        print(log_file)

    except Exception as error:

        print()
        print("Unexpected error:")
        print(error)


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()
