import time
import os
import random

log_file = "logs/access_test.log"
os.makedirs("logs", exist_ok=True)

ips = ["192.168.1.1", "10.0.0.5", "172.16.0.10"]
methods = ["GET", "POST"]

print(f"Writing to {log_file}...")

with open(log_file, "a") as f:
    while True:
        ip = random.choice(ips)
        timestamp = time.strftime("%d/%b/%Y:%H:%M:%S +0530")
        line = f'{ip} - - [{timestamp}] "{random.choice(methods)} / HTTP/1.1" 200 {random.randint(100, 1000)}\n'
        f.write(line)
        f.flush()
        print(f"Added: {line.strip()}")
        time.sleep(2)
