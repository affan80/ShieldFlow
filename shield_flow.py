import sys
import time
import os
from parser.nginx_parser import NginxParser
from metrics.metrics_engine import MetricsEngine
from detection.engine import DetectionEngine, RiskScorer
from baseline.baseline import BaselineManager
from events.event_logger import EventLogger
from config.config_manager import ConfigManager
from cli.dashboard import TUIDashboard
from rich.live import Live

def main():
    config = ConfigManager()
    parser = NginxParser()
    metrics = MetricsEngine(config.get("WINDOW_SECONDS"))
    detection = DetectionEngine(config.config)
    scorer = RiskScorer(config.config)
    baseline = BaselineManager(config.get("BASELINE_SAMPLES"))
    events = EventLogger()
    dashboard = TUIDashboard()

    log_path = "logs/access_test.log" # For testing/prototype
    
    if not os.path.exists(log_path):
        print(f"Log file not found: {log_path}")
        return

    with open(log_path, "r", encoding="utf-8", errors="replace") as f:
        f.seek(0, os.SEEK_END)
        
        with Live(refresh_per_second=1) as live:
            while True:
                line = f.readline()
                if line:
                    req = parser.parse_line(line)
                    if req:
                        metrics.add_request(req)
                else:
                    time.sleep(0.1)
                
                # Update logic
                global_m = metrics.get_global_metrics()
                ip_m = metrics.get_ip_metrics()
                baseline.add_sample(global_m["rps"])
                
                signals = detection.detect_all(global_m, ip_m, baseline.get_baseline())
                score, state = scorer.calculate_score(signals)
                events.check_state_change(state)
                
                # Render
                live.update(dashboard.render(global_m, ip_m, signals, score, state, events.get_events()))

if __name__ == "__main__":
    main()
