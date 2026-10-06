import argparse
from collections import deque
from pathlib import Path
import time
from parser.nginx_parser import NginxParser
from metrics.metrics_engine import MetricsEngine
from detection.engine import DetectionEngine, RiskScorer
from baseline.baseline import BaselineManager
from events.event_logger import EventLogger
from config.config_manager import ConfigManager
from cli.dashboard import TUIDashboard
from cli.log_reader import choose_log, LogReader
from rich.live import Live

def main():
    arguments = argparse.ArgumentParser(description='Compact live Nginx traffic dashboard')
    arguments.add_argument('--log', help='Log to follow (default: newest logs/access_*.log)')
    args = arguments.parse_args()
    try:
        log_path = choose_log(args.log)
    except OSError as error:
        arguments.error(str(error))

    config = ConfigManager(Path(__file__).resolve().parent / 'config/config.json')
    parser = NginxParser()
    metrics = MetricsEngine(config.get("WINDOW_SECONDS"))
    detection = DetectionEngine(config.config)
    scorer = RiskScorer(config.config)
    baseline = BaselineManager(config.get("BASELINE_SAMPLES"))
    events = EventLogger()
    dashboard = TUIDashboard()
    recent_requests = deque(maxlen=3)
    parsed = 0
    started = time.monotonic()
    last_request = None
    next_display = started
    last_error = ''
    events.log_event('Monitoring started; waiting for new log entries')

    try:
        with LogReader(log_path) as reader:
            print(f'Monitoring: {log_path}', flush=True)
            with Live(console=dashboard.console, refresh_per_second=4, vertical_overflow='visible') as live:
                while True:
                    for line in reader.read_lines():
                        request = parser.parse_line(line)
                        if request:
                            metrics.add_request(request)
                            recent_requests.append(request)
                            parsed += 1
                            last_request = time.monotonic()

                    now = time.monotonic()
                    if now >= next_display:
                        global_m = metrics.get_global_metrics()
                        ip_m = metrics.get_ip_metrics()
                        baseline_rps = baseline.get_baseline()
                        signals = detection.detect_all(global_m, ip_m, baseline_rps)
                        learning = now - started < config.get('WARMUP_SECONDS')
                        if learning:
                            signals['rps_anomaly']['active'] = False
                        score, state = scorer.calculate_score(signals)
                        events.check_state_change(state)
                        # Compare against earlier traffic before learning this sample.
                        if learning or state == 'NORMAL':
                            baseline.add_sample(global_m['rps'])

                        if reader.error != last_error:
                            events.log_event(reader.error or 'Log file available again')
                            last_error = reader.error
                        if reader.error:
                            ingestion = 'LOG ERROR'
                        elif last_request is None:
                            ingestion = 'WAITING for new valid entries'
                        elif now - last_request > config.get('WINDOW_SECONDS'):
                            ingestion = f'IDLE ({now - last_request:.0f}s since last request)'
                        else:
                            ingestion = 'LIVE'
                        health = {
                            'log_path': str(log_path), 'status': ingestion, 'parsed': parsed,
                            'skipped': parser.error_count, 'uptime': now - started,
                            'window': config.get('WINDOW_SECONDS'), 'baseline': baseline_rps,
                            'learning': learning,
                        }
                        live.update(dashboard.render(global_m, ip_m, signals, score, state,
                                                     events.get_events(), health, recent_requests))
                        next_display = now + 1
                    time.sleep(0.1)
    except KeyboardInterrupt:
        print('\nShield Flow stopped.')
    except OSError as error:
        arguments.error(str(error))

if __name__ == "__main__":
    main()
