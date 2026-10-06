import io
import unittest

from rich.console import Console

from cli.dashboard import TUIDashboard
from metrics.metrics_engine import MetricsEngine


class DashboardTests(unittest.TestCase):
    def test_small_real_traffic_stays_visible_in_medium_dashboard(self):
        engine = MetricsEngine(10)
        for _ in range(5):
            engine.add_request({'ip': '192.0.2.1', 'status': 200, 'bytes': 500})
        dashboard = TUIDashboard()
        dashboard.console = Console(width=270, height=60)
        output = io.StringIO()
        Console(file=output, width=270, height=60, color_system=None).print(
            dashboard.render(engine.get_global_metrics(), engine.get_ip_metrics(),
                             {'rps_anomaly': {'active': False, 'score': 30}},
                             0, 'NORMAL', ['12:00:00 Monitoring started'])
        )
        rendered = output.getvalue()
        self.assertIn('250.0 B/s', rendered)
        self.assertIn('0.50', rendered)
        self.assertIn('192.0.2.1', rendered)
        self.assertIn('Monitoring started', rendered)
        self.assertLessEqual(max(map(len, rendered.splitlines())), 110)
        self.assertLessEqual(len(rendered.splitlines()), 36)


if __name__ == '__main__':
    unittest.main()
