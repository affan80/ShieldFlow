from rich.layout import Layout
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.console import Console

class TUIDashboard:
    def __init__(self):
        self.console = Console()

    def render(self, metrics, ip_metrics, detection, score, state, events):
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body"),
            Layout(name="footer", size=3)
        )
        layout["body"].split_row(
            Layout(name="traffic"),
            Layout(name="detection")
        )

        # Header
        layout["header"].update(Panel("SHIELD FLOW - MULTI-SIGNAL DETECTOR", style="bold white on blue"))

        # Traffic panel
        traffic_table = Table(title="Traffic Metrics")
        traffic_table.add_column("Metric")
        traffic_table.add_column("Value")
        traffic_table.add_row("RPS", f"{metrics['rps']:.2f}")
        traffic_table.add_row("Error Rate", f"{metrics['error_rate']:.1%}")
        traffic_table.add_row("Bandwidth", f"{metrics['bytes_per_sec']/1024/1024:.2f} MB/s")
        layout["traffic"].update(Panel(traffic_table))

        # Detection panel
        detection_table = Table(title="Detection")
        detection_table.add_column("Signal")
        detection_table.add_column("Active")
        for sig, val in detection.items():
            detection_table.add_row(sig, "YES" if val["active"] else "NO")
        layout["detection"].update(Panel(detection_table))

        # Footer
        layout["footer"].update(Panel(f"STATUS: {state} | Risk Score: {score}/100", style=f"bold {'red' if state=='ANOMALOUS' else 'yellow' if state=='SUSPICIOUS' else 'green'}"))

        return layout
