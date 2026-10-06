import os

from rich import box
from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


def format_bandwidth(value):
    for unit in ('B/s', 'KiB/s', 'MiB/s', 'GiB/s'):
        if value < 1024 or unit == 'GiB/s':
            return f'{value:.1f} {unit}'
        value /= 1024


class TUIDashboard:
    def __init__(self):
        self.console = Console()

    def render(self, metrics, ip_metrics, detection, score, state, events, health=None, requests=()):
        health = health or {}
        width = min(110, self.console.width)
        colour = {'ANOMALOUS': '#f7768e', 'SUSPICIOUS': '#e0af68'}.get(state, '#9ece6a')

        traffic = Table('Metric', 'Value', title='Traffic', box=box.SIMPLE, show_edge=False, expand=True)
        traffic.add_row('Requests / sec', f"{metrics['rps']:.2f}")
        traffic.add_row('Requests in window', str(metrics['total']))
        traffic.add_row('Unique client IPs', str(ip_metrics['unique_ips']))
        traffic.add_row('Error rate', f"{metrics['error_rate']:.1%}")
        traffic.add_row('Bandwidth', format_bandwidth(metrics['bytes_per_sec']))

        signals = Table('Signal', 'Active', title='Detection', box=box.SIMPLE, show_edge=False, expand=True)
        for name, signal in detection.items():
            signals.add_row(name.replace('_', ' ').title(),
                            Text('YES' if signal['active'] else 'NO',
                                 style='#f7768e' if signal['active'] else '#9ece6a'))

        sources = Table('IP', 'RPS', 'Share', title='Top sources', box=box.SIMPLE, show_edge=False, expand=True)
        for source in ip_metrics['top_ips'][:3]:
            sources.add_row(Text(source['ip']), f"{source['rps']:.2f}", f"{source['share']:.0%}")
        if not ip_metrics['top_ips']:
            sources.add_row('No requests in window', '-', '-')

        recent = Table('Method / path', 'Status', title='Recent requests', box=box.SIMPLE, show_edge=False, expand=True)
        for request in list(requests)[-3:]:
            recent.add_row(Text(f"{request['method']} {request['path']}"), str(request['status']))
        if not requests:
            recent.add_row('Waiting for new log entries', '-')

        def pair(left, right):
            if width < 72:
                return Group(left, right)
            row = Table.grid(expand=True, padding=(0, 1))
            row.add_column(ratio=1)
            row.add_column(ratio=1)
            row.add_row(left, right)
            return row

        status = Text(f'STATUS: {state}  |  Risk: {score}/100', style=f'bold {colour}')
        ingestion = Text(f"Log: {health.get('log_path', 'not specified')}")
        counters = Text(
            f"Ingestion: {health.get('status', 'LIVE')}  |  "
            f"Parsed: {health.get('parsed', 0)}  |  Skipped: {health.get('skipped', 0)}  |  "
            f"Uptime: {health.get('uptime', 0):.0f}s"
        )
        load = f'{os.getloadavg()[0]:.2f}' if hasattr(os, 'getloadavg') else 'unavailable'
        system = Text(f"System load (1m): {load}  |  Window: {health.get('window', 10)}s  |  "
                      f"Baseline: {health.get('baseline', 0):.2f} r/s")
        if health.get('learning'):
            system.append(' (learning)')
        event_text = Text('\n'.join(events[-2:]) if events else 'No state changes yet.', style='#a9b1d6')
        return Panel(Group(status, pair(traffic, signals), pair(sources, recent),
                           ingestion, counters, system, Text('Events', style='bold #7aa2f7'), event_text),
                     title='SHIELD FLOW · MULTI-SIGNAL DETECTOR', subtitle='Ctrl+C to stop',
                     width=width, border_style='#7aa2f7')
