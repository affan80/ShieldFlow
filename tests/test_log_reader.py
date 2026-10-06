import os
from pathlib import Path
import tempfile
import unittest

from cli import log_reader
from parser.nginx_parser import NginxParser
from metrics.metrics_engine import MetricsEngine


class LogReaderTests(unittest.TestCase):
    def test_default_selects_latest_collector_log(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            old = root / 'access_test.log'
            old.write_text('old')
            new = root / 'access_20261004.log'
            new.write_text('new')
            os.utime(old, (1, 1))
            os.utime(new, (2, 2))
            self.assertEqual(log_reader.choose_log(directory=root), new)
            self.assertTrue(log_reader.choose_log(old).samefile(old))

    def test_appended_traffic_reaches_metrics_without_replaying_history(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            line = '192.0.2.1 - - [04/Oct/2026:12:00:00 +0530] "GET /api HTTP/1.1" 503 500\n'
            path.write_text(line)
            with log_reader.LogReader(path) as reader:
                self.assertEqual(reader.read_lines(), [])
                with path.open('a') as output:
                    output.write(line * 5)
                engine = MetricsEngine(10)
                parser = NginxParser()
                for entry in reader.read_lines():
                    engine.add_request(parser.parse_line(entry))
                self.assertEqual(engine.get_global_metrics(), {
                    'rps': 0.5, 'error_rate': 1.0, 'bytes_per_sec': 250.0, 'total': 5})

    def test_truncation_rotation_and_partial_lines_do_not_stop_ingestion(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            path.write_text('old history\n' * 20)
            with log_reader.LogReader(path) as reader:
                path.write_text('fresh\n')
                self.assertEqual(reader.read_lines(), ['fresh\n'])
                path.rename(path.with_suffix('.old'))
                self.assertEqual(reader.read_lines(), [])
                self.assertTrue(reader.error)
                path.write_text('rotated\npartial')
                self.assertEqual(reader.read_lines(), ['rotated\n'])
                self.assertFalse(reader.error)
                with path.open('a') as output:
                    output.write(' completed\n')
                self.assertEqual(reader.read_lines(), ['partial completed\n'])


if __name__ == '__main__':
    unittest.main()
