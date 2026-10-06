from pathlib import Path
import select
import signal
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]


class RuntimeTests(unittest.TestCase):
    def test_explicit_log_from_other_directory_reports_ingested_and_skipped_lines(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'access.log'
            path.touch()
            process = subprocess.Popen(
                [sys.executable, '-B', str(ROOT / 'shield_flow.py'), '--log', str(path)],
                cwd=directory, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            try:
                ready, _, _ = select.select([process.stdout], [], [], 5)
                self.assertTrue(ready, 'Dashboard did not finish opening the log')
                self.assertTrue(process.stdout.readline().startswith('Monitoring:'))
                line = '192.0.2.1 - - [04/Oct/2026:12:00:00 +0530] "GET /api HTTP/1.1" 503 500\n'
                with path.open('a') as output:
                    output.write(line * 5 + 'malformed\n')
                time.sleep(1.5)
                if process.poll() is None:
                    process.send_signal(signal.SIGINT)
                output, _ = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, output)
                self.assertIn('Parsed: 5', output)
                self.assertIn('Skipped: 1', output)
                self.assertIn('250.0 B/s', output)
                self.assertIn('192.0.2.1', output)
                self.assertNotIn('Traceback', output)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()


if __name__ == '__main__':
    unittest.main()
