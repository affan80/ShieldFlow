from pathlib import Path
import os


def choose_log(path=None, directory=None):
    if path is not None:
        selected = Path(path).expanduser().resolve()
        if not selected.is_file():
            raise FileNotFoundError(f'Log file not found: {selected}')
        return selected
    directory = Path(directory) if directory is not None else Path(__file__).resolve().parents[1] / 'logs'
    files = [entry for entry in directory.glob('access_*.log') if entry.is_file()]
    if not files:
        raise FileNotFoundError('No access logs found. Start generate_logs.py or pass --log /path/to/access.log.')
    return max(files, key=lambda entry: entry.stat().st_mtime)


class LogReader:
    """Follow appended complete lines, reopening after rotation or truncation."""

    def __init__(self, path):
        self.path = Path(path)
        self.file = self.path.open(encoding='utf-8', errors='replace')
        self.file.seek(0, os.SEEK_END)
        self.error = ''

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.file.close()

    def read_lines(self, limit=2000):
        try:
            current = self.path.stat()
            opened = os.fstat(self.file.fileno())
            if (current.st_dev, current.st_ino) != (opened.st_dev, opened.st_ino):
                replacement = self.path.open(encoding='utf-8', errors='replace')
                self.file.close()
                self.file = replacement
            elif current.st_size < self.file.tell():
                self.file.seek(0)
            lines = []
            for _ in range(limit):
                position = self.file.tell()
                line = self.file.readline()
                if not line.endswith('\n'):
                    self.file.seek(position)
                    break
                lines.append(line)
            self.error = ''
            return lines
        except OSError as error:
            self.error = str(error)
            return []
