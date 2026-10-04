import re

# Standard Nginx Access Log pattern
LOG_PATTERN = re.compile(
    r'^(?P<ip>\S+)\s+'
    r'\S+\s+'
    r'\S+\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<path>\S+)\s+'
    r'(?P<protocol>[^"]*)"\s+'
    r'(?P<status>\d{3})\s+'
    r'(?P<bytes>\d+|-)'
)

class NginxParser:
    def __init__(self):
        self.error_count = 0

    def parse_line(self, line: str):
        """
        Parses a single Nginx access log line.
        Returns a dict of parsed fields if successful, or None if malformed.
        Does not raise exceptions.
        """
        try:
            match = LOG_PATTERN.search(line)
            if not match:
                self.error_count += 1
                return None
            
            bytes_val = match.group("bytes")
            if bytes_val == "-":
                bytes_val = 0
            else:
                bytes_val = int(bytes_val)

            return {
                "ip": match.group("ip"),
                "timestamp": match.group("timestamp"),
                "method": match.group("method"),
                "path": match.group("path"),
                "protocol": match.group("protocol"),
                "status": int(match.group("status")),
                "bytes": bytes_val,
            }
        except Exception:
            self.error_count += 1
            return None
