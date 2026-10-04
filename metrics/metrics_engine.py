from collections import deque
import time

class MetricsEngine:
    def __init__(self, window_seconds=10):
        self.window_seconds = window_seconds
        self.requests = deque() # (timestamp, ip, status, bytes)

    def add_request(self, request):
        self.requests.append((
            time.time(),
            request["ip"],
            request["status"],
            request["bytes"],
        ))

    def _remove_old_requests(self):
        cutoff = time.time() - self.window_seconds
        while self.requests and self.requests[0][0] < cutoff:
            self.requests.popleft()

    def get_global_metrics(self):
        self._remove_old_requests()
        count = len(self.requests)
        if count == 0:
            return {"rps": 0.0, "error_rate": 0.0, "bytes_per_sec": 0.0, "total": 0}
        
        errors = sum(1 for _, _, s, _ in self.requests if s >= 400)
        total_bytes = sum(b for _, _, _, b in self.requests)
        
        return {
            "rps": count / self.window_seconds,
            "error_rate": errors / count,
            "bytes_per_sec": total_bytes / self.window_seconds,
            "total": count
        }

    def get_ip_metrics(self):
        self._remove_old_requests()
        if not self.requests:
            return {"unique_ips": 0, "top_ips": []}
        
        ip_counts = {}
        for _, ip, _, _ in self.requests:
            ip_counts[ip] = ip_counts.get(ip, 0) + 1
        
        unique_ips = len(ip_counts)
        sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
        
        total_requests = len(self.requests)
        top_ips = [
            {"ip": ip, "count": count, "rps": count / self.window_seconds, "share": count / total_requests}
            for ip, count in sorted_ips[:5]
        ]
        
        return {"unique_ips": unique_ips, "top_ips": top_ips}
