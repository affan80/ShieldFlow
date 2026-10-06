from collections import deque
import time

class BaselineManager:
    def __init__(self, max_samples=30):
        self.samples = deque(maxlen=max_samples)
        self.last_sample = None

    def add_sample(self, rps):
        now = time.monotonic()
        if self.last_sample is None or now - self.last_sample >= 1:
            self.samples.append(rps)
            self.last_sample = now

    def get_baseline(self):
        if not self.samples:
            return 0.0
        return sum(self.samples) / len(self.samples)
