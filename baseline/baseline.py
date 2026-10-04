from collections import deque
import math

class BaselineManager:
    def __init__(self, max_samples=30):
        self.samples = deque(maxlen=max_samples)

    def add_sample(self, rps):
        self.samples.append(rps)

    def get_baseline(self):
        if not self.samples:
            return 0.0
        return sum(self.samples) / len(self.samples)
