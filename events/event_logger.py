import time
from collections import deque

class EventLogger:
    def __init__(self, max_events=10):
        self.events = deque(maxlen=max_events)
        self.last_state = "NORMAL"

    def log_event(self, message):
        timestamp = time.strftime("%H:%M:%S")
        self.events.append(f"{timestamp} {message}")

    def check_state_change(self, new_state):
        if new_state != self.last_state:
            self.log_event(f"STATE_CHANGED -> {new_state}")
            self.last_state = new_state
            return True
        return False

    def get_events(self):
        return list(self.events)
