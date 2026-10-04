import json

class ConfigManager:
    def __init__(self, config_path="config/config.json"):
        with open(config_path, "r") as f:
            self.config = json.load(f)

    def get(self, key):
        return self.config.get(key)
