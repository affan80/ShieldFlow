class DetectionEngine:
    def __init__(self, config):
        self.config = config

    def detect_all(self, global_metrics, ip_metrics, baseline_rps):
        signals = {}
        
        # RPS Anomaly
        signals["rps_anomaly"] = {
            "active": global_metrics["rps"] > (baseline_rps * self.config["RPS_MULTIPLIER"]),
            "score": 30
        }
        
        # Error Rate Anomaly
        signals["error_anomaly"] = {
            "active": global_metrics["error_rate"] > self.config["ERROR_RATE_WARNING"],
            "score": 15
        }
        
        # Bandwidth Anomaly
        signals["bandwidth_anomaly"] = {
            "active": (global_metrics["bytes_per_sec"] / 1024 / 1024) > self.config["BANDWIDTH_THRESHOLD_MB"],
            "score": 10
        }
        
        # Per-IP / Concentration Anomaly
        top_share = ip_metrics["top_ips"][0]["share"] if ip_metrics["top_ips"] else 0
        signals["ip_concentration"] = {
            "active": top_share > self.config["IP_CONCENTRATION_THRESHOLD"],
            "score": 25
        }
        
        signals["per_ip_anomaly"] = {
            "active": any(ip["rps"] > self.config["MAX_IP_RPS"] for ip in ip_metrics["top_ips"]),
            "score": 20
        }
        
        return signals

class RiskScorer:
    def __init__(self, config):
        self.config = config
        
    def calculate_score(self, signals):
        score = sum(s["score"] for s in signals.values() if s["active"])
        score = min(score, 100)
        
        if score >= 60:
            state = "ANOMALOUS"
        elif score >= 30:
            state = "SUSPICIOUS"
        else:
            state = "NORMAL"
            
        return score, state
