import re
import json
import uuid
import os
from datetime import datetime, timedelta
from collections import deque

RULES_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules.json")

def parse_naive_datetime(ts_str: str) -> datetime:
    # Strips timezone offsets (+05:30, -08:00, Z) to return a naive datetime
    clean_ts = re.sub(r'Z|[+-]\d{2}:?\d{2}$', '', ts_str)
    return datetime.fromisoformat(clean_ts)

class CorrelationEngine:
    def __init__(self, alert_callback):
        self.alert_callback = alert_callback
        self.rules = []
        self.log_buffer = deque()
        self.recent_alerts = {}  # To deduplicate/rate-limit alerts: rule_id -> {group_key -> timestamp}
        self.load_rules()

    def load_rules(self):
        try:
            if os.path.exists(RULES_FILE):
                with open(RULES_FILE, "r") as f:
                    self.rules = json.load(f)
                print(f"Loaded {len(self.rules)} correlation rules from {RULES_FILE}")
            else:
                print(f"Rules file {RULES_FILE} not found. Running with empty rules.")
                self.rules = []
        except Exception as e:
            print(f"Error loading correlation rules: {e}")
            self.rules = []

    def log_matches_filter(self, log: dict, rule_filter: dict) -> bool:
        """
        Helper to check if a log matches a rule's filter criteria
        """
        # 1. Match source if specified
        if "source" in rule_filter:
            if log["source"] != rule_filter["source"]:
                return False
                
        # 2. Match levels if specified
        if "level" in rule_filter:
            allowed_levels = rule_filter["level"]
            if isinstance(allowed_levels, list):
                if log["level"] not in allowed_levels:
                    return False
            elif log["level"] != allowed_levels:
                return False
                
        # 3. Match message pattern (regex search)
        if "message_pattern" in rule_filter:
            pattern = rule_filter["message_pattern"]
            if not re.search(pattern, log["message"], re.IGNORECASE):
                return False
                
        return True

    def evaluate(self, new_log: dict):
        """
        Evaluates a newly received log against all loaded rules.
        """
        try:
            now = parse_naive_datetime(new_log["timestamp"])
        except Exception:
            now = datetime.now()
            
        self.log_buffer.append((now, new_log))
        
        # Keep buffer tidy - clean up logs older than 5 minutes (max window we'd care about)
        max_cutoff = now - timedelta(minutes=5)
        while self.log_buffer and self.log_buffer[0][0] < max_cutoff:
            self.log_buffer.popleft()

        # Evaluate rules
        for rule in self.rules:
            rule_id = rule["id"]
            rule_name = rule["name"]
            description = rule["description"]
            severity = rule["severity"]
            time_window = rule.get("time_window", 0)
            threshold = rule.get("threshold", 1)
            group_by = rule.get("group_by", None)
            unique_field = rule.get("unique_field", None)
            rule_filter = rule.get("filter", {})

            # If new log doesn't match the basic filter, skip it
            if not self.log_matches_filter(new_log, rule_filter):
                continue

            # Case 1: Threshold is 1 (immediate alert on match, time_window is 0 or ignored)
            if threshold <= 1:
                self.trigger_alert(rule_id, rule_name, description, severity, [new_log])
                continue

            # Case 2: Multi-event correlation (threshold > 1 and time_window > 0)
            if time_window > 0:
                cutoff_time = now - timedelta(seconds=time_window)
                
                # Gather matches in the time window
                matching_logs = []
                for log_time, log in self.log_buffer:
                    if log_time >= cutoff_time and self.log_matches_filter(log, rule_filter):
                        matching_logs.append(log)

                # Filter by group_by field value if specified (e.g. only matching logs from the SAME src_ip)
                if group_by:
                    group_val = new_log.get("parsed_data", {}).get(group_by)
                    if not group_val:
                        continue  # Log doesn't have the group_by attribute, ignore correlation
                    
                    matching_logs = [
                        log for log in matching_logs 
                        if log.get("parsed_data", {}).get(group_by) == group_val
                    ]

                # Evaluate threshold
                if unique_field:
                    # Count distinct values of the unique_field across matching logs
                    unique_vals = set(
                        log.get("parsed_data", {}).get(unique_field) 
                        for log in matching_logs 
                        if log.get("parsed_data", {}).get(unique_field) is not None
                    )
                    metric_count = len(unique_vals)
                else:
                    metric_count = len(matching_logs)

                if metric_count >= threshold:
                    # Check rate limits for this rule / group to prevent alarm fatigue
                    group_key = str(new_log.get("parsed_data", {}).get(group_by, "global")) if group_by else "global"
                    rate_limit_expiry = self.recent_alerts.get(rule_id, {}).get(group_key)
                    
                    if rate_limit_expiry and now < rate_limit_expiry:
                        # Rate limit active, suppress duplicate alert
                        continue
                        
                    # Set rate limit to 30 seconds from now
                    if rule_id not in self.recent_alerts:
                        self.recent_alerts[rule_id] = {}
                    self.recent_alerts[rule_id][group_key] = now + timedelta(seconds=30)
                    
                    # Construct description detail
                    trigger_desc = f"{description} (Detected {metric_count} occurrences from {group_key})"
                    self.trigger_alert(rule_id, rule_name, trigger_desc, severity, matching_logs)

    def trigger_alert(self, rule_id: str, rule_name: str, description: str, severity: str, triggering_logs: list):
        alert_id = str(uuid.uuid4())
        timestamp = datetime.now().isoformat()
        
        alert = {
            "id": alert_id,
            "timestamp": timestamp,
            "rule_id": rule_id,
            "rule_name": rule_name,
            "description": description,
            "severity": severity,
            "triggering_logs": triggering_logs
        }
        
        # Run alert callback (saving to DB and sending to WebSocket)
        self.alert_callback(alert)
