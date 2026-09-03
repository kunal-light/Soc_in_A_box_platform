import datetime
from collections import defaultdict
from typing import Dict

from modules.threat_detection.alerts import create_alert


class BehaviorAnalyzer:
    """
    Detects brute-force login attempts by tracking repeated
    failed login events from the same source IP.
    """

    def __init__(self, max_failures=5, timeframe_seconds=60):
        self.max_failures = max_failures
        self.timeframe_seconds = timeframe_seconds

        # {source_ip: [timestamps]}
        self.failed_logins: Dict[str, list] = defaultdict(list)

    def process_log(self, log_data):
        """
        Processes one normalized log record.

        Expected fields from parsed_logs:

            id
            source_ip
            destination_ip
            action
            username
            hostname
            severity
            event_type
        """

        source_ip = log_data.get("source_ip")
        action = log_data.get("action")

        # Only interested in failed login events
        if not source_ip or action != "login_failed":
            return

        now = datetime.datetime.utcnow()

        failures = self.failed_logins[source_ip]

        # Add latest failure
        failures.append(now)

        # Keep only failures within the configured time window
        failures = [
            t
            for t in failures
            if (now - t).total_seconds() <= self.timeframe_seconds
        ]

        self.failed_logins[source_ip] = failures

        # Trigger brute-force alert
        if len(failures) >= self.max_failures:

            create_alert(
    parsed_log_id=log_data.get("id"),
    rule_name="Brute Force Detection",
    alert_type="Behavior",
    severity="High",
    title="Possible SSH Brute Force Attack",
    description=(
        f"{len(failures)} failed login attempts "
        f"from {source_ip} within "
        f"{self.timeframe_seconds} seconds."
    ),

    risk_score=log_data.get("risk_score"),
    risk_level=log_data.get("risk_level"),

    mitre_id=log_data.get("mitre_id"),
    mitre_technique=log_data.get("mitre_technique"),
)
            

            print(
                f"[Behavior Detector] Brute force detected from {source_ip}"
            )

            # Reset counter after alert
            self.failed_logins[source_ip] = []