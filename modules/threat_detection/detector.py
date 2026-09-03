from modules.database import get_connection

from modules.threat_detection.detectors.behavior import BehaviorAnalyzer
# from modules.threat_detection.detectors.anomaly import AnomalyAnalyzer
# from modules.threat_detection.detectors.malware import MalwareAnalyzer
# from modules.threat_detection.detectors.intrusion import IntrusionAnalyzer

from modules.threat_detection.risk_scoring import calculate_risk_score
from modules.threat_detection.mitre_mapping import get_mitre_mapping


class ThreatDetector:

    def __init__(self):

        self.behavior = BehaviorAnalyzer()

        # Enable these after we adapt them
        # self.anomaly = AnomalyAnalyzer()
        # self.malware = MalwareAnalyzer()
        # self.intrusion = IntrusionAnalyzer()

    def fetch_new_logs(self, last_processed_id):

        conn = get_connection()
        cur = conn.cursor()

        cur.execute(
            """
            SELECT
                id,
                event_time,
                source,
                source_ip,
                destination_ip,
                username,
                hostname,
                event_type,
                severity,
                protocol,
                action,
                raw_message
            FROM parsed_logs
            WHERE id > %s
            ORDER BY id ASC;
            """,
            (last_processed_id,)
        )

        columns = [desc[0] for desc in cur.description]

        rows = cur.fetchall()

        cur.close()
        conn.close()

        logs = []

        for row in rows:
            logs.append(dict(zip(columns, row)))

        return logs

    def analyze_logs(self, last_processed_id):

        logs = self.fetch_new_logs(last_processed_id)

        latest_id = last_processed_id

        for log in logs:


            # -------------------------
        # Risk Scoring
        # -------------------------

            risk_score, risk_level = calculate_risk_score(
            log.get("event_type")
        )

        # -------------------------
        # MITRE ATT&CK Mapping
        # -------------------------

            mitre_id, mitre_technique = get_mitre_mapping(
            log.get("event_type")
        )

            log["risk_score"] = risk_score
            log["risk_level"] = risk_level
            log["mitre_id"] = mitre_id
            log["mitre_technique"] = mitre_technique
            # Behavior Detection
            self.behavior.process_log(log)

            # Enable later
            # self.anomaly.process_log(log)
            # self.malware.process_log(log)
            # self.intrusion.process_log(log)

            latest_id = log["id"]

        return latest_id