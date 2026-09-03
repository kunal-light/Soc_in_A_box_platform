from modules.database import get_connection
from modules.threat_detection.detector import ThreatDetector


class ThreatDetectionService:

    def __init__(self):
        self.detector = ThreatDetector()

    def get_last_processed_id(self):
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            SELECT last_processed_log_id
            FROM threat_detection_state
            ORDER BY id
            LIMIT 1;
        """)

        row = cur.fetchone()

        if row is None:
            cur.execute("""
                INSERT INTO threat_detection_state(last_processed_log_id)
                VALUES (0)
                RETURNING last_processed_log_id;
            """)
            conn.commit()
            last_processed = 0
        else:
            last_processed = row[0]

        cur.close()
        conn.close()

        return last_processed

    def update_last_processed_id(self, latest_id):
        conn = get_connection()
        cur = conn.cursor()

        cur.execute("""
            UPDATE threat_detection_state
            SET
                last_processed_log_id = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = (
                SELECT id
                FROM threat_detection_state
                ORDER BY id
                LIMIT 1
            );
        """, (latest_id,))

        conn.commit()

        cur.close()
        conn.close()

    def run_detection(self):

        last_processed = self.get_last_processed_id()

        latest_id = self.detector.analyze_logs(last_processed)

        processed = latest_id - last_processed

        self.update_last_processed_id(latest_id)

        return {
            "success": True,
            "processed_logs": processed,
            "last_processed_id": latest_id
        }

    def reset_detector(self):

        self.update_last_processed_id(0)

        return {
            "success": True,
            "message": "Threat detector reset successfully."
        }


threat_detection_service = ThreatDetectionService()