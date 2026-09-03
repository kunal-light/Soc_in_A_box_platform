from modules.database import get_connection


def create_alert(
    parsed_log_id,
    rule_name,
    alert_type,
    severity,
    title,
    description,
    risk_score=None,
    risk_level=None,
    mitre_id=None,
    mitre_technique=None
):
    """
    Creates a new threat detection alert
    with risk and MITRE ATT&CK metadata.
    """

    conn = get_connection()
    cur = conn.cursor()

    try:

        cur.execute(
            """
            INSERT INTO threat_alerts
            (
                parsed_log_id,
                rule_name,
                alert_type,
                severity,
                description,
                status,
                risk_score,
                risk_level,
                mitre_id,
                mitre_technique
            )
            VALUES
            (
                %s, %s, %s, %s, %s,
                %s, %s, %s, %s, %s
            )
            RETURNING id;
            """,
            (
                parsed_log_id,
                rule_name,
                alert_type,
                severity,
                description,
                "OPEN",
                risk_score,
                risk_level,
                mitre_id,
                mitre_technique
            )
        )

        alert_id = cur.fetchone()[0]

        conn.commit()

        print(f"[Threat Detection] Alert Created #{alert_id}")

        return alert_id

    except Exception as e:

        conn.rollback()

        print(f"[Threat Detection Error] {e}")

        return None

    finally:

        cur.close()
        conn.close()