from modules.database import get_connection


def get_report_summary():

    conn = get_connection()
    cur = conn.cursor()

    # Total Alerts
    cur.execute("SELECT COUNT(*) FROM threat_alerts")
    total_alerts = cur.fetchone()[0]

    # Open Incidents
    cur.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE UPPER(status) != 'RESOLVED'
    """)
    open_incidents = cur.fetchone()[0]

    # Resolved Incidents
    cur.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE UPPER(status) = 'RESOLVED'
    """)
    resolved_incidents = cur.fetchone()[0]

    # Critical Alerts
    cur.execute("""
        SELECT COUNT(*)
        FROM threat_alerts
        WHERE UPPER(severity) = 'CRITICAL'
    """)
    critical_alerts = cur.fetchone()[0]

    cur.close()
    conn.close()

    return {
        "total_alerts": total_alerts,
        "open_incidents": open_incidents,
        "resolved_incidents": resolved_incidents,
        "critical_alerts": critical_alerts
    }

def get_all_report_data():

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            ta.id,
            ta.rule_name,
            ta.alert_type,
            ta.severity,
            ta.status,
            ta.detected_at,

            i.assigned_to

        FROM threat_alerts ta

        LEFT JOIN incidents i
            ON ta.id = i.alert_id

        ORDER BY ta.detected_at DESC
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows