from modules.database import get_connection


def get_all_incidents():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            alert_id,
            title,
            threat_type,
            severity,
            status,
            assigned_to,
            created_at
        FROM incidents
        ORDER BY created_at DESC
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows


def get_open_count():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE status='OPEN'
    """)

    count = cur.fetchone()[0]

    cur.close()
    conn.close()

    return count


def get_critical_count():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE UPPER(severity) = 'CRITICAL'
    """)

    count = cur.fetchone()[0]

    cur.close()
    conn.close()

    return count


def get_assigned_count():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*)
        FROM incidents
        WHERE assigned_to IS NOT NULL
          AND assigned_to <> ''
    """)

    count = cur.fetchone()[0]

    cur.close()
    conn.close()

    return count

def get_incident_by_id(incident_id):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            i.id,
            i.alert_id,
            i.title,
            i.threat_type,
            i.severity,
            i.status,
            i.assigned_to,
            i.playbook,
            i.notes,
            i.created_at,
            i.updated_at,

            ta.risk_score,
            ta.risk_level,
            ta.mitre_id,
            ta.mitre_technique

        FROM incidents i

        LEFT JOIN threat_alerts ta
            ON i.alert_id = ta.id

        WHERE i.id = %s
    """, (incident_id,))

    row = cur.fetchone()

    cur.close()
    conn.close()

    return row