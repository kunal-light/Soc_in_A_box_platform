from modules.database import get_connection


def get_total_alerts():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT COUNT(*)
        FROM threat_alerts
    """)

    total = cur.fetchone()[0]

    cur.close()
    conn.close()

    return total


def get_recent_alerts(limit=10):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            id,
            rule_name,
            alert_type,
            severity,
            description,
            status,
            detected_at,
            risk_score,
            risk_level,
            mitre_id,
            mitre_technique
        FROM threat_alerts
        ORDER BY detected_at DESC
        LIMIT %s
    """, (limit,))

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows


def get_alerts_by_severity():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT severity, COUNT(*)
        FROM threat_alerts
        GROUP BY severity
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows
from modules.database import get_connection


def get_alert_by_id(alert_id):
    """
    Returns a single threat alert along with its associated parsed log.
    """

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            ta.id,
            ta.rule_name,
            ta.alert_type,
            ta.severity,
            ta.status,
            ta.description,
            ta.detected_at,
            ta.risk_score,
            ta.risk_level,
            ta.mitre_id,
            ta.mitre_technique, 

            pl.event_time,
            pl.source_ip,
            pl.destination_ip,
            pl.username,
            pl.hostname,
            pl.event_type,
            pl.protocol,
            pl.action,
            pl.source,
            pl.raw_message

        FROM threat_alerts ta

        LEFT JOIN parsed_logs pl
            ON ta.parsed_log_id = pl.id

        WHERE ta.id = %s;

    """, (alert_id,))

    row = cur.fetchone()

    cur.close()
    conn.close()

    if not row:
        return None

    return {

        "id": row[0],
        "rule_name": row[1],
        "alert_type": row[2],
        "severity": row[3],
        "status": row[4],
        "description": row[5],
        "detected_at": row[6],

        "risk_score": row[7],
        "risk_level": row[8],
        "mitre_id": row[9],
        "mitre_technique": row[10],

        "event_time": row[11],
        "source_ip": row[12],
        "destination_ip": row[13],
        "username": row[14],
        "hostname": row[15],
        "event_type": row[16],
        "protocol": row[17],
        "action": row[18],
        "source": row[19],
        "raw_message": row[20]

    }
def update_alert_status(alert_id, status):
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE threat_alerts
        SET status = %s
        WHERE id = %s
    """, (status, alert_id))

    conn.commit()

    cur.close()
    conn.close()

def search_alerts(search="", severity="", status=""):
    """
    Search and filter threat alerts.
    """

    conn = get_connection()
    cur = conn.cursor()

    query = """
        SELECT
        id,
        rule_name,
        alert_type,
        severity,
        description,
        status,
        detected_at,
        risk_score,
        risk_level,
        mitre_id,
        mitre_technique
    FROM threat_alerts
    WHERE 1=1
    """

    params = []

    if search:
        query += """
            AND (
                rule_name ILIKE %s
                OR description ILIKE %s
            )
        """
        params.extend([
            f"%{search}%",
            f"%{search}%"
        ])

    if severity:
     query += " AND UPPER(severity) = UPPER(%s)"
     params.append(severity)

    if status:
     query += " AND UPPER(status) = UPPER(%s)"
     params.append(status)

    query += " ORDER BY detected_at DESC"

    cur.execute(query, tuple(params))

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows
def get_alert_trend():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            DATE(detected_at) AS day,
            COUNT(*) AS total
        FROM threat_alerts
        GROUP BY DATE(detected_at)
        ORDER BY day;
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows
def get_severity_chart():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            severity,
            COUNT(*)
        FROM threat_alerts
        GROUP BY severity
        ORDER BY COUNT(*) DESC;
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows
def get_top_rules():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            rule_name,
            COUNT(*)
        FROM threat_alerts
        GROUP BY rule_name
        ORDER BY COUNT(*) DESC
        LIMIT 5;
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows
def get_top_source_ips():
    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT
            pl.source_ip,
            COUNT(*)
        FROM threat_alerts ta
        JOIN parsed_logs pl
            ON ta.parsed_log_id = pl.id
        GROUP BY pl.source_ip
        ORDER BY COUNT(*) DESC
        LIMIT 5;
    """)

    rows = cur.fetchall()

    cur.close()
    conn.close()

    return rows