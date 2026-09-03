from config import Config
import psycopg2

DB_NAME = "IOC_DATABASE"
DB_USER = "postgres"
DB_PASSWORD = "Postgres@admin#1234"
DB_HOST = "localhost"
DB_PORT = "5432"


def get_connection():

    return psycopg2.connect(
        database=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )


def create_database():

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""

    CREATE TABLE IF NOT EXISTS iocs(

        id SERIAL PRIMARY KEY,

        indicator TEXT UNIQUE,

        ioc_type TEXT,

        source TEXT,

        severity TEXT

    )

    """)

    conn.commit()

    cursor.close()
    conn.close()


def insert_ioc(

    indicator,

    ioc_type,

    source="LOCAL",

    severity="LOW"

):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO iocs
        (
            indicator,
            ioc_type,
            source,
            severity
        )

        VALUES (%s,%s,%s,%s)

        ON CONFLICT (indicator)

        DO UPDATE SET

            ioc_type = EXCLUDED.ioc_type,

            source = EXCLUDED.source,

            severity = EXCLUDED.severity

        """,

        (
            indicator,
            ioc_type,
            source,
            severity
        )

    )

    conn.commit()

    cursor.close()
    conn.close()


def insert_multiple_iocs(ioc_list):

    conn = get_connection()
    cursor = conn.cursor()

    for indicator, ioc_type, source, severity in ioc_list:

        cursor.execute(
            """
            INSERT INTO iocs
            (
                indicator,
                ioc_type,
                source,
                severity
            )

            VALUES (%s,%s,%s,%s)

            ON CONFLICT (indicator)

            DO UPDATE SET

                ioc_type = EXCLUDED.ioc_type,

                source = EXCLUDED.source,

                severity = EXCLUDED.severity

            """,

            (
                indicator,
                ioc_type,
                source,
                severity
            )

        )

    conn.commit()

    cursor.close()
    conn.close()


def insert_domain_reputation(

    domain,

    pulse_count,

    status

):

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO domain_reputation
        (
            domain_name,
            pulse_count,
            reputation_status
        )

        VALUES (%s,%s,%s)

        """,

        (
            domain,
            pulse_count,
            status
        )

    )

    conn.commit()

    cursor.close()
    conn.close()

# ============================================================
# Alert Management - Version 3
# ============================================================

def create_alerts_table():
    """Create the enterprise alert table if it does not already exist."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id SERIAL PRIMARY KEY,
            indicator TEXT NOT NULL,
            ioc_type VARCHAR(50),
            source VARCHAR(100),
            severity VARCHAR(20) NOT NULL DEFAULT 'MEDIUM',
            status VARCHAR(30) NOT NULL DEFAULT 'OPEN',
            title TEXT,
            description TEXT,
            correlation_details TEXT,
            first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            resolved_at TIMESTAMP NULL
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_status
        ON alerts(status)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_severity
        ON alerts(severity)
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_alerts_indicator
        ON alerts(indicator)
    """)
    conn.commit()
    cursor.close()
    conn.close()


def insert_alert(indicator, ioc_type=None, source=None, severity="MEDIUM",
                 title=None, description=None, correlation_details=None):
    """Persist a new alert and avoid duplicate open alerts for the same IOC."""
    create_alerts_table()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT id
        FROM alerts
        WHERE indicator = %s
          AND UPPER(status) IN ('OPEN', 'INVESTIGATING')
        ORDER BY first_seen DESC
        LIMIT 1
    """, (indicator,))
    existing = cursor.fetchone()

    if existing:
        cursor.execute("""
            UPDATE alerts
            SET updated_at = CURRENT_TIMESTAMP,
                severity = %s,
                source = COALESCE(%s, source),
                correlation_details = COALESCE(%s, correlation_details)
            WHERE id = %s
        """, (severity, source, correlation_details, existing[0]))
        alert_id = existing[0]
    else:
        cursor.execute("""
            INSERT INTO alerts (
                indicator, ioc_type, source, severity, status,
                title, description, correlation_details
            )
            VALUES (%s, %s, %s, %s, 'OPEN', %s, %s, %s)
            RETURNING id
        """, (
            indicator, ioc_type, source, severity,
            title or "Threat Intelligence Match",
            description,
            correlation_details
        ))
        alert_id = cursor.fetchone()[0]

    conn.commit()
    cursor.close()
    conn.close()
    return alert_id


def update_alert_status(alert_id, status):
    """Update an alert workflow status."""
    allowed = {"OPEN", "INVESTIGATING", "RESOLVED"}
    normalized = status.upper()
    if normalized not in allowed:
        raise ValueError("Invalid alert status")

    conn = get_connection()
    cursor = conn.cursor()

    if normalized == "RESOLVED":
        cursor.execute("""
            UPDATE alerts
            SET status = %s,
                updated_at = CURRENT_TIMESTAMP,
                resolved_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (normalized, alert_id))
    else:
        cursor.execute("""
            UPDATE alerts
            SET status = %s,
                updated_at = CURRENT_TIMESTAMP,
                resolved_at = NULL
            WHERE id = %s
        """, (normalized, alert_id))

    conn.commit()
    cursor.close()
    conn.close()

# ============================================================
# Threat Feed Health - Version 10
# ============================================================

def create_feed_sync_table():
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS threat_feed_sync (
            id SERIAL PRIMARY KEY,
            feed_name VARCHAR(100) NOT NULL,
            status VARCHAR(30) NOT NULL,
            records_processed INTEGER DEFAULT 0,
            message TEXT,
            synced_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE INDEX IF NOT EXISTS idx_threat_feed_sync_name_time
        ON threat_feed_sync(feed_name, synced_at DESC)
    """)
    conn.commit()
    cursor.close()
    conn.close()


def record_feed_sync(feed_name, status, records_processed=0, message=None):
    create_feed_sync_table()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO threat_feed_sync(feed_name, status, records_processed, message)
        VALUES (%s, %s, %s, %s)
    """, (feed_name, status, records_processed, message))
    conn.commit()
    cursor.close()
    conn.close()


def get_latest_feed_sync(feed_name):
    create_feed_sync_table()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT status, records_processed, message, synced_at
        FROM threat_feed_sync
        WHERE UPPER(feed_name) = UPPER(%s)
        ORDER BY synced_at DESC
        LIMIT 1
    """, (feed_name,))
    row = cursor.fetchone()
    cursor.close()
    conn.close()
    return row

