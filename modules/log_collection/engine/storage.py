from modules.database import get_connection


def save_parsed_log(log_data):
    """
    Save a normalized log into PostgreSQL.
    """

    conn = get_connection()
    cur = conn.cursor()

    try:
        parsed = log_data.get("parsed_data", {})
        print("\n========== NORMALIZED LOG ==========")
        print(parsed)
        print("====================================\n")
 
        cur.execute("""
            INSERT INTO parsed_logs (
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
            )
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
        """, (

            log_data.get("timestamp"),

            log_data.get("source"),

            parsed.get("src_ip"),

            parsed.get("dst_ip"),

            parsed.get("user") or parsed.get("username"),

            parsed.get("hostname"),

            parsed.get("event_type"),

            log_data.get("level"),

            parsed.get("proto"),

            parsed.get("action"),

            log_data.get("message")

        ))

        conn.commit()

        return True

    except Exception as e:

          conn.rollback()

          import traceback

          print("\n==============================")
          print("DATABASE ERROR")
          traceback.print_exc()
          print("==============================\n")

          return False

    finally:

        cur.close()

        conn.close()