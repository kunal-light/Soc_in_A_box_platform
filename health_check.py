"""Local pre-demo health check for SOC-in-a-Box Threat Intelligence."""
from CORE.database import get_connection

def main():
    checks = []
    try:
        conn = get_connection()
        cur = conn.cursor()
        checks.append(("PostgreSQL", True, "Connected"))

        for table in ("iocs", "alerts", "domain_reputation", "threat_feed_sync"):
            try:
                cur.execute(f"SELECT COUNT(*) FROM {table}")
                count = cur.fetchone()[0]
                checks.append((table, True, f"{count} records"))
            except Exception as exc:
                conn.rollback()
                checks.append((table, False, str(exc)))

        try:
            cur.execute("""
                SELECT UPPER(COALESCE(source,'UNKNOWN')), COUNT(*)
                FROM iocs GROUP BY UPPER(COALESCE(source,'UNKNOWN'))
                ORDER BY COUNT(*) DESC
            """)
            sources = cur.fetchall()
            checks.append(("IOC sources", True, ", ".join(f"{s}: {c}" for s,c in sources)))
        except Exception as exc:
            conn.rollback()
            checks.append(("IOC sources", False, str(exc)))

        cur.close()
        conn.close()
    except Exception as exc:
        checks.append(("PostgreSQL", False, str(exc)))

    print("\\nSOC-in-a-Box Threat Intelligence Health Check")
    print("=" * 52)
    for name, ok, detail in checks:
        print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")

if __name__ == "__main__":
    main()
