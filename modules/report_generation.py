from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

from CORE.database import get_connection


def generate_report():

    conn = get_connection()
    cursor = conn.cursor()

    # Total IOCs
    cursor.execute("SELECT COUNT(*) FROM iocs")
    total_iocs = cursor.fetchone()[0]

    # IOC Types
    cursor.execute("""
        SELECT ioc_type, COUNT(*)
        FROM iocs
        GROUP BY ioc_type
    """)
    type_stats = cursor.fetchall()

    # Sources
    cursor.execute("""
        SELECT source, COUNT(*)
        FROM iocs
        GROUP BY source
    """)
    source_stats = cursor.fetchall()

    cursor.close()
    conn.close()

    pdf = SimpleDocTemplate("Threat_Report.pdf")

    styles = getSampleStyleSheet()

    content = []

    content.append(
        Paragraph(
            "Threat Intelligence Report",
            styles['Title']
        )
    )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            f"Total IOCs: {total_iocs}",
            styles['Normal']
        )
    )

    content.append(Spacer(1, 10))

    content.append(
        Paragraph(
            "IOC Type Statistics",
            styles['Heading2']
        )
    )

    for row in type_stats:

        content.append(
            Paragraph(
                f"{row[0]} : {row[1]}",
                styles['Normal']
            )
        )

    content.append(Spacer(1, 10))

    content.append(
        Paragraph(
            "Threat Sources",
            styles['Heading2']
        )
    )

    for row in source_stats:

        content.append(
            Paragraph(
                f"{row[0]} : {row[1]}",
                styles['Normal']
            )
        )

    content.append(Spacer(1, 20))

    content.append(
        Paragraph(
            "Recommendations",
            styles['Heading2']
        )
    )

    content.append(
        Paragraph(
            """
            • Block malicious IP addresses.
            <br/>
            • Investigate suspicious activity.
            <br/>
            • Update firewall and IDS rules.
            <br/>
            • Continue monitoring threat feeds.
            """,
            styles['Normal']
        )
    )

    pdf.build(content)

    print("Threat Report Generated Successfully!")