from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import mm
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
from modules.otx_ingestion import ingest_otx_feed
from config import Config
from pathlib import Path
from datetime import datetime
from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    send_from_directory,
    session,
    flash
)

from modules.database import get_connection, create_alerts_table, update_alert_status, create_feed_sync_table, get_latest_feed_sync
from modules.matcher import match_ioc
from modules.log_collection import log_collection_bp
from modules.threat_detection import threat_detection_bp

from modules.threat_detection.dashboard import (
    get_total_alerts,
    get_recent_alerts,
    get_alerts_by_severity
)

from modules.incident_response.routes import incident_bp
from modules.reports.routes import reports_bp

from functools import wraps
from werkzeug.security import check_password_hash

app = Flask(__name__)
app.config.from_object(Config)
app.config["SECRET_KEY"] = Config.SECRET_KEY

print("Blueprint ID in app:", id(log_collection_bp))
app.register_blueprint(log_collection_bp)

print("Blueprint ID in app:", id(threat_detection_bp))
app.register_blueprint(threat_detection_bp)

app.register_blueprint(incident_bp)

app.register_blueprint(reports_bp)



@app.before_request
def require_admin_login():

    allowed_endpoints = {
        "login",
        "static"
    }

    if request.endpoint in allowed_endpoints:
        return

    if not session.get("admin_logged_in"):
        return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        if (
            username == Config.ADMIN_USERNAME
            and check_password_hash(
                Config.ADMIN_PASSWORD_HASH,
                password
            )
        ):
            session["admin_logged_in"] = True
            session["admin_username"] = username

            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")

@app.route("/logout")
def logout():

    session.pop("admin_logged_in", None)
    session.pop("admin_username", None)


    return redirect(url_for("login"))

def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):

        if not session.get("admin_logged_in"):
            return redirect(url_for("login"))

        return view(*args, **kwargs)

    return wrapped_view

@app.route("/")
@login_required
def dashboard():
    create_alerts_table()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM iocs")
    total_iocs = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM iocs WHERE UPPER(severity) = 'HIGH'")
    high_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM iocs WHERE UPPER(ioc_type) = 'DOMAIN'")
    domain_count = cursor.fetchone()[0]

    cursor.execute("SELECT COUNT(*) FROM iocs WHERE UPPER(ioc_type) = 'IP'")
    ip_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM alerts
        WHERE UPPER(status) IN ('OPEN', 'INVESTIGATING')
    """)
    alert_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT UPPER(COALESCE(ioc_type, 'UNKNOWN')), COUNT(*)
        FROM iocs GROUP BY UPPER(COALESCE(ioc_type, 'UNKNOWN'))
        ORDER BY COUNT(*) DESC
    """)
    type_stats = cursor.fetchall()

    cursor.execute("""
        SELECT UPPER(COALESCE(source, 'UNKNOWN')), COUNT(*)
        FROM iocs GROUP BY UPPER(COALESCE(source, 'UNKNOWN'))
        ORDER BY COUNT(*) DESC
    """)
    source_stats = cursor.fetchall()

    cursor.execute("""
        SELECT UPPER(COALESCE(severity, 'UNKNOWN')), COUNT(*)
        FROM iocs GROUP BY UPPER(COALESCE(severity, 'UNKNOWN'))
        ORDER BY COUNT(*) DESC
    """)
    severity_stats = cursor.fetchall()

    cursor.execute("""
        SELECT indicator, ioc_type, source, severity, created_at
        FROM iocs ORDER BY created_at DESC LIMIT 10
    """)
    recent_iocs = cursor.fetchall()

    cursor.execute("""
        SELECT domain_name, pulse_count, reputation_status, checked_at
        FROM domain_reputation ORDER BY checked_at DESC LIMIT 10
    """)
    recent_domains = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM domain_reputation")
    domains_checked = cursor.fetchone()[0]

    # -----------------------------
# Threat Detection Statistics
# -----------------------------

    td_total_alerts = get_total_alerts()

    td_recent_alerts = get_recent_alerts()

    td_severity = get_alerts_by_severity()

    td_severity_dict = {
    row[0]: row[1]
    for row in td_severity
}
    
    cursor.close()
    conn.close()

    return render_template(
     "dashboard/dashboard.html",
        total_iocs=total_iocs,
        high_count=high_count,
        domain_count=domain_count,
        domains_checked=domains_checked,
        alert_count=alert_count,
        ip_count=ip_count,
        recent_iocs=recent_iocs,
        recent_domains=recent_domains,
        type_stats=type_stats,
        source_stats=source_stats,
        severity_stats=severity_stats,
        type_labels=[r[0] for r in type_stats],
        type_values=[r[1] for r in type_stats],
        severity_labels=[r[0] for r in severity_stats],
        severity_values=[r[1] for r in severity_stats],
        td_total_alerts= td_total_alerts,
        td_recent_alerts= td_recent_alerts,
        td_critical= td_severity_dict.get("CRITICAL", 0),
        td_high= td_severity_dict.get("HIGH", 0),
        td_medium= td_severity_dict.get("MEDIUM", 0),
        td_low= td_severity_dict.get("LOW", 0),
          ) 


@app.route("/alerts")
@login_required
def alerts():
    create_alerts_table()
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT id, indicator, ioc_type, source, severity, status,
               title, description, first_seen, updated_at
        FROM alerts
        ORDER BY
            CASE UPPER(severity)
                WHEN 'CRITICAL' THEN 1
                WHEN 'HIGH' THEN 2
                WHEN 'MEDIUM' THEN 3
                WHEN 'LOW' THEN 4
                ELSE 5
            END,
            first_seen DESC
    """)
    alert_rows = cursor.fetchall()

    cursor.execute("SELECT COUNT(*) FROM alerts WHERE UPPER(status) = 'OPEN'")
    open_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE UPPER(status) = 'INVESTIGATING'")
    investigating_count = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM alerts WHERE UPPER(status) = 'RESOLVED'")
    resolved_count = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    return render_template(
        "alerts.html",
        alerts=alert_rows,
        open_count=open_count,
        investigating_count=investigating_count,
        resolved_count=resolved_count
    )


@app.route("/alerts/<int:alert_id>/status", methods=["POST"])
def alert_status(alert_id):
    status = request.form.get("status", "OPEN")
    update_alert_status(alert_id, status)
    return redirect(url_for("alerts"))


@app.route("/domain-reputation")
@login_required
def domain_reputation_dashboard():
    """Enterprise domain reputation explorer backed by stored reputation checks."""
    search = request.args.get("search", "").strip()
    risk = request.args.get("risk", "").strip()

    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1

    per_page = 25
    offset = (page - 1) * per_page

    conditions = []
    params = []

    if search:
        conditions.append("domain_name ILIKE %s")
        params.append(f"%{search}%")

    if risk:
        conditions.append("UPPER(reputation_status) = UPPER(%s)")
        params.append(risk)

    where_clause = ""
    if conditions:
        where_clause = " WHERE " + " AND ".join(conditions)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM domain_reputation")
    total_checks = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM domain_reputation
        WHERE UPPER(reputation_status) = 'HIGH RISK'
    """)
    high_risk_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM domain_reputation
        WHERE UPPER(reputation_status) = 'SUSPICIOUS'
    """)
    suspicious_count = cursor.fetchone()[0]

    cursor.execute("""
        SELECT COUNT(*) FROM domain_reputation
        WHERE UPPER(reputation_status) NOT IN ('HIGH RISK', 'SUSPICIOUS')
    """)
    low_risk_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM domain_reputation" + where_clause,
        tuple(params)
    )
    filtered_total = cursor.fetchone()[0]
    total_pages = max((filtered_total + per_page - 1) // per_page, 1)

    if page > total_pages:
        page = total_pages
        offset = (page - 1) * per_page

    cursor.execute(
        """
        SELECT domain_name, pulse_count, reputation_status, checked_at
        FROM domain_reputation
        """ + where_clause + """
        ORDER BY checked_at DESC
        LIMIT %s OFFSET %s
        """,
        tuple(params + [per_page, offset])
    )
    domains = cursor.fetchall()

    cursor.execute("""
        SELECT UPPER(COALESCE(reputation_status, 'UNKNOWN')), COUNT(*)
        FROM domain_reputation
        GROUP BY UPPER(COALESCE(reputation_status, 'UNKNOWN'))
        ORDER BY COUNT(*) DESC
    """)
    reputation_stats = cursor.fetchall()

    cursor.execute("""
        SELECT DISTINCT reputation_status
        FROM domain_reputation
        WHERE reputation_status IS NOT NULL
        ORDER BY reputation_status
    """)
    statuses = [row[0] for row in cursor.fetchall()]

    cursor.close()
    conn.close()

    return render_template(
        "domain_reputation_dashboard.html",
        domains=domains,
        total_checks=total_checks,
        high_risk_count=high_risk_count,
        suspicious_count=suspicious_count,
        low_risk_count=low_risk_count,
        filtered_total=filtered_total,
        page=page,
        total_pages=total_pages,
        search=search,
        selected_risk=risk,
        statuses=statuses,
        reputation_labels=[row[0] for row in reputation_stats],
        reputation_values=[row[1] for row in reputation_stats]
    )


@app.route("/threat-intelligence")
@login_required
def threat_intelligence():
    """Threat Intelligence feed dashboard backed by PostgreSQL IOC data."""
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) FROM iocs")
    total_iocs = cursor.fetchone()[0]

    cursor.execute("""
        SELECT UPPER(COALESCE(source, 'UNKNOWN')), COUNT(*)
        FROM iocs
        GROUP BY UPPER(COALESCE(source, 'UNKNOWN'))
        ORDER BY COUNT(*) DESC
    """)
    source_stats = cursor.fetchall()

    cursor.execute("""
        SELECT UPPER(COALESCE(ioc_type, 'UNKNOWN')), COUNT(*)
        FROM iocs
        GROUP BY UPPER(COALESCE(ioc_type, 'UNKNOWN'))
        ORDER BY COUNT(*) DESC
    """)
    type_stats = cursor.fetchall()

    cursor.execute("""
        SELECT UPPER(COALESCE(severity, 'UNKNOWN')), COUNT(*)
        FROM iocs
        GROUP BY UPPER(COALESCE(severity, 'UNKNOWN'))
        ORDER BY COUNT(*) DESC
    """)
    severity_stats = cursor.fetchall()

    cursor.execute("""
        SELECT indicator, ioc_type, source, severity, created_at
        FROM iocs
        ORDER BY created_at DESC
        LIMIT 25
    """)
    recent_intelligence = cursor.fetchall()

    cursor.execute("""
        SELECT MAX(created_at)
        FROM iocs
    """)
    last_ingestion = cursor.fetchone()[0]

    cursor.close()
    conn.close()

    create_feed_sync_table()
    otx_sync = get_latest_feed_sync("AlienVault OTX")
    abuse_sync = get_latest_feed_sync("AbuseIPDB")

    source_map = {str(row[0]).upper(): row[1] for row in source_stats}
    otx_count = sum(
        count for source_name, count in source_stats
        if "OTX" in str(source_name).upper() or "ALIENVAULT" in str(source_name).upper()
    )
    abuseipdb_count = sum(
        count for source_name, count in source_stats
        if "ABUSE" in str(source_name).upper()
    )

    return render_template(
        "threat_intelligence/dashboard.html",
        total_iocs=total_iocs,
        otx_count=otx_count,
        abuseipdb_count=abuseipdb_count,
        source_stats=source_stats,
        type_stats=type_stats,
        severity_stats=severity_stats,
        recent_intelligence=recent_intelligence,
        last_ingestion=last_ingestion,
        otx_sync=otx_sync,
        abuse_sync=abuse_sync,
        source_labels=[row[0] for row in source_stats],
        source_values=[row[1] for row in source_stats],
        type_labels=[row[0] for row in type_stats],
        type_values=[row[1] for row in type_stats]
    )


@app.route("/iocs")
@login_required
def ioc_explorer():
    """Enterprise IOC Explorer with search, filters, and pagination."""
    search = request.args.get("search", "").strip()
    ioc_type = request.args.get("type", "").strip()
    severity = request.args.get("severity", "").strip()
    source = request.args.get("source", "").strip()

    try:
        page = max(int(request.args.get("page", 1)), 1)
    except ValueError:
        page = 1

    per_page = 50
    offset = (page - 1) * per_page

    conditions = []
    params = []

    if search:
        conditions.append("indicator ILIKE %s")
        params.append(f"%{search}%")

    if ioc_type:
        conditions.append("UPPER(ioc_type) = UPPER(%s)")
        params.append(ioc_type)

    if severity:
        conditions.append("UPPER(severity) = UPPER(%s)")
        params.append(severity)

    if source:
        conditions.append("UPPER(source) = UPPER(%s)")
        params.append(source)

    where_clause = ""
    if conditions:
        where_clause = " WHERE " + " AND ".join(conditions)

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT COUNT(*) FROM iocs" + where_clause,
        tuple(params)
    )
    total = cursor.fetchone()[0]
    total_pages = max((total + per_page - 1) // per_page, 1)

    if page > total_pages:
        page = total_pages
        offset = (page - 1) * per_page

    cursor.execute(
        """
        SELECT indicator, ioc_type, source, severity, created_at
        FROM iocs
        """ + where_clause + """
        ORDER BY created_at DESC
        LIMIT %s OFFSET %s
        """,
        tuple(params + [per_page, offset])
    )
    iocs = cursor.fetchall()

    cursor.execute("""
        SELECT DISTINCT ioc_type FROM iocs
        WHERE ioc_type IS NOT NULL
        ORDER BY ioc_type
    """)
    types = [row[0] for row in cursor.fetchall()]

    cursor.execute("""
        SELECT DISTINCT severity FROM iocs
        WHERE severity IS NOT NULL
        ORDER BY severity
    """)
    severities = [row[0] for row in cursor.fetchall()]

    cursor.execute("""
        SELECT DISTINCT source FROM iocs
        WHERE source IS NOT NULL
        ORDER BY source
    """)
    sources = [row[0] for row in cursor.fetchall()]

    cursor.close()
    conn.close()

    return render_template(
        "ioc_explorer.html",
        iocs=iocs,
        total=total,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        search=search,
        selected_type=ioc_type,
        selected_severity=severity,
        selected_source=source,
        types=types,
        severities=severities,
        sources=sources
    )


@app.route("/correlate", methods=["POST"])
def correlate():
    """
    Correlate an incoming indicator against the IOC repository.
    Accepts either JSON or form data.
    """
    payload = request.get_json(silent=True) or request.form

    indicator = payload.get("indicator")
    source = payload.get("source", "Manual Correlation Test")
    details = payload.get("details")

    if not indicator:
        return {
            "success": False,
            "error": "indicator is required"
        }, 400

    result = match_ioc(
        indicator=indicator,
        event_source=source,
        event_details=details
    )

    return {
        "success": True,
        "result": result
    }


REPORTS_DIR = Path(__file__).resolve().parent / "generated_reports"
REPORTS_DIR.mkdir(exist_ok=True)


@app.route("/reports")
@login_required
def reports():
    report_files = sorted(
        [p for p in REPORTS_DIR.iterdir() if p.is_file() and p.suffix.lower() in (".pdf", ".txt")],
        key=lambda p: p.stat().st_mtime,
        reverse=True
    )
    reports_data = [{
        "name": p.name,
        "size_kb": round(p.stat().st_size / 1024, 2),
        "modified": datetime.fromtimestamp(p.stat().st_mtime)
    } for p in report_files]
    return render_template("reports.html", reports=reports_data)




@app.route("/reports/generate", methods=["POST"])
def generate_report():
    conn = get_connection()
    cur = conn.cursor()
    def one(q):
        try:
            cur.execute(q); r=cur.fetchone(); return r[0] if r else 0
        except Exception:
            conn.rollback(); return 0
    def many(q):
        try:
            cur.execute(q); return cur.fetchall()
        except Exception:
            conn.rollback(); return []
    total=one("SELECT COUNT(*) FROM iocs")
    high=one("SELECT COUNT(*) FROM iocs WHERE UPPER(COALESCE(severity,''))='HIGH'")
    alerts=one("SELECT COUNT(*) FROM alerts WHERE UPPER(COALESCE(status,'')) IN ('OPEN','INVESTIGATING')")
    domains=one("SELECT COUNT(*) FROM domain_reputation")
    sources=many("SELECT UPPER(COALESCE(source,'UNKNOWN')),COUNT(*) FROM iocs GROUP BY UPPER(COALESCE(source,'UNKNOWN')) ORDER BY COUNT(*) DESC")
    types=many("SELECT UPPER(COALESCE(ioc_type,'UNKNOWN')),COUNT(*) FROM iocs GROUP BY UPPER(COALESCE(ioc_type,'UNKNOWN')) ORDER BY COUNT(*) DESC")
    cur.close(); conn.close()

    REPORTS_DIR.mkdir(parents=True,exist_ok=True)
    now=datetime.now()
    filename=f"soc_threat_report_{now.strftime('%Y%m%d_%H%M%S')}.pdf"
    path=REPORTS_DIR/filename
    styles=getSampleStyleSheet()
    doc=SimpleDocTemplate(str(path),pagesize=A4,leftMargin=18*mm,rightMargin=18*mm,topMargin=18*mm,bottomMargin=18*mm)
    story=[
        Paragraph("SOC-in-a-Box Platform",styles["Title"]),
        Paragraph("Enterprise Threat Intelligence Report",styles["Heading1"]),
        Paragraph(f"Generated: {now.strftime('%d %B %Y at %H:%M:%S')}",styles["Normal"]),
        Spacer(1,12),
        Paragraph("Executive Summary",styles["Heading2"]),
        Paragraph("Automated point-in-time security intelligence report generated from the live PostgreSQL SOC datastore.",styles["BodyText"]),
        Spacer(1,12)
    ]
    k=Table([["Total IOCs","High Severity","Active Alerts","Domain Checks"],[str(total),str(high),str(alerts),str(domains)]])
    k.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#1f2937")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),("ALIGN",(0,0),(-1,-1),"CENTER"),("GRID",(0,0),(-1,-1),0.5,colors.grey),("PADDING",(0,0),(-1,-1),8)]))
    story += [k,Spacer(1,14),Paragraph("IOC Source Distribution",styles["Heading2"])]
    s=Table([["Source","IOC Count"]]+[[str(a),str(b)] for a,b in (sources or [("No data",0)])])
    s.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#374151")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.grey)]))
    story += [s,Spacer(1,14),Paragraph("IOC Classification Distribution",styles["Heading2"])]
    t=Table([["IOC Type","IOC Count"]]+[[str(a),str(b)] for a,b in (types or [("No data",0)])])
    t.setStyle(TableStyle([("BACKGROUND",(0,0),(-1,0),colors.HexColor("#374151")),("TEXTCOLOR",(0,0),(-1,0),colors.white),("GRID",(0,0),(-1,-1),0.4,colors.grey)]))
    story.append(t)
    doc.build(story)
    return redirect(url_for("reports"))


@app.route("/reports/download/<path:filename>")
@login_required
def download_report(filename):
    return send_from_directory(REPORTS_DIR, filename, as_attachment=True)


@app.route("/settings")
@login_required
def settings():
    """Read-only platform configuration and health overview."""
    import os

    db_status = "Unavailable"
    db_error = None
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("SELECT 1")
        cursor.fetchone()
        cursor.close()
        conn.close()
        db_status = "Connected"
    except Exception as exc:
        db_error = str(exc)

    config_status = {
        "database": db_status,
        "otx_key_configured": bool(os.getenv("OTX_API_KEY")),
        "abuseipdb_key_configured": bool(os.getenv("ABUSEIPDB_API_KEY")),
        "flask_debug": bool(app.debug),
    }

    return render_template(
        "settings/settings.html",
        config_status=config_status,
        db_error=db_error
    )


@app.route("/threat-intelligence/sync/otx", methods=["POST"])
def sync_otx_feed():
    """Synchronize AlienVault OTX indicators from the SOC dashboard."""
    try:
        result = ingest_otx_feed(limit=10)
        return redirect(
            url_for(
                "threat_intelligence",
                sync_status="success",
                fetched=result["fetched"],
                inserted=result["inserted"]
            )
        )
    except Exception as exc:
        return redirect(
            url_for(
                "threat_intelligence",
                sync_status="failed",
                sync_error=str(exc)[:300]
            )
        )


if __name__ == "__main__":
    create_alerts_table()
  
    app.run(debug=Config.DEBUG)
from pathlib import Path
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, send_from_directory
from modules.database import get_connection, create_alerts_table, update_alert_status, create_feed_sync_table, get_latest_feed_sync
from modules.matcher import match_ioc





