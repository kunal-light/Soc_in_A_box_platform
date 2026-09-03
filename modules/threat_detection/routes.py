from flask import render_template, request

from . import threat_detection_bp
from .dashboard import (
    get_total_alerts,
    get_recent_alerts,
    get_alerts_by_severity,
    get_alert_by_id,
    update_alert_status,
    search_alerts,
    get_alert_trend,
    get_severity_chart,
    get_top_rules,
    get_top_source_ips
)


@threat_detection_bp.route("/threat-detection")
def dashboard():

    total_alerts = get_total_alerts()

    search = request.args.get("search", "")
    severity_filter = request.args.get("severity", "")
    status_filter = request.args.get("status", "")

    if search or severity_filter or status_filter:
     recent_alerts = search_alerts(
        search,
        severity_filter,
        status_filter
    )
    else:
     recent_alerts = get_recent_alerts()

    severity = {
        row[0]: row[1]
        for row in get_alerts_by_severity()
    }
    trend = get_alert_trend()
    severity_chart = get_severity_chart()
    top_rules = get_top_rules()
    top_source_ips = get_top_source_ips()

    print("Trend:", trend)
    print("Severity:", severity_chart)
    print("Top Rules:", top_rules)
    print("Top Source IPs:", top_source_ips)

    return render_template(

        "threat_detection/dashboard.html",

        total_alerts=total_alerts,

        recent_alerts=recent_alerts,

        critical_alerts=severity.get("Critical", 0),

        high_alerts=severity.get("High", 0),

        medium_alerts=severity.get("Medium", 0),

        low_alerts=severity.get("Low", 0),

        search=search,
        severity_filter=severity_filter,
        status_filter=status_filter,

        trend=trend,
        severity_chart=severity_chart,
        top_rules=top_rules,
        top_source_ips=top_source_ips,

    )
from flask import redirect, url_for


@threat_detection_bp.route("/threat-detection/view/<int:alert_id>")
def view_alert(alert_id):

    alert = get_alert_by_id(alert_id)

    if not alert:
        return "Alert not found", 404

    return render_template(
        "threat_detection/alert_details.html",
        alert=alert
    )


@threat_detection_bp.route("/threat-detection/investigate/<int:alert_id>")
def investigate_alert(alert_id):

    update_alert_status(alert_id, "INVESTIGATING")

    return redirect(url_for("threat_detection.view_alert", alert_id=alert_id))

@threat_detection_bp.route("/threat-detection/resolve/<int:alert_id>")
def resolve_alert(alert_id):

    update_alert_status(alert_id, "RESOLVED")

    return redirect(url_for("threat_detection.view_alert", alert_id=alert_id))