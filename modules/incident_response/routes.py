from flask import Blueprint, render_template

from modules.incident_response.dashboard import (
    get_all_incidents,
    get_open_count,
    get_critical_count,
    get_assigned_count
)

from flask import redirect
from modules.database import get_connection
from flask import redirect, url_for

incident_bp = Blueprint(
    "incident_response",
    __name__,
    template_folder="../../templates/incident_response"
)


@incident_bp.route("/incident-response")
def dashboard():

    incidents = get_all_incidents()

    return render_template(

        "incident_response/dashboard.html",

        incidents=incidents,

        open_count=get_open_count(),

        critical_count=get_critical_count(),

        assigned_count=get_assigned_count()

    )




@incident_bp.route("/incident-response/create/<int:alert_id>")
def create_incident(alert_id):

    conn = get_connection()
    cur = conn.cursor()

     # Check whether an incident already exists for this alert
    cur.execute("""
        SELECT id
        FROM incidents
        WHERE alert_id = %s
        LIMIT 1
    """, (alert_id,))

    existing = cur.fetchone()

    if existing:
        cur.close()
        conn.close()
        return redirect("/incident-response")

    # Fetch alert details
    cur.execute("""
        SELECT
            rule_name,
            alert_type,
            severity
        FROM threat_alerts
        WHERE id = %s
    """, (alert_id,))

    alert = cur.fetchone()

    if not alert:
        cur.close()
        conn.close()
        return redirect("/threat-detection")

    # Insert into incidents
    cur.execute("""
    INSERT INTO incidents (
        alert_id,
        title,
        threat_type,
        severity
    )
    VALUES (%s, %s, %s, %s)
    ON CONFLICT (alert_id) DO NOTHING
""", (
    alert_id,
    alert[0],
    alert[1],
    alert[2]
))

    conn.commit()

    cur.close()
    conn.close()

    return redirect("/incident-response")

@incident_bp.route("/incident-response/view/<int:incident_id>")
def view_incident(incident_id):

    from modules.incident_response.dashboard import get_incident_by_id

    incident = get_incident_by_id(incident_id)

    return render_template(
        "incident_response/incident_details.html",
        incident=incident
    )

@incident_bp.route("/incident-response/assign/<int:incident_id>", methods=["GET", "POST"])
def assign_incident(incident_id):

    from flask import request, redirect

    conn = get_connection()
    cur = conn.cursor()

    if request.method == "POST":

        analyst = request.form["assigned_to"]

        cur.execute("""
            UPDATE incidents
            SET assigned_to = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (analyst, incident_id))

        conn.commit()

        cur.close()
        conn.close()

        return redirect("/incident-response")

    cur.execute("""
        SELECT
            id,
            title,
            assigned_to
        FROM incidents
        WHERE id=%s
    """, (incident_id,))

    incident = cur.fetchone()

    cur.close()
    conn.close()

    return render_template(
        "incident_response/assign_incident.html",
        incident=incident
    )

@incident_bp.route("/incident-response/status/<int:incident_id>", methods=["GET", "POST"])
def update_status(incident_id):

    from flask import request, redirect

    conn = get_connection()
    cur = conn.cursor()

    if request.method == "POST":

        status = request.form["status"]

        cur.execute("""
            UPDATE incidents
            SET status = %s,
                updated_at = CURRENT_TIMESTAMP
            WHERE id = %s
        """, (status, incident_id))

        conn.commit()

        cur.close()
        conn.close()

        return redirect("/incident-response")

    cur.execute("""
        SELECT
            id,
            title,
            status
        FROM incidents
        WHERE id=%s
    """, (incident_id,))

    incident = cur.fetchone()

    cur.close()
    conn.close()

    return render_template(
        "incident_response/update_status.html",
        incident=incident
    )

@incident_bp.route(
    "/incident-response/investigate/<int:incident_id>",
    methods=["POST"]
)
def investigate_incident(incident_id):

    from flask import request

    playbook = request.form.get("playbook", "").strip()
    notes = request.form.get("notes", "").strip()

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        UPDATE incidents
        SET
            playbook = %s,
            notes = %s,
            updated_at = CURRENT_TIMESTAMP
        WHERE id = %s
    """, (
        playbook,
        notes,
        incident_id
    ))

    conn.commit()

    cur.close()
    conn.close()

    return redirect(
        url_for(
            "incident_response.view_incident",
            incident_id=incident_id
        )
    )

@incident_bp.route("/incident-response/delete/<int:incident_id>", methods=["POST"])
def delete_incident(incident_id):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        DELETE FROM incidents
        WHERE id = %s
    """, (incident_id,))

    conn.commit()

    cur.close()
    conn.close()

    return redirect("/incident-response")