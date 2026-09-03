from flask import Blueprint, render_template

from modules.reports.dashboard import (
    get_report_summary,
    get_all_report_data
)
reports_bp = Blueprint(
    "reports",
    __name__,
    template_folder="../../templates/reports"
)

from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import (
    SimpleDocTemplate,
    Table,
    TableStyle,
    Paragraph
)

from io import BytesIO
from flask import send_file

@reports_bp.route("/reports")
def dashboard():

    summary = get_report_summary()

    return render_template(
        "reports/dashboard.html",
        summary=summary
    )

import csv

from flask import Response

@reports_bp.route("/reports/export/csv")
def export_csv():

    data = get_all_report_data()

    def generate():

        yield "Alert ID,Rule,Type,Severity,Status,Detected At,Assigned Analyst\n"

        for row in data:

            yield ",".join([
                str(row[0]),
                str(row[1]),
                str(row[2]),
                str(row[3]),
                str(row[4]),
                str(row[5]),
                str(row[6] or "")
            ]) + "\n"

    return Response(

        generate(),

        mimetype="text/csv",

        headers={

            "Content-Disposition":
            "attachment; filename=soc_report.csv"

        }

    )

@reports_bp.route("/reports/export/pdf")
def export_pdf():

    data = get_all_report_data()

    buffer = BytesIO()

    doc = SimpleDocTemplate(buffer)

    styles = getSampleStyleSheet()

    elements = []

    elements.append(
        Paragraph(
            "<b>SOC Threat Report</b>",
            styles["Title"]
        )
    )

    table_data = [[
        "Alert ID",
        "Rule",
        "Type",
        "Severity",
        "Status",
        "Assigned"
    ]]

    for row in data:

        table_data.append([

            str(row[0]),
            row[1],
            row[2],
            row[3],
            row[4],
            row[6] or "-"

        ])

    table = Table(table_data)

    table.setStyle(TableStyle([

        ("BACKGROUND",(0,0),(-1,0),colors.darkblue),

        ("TEXTCOLOR",(0,0),(-1,0),colors.white),

        ("GRID",(0,0),(-1,-1),1,colors.black),

        ("BACKGROUND",(0,1),(-1,-1),colors.beige),

        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),

        ("BOTTOMPADDING",(0,0),(-1,0),10),

    ]))

    elements.append(table)

    doc.build(elements)

    buffer.seek(0)

    return send_file(

        buffer,

        as_attachment=True,

        download_name="SOC_Report.pdf",

        mimetype="application/pdf"

    )

