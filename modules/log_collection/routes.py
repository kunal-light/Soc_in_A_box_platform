import os
from .services import parse_uploaded_file
from datetime import datetime

from flask import (
    render_template,
    request,
    redirect,
    url_for,
    flash
)

from werkzeug.utils import secure_filename

from config import Config
from . import log_collection_bp
from modules.database import get_connection   # Change this if your function name differs


print("Routes imported")
print("Blueprint ID in routes:", id(log_collection_bp))


# ----------------------------------------
# Allowed File Types
# ----------------------------------------

ALLOWED_EXTENSIONS = {
    "evtx",
    "log",
    "txt",
    "json",
    "csv"
}

UPLOAD_SUBFOLDERS = {
    "evtx": "windows",
    "log": "linux",
    "txt": "linux",
    "json": "json",
    "csv": "csv"
}


def allowed_file(filename):
    return (
        "." in filename and
        filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS
    )


# ----------------------------------------
# Dashboard
# ----------------------------------------

@log_collection_bp.route("/log-collection")
def log_collection_dashboard():

    conn = get_connection()
    cur = conn.cursor()

    # Recent uploads
    cur.execute("""
        SELECT
    id,
    original_filename,
    stored_filename,
    upload_path,
    file_type,
    file_size,
    status,
    uploaded_at
FROM log_uploads
ORDER BY uploaded_at DESC
LIMIT 10;
    """)

    uploads = cur.fetchall()

    # Total uploads
    cur.execute("""
        SELECT COUNT(*)
        FROM log_uploads;
    """)
    total_uploads = cur.fetchone()[0]

    # Windows uploads
    cur.execute("""
        SELECT COUNT(*)
        FROM log_uploads
        WHERE file_type='EVTX';
    """)
    windows_logs = cur.fetchone()[0]

    # Linux uploads
    cur.execute("""
        SELECT COUNT(*)
        FROM log_uploads
        WHERE file_type IN ('LOG','TXT');
    """)
    linux_logs = cur.fetchone()[0]

    # Distinct log source types
    cur.execute("""
        SELECT COUNT(DISTINCT file_type)
        FROM log_uploads;
    """)
    registered_sources = cur.fetchone()[0]

# -----------------------------
# Collector Statistics
# -----------------------------

# Total parsed events
    cur.execute("""
    SELECT COUNT(*)
    FROM parsed_logs;
""")

    files_parsed = cur.fetchone()[0]


# Last collected event
    cur.execute("""
    SELECT MAX(event_time)
    FROM parsed_logs;
""")

    last_collection = cur.fetchone()[0]


# Failed imports
    cur.execute("""
SELECT COUNT(*)
FROM log_uploads
WHERE status='Failed';
""")

    failed_imports = cur.fetchone()[0]

    

    cur.close()
    conn.close()
    

    return render_template(
    "log_collection/dashboard.html",

    uploads=uploads,

    total_uploads=total_uploads,

    windows_logs=windows_logs,

    linux_logs=linux_logs,

    registered_sources=registered_sources,

    files_parsed=files_parsed,

    last_collection=last_collection,

    failed_imports=failed_imports
)

# ----------------------------------------
# Upload Route
# ----------------------------------------

@log_collection_bp.route("/log-collection/upload", methods=["POST"])
def upload_log():

    if "log_file" not in request.files:
        flash("No file selected.", "danger")
        return redirect(url_for("log_collection.log_collection_dashboard"))

    file = request.files["log_file"]

    if file.filename == "":
        flash("Please choose a file.", "warning")
        return redirect(url_for("log_collection.log_collection_dashboard"))

    if not allowed_file(file.filename):
        flash("Unsupported file type.", "danger")
        return redirect(url_for("log_collection.log_collection_dashboard"))

    # Original filename
    original_filename = secure_filename(file.filename)

    # File extension
    extension = original_filename.rsplit(".", 1)[1].lower()

    # File type stored in database (CSV, JSON, EVTX, LOG, TXT)
    file_type = extension.upper()

    # Determine upload folder
    folder = UPLOAD_SUBFOLDERS.get(extension, "temp")

    upload_directory = os.path.join(
        Config.UPLOAD_FOLDER,
        folder
    )

    os.makedirs(upload_directory, exist_ok=True)

    # Create unique filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    stored_filename = f"{timestamp}_{original_filename}"

    save_path = os.path.join(
        upload_directory,
        stored_filename
    )

    # Save uploaded file
    file.save(save_path)

    file_size = os.path.getsize(save_path)

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO log_uploads
        (
            original_filename,
            stored_filename,
            file_type,
            file_size,
            upload_path,
            uploaded_by,
            status
        )
        VALUES
        (
            %s,%s,%s,%s,%s,%s,%s
        )
        RETURNING id;
    """,
    (
        original_filename,
        stored_filename,
        file_type,
        file_size,
        save_path,
        "Admin",
        "Uploaded"
    ))

    # Get the generated upload ID
    upload_id = cur.fetchone()[0]

    conn.commit()

    cur.close()
    conn.close()

    # Automatically send the file to the appropriate parser
    parse_uploaded_file(
        upload_id,
        save_path,
        file_type
    )

    flash("Log uploaded successfully.", "success")

    return redirect(
        url_for("log_collection.log_collection_dashboard")
    )
@log_collection_bp.route("/log-collection/delete/<int:upload_id>")
def delete_upload(upload_id):

    conn = get_connection()
    cur = conn.cursor()

    cur.execute("""
        SELECT upload_path
        FROM log_uploads
        WHERE id=%s;
    """, (upload_id,))

    row = cur.fetchone()

    if row is None:

        flash("Upload not found.", "danger")

        cur.close()
        conn.close()

        return redirect(url_for("log_collection.log_collection_dashboard"))

    file_path = row[0]

    if os.path.exists(file_path):
        os.remove(file_path)

    cur.execute("""
        DELETE FROM log_uploads
        WHERE id=%s;
    """, (upload_id,))

    conn.commit()

    cur.close()
    conn.close()

    flash("Upload deleted successfully.", "success")

    return redirect(url_for("log_collection.log_collection_dashboard"))