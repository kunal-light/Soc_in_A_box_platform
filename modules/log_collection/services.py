import os
import csv
import json

from Evtx.Evtx import Evtx

from .engine.collector import process_log
from modules.threat_detection.services import threat_detection_service

def parse_uploaded_file(upload_id, file_path, file_type):
    """
    Dispatch uploaded files to the appropriate reader.
    """

    file_type = file_type.upper()

    if file_type == "CSV":
        return process_csv(file_path)

    elif file_type == "JSON":
        return process_json(file_path)

    elif file_type == "EVTX":
        return process_evtx(file_path)

    elif file_type in ["LOG", "TXT"]:
        return process_log_file(file_path)

    else:
        raise ValueError(f"Unsupported file type: {file_type}")


# ----------------------------------------------------
# CSV
# ----------------------------------------------------

def process_csv(file_path):

    processed = 0

    with open(
        file_path,
        newline="",
        encoding="utf-8",
        errors="ignore"
    ) as csvfile:

        reader = csv.DictReader(csvfile)

        for row in reader:

            raw_log = json.dumps(row)

            process_log(
                raw_log,
                f"CSV:{os.path.basename(file_path)}"
            )

            processed += 1

    print(f"[CSV] Processed {processed} events.")

    # Run threat detection after all CSV logs
    # have been inserted into parsed_logs.
    detection_result = threat_detection_service.run_detection()

    print(
        f"[CSV] Threat detection processed "
        f"{detection_result['processed_logs']} logs."
    )

    return processed


# ----------------------------------------------------
# JSON
# ----------------------------------------------------

def process_json(file_path):

    processed = 0

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as f:

        data = json.load(f)

    if isinstance(data, list):

        for item in data:

            process_log(
                json.dumps(item),
                f"JSON:{os.path.basename(file_path)}"
            )

            processed += 1

    elif isinstance(data, dict):

        process_log(
            json.dumps(data),
            f"JSON:{os.path.basename(file_path)}"
        )

        processed = 1

    print(f"[JSON] Processed {processed} events.")

    return processed


# ----------------------------------------------------
# LOG / TXT
# ----------------------------------------------------

def process_log_file(file_path):

    processed = 0

    with open(
        file_path,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as logfile:

        for line in logfile:

            line = line.strip()

            if not line:
                continue

            process_log(
                line,
                f"LOG:{os.path.basename(file_path)}"
            )

            processed += 1

    print(f"[LOG] Processed {processed} events.")

    return processed


# ----------------------------------------------------
# EVTX
# ----------------------------------------------------

def process_evtx(file_path):

    processed = 0

    with Evtx(file_path) as log:

        for record in log.records():

            xml = record.xml()

            process_log(
                xml,
                f"EVTX:{os.path.basename(file_path)}"
            )

            processed += 1

    print(f"[EVTX] Processed {processed} events.")

    return processed