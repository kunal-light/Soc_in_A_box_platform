"""SOC-in-a-Box Threat Correlation Engine.

Correlates incoming event indicators against the PostgreSQL IOC repository.
A confirmed IOC match automatically creates or refreshes a persisted SOC alert.
"""

from modules.database import get_connection
from modules.alert import generate_alert


def _normalize_indicator(indicator):
    """Normalize an incoming indicator before correlation."""
    if indicator is None:
        return ""
    return str(indicator).strip()


def match_ioc(indicator, event_source="Security Event", event_details=None):
    """
    Match one incoming indicator against the IOC database.

    Returns a dictionary describing the correlation result. If a match is found,
    a database-backed alert is generated automatically.
    """
    normalized = _normalize_indicator(indicator)

    if not normalized:
        return {
            "matched": False,
            "indicator": normalized,
            "reason": "Empty indicator"
        }

    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("""
        SELECT indicator, ioc_type, source, severity
        FROM iocs
        WHERE LOWER(indicator) = LOWER(%s)
        ORDER BY created_at DESC
        LIMIT 1
    """, (normalized,))

    row = cursor.fetchone()
    cursor.close()
    conn.close()

    if not row:
        return {
            "matched": False,
            "indicator": normalized,
            "reason": "Indicator not found in IOC database"
        }

    matched_indicator, ioc_type, intelligence_source, severity = row
    severity = severity or "HIGH"

    correlation_details = (
        f"Incoming source: {event_source}. "
        f"Matched IOC source: {intelligence_source or 'Unknown'}."
    )

    if event_details:
        correlation_details += f" Event details: {event_details}"

    alert_id = generate_alert(
        indicator=matched_indicator,
        ioc_type=ioc_type,
        source=intelligence_source or event_source,
        severity=severity,
        description=(
            f"Incoming security event matched known {ioc_type or 'IOC'} "
            f"indicator {matched_indicator}."
        ),
        correlation_details=correlation_details
    )

    return {
        "matched": True,
        "alert_id": alert_id,
        "indicator": matched_indicator,
        "ioc_type": ioc_type,
        "source": intelligence_source,
        "severity": severity
    }


def correlate_event(event):
    """
    Correlate a dictionary-based security event.

    Supported indicator keys:
    indicator, ip, ip_address, domain, url, hash, file_hash
    """
    if not isinstance(event, dict):
        raise TypeError("event must be a dictionary")

    indicator = (
        event.get("indicator")
        or event.get("ip")
        or event.get("ip_address")
        or event.get("domain")
        or event.get("url")
        or event.get("hash")
        or event.get("file_hash")
    )

    source = event.get("source") or event.get("event_source") or "Security Event"
    details = event.get("details") or event.get("message") or event.get("description")

    return match_ioc(
        indicator=indicator,
        event_source=source,
        event_details=details
    )


def match_events(events):
    """Correlate multiple incoming events and return all correlation results."""
    return [correlate_event(event) for event in events]


# Backwards-compatible alias for simple callers.
def match_indicator(indicator):
    return match_ioc(indicator)
