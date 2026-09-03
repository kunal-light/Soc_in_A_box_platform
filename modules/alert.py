"""SOC-in-a-Box Alert Generation and Persistence."""

from modules.database import insert_alert


def generate_alert(indicator, ioc_type=None, source=None, severity="HIGH",
                   description=None, correlation_details=None):
    """
    Generate and persist an alert.

    Existing callers may pass only an indicator. Additional metadata is
    optional so this remains compatible with the current project architecture.
    """
    alert_id = insert_alert(
        indicator=indicator,
        ioc_type=ioc_type,
        source=source,
        severity=severity,
        title="Threat Intelligence Alert",
        description=description or f"Threat activity detected for {indicator}.",
        correlation_details=correlation_details
    )

    print(f"[ALERT #{alert_id}] {severity}: {indicator}")
    return alert_id
