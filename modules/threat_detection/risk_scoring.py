def calculate_risk_score(event_type):
    """
    Calculate a risk score based on the normalized event type.

    Returns:
        tuple: (score, risk_level)
    """

    event_type = (event_type or "").upper()

    scores = {
        "LOGIN_SUCCESS": (10, "LOW"),
        "LOGIN_FAILED": (40, "MEDIUM"),
        "PORT_SCAN": (75, "HIGH"),
        "MALWARE_DETECTED": (100, "CRITICAL"),
    }

    return scores.get(
        event_type,
        (0, "UNKNOWN")
    )