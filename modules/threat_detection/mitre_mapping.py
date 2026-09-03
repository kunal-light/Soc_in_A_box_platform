def get_mitre_mapping(event_type):
    event_type = (event_type or "").upper()

    mapping = {
        "LOGIN_SUCCESS": (
            "N/A",
            "Benign Activity"
        ),

        "LOGIN_FAILED": (
            "T1110",
            "Brute Force"
        ),

        "PORT_SCAN": (
            "T1046",
            "Network Service Discovery"
        ),

        "MALWARE_DETECTED": (
            "T1204",
            "User Execution"
        )
    }

    return mapping.get(
        event_type,
        (
            "Unknown",
            "Unknown Technique"
        )
    )