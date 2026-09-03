import requests
from modules.database import insert_domain_reputation

API_KEY = "83eb5040fed3d4a8684ff1693f686e673bca1c304bdd3dd6809f1856a784e18f"

def check_domain_reputation(domain):

    headers = {
        "X-OTX-API-KEY": API_KEY
    }

    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general"

    try:

        response = requests.get(
            url,
            headers=headers,
            timeout=30
        )

        if response.status_code != 200:

            print("OTX Error:", response.status_code)

            return None

        data = response.json()

        pulse_count = len(
            data.get("pulse_info", {}).get("pulses", [])
        )

        if pulse_count >= 10:

            status = "HIGH RISK"

        elif pulse_count > 0:

            status = "SUSPICIOUS"

        else:

            status = "CLEAN"

        print("\n========== DOMAIN REPUTATION ==========")
        print("Domain :", domain)
        print("OTX Pulses :", pulse_count)
        print("Status :", status)
        print("=======================================\n")

        insert_domain_reputation(
            domain,
            pulse_count,
            status
        )

        return {
            "domain": domain,
            "pulse_count": pulse_count,
            "status": status
        }

    except Exception as e:

        print("Error:", e)

        return None