import requests
from modules.database import insert_multiple_iocs

API_KEY = "2954c7315faa12622510fad8677ae6d60d48450f9e41b2d1dcd42c83f643f64d70a5206e0157286c"

def fetch_threat_feed():

    url = "https://api.abuseipdb.com/api/v2/blacklist"

    headers = {
        "Key": API_KEY,
        "Accept": "application/json"
    }

    params = {
        "confidenceMinimum": 90
    }

    response = requests.get(
        url,
        headers=headers,
        params=params
    )

    if response.status_code == 200:

        data = response.json()

        print("Threat feed fetched successfully!")

        ioc_batch = []

        for ip in data["data"]:

            indicator = ip["ipAddress"]

            ioc_batch.append(
                (
                    indicator,
                    "IP",
                    "ABUSEIPDB",
                    "HIGH"
                )
            )

        insert_multiple_iocs(ioc_batch)

        print(
            f"Stored {len(ioc_batch)} threat feed IPs in PostgreSQL!"
        )

        return data

    else:

        print("Error:", response.status_code)
        print(response.text)

        return None