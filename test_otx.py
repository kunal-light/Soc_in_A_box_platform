import requests

API_KEY = "83eb5040fed3d4a8684ff1693f686e673bca1c304bdd3dd6809f1856a784e18f"

headers = {
    "X-OTX-API-KEY": API_KEY
}

url = "https://otx.alienvault.com/api/v1/indicators/domain/google.com/general"

response = requests.get(
    url,
    headers=headers,
    timeout=10
)

print("Status Code:", response.status_code)

if response.status_code == 200:
    data = response.json()
    print("Domain:", data.get("indicator"))
    print("Pulse Count:", len(data.get("pulse_info", {}).get("pulses", [])))
else:
    print(response.text)