import re

def collect_iocs():

    with open("logs/sample_logs.txt", "r") as file:
        logs = file.readlines()

    iocs = []

    # IPv4 Address
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    # URL
    url_pattern = r"https?://[^\s]+"

    # Domain
    domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"

    for log in logs:

        # Extract IPs
        ips = re.findall(ip_pattern, log)
        iocs.extend(ips)

        # Extract URLs
        urls = re.findall(url_pattern, log)
        iocs.extend(urls)

        # Extract Domains
        domains = re.findall(domain_pattern, log)

        for domain in domains:

            # Skip domains already present inside URLs
            if not any(domain in url for url in urls):
                iocs.append(domain)

    return iocs