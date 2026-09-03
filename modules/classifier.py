import re

def classify_ioc(ioc):

    ip_pattern = r"^(?:\d{1,3}\.){3}\d{1,3}$"

    url_pattern = r"^https?://"

    domain_pattern = r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"

    hash_pattern = r"^[a-fA-F0-9]{32,64}$"

    if re.match(ip_pattern, ioc):
        return "IP"

    elif re.match(url_pattern, ioc):
        return "URL"

    elif re.match(domain_pattern, ioc):
        return "DOMAIN"

    elif re.match(hash_pattern, ioc):
        return "HASH"

    else:
        return "UNKNOWN"