from CORE.collector import collect_iocs
from CORE.validator import validate_iocs
from CORE.classifier import classify_ioc
from CORE.database import create_database
from CORE.matcher import match_logs
from CORE.alert import generate_alert
from CORE.threat_feed import fetch_threat_feed
from CORE.domain_reputation import check_domain_reputation

# Create Database
create_database()

# Download latest threat feed
fetch_threat_feed()

# Extract IOCs from logs
iocs = collect_iocs()

# Remove duplicates
validated = validate_iocs(iocs)

print("\n========== EXTRACTED IOCs ==========\n")

for ioc in validated:

    ioc_type = classify_ioc(ioc)

    print(ioc, "-->", ioc_type)

    if ioc_type == "DOMAIN":

        check_domain_reputation(ioc)

print("\n========== THREAT CORRELATION ==========\n")

matches = match_logs()

generate_alert(matches)