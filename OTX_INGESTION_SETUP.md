# Version 12 - OTX Ingestion
Run `python sync_otx.py` in the same PowerShell session where PostgreSQL and OTX environment variables are set.
The script fetches subscribed OTX pulses, extracts IP/domain/URL/hash indicators, validates them, skips existing indicators, inserts new records with source `AlienVault OTX`, and records synchronization health.
If it returns zero fetched indicators, the OTX account may have no subscribed pulses.
