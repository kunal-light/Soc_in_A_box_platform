# Version 13 - Dashboard Threat Feed Sync

Version 13 adds an AlienVault OTX synchronization action to the Threat Intelligence page.

## Use

1. Start the project in a PowerShell session where OTX_API_KEY and PostgreSQL environment variables are configured.
2. Open Threat Intelligence.
3. Click `Sync AlienVault OTX`.
4. Wait for the request to complete.
5. A success message shows valid indicators fetched and new IOCs inserted.
6. The page refreshes with updated PostgreSQL-backed OTX counts and recorded feed synchronization health.

The existing `sync_otx.py` CLI remains available as a fallback.

Note: The synchronization is synchronous in this internship-scale version. A production deployment should move external feed synchronization to a background job/task queue with authentication, CSRF protection, rate limiting, and scheduled execution.
