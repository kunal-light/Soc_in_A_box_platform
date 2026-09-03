"""Threat feed synchronization monitoring.

Use run_monitored_feed() around existing OTX/AbuseIPDB collector functions.
It records actual success/failure and processed-record counts without replacing
the existing collection implementation.
"""
from modules.database import record_feed_sync


def run_monitored_feed(feed_name, collector, *args, **kwargs):
    try:
        result = collector(*args, **kwargs)

        if isinstance(result, int):
            processed = result
        elif isinstance(result, (list, tuple, set, dict)):
            processed = len(result)
        else:
            processed = 0

        record_feed_sync(
            feed_name=feed_name,
            status="SUCCESS",
            records_processed=processed,
            message="Feed synchronization completed successfully."
        )
        return result
    except Exception as exc:
        record_feed_sync(
            feed_name=feed_name,
            status="FAILED",
            records_processed=0,
            message=str(exc)[:1000]
        )
        raise
