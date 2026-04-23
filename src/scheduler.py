"""Background scheduler for periodic data sync.

Uses APScheduler to run CVE and advisory sync jobs every hour.
"""

import logging
import os
import sys
from datetime import datetime, timezone

logger = logging.getLogger('scheduler')

# Sync status storage (in-memory)
sync_status = {
    'cve': {
        'last_sync': None,
        'next_sync': None,
        'result': None,
        'files_changed': 0,
        'records_updated': 0,
        'duration': 0,
    },
    'advisory': {
        'last_sync': None,
        'next_sync': None,
        'result': None,
        'files_changed': 0,
        'records_updated': 0,
        'duration': 0,
    },
}

SYNC_INTERVAL_HOURS = int(os.environ.get('SYNC_INTERVAL_HOURS', 1))


def _get_scripts_dir():
    """Resolve scripts directory relative to this file or /app."""
    # In container: /app/scheduler.py → /app/scripts
    # In dev: src/scheduler.py → scripts/
    app_dir = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(app_dir, 'scripts')
    if os.path.isdir(candidate):
        return candidate
    # Fallback: parent directory (dev layout: src/ → project root)
    parent = os.path.dirname(app_dir)
    candidate = os.path.join(parent, 'scripts')
    if os.path.isdir(candidate):
        return candidate
    return candidate  # return anyway, will fail gracefully


def _run_cve_sync():
    """Execute CVE sync job."""
    logger.info("Starting CVE sync job...")
    try:
        # Add scripts to path
        scripts_dir = _get_scripts_dir()
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)

        from sync_cves import sync
        result = sync()

        sync_status['cve']['last_sync'] = datetime.now(timezone.utc).isoformat()
        sync_status['cve']['result'] = result.get('status', 'unknown')
        sync_status['cve']['files_changed'] = result.get('files_changed', 0)
        sync_status['cve']['records_updated'] = result.get('records_updated', 0)
        sync_status['cve']['duration'] = result.get('duration', 0)
    except Exception as e:
        logger.error(f"CVE sync job failed: {e}")
        sync_status['cve']['last_sync'] = datetime.now(timezone.utc).isoformat()
        sync_status['cve']['result'] = f'error: {e}'


def _run_advisory_sync():
    """Execute advisory sync job."""
    logger.info("Starting advisory sync job...")
    try:
        scripts_dir = _get_scripts_dir()
        if scripts_dir not in sys.path:
            sys.path.insert(0, scripts_dir)

        from sync_advisories import sync
        result = sync()

        sync_status['advisory']['last_sync'] = datetime.now(timezone.utc).isoformat()
        sync_status['advisory']['result'] = result.get('status', 'unknown')
        sync_status['advisory']['files_changed'] = result.get('files_changed', 0)
        sync_status['advisory']['records_updated'] = result.get('records_updated', 0)
        sync_status['advisory']['duration'] = result.get('duration', 0)
    except Exception as e:
        logger.error(f"Advisory sync job failed: {e}")
        sync_status['advisory']['last_sync'] = datetime.now(timezone.utc).isoformat()
        sync_status['advisory']['result'] = f'error: {e}'


def init_scheduler(app):
    """Initialize and start the background scheduler."""
    if os.environ.get('DISABLE_SCHEDULER', '').lower() in ('1', 'true', 'yes'):
        logger.info("Scheduler disabled via DISABLE_SCHEDULER env var")
        return

    try:
        from apscheduler.schedulers.background import BackgroundScheduler
    except ImportError:
        logger.warning("APScheduler not installed. Scheduler disabled.")
        return

    scheduler = BackgroundScheduler(daemon=True)

    scheduler.add_job(
        _run_cve_sync,
        'cron',
        minute=15,
        id='sync_cves',
        name='Sync CVE data',
    )

    scheduler.add_job(
        _run_advisory_sync,
        'cron',
        minute=15,
        id='sync_advisories',
        name='Sync advisory data',
    )

    scheduler.start()
    logger.info(f"Scheduler started. Sync interval: {SYNC_INTERVAL_HOURS}h")

    # Update next_sync times
    for job in scheduler.get_jobs():
        if job.id == 'sync_cves':
            sync_status['cve']['next_sync'] = str(job.next_run_time) if job.next_run_time else 'pending'
        elif job.id == 'sync_advisories':
            sync_status['advisory']['next_sync'] = str(job.next_run_time) if job.next_run_time else 'pending'

    app.extensions['scheduler'] = scheduler


def get_sync_status():
    """Return current sync status for API."""
    return sync_status
