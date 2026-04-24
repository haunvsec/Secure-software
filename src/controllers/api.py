"""API controller for sync status and management."""

from flask import Blueprint, jsonify
from database import get_session
from scheduler import get_sync_status

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/sync/status')
def sync_status():
    """Return sync status from DB (commit hashes) + in-memory scheduler status."""
    from models.orm import SyncState

    # DB state (commit hashes)
    session = get_session()
    rows = session.query(SyncState).all()
    db_state = {}
    for r in rows:
        db_state[r.source] = {
            'last_commit_hash': r.last_commit_hash,
            'last_sync_time': r.last_sync_time,
            'files_changed': r.files_changed,
            'records_updated': r.records_updated,
            'status': r.status,
        }

    # Merge with in-memory scheduler status
    sched_status = get_sync_status()

    result = {}
    for key in ('cve', 'advisory'):
        result[key] = {**sched_status.get(key, {}), **db_state.get(key, {})}

    return jsonify(result)
