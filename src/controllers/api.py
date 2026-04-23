"""API controller for sync status and management."""

from flask import Blueprint, jsonify
from scheduler import get_sync_status

api_bp = Blueprint('api', __name__, url_prefix='/api')


@api_bp.route('/sync/status')
def sync_status():
    """Return current sync status as JSON."""
    return jsonify(get_sync_status())
