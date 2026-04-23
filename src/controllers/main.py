"""Homepage controller."""

from flask import Blueprint, render_template
from database import get_session
from models.queries import get_stats, get_latest_cves

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    session = get_session()
    stats = get_stats(session)
    latest_cves = get_latest_cves(session)
    return render_template('index.html', active_page='home', stats=stats, latest_cves=latest_cves)
