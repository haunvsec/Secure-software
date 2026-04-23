"""Homepage controller."""

from flask import Blueprint, render_template
from database import get_db
from models import get_stats, get_latest_cves

main_bp = Blueprint('main', __name__)


@main_bp.route('/')
def index():
    db = get_db()
    stats = get_stats(db)
    latest_cves = get_latest_cves(db)
    return render_template('index.html', active_page='home', stats=stats, latest_cves=latest_cves)
