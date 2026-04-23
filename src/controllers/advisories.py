"""Security advisories controller."""

from flask import Blueprint, render_template, request
from database import get_db
from models import (
    get_advisories, get_advisory_sources, get_advisory_detail,
    get_advisory_affected, get_advisory_cves, get_advisory_refs, sanitize_page,
)

advisories_bp = Blueprint('advisories', __name__)


@advisories_bp.route('/advisories')
def advisories_list():
    db = get_db()
    page = sanitize_page(request.args.get('page'))
    source = request.args.get('source', '').strip() or None
    severity = request.args.get('severity', '').strip() or None
    result = get_advisories(db, page, source=source, severity=severity)
    sources = get_advisory_sources(db)
    return render_template('advisories.html', active_page='advisories',
                           advisories=result['items'], pagination=result,
                           sources=sources, current_source=source,
                           current_severity=severity, base_url='/advisories')


@advisories_bp.route('/advisories/<path:advisory_id>')
def advisory_detail_page(advisory_id):
    db = get_db()
    adv = get_advisory_detail(db, advisory_id)
    if adv is None:
        return render_template('404.html', active_page=''), 404
    affected = get_advisory_affected(db, advisory_id)
    cves = get_advisory_cves(db, advisory_id)
    references = get_advisory_refs(db, advisory_id)
    return render_template('advisory_detail.html', active_page='advisories',
                           advisory=adv, affected=affected, cves=cves,
                           references=references)
