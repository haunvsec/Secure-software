"""CVE list and detail controller."""

from flask import Blueprint, render_template, request
from database import get_session
from models.queries import (
    get_cves, get_cve_detail, get_cve_cvss, get_cve_affected,
    get_cve_cwes, get_cve_references, sanitize_page, sanitize_severity,
    sanitize_year,
)

cves_bp = Blueprint('cves', __name__)


@cves_bp.route('/cves')
def cves_list():
    session = get_session()
    page = sanitize_page(request.args.get('page'))
    year = sanitize_year(request.args.get('year'))
    severity = sanitize_severity(request.args.get('severity'))
    result = get_cves(session, page, year=year, severity=severity)
    return render_template('cves.html', active_page='cves', pagination=result,
                           cves=result['items'], current_year=year,
                           current_severity=severity, base_url='/cves')


@cves_bp.route('/cves/<cve_id>')
def cve_detail(cve_id):
    session = get_session()
    cve = get_cve_detail(session, cve_id)
    if cve is None:
        return render_template('404.html', active_page=''), 404
    cvss_scores = get_cve_cvss(session, cve_id)
    affected = get_cve_affected(session, cve_id)
    cwes = get_cve_cwes(session, cve_id)
    references = get_cve_references(session, cve_id)
    return render_template('cve_detail.html', active_page='cves', cve=cve,
                           cvss_scores=cvss_scores, affected=affected,
                           cwes=cwes, references=references)
