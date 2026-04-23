"""Browse by date/type/severity/assigner controller."""

from flask import Blueprint, render_template, request
from database import get_db
from models import (
    get_years_with_counts, get_months_for_year, get_cves_by_month,
    get_cwe_types, get_cves_by_cwe,
    get_severity_summary, get_cves_by_severity,
    get_assigners, get_cves_by_assigner,
    sanitize_page, sanitize_severity, sanitize_year, _MONTH_NAMES,
)

browse_bp = Blueprint('browse', __name__)


@browse_bp.route('/cves/by-severity')
def by_severity():
    db = get_db()
    sev = sanitize_severity(request.args.get('severity'))
    page = sanitize_page(request.args.get('page'))
    if sev:
        result = get_cves_by_severity(db, sev, page)
        return render_template('by_severity.html', active_page='by_severity',
                               selected_severity=sev, cves=result['items'],
                               pagination=result, base_url='/cves/by-severity')
    summary = get_severity_summary(db)
    return render_template('by_severity.html', active_page='by_severity',
                           selected_severity=None, summary=summary)


@browse_bp.route('/cves/by-type')
def by_type():
    db = get_db()
    cwe = request.args.get('cwe')
    page = sanitize_page(request.args.get('page'))
    if cwe:
        result = get_cves_by_cwe(db, cwe, page)
        return render_template('by_type.html', active_page='by_type',
                               selected_cwe=cwe, cves=result['items'],
                               pagination=result, base_url='/cves/by-type')
    result = get_cwe_types(db, page)
    return render_template('by_type.html', active_page='by_type',
                           selected_cwe=None, types=result['items'],
                           pagination=result, base_url='/cves/by-type')


@browse_bp.route('/cves/by-date')
def by_date():
    db = get_db()
    year = sanitize_year(request.args.get('year'))
    month = request.args.get('month')
    if year and month and len(month) == 2 and month.isdigit() and 1 <= int(month) <= 12:
        page = sanitize_page(request.args.get('page'))
        result = get_cves_by_month(db, year, month, page)
        month_name = _MONTH_NAMES[int(month) - 1]
        return render_template('by_date.html', active_page='by_date',
                               selected_year=year, selected_month=month,
                               month_name=month_name, cves=result['items'],
                               pagination=result, base_url='/cves/by-date')
    elif year:
        months = get_months_for_year(db, year)
        return render_template('by_date.html', active_page='by_date',
                               selected_year=year, selected_month=None, months=months)
    years = get_years_with_counts(db)
    return render_template('by_date.html', active_page='by_date',
                           selected_year=None, selected_month=None, years=years)


@browse_bp.route('/assigners')
def assigners_list():
    db = get_db()
    page = sanitize_page(request.args.get('page'))
    result = get_assigners(db, page)
    return render_template('assigners.html', active_page='assigners',
                           selected_assigner=None, assigners=result['items'],
                           pagination=result, base_url='/assigners')


@browse_bp.route('/assigners/<assigner>')
def assigner_detail(assigner):
    db = get_db()
    page = sanitize_page(request.args.get('page'))
    result = get_cves_by_assigner(db, assigner, page)
    return render_template('assigners.html', active_page='assigners',
                           selected_assigner=assigner, cves=result['items'],
                           pagination=result, base_url=f'/assigners/{assigner}')
