import os
import sqlite3
import time
from typing import Any

from flask import Flask, g, redirect, render_template, request


class SimpleCache:
    """In-memory cache với TTL."""

    def __init__(self):
        self._cache: dict[str, tuple[float, Any]] = {}

    def get(self, key: str) -> Any | None:
        """Trả về cached value nếu chưa hết TTL, None nếu miss."""
        if key not in self._cache:
            return None
        expiry, value = self._cache[key]
        if time.time() > expiry:
            del self._cache[key]
            return None
        return value

    def set(self, key: str, value: Any, ttl: int = 3600):
        """Lưu value với TTL (giây)."""
        self._cache[key] = (time.time() + ttl, value)


cache = SimpleCache()

app = Flask(__name__)

DATABASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cve_database.db')


def get_db():
    """Get database connection for the current request (stored in g).

    Opens a read-only SQLite connection with WAL journal mode.
    Raises an error page if the database file does not exist.
    """
    if 'db' not in g:
        if not os.path.isfile(DATABASE):
            raise FileNotFoundError(f"Database file not found: {DATABASE}")
        db_uri = f"file:{DATABASE}?mode=ro"
        g.db = sqlite3.connect(db_uri, uri=True)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA journal_mode=WAL")
    return g.db


def close_db(exception=None):
    """Close database connection when the request ends."""
    db = g.pop('db', None)
    if db is not None:
        db.close()


app.teardown_appcontext(close_db)


@app.route('/')
def index():
    db = get_db()
    from models import get_stats, get_latest_cves
    stats = get_stats(db)
    latest_cves = get_latest_cves(db)
    return render_template('index.html', active_page='home', stats=stats, latest_cves=latest_cves)


@app.route('/cves')
def cves_list():
    db = get_db()
    from models import get_cves, sanitize_page, sanitize_severity, sanitize_year
    page = sanitize_page(request.args.get('page'))
    year = sanitize_year(request.args.get('year'))
    severity = sanitize_severity(request.args.get('severity'))
    result = get_cves(db, page, year=year, severity=severity)
    return render_template('cves.html', active_page='cves', pagination=result,
                           cves=result['items'], current_year=year,
                           current_severity=severity, base_url='/cves')


@app.route('/cves/by-severity')
def by_severity():
    db = get_db()
    from models import get_severity_summary, get_cves_by_severity, sanitize_page, sanitize_severity
    sev = sanitize_severity(request.args.get('severity'))
    page = sanitize_page(request.args.get('page'))

    if sev:
        result = get_cves_by_severity(db, sev, page)
        return render_template('by_severity.html', active_page='by_severity',
                               selected_severity=sev, cves=result['items'],
                               pagination=result, base_url='/cves/by-severity')
    else:
        summary = get_severity_summary(db)
        return render_template('by_severity.html', active_page='by_severity',
                               selected_severity=None, summary=summary)


@app.route('/cves/by-type')
def by_type():
    db = get_db()
    from models import get_cwe_types, get_cves_by_cwe, sanitize_page
    cwe = request.args.get('cwe')
    page = sanitize_page(request.args.get('page'))

    if cwe:
        result = get_cves_by_cwe(db, cwe, page)
        return render_template('by_type.html', active_page='by_type',
                               selected_cwe=cwe, cves=result['items'],
                               pagination=result, base_url='/cves/by-type')
    else:
        result = get_cwe_types(db, page)
        return render_template('by_type.html', active_page='by_type',
                               selected_cwe=None, types=result['items'],
                               pagination=result, base_url='/cves/by-type')


@app.route('/cves/by-date')
def by_date():
    db = get_db()
    from models import get_years_with_counts, get_months_for_year, get_cves_by_month, sanitize_page, sanitize_year, _MONTH_NAMES
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
    else:
        years = get_years_with_counts(db)
        return render_template('by_date.html', active_page='by_date',
                               selected_year=None, selected_month=None, years=years)


@app.route('/cves/<cve_id>')
def cve_detail(cve_id):
    db = get_db()
    from models import get_cve_detail, get_cve_cvss, get_cve_affected, get_cve_cwes, get_cve_references
    cve = get_cve_detail(db, cve_id)
    if cve is None:
        return render_template('404.html', active_page=''), 404
    cvss_scores = get_cve_cvss(db, cve_id)
    affected = get_cve_affected(db, cve_id)
    cwes = get_cve_cwes(db, cve_id)
    references = get_cve_references(db, cve_id)
    return render_template('cve_detail.html', active_page='cves', cve=cve,
                           cvss_scores=cvss_scores, affected=affected,
                           cwes=cwes, references=references)


@app.route('/products')
def products_list():
    db = get_db()
    from models import get_products, sanitize_page
    page = sanitize_page(request.args.get('page'))
    search = request.args.get('search', '').strip()
    result = get_products(db, search=search or None, page=page)
    return render_template('products.html', active_page='products',
                           products=result['items'], pagination=result,
                           current_search=search or None, base_url='/products')


@app.route('/search')
def search():
    db = get_db()
    from models import search_cves, sanitize_page
    cve_id = request.args.get('cve_id', '').strip()
    keyword = request.args.get('keyword', '').strip()
    vendor = request.args.get('vendor', '').strip()
    product = request.args.get('product', '').strip()
    page = sanitize_page(request.args.get('page'))

    searched = bool(cve_id or keyword or vendor or product)
    if not searched:
        return render_template('search.html', active_page='search',
                               searched=False, q_cve_id=None, q_keyword=None,
                               q_vendor=None, q_product=None)

    result = search_cves(db, cve_id=cve_id or None, keyword=keyword or None,
                         vendor=vendor or None, product=product or None, page=page)

    # If exact CVE ID match, redirect
    if isinstance(result, str):
        return redirect(f'/cves/{result}')

    return render_template('search.html', active_page='search', searched=True,
                           cves=result['items'], pagination=result,
                           q_cve_id=cve_id, q_keyword=keyword,
                           q_vendor=vendor, q_product=product,
                           base_url='/search')


@app.route('/products/<vendor>/<product>')
def product_detail(vendor, product):
    db = get_db()
    from models import get_product_detail, get_product_cves, get_product_version_ranges, sanitize_page
    from safe_version import compute_safe_versions
    pd = get_product_detail(db, vendor, product)
    if pd is None:
        return render_template('404.html', active_page=''), 404
    page = sanitize_page(request.args.get('page'))
    result = get_product_cves(db, vendor, product, page)
    version_ranges = get_product_version_ranges(db, vendor, product)
    safe_versions = compute_safe_versions(version_ranges)
    return render_template('product_detail.html', active_page='products',
                           product_info=pd, cves=result['items'],
                           pagination=result, safe_versions=safe_versions,
                           base_url=f'/products/{vendor}/{product}')


@app.route('/vendors')
def vendors_list():
    db = get_db()
    from models import get_vendors, sanitize_page
    page = sanitize_page(request.args.get('page'))
    search = request.args.get('search', '').strip()
    letter = request.args.get('letter', '').strip().upper()

    if search:
        result = get_vendors(db, search=search, page=page)
        return render_template('vendors.html', active_page='vendors',
                               vendors=result['items'], pagination=result,
                               current_letter=None, current_search=search,
                               base_url='/vendors')
    else:
        if not letter:
            letter = 'A'
        result = get_vendors(db, letter=letter, page=page)
        return render_template('vendors.html', active_page='vendors',
                               vendors=result['items'], pagination=result,
                               current_letter=letter, current_search=None,
                               base_url='/vendors')


@app.route('/vendors/<vendor>')
def vendor_detail(vendor):
    db = get_db()
    from models import get_vendor_detail, get_vendor_products, sanitize_page
    vd = get_vendor_detail(db, vendor)
    if vd is None:
        return render_template('404.html', active_page=''), 404
    page = sanitize_page(request.args.get('page'))
    result = get_vendor_products(db, vendor, page)
    return render_template('vendor_detail.html', active_page='vendors',
                           vendor=vd, products=result['items'],
                           pagination=result, base_url=f'/vendors/{vendor}')


@app.route('/assigners')
def assigners_list():
    db = get_db()
    from models import get_assigners, sanitize_page
    page = sanitize_page(request.args.get('page'))
    result = get_assigners(db, page)
    return render_template('assigners.html', active_page='assigners',
                           selected_assigner=None, assigners=result['items'],
                           pagination=result, base_url='/assigners')


@app.route('/assigners/<assigner>')
def assigner_detail(assigner):
    db = get_db()
    from models import get_cves_by_assigner, sanitize_page
    page = sanitize_page(request.args.get('page'))
    result = get_cves_by_assigner(db, assigner, page)
    return render_template('assigners.html', active_page='assigners',
                           selected_assigner=assigner, cves=result['items'],
                           pagination=result, base_url=f'/assigners/{assigner}')


@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html', active_page=''), 404


@app.errorhandler(500)
def internal_error(e):
    return render_template('500.html', active_page=''), 500


@app.errorhandler(Exception)
def handle_db_missing(error):
    if isinstance(error, FileNotFoundError):
        return render_template('db_error.html', error=str(error)), 503
    raise error


if __name__ == '__main__':
    app.run(debug=True)
