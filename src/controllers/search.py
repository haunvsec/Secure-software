"""Search controller."""

from flask import Blueprint, redirect, render_template, request
from database import get_session
from models.queries import search_cves, sanitize_page

search_bp = Blueprint('search', __name__)


@search_bp.route('/search')
def search():
    session = get_session()
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

    result = search_cves(session, cve_id=cve_id or None, keyword=keyword or None,
                             vendor=vendor or None, product=product or None, page=page)
    if isinstance(result, str):
        return redirect(f'/cves/{result}')

    return render_template('search.html', active_page='search', searched=True,
                           cves=result['items'], pagination=result,
                           q_cve_id=cve_id, q_keyword=keyword,
                           q_vendor=vendor, q_product=product, base_url='/search')
