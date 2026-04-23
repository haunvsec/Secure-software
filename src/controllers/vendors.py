"""Vendor list and detail controller."""

from flask import Blueprint, render_template, request
from database import get_db
from models import get_vendors, get_vendor_detail, get_vendor_products, sanitize_page

vendors_bp = Blueprint('vendors', __name__)


@vendors_bp.route('/vendors')
def vendors_list():
    db = get_db()
    page = sanitize_page(request.args.get('page'))
    search = request.args.get('search', '').strip()
    letter = request.args.get('letter', '').strip().upper()
    if search:
        result = get_vendors(db, search=search, page=page)
        return render_template('vendors.html', active_page='vendors',
                               vendors=result['items'], pagination=result,
                               current_letter=None, current_search=search, base_url='/vendors')
    if not letter:
        letter = 'A'
    result = get_vendors(db, letter=letter, page=page)
    return render_template('vendors.html', active_page='vendors',
                           vendors=result['items'], pagination=result,
                           current_letter=letter, current_search=None, base_url='/vendors')


@vendors_bp.route('/vendors/<vendor>')
def vendor_detail(vendor):
    db = get_db()
    vd = get_vendor_detail(db, vendor)
    if vd is None:
        return render_template('404.html', active_page=''), 404
    page = sanitize_page(request.args.get('page'))
    result = get_vendor_products(db, vendor, page)
    return render_template('vendor_detail.html', active_page='vendors',
                           vendor=vd, products=result['items'],
                           pagination=result, base_url=f'/vendors/{vendor}')
