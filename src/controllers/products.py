"""Product detail, versions, and fixed CVEs controller."""

from flask import Blueprint, render_template, request
from database import get_session
from models.queries import (
    get_products, get_product_detail, get_product_cves,
    get_product_version_ranges, get_product_versions,
    get_safe_version_references, get_product_advisories,
    get_fixed_cves_by_branch, get_version_detail,
    get_version_cves, sanitize_page,
)
from safe_version import compute_safe_versions, merge_advisory_into_safe_versions

products_bp = Blueprint('products', __name__)


@products_bp.route('/products')
def products_list():
    session = get_session()
    page = sanitize_page(request.args.get('page'))
    search = request.args.get('search', '').strip()
    result = get_products(session, search=search or None, page=page)
    return render_template('products.html', active_page='products',
                           products=result['items'], pagination=result,
                           current_search=search or None, base_url='/products')


@products_bp.route('/products/<vendor>/<product>')
def product_detail(vendor, product):
    session = get_session()
    pd = get_product_detail(session, vendor, product)
    if pd is None:
        return render_template('404.html', active_page=''), 404
    page = sanitize_page(request.args.get('page'))
    result = get_product_cves(session, vendor, product, page)
    version_ranges = get_product_version_ranges(session, vendor, product)
    safe_versions = compute_safe_versions(version_ranges)
    advisories = get_product_advisories(session, vendor, product)
    safe_versions = merge_advisory_into_safe_versions(safe_versions, advisories)
    for sv in safe_versions:
        max_cve = sv.get('max_cve_id', '')
        if max_cve:
            sv['references'] = get_safe_version_references(session, max_cve)
    versions = get_product_versions(session, vendor, product,
                                        page=sanitize_page(request.args.get('vpage')))
    return render_template('product_detail.html', active_page='products',
                           product_info=pd, cves=result['items'],
                           pagination=result, safe_versions=safe_versions,
                           versions=versions, advisories=advisories,
                           base_url=f'/products/{vendor}/{product}')


@products_bp.route('/products/<vendor>/<product>/fixed/<path:branch>')
def fixed_cves(vendor, product, branch):
    session = get_session()
    page = sanitize_page(request.args.get('page'))
    result = get_fixed_cves_by_branch(session, vendor, product, branch, page)
    return render_template('fixed_cves.html', active_page='products',
                           vendor=vendor, product=product, branch=branch,
                           cves=result['items'], pagination=result,
                           base_url=f'/products/{vendor}/{product}/fixed/{branch}')


@products_bp.route('/products/<vendor>/<product>/versions/<path:version>')
def version_detail(vendor, product, version):
    session = get_session()
    vd = get_version_detail(session, vendor, product, version)
    if vd is None:
        return render_template('404.html', active_page=''), 404
    page = sanitize_page(request.args.get('page'))
    result = get_version_cves(session, vendor, product, version, page)
    return render_template('version_detail.html', active_page='products',
                           version_info=vd, cves=result['items'],
                           pagination=result,
                           base_url=f'/products/{vendor}/{product}/versions/{version}')
