"""Controllers package — Flask Blueprints for each route group."""

from controllers.main import main_bp
from controllers.cves import cves_bp
from controllers.browse import browse_bp
from controllers.vendors import vendors_bp
from controllers.products import products_bp
from controllers.search import search_bp
from controllers.advisories import advisories_bp

ALL_BLUEPRINTS = [
    main_bp,
    cves_bp,
    browse_bp,
    vendors_bp,
    products_bp,
    search_bp,
    advisories_bp,
]
