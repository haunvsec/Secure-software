"""Secure Software Board — Flask Application Factory."""

import pymysql
from flask import Flask, render_template

from config import Config
from database import init_db
from filters import init_filters
from controllers import ALL_BLUEPRINTS


def create_app(config_class=Config):
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize database
    init_db(app)

    # Initialize template filters
    init_filters(app)

    # Register blueprints (controllers)
    for bp in ALL_BLUEPRINTS:
        app.register_blueprint(bp)

    # Error handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template('404.html', active_page=''), 404

    @app.errorhandler(500)
    def internal_error(e):
        return render_template('500.html', active_page=''), 500

    @app.errorhandler(Exception)
    def handle_db_error(error):
        if isinstance(error, (ConnectionError, pymysql.err.OperationalError)):
            return render_template('db_error.html', error=str(error)), 503
        raise error

    return app


# Application instance for gunicorn: gunicorn app:app
app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
