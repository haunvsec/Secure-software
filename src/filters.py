"""Jinja2 template filters."""

from datetime import datetime


def format_date(value):
    """Format various date string formats to full readable date."""
    if not value:
        return '—'
    formats = [
        '%Y-%m-%dT%H:%M:%SZ',
        '%Y-%m-%dT%H:%M:%S',
        '%Y-%m-%dT%H:%M:%S%z',
        '%Y-%m-%d',
        '%a, %d %b %Y %H:%M:%S %z',
        '%d %B %Y',
        '%B %d, %Y',
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(value.strip(), fmt)
            return dt.strftime('%B %d, %Y')
        except (ValueError, TypeError):
            continue
    return value[:10] if len(value) >= 10 else value


def init_filters(app):
    """Register all template filters with Flask app."""
    app.template_filter('format_date')(format_date)
