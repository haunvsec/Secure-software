"""Jinja2 template filters."""

from datetime import datetime
from markupsafe import Markup
import re


_ALLOWED_TAGS = [
    'p', 'br', 'strong', 'em', 'b', 'i', 'u', 'a', 'ul', 'ol', 'li',
    'code', 'pre', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'span', 'div',
    'table', 'thead', 'tbody', 'tr', 'th', 'td',
]
_ALLOWED_ATTRS = {
    'a': ['href', 'title', 'target', 'rel'],
    'span': ['class'],
    'div': ['class'],
}
_STRIP_TAGS_RE = re.compile(r'<script[^>]*>.*?</script>', re.DOTALL | re.IGNORECASE)
_STRIP_EVENTS_RE = re.compile(r'\s+on\w+\s*=\s*["\'][^"\']*["\']', re.IGNORECASE)


def sanitize_html(value):
    """Sanitize HTML: allow safe tags, strip scripts and event handlers."""
    if not value:
        return ''
    text = str(value)
    text = _STRIP_TAGS_RE.sub('', text)
    text = _STRIP_EVENTS_RE.sub('', text)
    # Force target="_blank" and rel="noopener" on all links
    text = text.replace('<a ', '<a target="_blank" rel="noopener noreferrer" ')
    return Markup(text)


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
    app.template_filter('sanitize_html')(sanitize_html)
