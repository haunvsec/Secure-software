"""Unit tests for models.py — sanitize functions and get_paginated_result."""

import sqlite3
import pytest
from models import (
    sanitize_page,
    sanitize_severity,
    sanitize_year,
    sanitize_search,
    get_paginated_result,
)


# ---------------------------------------------------------------------------
# sanitize_page
# ---------------------------------------------------------------------------

class TestSanitizePage:
    def test_valid_int(self):
        assert sanitize_page('3') == 3

    def test_string_one(self):
        assert sanitize_page('1') == 1

    def test_zero_returns_one(self):
        assert sanitize_page('0') == 1

    def test_negative_returns_one(self):
        assert sanitize_page('-5') == 1

    def test_none_returns_one(self):
        assert sanitize_page(None) == 1

    def test_non_numeric_returns_one(self):
        assert sanitize_page('abc') == 1

    def test_float_string_returns_one(self):
        assert sanitize_page('2.5') == 1

    def test_large_number(self):
        assert sanitize_page('9999') == 9999


# ---------------------------------------------------------------------------
# sanitize_severity
# ---------------------------------------------------------------------------

class TestSanitizeSeverity:
    def test_critical(self):
        assert sanitize_severity('CRITICAL') == 'CRITICAL'

    def test_high(self):
        assert sanitize_severity('HIGH') == 'HIGH'

    def test_medium(self):
        assert sanitize_severity('MEDIUM') == 'MEDIUM'

    def test_low(self):
        assert sanitize_severity('LOW') == 'LOW'

    def test_lowercase_accepted(self):
        assert sanitize_severity('high') == 'HIGH'

    def test_invalid_returns_none(self):
        assert sanitize_severity('INVALID') is None

    def test_none_returns_none(self):
        assert sanitize_severity(None) is None

    def test_empty_returns_none(self):
        assert sanitize_severity('') is None


# ---------------------------------------------------------------------------
# sanitize_year
# ---------------------------------------------------------------------------

class TestSanitizeYear:
    def test_valid_year(self):
        assert sanitize_year('2024') == 2024

    def test_min_year(self):
        assert sanitize_year('1999') == 1999

    def test_max_year(self):
        assert sanitize_year('2099') == 2099

    def test_below_range(self):
        assert sanitize_year('1998') is None

    def test_above_range(self):
        assert sanitize_year('2100') is None

    def test_none_returns_none(self):
        assert sanitize_year(None) is None

    def test_non_numeric(self):
        assert sanitize_year('abc') is None


# ---------------------------------------------------------------------------
# sanitize_search
# ---------------------------------------------------------------------------

class TestSanitizeSearch:
    def test_none_returns_empty(self):
        assert sanitize_search(None) == ''

    def test_empty_returns_empty(self):
        assert sanitize_search('') == ''

    def test_plain_text_wraps_with_percent(self):
        assert sanitize_search('apache') == '%apache%'

    def test_wildcard_converted(self):
        result = sanitize_search('apache*')
        assert result == 'apache%'

    def test_wildcard_at_start(self):
        result = sanitize_search('*server')
        assert result == '%server'

    def test_percent_escaped(self):
        result = sanitize_search('100%')
        assert result == r'%100\%%'

    def test_underscore_escaped(self):
        result = sanitize_search('my_app')
        assert result == r'%my\_app%'

    def test_max_200_chars(self):
        long_input = 'a' * 300
        result = sanitize_search(long_input)
        # 200 chars + 2 for wrapping %
        assert len(result) == 202

    def test_wildcard_in_middle(self):
        result = sanitize_search('apache*server')
        assert result == 'apache%server'


# ---------------------------------------------------------------------------
# get_paginated_result
# ---------------------------------------------------------------------------

@pytest.fixture
def mem_db():
    """Create an in-memory SQLite database with sample data."""
    conn = sqlite3.connect(':memory:')
    conn.row_factory = sqlite3.Row
    conn.execute('CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)')
    for i in range(1, 121):
        conn.execute('INSERT INTO items (id, name) VALUES (?, ?)', (i, f'item_{i}'))
    conn.commit()
    return conn


class TestGetPaginatedResult:
    def test_first_page(self, mem_db):
        result = get_paginated_result(
            mem_db,
            'SELECT * FROM items ORDER BY id',
            'SELECT COUNT(*) FROM items',
            (),
            page=1,
            per_page=50,
        )
        assert result['total'] == 120
        assert result['page'] == 1
        assert result['pages'] == 3
        assert result['per_page'] == 50
        assert len(result['items']) == 50
        assert result['items'][0]['id'] == 1

    def test_last_page(self, mem_db):
        result = get_paginated_result(
            mem_db,
            'SELECT * FROM items ORDER BY id',
            'SELECT COUNT(*) FROM items',
            (),
            page=3,
            per_page=50,
        )
        assert len(result['items']) == 20  # 120 - 100
        assert result['items'][0]['id'] == 101

    def test_page_beyond_max_clamped(self, mem_db):
        result = get_paginated_result(
            mem_db,
            'SELECT * FROM items ORDER BY id',
            'SELECT COUNT(*) FROM items',
            (),
            page=999,
            per_page=50,
        )
        assert result['page'] == 3  # clamped to last page

    def test_empty_table(self, mem_db):
        mem_db.execute('DELETE FROM items')
        mem_db.commit()
        result = get_paginated_result(
            mem_db,
            'SELECT * FROM items ORDER BY id',
            'SELECT COUNT(*) FROM items',
            (),
            page=1,
            per_page=50,
        )
        assert result['total'] == 0
        assert result['pages'] == 1
        assert result['items'] == []

    def test_items_are_dicts(self, mem_db):
        result = get_paginated_result(
            mem_db,
            'SELECT * FROM items ORDER BY id',
            'SELECT COUNT(*) FROM items',
            (),
            page=1,
            per_page=5,
        )
        assert isinstance(result['items'][0], dict)
        assert 'id' in result['items'][0]
        assert 'name' in result['items'][0]

    def test_with_params(self, mem_db):
        result = get_paginated_result(
            mem_db,
            'SELECT * FROM items WHERE id > ? ORDER BY id',
            'SELECT COUNT(*) FROM items WHERE id > ?',
            (100,),
            page=1,
            per_page=50,
        )
        assert result['total'] == 20
        assert result['pages'] == 1
        assert len(result['items']) == 20
