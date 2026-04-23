"""Unit tests for SimpleCache in app.py."""

import time
from unittest.mock import patch

from database import SimpleCache


class TestSimpleCache:
    def test_get_missing_key_returns_none(self):
        c = SimpleCache()
        assert c.get("nonexistent") is None

    def test_set_and_get(self):
        c = SimpleCache()
        c.set("key1", "value1", ttl=60)
        assert c.get("key1") == "value1"

    def test_expired_key_returns_none(self):
        c = SimpleCache()
        c.set("key1", "value1", ttl=1)
        with patch("database.time") as mock_time:
            # First call is for set (already done), subsequent for get
            mock_time.time.return_value = time.time() + 2
            assert c.get("key1") is None

    def test_expired_key_is_deleted(self):
        c = SimpleCache()
        c.set("key1", "value1", ttl=1)
        with patch("database.time") as mock_time:
            mock_time.time.return_value = time.time() + 2
            c.get("key1")
            assert "key1" not in c._cache

    def test_default_ttl_is_3600(self):
        c = SimpleCache()
        before = time.time()
        c.set("key1", "value1")
        expiry, _ = c._cache["key1"]
        assert expiry >= before + 3600
        assert expiry <= before + 3601

    def test_overwrite_existing_key(self):
        c = SimpleCache()
        c.set("key1", "old", ttl=60)
        c.set("key1", "new", ttl=60)
        assert c.get("key1") == "new"

    def test_stores_various_types(self):
        c = SimpleCache()
        c.set("dict", {"a": 1}, ttl=60)
        c.set("list", [1, 2, 3], ttl=60)
        c.set("int", 42, ttl=60)
        assert c.get("dict") == {"a": 1}
        assert c.get("list") == [1, 2, 3]
        assert c.get("int") == 42
