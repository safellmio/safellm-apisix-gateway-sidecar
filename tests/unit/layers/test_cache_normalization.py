import pytest

from sidecar.layers.cache import CacheLayer


def test_cache_hash_json_key_order_invariant():
    a = '{"prompt":"hello","max_tokens":50,"temperature":0.2}'
    b = '{"temperature":0.2,"max_tokens":50,"prompt":"hello"}'
    assert CacheLayer._hash_text(a) == CacheLayer._hash_text(b)
