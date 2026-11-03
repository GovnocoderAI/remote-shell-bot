from __future__ import annotations

import pytest

from rsb.server import policy


def test_normalize_orders_and_deduplicates() -> None:
    assert policy.normalize(["screenshot", "shell", "shell", "unknown"]) == [
        "shell",
        "screenshot",
    ]


def test_require_valid_rejects_empty_and_unknown() -> None:
    with pytest.raises(policy.CapabilityError):
        policy.require_valid([])
    with pytest.raises(policy.CapabilityError):
        policy.require_valid(["root"])


def test_sanitize_allows_empty_policy() -> None:
    assert policy.sanitize([], allow_empty=True) == []
    with pytest.raises(policy.CapabilityError):
        policy.sanitize([])


def test_subset_and_describe() -> None:
    assert policy.is_subset(["shell"], ["shell", "screenshot"])
    assert not policy.is_subset(["screenshot"], ["shell"])
    assert policy.describe(["screenshot", "shell"]) == "shell, снимок экрана"
    assert policy.describe([]) == "нет"
