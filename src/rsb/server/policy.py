from __future__ import annotations

from collections.abc import Iterable

from rsb.errors import RsbError

CAP_SHELL = "shell"
CAP_SCREENSHOT = "screenshot"
CAPABILITY_ORDER = (CAP_SHELL, CAP_SCREENSHOT)
SUPPORTED_CAPABILITIES = frozenset(CAPABILITY_ORDER)

STATE_PENDING = "pending"
STATE_ACTIVE = "active"
STATE_CLOSED = "closed"
STATE_DENIED = "denied"
STATE_EXPIRED = "expired"
OPEN_STATES = frozenset({STATE_PENDING, STATE_ACTIVE})

CAPABILITY_LABELS = {
    CAP_SHELL: "shell",
    CAP_SCREENSHOT: "снимок экрана",
}


class CapabilityError(RsbError):
    pass


def normalize(capabilities: Iterable[object]) -> list[str]:
    requested = {str(item) for item in capabilities if str(item) in SUPPORTED_CAPABILITIES}
    return [capability for capability in CAPABILITY_ORDER if capability in requested]


def require_valid(capabilities: Iterable[object]) -> list[str]:
    values = [str(item) for item in capabilities]
    unknown = sorted(set(values) - SUPPORTED_CAPABILITIES)
    if unknown:
        raise CapabilityError(f"unsupported capabilities: {', '.join(unknown)}")
    result = normalize(values)
    if not result:
        raise CapabilityError("at least one capability is required")
    return result


def sanitize(capabilities: Iterable[object], allow_empty: bool = False) -> list[str]:
    values = [str(item) for item in capabilities]
    unknown = sorted(set(values) - SUPPORTED_CAPABILITIES)
    if unknown:
        raise CapabilityError(f"unsupported capabilities: {', '.join(unknown)}")
    result = normalize(values)
    if not result and not allow_empty:
        raise CapabilityError("at least one capability is required")
    return result


def is_subset(requested: Iterable[str], allowed: Iterable[str]) -> bool:
    return set(requested) <= set(allowed)


def describe(capabilities: Iterable[str]) -> str:
    labels = [CAPABILITY_LABELS[item] for item in normalize(capabilities)]
    return ", ".join(labels) if labels else "нет"
