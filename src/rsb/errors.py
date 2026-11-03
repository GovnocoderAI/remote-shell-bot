from __future__ import annotations


class RsbError(Exception):
    exit_code = 1


class ConfigError(RsbError):
    exit_code = 2


class ProtocolError(RsbError):
    pass


class AuthenticationError(RsbError):
    pass


class AuthorizationError(RsbError):
    pass


class NotFoundError(RsbError):
    pass


class ConflictError(RsbError):
    pass


class DeviceOfflineError(RsbError):
    pass


class SessionStateError(RsbError):
    pass


class CommandFailedError(RsbError):
    pass


class ScreenshotError(RsbError):
    pass


class AgentError(RsbError):
    pass
