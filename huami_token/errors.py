# Copyright (c) 2025 Kirill Snezhko
# MIT License

"""Module for storing error messages"""

from __future__ import annotations


class MigrationInProgressError(Exception):
    """Exception raised when a non-implemented feature is called.."""

    def __init__(self, message: str | None = None):
        self.message = message or (
            "This feature is not yet reverse-engineered. "
            "Track progress here: https://codeberg.org/argrento/huami-token/issues/119"
        )
        super().__init__(self.message)


class HuamiTokenError(Exception):
    """Base class for exceptions in Zepp/Amazfit module."""

    pass


class AuthenticationError(HuamiTokenError):
    """Exception raised for authentication errors."""

    def __init__(self, code: str | None = None, message: str | None = None):
        self.code = code
        self.message = message or f"Authentication failed (code={code})"
        super().__init__(self.message)


class LogoutError(HuamiTokenError):
    """Exception raised for logout errors."""

    def __init__(self, code: str | None = None, message: str | None = None):
        self.code = code
        self.message = message or f"Logout failed (code={code})"
        super().__init__(self.message)


class DeviceError(HuamiTokenError):
    """Exception raised for device-related errors."""

    def __init__(self, code: str | None = None, message: str | None = None):
        self.code = code
        self.message = message or f"Device error (code={code})"
        super().__init__(self.message)
