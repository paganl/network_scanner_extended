"""Provider package for the Network Scanner integration.

This module exports individual provider implementations so that the
coordinator can import them lazily.  Additional providers should be
added here and referenced by their name in :mod:`network_scanner.const`.
"""
from . import opnsense  # noqa: F401
from . import unifi     # noqa: F401
from . import adguard   # noqa: F401

__all__ = ["opnsense", "unifi", "adguard"]
