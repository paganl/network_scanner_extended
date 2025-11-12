"""Provider package for the Network Scanner integration.

This module exports individual provider implementations so that the
coordinator can import them lazily.  Additional providers should be
added here and referenced by their name in :mod:`network_scanner.const`.
"""

from .opnsense import async_get_devices as opnsense

__all__ = ["opnsense"]