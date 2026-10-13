"""
Backward-compatibility alias for Exporter.py (resolves historical typo).
"""
try:
    from .Exporter import *  # noqa: F401, F403
except (ImportError, ValueError):
    from Exporter import *  # noqa: F401, F403
