"""Pytest root configuration and path setup."""
import sys
import os

# Ensure framework root directory is on python search path
root_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_dir not in sys.path:
    sys.path.insert(0, root_dir)
