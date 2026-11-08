"""Make the provenance package importable as ``provenance`` when running
pytest from the repo root, without needing an installed package."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "gateway", "app"))
