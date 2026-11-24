"""pytest configuration: redirect DB to a temp file for every test session."""
import os
import sys
import tempfile
from pathlib import Path

# Ensure the project root is on sys.path
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Point the DB at a throwaway temp file so tests never touch data/soc.db.
# This must happen before any project module that reads SOC_DB_PATH is imported.
_tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
_tmp.close()
os.environ.setdefault("SOC_DB_PATH", _tmp.name)

import config  # noqa: E402
config.DB_PATH = Path(_tmp.name)
