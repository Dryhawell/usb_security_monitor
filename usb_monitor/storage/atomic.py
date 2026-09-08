"""Atomic JSON file helpers for local persistence.

Files stay on the authorized endpoint. Writes use a temp file plus
replace so a crash is less likely to leave a half-written document.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from usb_monitor.utils.logger import get_logger

_log = get_logger("storage")


def write_json_atomic(path: Path, payload: Any, *, prefix: str = "data.") -> None:
    """Serialize ``payload`` and replace ``path`` in one rename when possible."""
    path.parent.mkdir(parents=True, exist_ok=True)
    text = json.dumps(payload, indent=2)
    fd, tmp_name = tempfile.mkstemp(
        prefix=prefix,
        suffix=".json.tmp",
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.write("\n")
        tmp_path.replace(path)
    except OSError:
        tmp_path.unlink(missing_ok=True)
        raise


def read_json_file(path: Path) -> Any | None:
    """Return parsed JSON, or ``None`` if the file is missing or unreadable."""
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        _log.warning("Could not read %s (%s); treating as empty", path, exc)
        return None
