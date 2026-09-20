"""Atomic JSON file helpers for local persistence.

Files stay on the authorized endpoint. Writes use a temp file plus
replace so a crash is less likely to leave a half-written document.
After replace, the file is restricted to the current user. Store JSON
may optionally be DPAPI-wrapped (USB_MONITOR_DPAPI=1). There is no
telemetry.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from usb_monitor.utils.acl import restrict_owner_only
from usb_monitor.utils.logger import get_logger
from usb_monitor.utils.protect import (
    is_protection_enabled,
    unwrap_document,
    wrap_json_text,
)

_log = get_logger("storage")


def write_text_atomic(
    path: Path,
    text: str,
    *,
    prefix: str = "data.",
    suffix: str = ".tmp",
) -> None:
    """Write ``text`` and replace ``path`` in one rename when possible."""
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = text if text.endswith("\n") else f"{text}\n"
    fd, tmp_name = tempfile.mkstemp(
        prefix=prefix,
        suffix=suffix,
        dir=str(path.parent),
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            handle.write(payload)
        tmp_path.replace(path)
        try:
            restrict_owner_only(path)
        except Exception:
            _log.warning("Could not restrict ACLs on %s", path, exc_info=True)
    except OSError:
        tmp_path.unlink(missing_ok=True)
        raise


def write_json_atomic(
    path: Path,
    payload: Any,
    *,
    prefix: str = "data.",
    protect: bool | None = None,
) -> None:
    """Serialize ``payload`` and replace ``path`` in one rename when possible.

    ``protect=None`` follows ``USB_MONITOR_DPAPI``. Pass ``False`` for
    operator report files that must stay readable JSON.
    """
    text = json.dumps(payload, indent=2)
    should_protect = is_protection_enabled() if protect is None else protect
    if should_protect:
        try:
            text = wrap_json_text(text)
        except (OSError, ValueError) as exc:
            _log.warning("Could not protect %s (%s); writing plaintext", path, exc)
    write_text_atomic(
        path,
        text,
        prefix=prefix,
        suffix=".json.tmp",
    )


def read_json_file(path: Path) -> Any | None:
    """Return parsed JSON, or ``None`` if the file is missing or unreadable.

    DPAPI-wrapped store files are decrypted for the current Windows user.
    """
    if not path.exists():
        return None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return unwrap_document(raw)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        _log.warning("Could not read %s (%s); treating as empty", path, exc)
        return None
