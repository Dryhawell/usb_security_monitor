"""Owner-only ACLs on local persistence files. No USB hardware."""

import os
import stat

import pytest

from usb_monitor.storage.atomic import read_json_file, write_json_atomic, write_text_atomic
from usb_monitor.utils.acl import owner_only_sddl, restrict_owner_only


def test_owner_only_sddl_rejects_garbage() -> None:
    with pytest.raises(ValueError):
        owner_only_sddl("not-a-sid")
    with pytest.raises(ValueError):
        owner_only_sddl("S-1-5-21;whoami")


def test_owner_only_sddl_protects_and_includes_user() -> None:
    text = owner_only_sddl("S-1-5-21-1-2-3-1001")
    assert text.startswith("D:P(")
    assert "S-1-5-21-1-2-3-1001" in text
    assert "SY" in text
    assert "BA" in text


def test_write_json_atomic_restricts_and_stays_readable(tmp_path) -> None:
    path = tmp_path / "events.json"
    write_json_atomic(path, {"ok": True, "serial_number": "STORE01"})
    assert read_json_file(path) == {"ok": True, "serial_number": "STORE01"}
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert restrict_owner_only(path) is True


def test_restrict_missing_file_returns_false(tmp_path) -> None:
    assert restrict_owner_only(tmp_path / "missing.json") is False


def test_write_survives_acl_failure(tmp_path, monkeypatch) -> None:
    def boom(_path) -> bool:
        raise OSError("acl boom")

    monkeypatch.setattr("usb_monitor.storage.atomic.restrict_owner_only", boom)
    path = tmp_path / "events.json"
    write_text_atomic(path, '{"ok": true}')
    assert path.read_text(encoding="utf-8").startswith("{")
