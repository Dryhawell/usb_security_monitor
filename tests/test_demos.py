"""Offline --demo-* bodies. No USB hardware."""

import pytest

from usb_monitor.cli import parse_args
from usb_monitor.demos import DEMO_HANDLERS, run_requested_demo


@pytest.mark.parametrize(
    "flag",
    [
        "--" + name.replace("_", "-")
        for name, _handler in DEMO_HANDLERS
        if name != "demo_gui"
    ],
)
def test_offline_demo_flag_returns_ok(flag: str, capsys) -> None:
    """demo-gui is covered in test_gui.py; a second Tk() in this process can fail."""
    status = run_requested_demo(parse_args([flag]))
    captured = capsys.readouterr()
    assert status == 0
    assert "FAILED" not in captured.out
