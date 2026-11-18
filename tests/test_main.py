from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QSettings, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import QApplication

from src.main import SYSTEM_KEY, MainWindow, main
from src.sampler import (
    ProcSample,
    Snapshot,
    SystemBreakdown,
    build_snapshot,
    build_system_slices,
    parse_process_role,
    squarify,
)


def test_main() -> None:
    assert callable(main)


def test_squarify_preserves_area_and_bounds() -> None:
    assert squarify([], 0, 0, 100, 100) == []
    assert squarify([("a", 0), ("b", -5)], 0, 0, 100, 100) == []
    assert squarify([("a", 10)], 0, 0, 0, 100) == []

    items = [("browser", 60.0), ("ide", 30.0), ("terminal", 10.0), ("zero", 0.0)]
    x0, y0, width, height = 10.0, 20.0, 400.0, 200.0
    rects = squarify(items, x0, y0, width, height)

    assert len(rects) == 3
    by_key = {rect.key: rect for rect in rects}
    assert set(by_key) == {"browser", "ide", "terminal"}

    total_area = width * height
    rect_areas = sum(rect.w * rect.h for rect in rects)
    assert math.isclose(rect_areas, total_area, rel_tol=1e-6)

    for rect in rects:
        assert rect.w > 0 and rect.h > 0
        assert rect.x >= x0 - 1e-6
        assert rect.y >= y0 - 1e-6
        assert rect.x + rect.w <= x0 + width + 1e-6
        assert rect.y + rect.h <= y0 + height + 1e-6

    assert math.isclose(by_key["browser"].w * by_key["browser"].h, total_area * 0.6, rel_tol=1e-6)
    assert math.isclose(by_key["ide"].w * by_key["ide"].h, total_area * 0.3, rel_tol=1e-6)
    assert math.isclose(by_key["terminal"].w * by_key["terminal"].h, total_area * 0.1, rel_tol=1e-6)


def test_grouping_and_snapshot() -> None:
    sample = {
        0: ProcSample(0, 0, "System Idle Process", 0, 1000, 1000, 1000),
        10: ProcSample(10, 1, "explorer.exe", 100, 200_000_000, 250_000_000, 300_000_000),
        20: ProcSample(20, 10, "firefox.exe", 200, 500_000_000, 600_000_000, 700_000_000),
        21: ProcSample(21, 20, "firefox.exe", 210, 300_000_000, 350_000_000, 400_000_000),
        30: ProcSample(30, 99, "orphan.exe", 300, 100_000_000, 120_000_000, 140_000_000),
        # PID-reused parent created after child: should NOT group orphan.exe under reused_parent.exe
        99: ProcSample(99, 10, "reused_parent.exe", 400, 50_000_000, 60_000_000, 70_000_000),
    }

    snapshot = build_snapshot(
        sample, total_ram=4_000_000_000, used_ram=2_000_000_000, timestamp=123.0
    )

    assert snapshot.timestamp == 123.0
    assert snapshot.app_ram == 1_150_000_000
    assert snapshot.unattributed_ram == 850_000_000
    assert [group.name for group in snapshot.groups] == [
        "firefox.exe",
        "explorer.exe",
        "orphan.exe",
        "reused_parent.exe",
    ]
    assert [proc.pid for proc in snapshot.groups[0].processes] == [20, 21]
    assert snapshot.groups[0].private_ws == 800_000_000


def test_main_window_renders_snapshot(monkeypatch, tmp_path) -> None:
    app = QApplication.instance() or QApplication([])
    assert app is not None

    monkeypatch.setattr(
        "src.main.QSettings",
        lambda *_args: QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat),
    )

    window = MainWindow(start_worker=False)
    sample = {
        10: ProcSample(10, 1, "firefox.exe", 100, 700_000_000, 1_100_000_000, 900_000_000),
        11: ProcSample(11, 10, "firefox.exe", 110, 300_000_000, 400_000_000, 400_000_000),
        20: ProcSample(20, 1, "code.exe", 120, 500_000_000, 700_000_000, 700_000_000),
    }
    breakdown = SystemBreakdown(
        kernel_nonpaged=200_000_000,
        kernel_paged=100_000_000,
        system_cache=50_000_000,
        driver_images=40_000_000,
        top_drivers=[("ntoskrnl.exe", 20_000_000)],
    )
    snapshot: Snapshot = build_snapshot(
        sample, total_ram=4_000_000_000, used_ram=2_500_000_000, breakdown=breakdown
    )

    window._on_snapshot(snapshot)
    window.resize(900, 600)
    window._treemap._recompute_layout()
    window.repaint()

    assert "2 Anwendungen (3 Prozesse)" in window._status_label.text()
    assert len(window._treemap._rects) == 3  # firefox.exe, code.exe, __system__

    # Zoom into System / Shared / Kernel
    window._treemap.set_zoomed_group(SYSTEM_KEY)
    assert window._treemap.zoomed_group == SYSTEM_KEY
    assert "System / Geteilt / Kernel" in window._status_label.text()
    sys_keys = {rect.key for rect in window._treemap._rects}
    assert "shared:firefox.exe" in sys_keys
    assert "sys:nonpaged" in sys_keys

    # Left-clicking "shared:firefox.exe" jumps straight into firefox.exe process view
    shared_rect = next(rect for rect in window._treemap._rects if rect.key == "shared:firefox.exe")
    center = QPointF(shared_rect.x + shared_rect.w / 2, shared_rect.y + shared_rect.h / 2)
    click_event = QMouseEvent(
        QMouseEvent.Type.MouseButtonPress,
        center,
        window._treemap.mapToGlobal(center),
        Qt.MouseButton.LeftButton,
        Qt.MouseButton.LeftButton,
        Qt.KeyboardModifier.NoModifier,
    )
    window._treemap.mousePressEvent(click_event)
    assert window._treemap.zoomed_group == "firefox.exe"
    assert window._back_btn.isHidden() is False
    assert "firefox.exe" in window._status_label.text()
    assert {rect.key for rect in window._treemap._rects} == {"10", "11"}

    window._treemap.set_zoomed_group(None)
    assert window._treemap.zoomed_group is None
    assert window._back_btn.isHidden() is True
    assert "2 Anwendungen (3 Prozesse)" in window._status_label.text()

    window.toggle_theme()
    window.close()


def test_parse_process_role() -> None:
    assert (
        parse_process_role(
            "svchost.exe",
            "svchost.exe",
            ["svchost.exe", "-k", "netsvcs"],
            services=("Windows Update", "BITS"),
        )
        == "Windows Update, BITS"
    )
    assert (
        parse_process_role(
            "svchost.exe",
            "svchost.exe",
            [],
            services=("DNS-Client", "DHCP", "Netzwerk"),
        )
        == "DNS-Client, DHCP (+1)"
    )
    assert (
        parse_process_role(
            "Code.exe",
            "Code.exe",
            ["Code.exe", "--type=renderer", "--enable-sandbox"],
        )
        == "Renderer"
    )
    assert (
        parse_process_role(
            "Code.exe",
            "Code.exe",
            ["Code.exe", "--type=gpu-process"],
        )
        == "GPU-Prozess"
    )
    assert (
        parse_process_role(
            "Code.exe",
            "Code.exe",
            ["Code.exe", "--type=utility", "--utility-sub-type=node.mojom.NodeService"],
        )
        == "Node-Service"
    )
    assert (
        parse_process_role(
            "firefox.exe",
            "firefox.exe",
            ["firefox.exe", "-contentproc", "-isForBrowser", "-", "17", "tab"],
        )
        == "Tab #17"
    )
    assert (
        parse_process_role(
            "python.exe",
            "Code.exe",
            ["python.exe", "C:\\repo\\scripts\\worker.py", "--fast"],
        )
        == "worker.py"
    )
    assert parse_process_role("firefox.exe", "firefox.exe", ["firefox.exe"]) == "Hauptprozess"


def test_system_slices_breakdown() -> None:
    sample = {
        1: ProcSample(1, 0, "appA.exe", 10, 500_000_000, 1_100_000_000, 600_000_000),
        2: ProcSample(2, 0, "appB.exe", 20, 200_000_000, 500_000_000, 300_000_000),
    }
    snap = build_snapshot(sample, total_ram=4_000_000_000, used_ram=1_700_000_000)
    breakdown = SystemBreakdown(
        kernel_nonpaged=250_000_000,
        kernel_paged=150_000_000,
        system_cache=100_000_000,
        driver_images=50_000_000,
        top_drivers=[("nvlddmkm.sys", 30_000_000), ("ntoskrnl.exe", 20_000_000)],
    )

    slices = build_system_slices(snap.unattributed_ram, snap.groups, breakdown)
    by_key = {item.key: item for item in slices}

    assert sum(item.bytes_value for item in slices) == snap.unattributed_ram
    assert by_key["sys:nonpaged"].bytes_value == 200_000_000
    assert by_key["sys:drivers"].bytes_value == 50_000_000
    assert "nvlddmkm.sys" in by_key["sys:drivers"].description
    assert by_key["sys:paged"].bytes_value == 150_000_000
    assert by_key["sys:cache"].bytes_value == 100_000_000
    # Remaining 500_000_000 shared across 600M (appA) and 300M (appB) -> 2:1 ratio
    assert by_key["shared:appA.exe"].target_group == "appA.exe"
    assert by_key["shared:appB.exe"].target_group == "appB.exe"
    assert by_key["shared:appA.exe"].bytes_value > by_key["shared:appB.exe"].bytes_value

    # When kernel sum exceeds unattributed_ram, slices scale down cleanly to budget
    tight_slices = build_system_slices(200_000_000, snap.groups, breakdown)
    assert sum(item.bytes_value for item in tight_slices) == 200_000_000
    assert all(item.category == "kernel" for item in tight_slices)
