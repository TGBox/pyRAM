"""Desktop GUI entry point for pyRAM."""

from __future__ import annotations

import sys
import zlib
from typing import Any

from PySide6.QtCore import QPointF, QRectF, QSettings, Qt, Signal
from PySide6.QtGui import QColor, QFont, QFontMetrics, QKeySequence, QPainter, QPen, QShortcut
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMenu,
    QMessageBox,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

try:
    from src.sampler import (
        AppGroup,
        ProcessDetailResolver,
        ProcSample,
        SamplerWorker,
        Snapshot,
        SystemSlice,
        TreemapRect,
        squarify,
        terminate_processes,
    )
except ImportError:
    from sampler import (
        AppGroup,
        ProcessDetailResolver,
        ProcSample,
        SamplerWorker,
        Snapshot,
        SystemSlice,
        TreemapRect,
        squarify,
        terminate_processes,
    )

SYSTEM_KEY = "__system__"

_SYS_DARK_COLORS = {
    "sys:nonpaged": "#3b4c6b",
    "sys:paged": "#475569",
    "sys:cache": "#36535e",
    "sys:drivers": "#4b4563",
    "sys:shared_other": "#3f4c5e",
}

_SYS_LIGHT_COLORS = {
    "sys:nonpaged": "#bfdbfe",
    "sys:paged": "#cbd5e1",
    "sys:cache": "#bae6fd",
    "sys:drivers": "#ddd6fe",
    "sys:shared_other": "#e2e8f0",
}


def format_bytes(num_bytes: int) -> str:
    """Format a byte count into a German-formatted human-readable size string."""
    if num_bytes >= 100 * 1024**2:
        return f"{num_bytes / 1024**3:.2f}".replace(".", ",") + " GB"
    if num_bytes >= 1024**2:
        return f"{num_bytes / 1024**2:.0f} MB"
    if num_bytes >= 1024:
        return f"{num_bytes / 1024:.0f} KB"
    return f"{num_bytes} B"


def _tile_color(key: str, dark_mode: bool) -> QColor:
    """Return a deterministic, readable tile background color for a group, process, or slice."""
    if key == SYSTEM_KEY:
        return QColor("#334155") if dark_mode else QColor("#cbd5e1")
    if key.startswith("shared:"):
        return _tile_color(key.removeprefix("shared:"), dark_mode)
    if key.startswith("sys:"):
        palette = _SYS_DARK_COLORS if dark_mode else _SYS_LIGHT_COLORS
        return QColor(palette.get(key, "#475569" if dark_mode else "#cbd5e1"))
    hue = (zlib.crc32(key.encode("utf-8")) * 137) % 360
    if dark_mode:
        return QColor.fromHsl(hue, 130, 82)
    return QColor.fromHsl(hue, 150, 196)


def build_stylesheet(dark_mode: bool) -> str:
    """Return a consistent QSS stylesheet for dark or light mode."""
    if dark_mode:
        return """
        QMainWindow, QWidget#centralRoot {
            background-color: #0f172a;
            color: #f8fafc;
        }
        QLabel {
            color: #e2e8f0;
        }
        QPushButton {
            background-color: #1e293b;
            color: #f8fafc;
            border: 1px solid #334155;
            border-radius: 5px;
            padding: 5px 10px;
        }
        QPushButton:hover {
            background-color: #334155;
            border-color: #475569;
        }
        QPushButton:pressed {
            background-color: #475569;
        }
        QPushButton:disabled {
            color: #64748b;
            background-color: #162032;
            border-color: #1e293b;
        }
        QCheckBox {
            color: #e2e8f0;
            spacing: 6px;
        }
        QMenu {
            background-color: #1e293b;
            color: #f8fafc;
            border: 1px solid #475569;
        }
        QMenu::item:selected {
            background-color: #2563eb;
        }
        QToolTip {
            background-color: #1e293b;
            color: #f8fafc;
            border: 1px solid #475569;
            padding: 6px;
        }
        """

    return """
    QMainWindow, QWidget#centralRoot {
        background-color: #f8fafc;
        color: #0f172a;
    }
    QLabel {
        color: #1e293b;
    }
    QPushButton {
        background-color: #ffffff;
        color: #0f172a;
        border: 1px solid #cbd5e1;
        border-radius: 5px;
        padding: 5px 10px;
    }
    QPushButton:hover {
        background-color: #e2e8f0;
        border-color: #94a3b8;
    }
    QPushButton:pressed {
        background-color: #cbd5e1;
    }
    QPushButton:disabled {
        color: #94a3b8;
        background-color: #f1f5f9;
        border-color: #e2e8f0;
    }
    QCheckBox {
        color: #1e293b;
        spacing: 6px;
    }
    QMenu {
        background-color: #ffffff;
        color: #0f172a;
        border: 1px solid #cbd5e1;
    }
    QMenu::item:selected {
        background-color: #2563eb;
        color: #ffffff;
    }
    QToolTip {
        background-color: #ffffff;
        color: #0f172a;
        border: 1px solid #94a3b8;
        padding: 6px;
    }
    """


class SystemBarWidget(QWidget):
    """Horizontal stacked RAM bar showing total physical memory allocation."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._snapshot: Snapshot | None = None
        self._dark_mode = True
        self.setFixedHeight(40)

    def set_snapshot(self, snapshot: Snapshot | None) -> None:
        """Update the displayed snapshot and repaint."""
        self._snapshot = snapshot
        if snapshot is not None:
            available = max(0, snapshot.total_ram - snapshot.used_ram)
            self.setToolTip(
                f"Gesamt: {format_bytes(snapshot.total_ram)}\n"
                f"Anwendungen (Privat-WS): {format_bytes(snapshot.app_ram)}\n"
                f"System / Geteilt / Kernel: {format_bytes(snapshot.unattributed_ram)}\n"
                f"Verfügbar: {format_bytes(available)}"
            )
        self.update()

    def set_dark_mode(self, dark_mode: bool) -> None:
        """Apply theme colors."""
        self._dark_mode = dark_mode
        self.update()

    def paintEvent(self, event: Any) -> None:
        """Draw the summary text line and segmented RAM usage bar."""
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        rect = self.rect()
        text_color = QColor("#e2e8f0") if self._dark_mode else QColor("#0f172a")
        track_color = QColor("#1e293b") if self._dark_mode else QColor("#e2e8f0")
        app_color = QColor("#3b82f6") if self._dark_mode else QColor("#2563eb")
        sys_color = QColor("#64748b") if self._dark_mode else QColor("#94a3b8")
        border_color = QColor("#334155") if self._dark_mode else QColor("#cbd5e1")

        text_rect = QRectF(2, 0, max(0, rect.width() - 4), 20)
        bar_rect = QRectF(2, 23, max(0, rect.width() - 4), 12)

        if self._snapshot is None or self._snapshot.total_ram <= 0:
            painter.setPen(text_color)
            painter.drawText(
                text_rect,
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                "Arbeitsspeicher wird eingelesen…",
            )
            painter.setBrush(track_color)
            painter.setPen(border_color)
            painter.drawRoundedRect(bar_rect, 4, 4)
            return

        snap = self._snapshot
        available = max(0, snap.total_ram - snap.used_ram)
        used_pct = round((snap.used_ram / snap.total_ram) * 100)
        summary = (
            f"Belegt: {format_bytes(snap.used_ram)} / {format_bytes(snap.total_ram)} "
            f"({used_pct} %)  ·  "
            f"Anwendungen: {format_bytes(snap.app_ram)}  ·  "
            f"System/Geteilt: {format_bytes(snap.unattributed_ram)}  ·  "
            f"Verfügbar: {format_bytes(available)}"
        )

        font = QFont(painter.font())
        font.setPointSize(9)
        painter.setFont(font)
        painter.setPen(text_color)
        elided = QFontMetrics(font).elidedText(
            summary, Qt.TextElideMode.ElideRight, int(text_rect.width())
        )
        painter.drawText(
            text_rect, Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter, elided
        )

        painter.setBrush(track_color)
        painter.setPen(Qt.PenStyle.NoPen)
        painter.drawRoundedRect(bar_rect, 4, 4)

        total = float(max(snap.total_ram, snap.app_ram + snap.unattributed_ram, 1))
        app_w = bar_rect.width() * (snap.app_ram / total)
        sys_w = bar_rect.width() * (snap.unattributed_ram / total)

        painter.save()
        painter.setClipRect(bar_rect)
        if app_w > 0:
            painter.setBrush(app_color)
            painter.drawRect(QRectF(bar_rect.x(), bar_rect.y(), app_w, bar_rect.height()))
        if sys_w > 0:
            painter.setBrush(sys_color)
            painter.drawRect(QRectF(bar_rect.x() + app_w, bar_rect.y(), sys_w, bar_rect.height()))
        painter.restore()

        painter.setBrush(Qt.BrushStyle.NoBrush)
        painter.setPen(border_color)
        painter.drawRoundedRect(bar_rect, 4, 4)


class TreemapWidget(QWidget):
    """Interactive squarified treemap displaying application groups or zoomed processes."""

    zoom_changed = Signal(object)
    terminate_requested = Signal(str, list, int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._snapshot: Snapshot | None = None
        self._zoomed_group: str | None = None
        self._show_system_block = True
        self._dark_mode = True
        self._hovered_key: str | None = None
        self._rects: list[TreemapRect] = []
        self._resolver = ProcessDetailResolver()
        self.setMouseTracking(True)
        self.setMinimumSize(320, 240)

    @property
    def zoomed_group(self) -> str | None:
        """Currently zoomed application group name, SYSTEM_KEY, or None in overview mode."""
        return self._zoomed_group

    def set_snapshot(self, snapshot: Snapshot | None) -> None:
        """Update the rendered snapshot and reset zoom if the zoomed target vanished."""
        self._snapshot = snapshot
        if self._zoomed_group is not None and snapshot is not None:
            still_exists = (
                bool(snapshot.system_slices)
                if self._zoomed_group == SYSTEM_KEY
                else self._find_group(self._zoomed_group) is not None
            )
            if not still_exists:
                self._zoomed_group = None
                self.zoom_changed.emit(None)
        self._recompute_layout()
        self.update()

    def set_zoomed_group(self, group_name: str | None) -> None:
        """Switch between overview mode (None) and single-group process zoom."""
        if self._zoomed_group == group_name:
            return
        self._zoomed_group = group_name
        self._hovered_key = None
        self._recompute_layout()
        self.zoom_changed.emit(group_name)
        self.update()

    def set_show_system_block(self, show: bool) -> None:
        """Toggle visibility of the gray unattributed system/shared memory tile."""
        if self._show_system_block == show:
            return
        self._show_system_block = show
        self._recompute_layout()
        self.update()

    def set_dark_mode(self, dark_mode: bool) -> None:
        """Apply theme colors."""
        self._dark_mode = dark_mode
        self.update()

    def _find_group(self, group_name: str) -> AppGroup | None:
        if self._snapshot is None:
            return None
        for group in self._snapshot.groups:
            if group.name == group_name:
                return group
        return None

    def _find_proc(self, group: AppGroup, pid_str: str) -> ProcSample | None:
        for proc in group.processes:
            if str(proc.pid) == pid_str:
                return proc
        return None

    def _find_system_slice(self, key: str) -> SystemSlice | None:
        if self._snapshot is None:
            return None
        for item in self._snapshot.system_slices:
            if item.key == key:
                return item
        return None

    def _layout_items(self) -> list[tuple[str, float]]:
        if self._snapshot is None:
            return []
        if self._zoomed_group is None:
            items = [
                (group.name, float(group.private_ws))
                for group in self._snapshot.groups
                if group.private_ws > 0
            ]
            if self._show_system_block and self._snapshot.unattributed_ram > 0:
                items.append((SYSTEM_KEY, float(self._snapshot.unattributed_ram)))
            return items

        if self._zoomed_group == SYSTEM_KEY:
            return [
                (item.key, float(item.bytes_value))
                for item in self._snapshot.system_slices
                if item.bytes_value > 0
            ]

        group = self._find_group(self._zoomed_group)
        if group is None:
            return []
        return [
            (str(proc.pid), float(proc.private_ws))
            for proc in group.processes
            if proc.private_ws > 0
        ]

    def _recompute_layout(self) -> None:
        margin = 2.0
        w = max(0.0, self.width() - 2 * margin)
        h = max(0.0, self.height() - 2 * margin)
        self._rects = squarify(self._layout_items(), margin, margin, w, h)

    def _rect_at(self, pos: QPointF) -> TreemapRect | None:
        px, py = pos.x(), pos.y()
        for rect in self._rects:
            if rect.x <= px <= rect.x + rect.w and rect.y <= py <= rect.y + rect.h:
                return rect
        return None

    def resizeEvent(self, event: Any) -> None:
        """Recompute treemap coordinates on resize."""
        super().resizeEvent(event)
        self._recompute_layout()

    def leaveEvent(self, event: Any) -> None:
        """Clear hover highlight when the cursor leaves the widget."""
        super().leaveEvent(event)
        if self._hovered_key is not None:
            self._hovered_key = None
            self.update()

    def _tile_labels(self, key: str) -> tuple[str, str]:
        """Return (primary_label, secondary_label) for a treemap tile."""
        if self._snapshot is None:
            return key, ""
        if self._zoomed_group is None:
            if key == SYSTEM_KEY:
                return "System / Geteilt", format_bytes(self._snapshot.unattributed_ram)
            group = self._find_group(key)
            if group is None:
                return key, ""
            size_text = format_bytes(group.private_ws)
            if len(group.processes) > 1:
                return group.name, f"{size_text} · {len(group.processes)} Proz."
            return group.name, size_text

        if self._zoomed_group == SYSTEM_KEY:
            item = self._find_system_slice(key)
            if item is None:
                return key, ""
            if item.category == "shared" and item.raw_shared_ws > 0:
                return (
                    item.title,
                    f"{format_bytes(item.bytes_value)} · Brutto {format_bytes(item.raw_shared_ws)}",
                )
            return item.title, format_bytes(item.bytes_value)

        group = self._find_group(self._zoomed_group)
        proc = self._find_proc(group, key) if group is not None else None
        if proc is None or group is None:
            return key, ""
        role, _cmd, _services = self._resolver.resolve(proc, group.name)
        primary = f"{role} (PID {proc.pid})" if role else f"{proc.name} (PID {proc.pid})"
        if proc.shared_ws >= 1024**2:
            secondary = f"{format_bytes(proc.private_ws)} · Geteilt {format_bytes(proc.shared_ws)}"
        else:
            secondary = format_bytes(proc.private_ws)
        return primary, secondary

    def _tooltip_for(self, key: str) -> str:
        if self._snapshot is None:
            return ""
        used_base = max(self._snapshot.used_ram, 1)

        if self._zoomed_group is None:
            if key == SYSTEM_KEY:
                pct = (self._snapshot.unattributed_ram / used_base) * 100
                bd = self._snapshot.system_breakdown
                lines = [
                    "System / Geteilt / Kernel",
                    (
                        f"Größe: {format_bytes(self._snapshot.unattributed_ram)} "
                        f"({pct:.1f} % des belegten RAM)"
                    ),
                ]
                kernel_sum = bd.kernel_nonpaged + bd.kernel_paged
                shared_est = sum(
                    item.bytes_value
                    for item in self._snapshot.system_slices
                    if item.category == "shared"
                )
                if kernel_sum or bd.system_cache:
                    lines.append(
                        f"Kernel-Pools: {format_bytes(kernel_sum)} · "
                        f"Cache/Modified: {format_bytes(bd.system_cache)}"
                    )
                if shared_est:
                    lines.append(f"Geteilter App-RAM (geschätzt): {format_bytes(shared_est)}")
                lines.append("Linksklick: Aufschlüsselung öffnen")
                return "\n".join(lines)
            group = self._find_group(key)
            if group is None:
                return ""
            pct = (group.private_ws / used_base) * 100
            return (
                f"{group.name}\n"
                f"Prozesse: {len(group.processes)}\n"
                f"Privates Working Set: {format_bytes(group.private_ws)} "
                f"({pct:.1f} % des belegten RAM)\n"
                f"Geteiltes Working Set: {format_bytes(group.shared_ws)}\n"
                f"Working Set gesamt: {format_bytes(group.working_set)}\n"
                f"Private Bytes (Commit): {format_bytes(group.private_bytes)}\n"
                "Linksklick: Zoomen · Rechtsklick: Beenden"
            )

        if self._zoomed_group == SYSTEM_KEY:
            item = self._find_system_slice(key)
            if item is None:
                return ""
            unattr_base = max(self._snapshot.unattributed_ram, 1)
            pct = (item.bytes_value / unattr_base) * 100
            lines = [
                item.title,
                f"Größe: {format_bytes(item.bytes_value)} ({pct:.1f} % des System-/Geteilt-Blocks)",
            ]
            if item.raw_shared_ws > 0:
                lines.append(f"Brutto-Shared-WS der App: {format_bytes(item.raw_shared_ws)}")
            lines.append(item.description)
            return "\n".join(lines)

        group = self._find_group(self._zoomed_group)
        proc = self._find_proc(group, key) if group is not None else None
        if proc is None or group is None:
            return ""
        role, short_cmd, services = self._resolver.resolve(proc, group.name)
        lines = [f"{proc.name} (PID {proc.pid})"]
        if role:
            lines.append(f"Rolle / Dienst: {role}")
        if len(services) > 2:
            lines.append(f"Dienste: {', '.join(services)}")
        lines.extend(
            [
                f"Eltern-PID: {proc.ppid}",
                f"Privates Working Set: {format_bytes(proc.private_ws)}",
                f"Geteiltes Working Set: {format_bytes(proc.shared_ws)}",
                f"Working Set gesamt: {format_bytes(proc.working_set)}",
                f"Private Bytes (Commit): {format_bytes(proc.private_bytes)}",
            ]
        )
        if short_cmd:
            lines.append(f"Befehlszeile: {short_cmd}")
        lines.append("Rechtsklick: Prozess beenden · Esc/Zurück: Übersicht")
        return "\n".join(lines)

    def paintEvent(self, event: Any) -> None:
        """Render all treemap tiles and readable clipped labels."""
        super().paintEvent(event)
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing, False)

        bg_color = QColor("#0f172a") if self._dark_mode else QColor("#f8fafc")
        painter.fillRect(self.rect(), bg_color)

        if self._snapshot is None or not self._rects:
            painter.setPen(QColor("#94a3b8") if self._dark_mode else QColor("#475569"))
            msg = (
                "Keine Prozessdaten verfügbar."
                if self._snapshot is not None
                else "Lade Arbeitsspeicher-Übersicht…"
            )
            painter.drawText(self.rect(), Qt.AlignmentFlag.AlignCenter, msg)
            return

        sep_color = QColor("#0f172a") if self._dark_mode else QColor("#f8fafc")
        hover_color = QColor("#93c5fd") if self._dark_mode else QColor("#1d4ed8")
        text_color = QColor("#f8fafc") if self._dark_mode else QColor("#0f172a")
        subtext_color = QColor("#e2e8f0") if self._dark_mode else QColor("#334155")

        title_font = QFont(painter.font())
        title_font.setPointSize(9)
        title_font.setBold(True)
        sub_font = QFont(painter.font())
        sub_font.setPointSize(8)

        title_metrics = QFontMetrics(title_font)
        sub_metrics = QFontMetrics(sub_font)

        for rect in self._rects:
            qrect = QRectF(rect.x, rect.y, rect.w, rect.h)
            fill = _tile_color(rect.key, self._dark_mode)
            is_hovered = rect.key == self._hovered_key
            if is_hovered:
                fill = fill.lighter(115) if self._dark_mode else fill.darker(106)

            painter.fillRect(qrect, fill)
            painter.setPen(QPen(hover_color if is_hovered else sep_color, 2 if is_hovered else 1))
            painter.drawRect(qrect)

            if rect.w < 55 or rect.h < 22:
                continue

            title, subtitle = self._tile_labels(rect.key)
            pad = 6.0
            inner_w = int(rect.w - 2 * pad)
            if inner_w <= 4:
                continue

            painter.save()
            painter.setClipRect(qrect.adjusted(2, 2, -2, -2))

            painter.setFont(title_font)
            painter.setPen(text_color)
            elided_title = title_metrics.elidedText(title, Qt.TextElideMode.ElideRight, inner_w)
            title_h = title_metrics.height()
            painter.drawText(
                QRectF(rect.x + pad, rect.y + 4, inner_w, title_h),
                Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                elided_title,
            )

            if rect.w >= 65 and rect.h >= 40 and subtitle:
                painter.setFont(sub_font)
                painter.setPen(subtext_color)
                elided_sub = sub_metrics.elidedText(subtitle, Qt.TextElideMode.ElideRight, inner_w)
                painter.drawText(
                    QRectF(rect.x + pad, rect.y + 5 + title_h, inner_w, sub_metrics.height()),
                    Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                    elided_sub,
                )

            painter.restore()

    def mouseMoveEvent(self, event: Any) -> None:
        """Highlight the hovered tile and show detailed RAM metrics in a tooltip."""
        from PySide6.QtWidgets import QToolTip

        rect = self._rect_at(event.position())
        new_key = rect.key if rect is not None else None
        if new_key != self._hovered_key:
            self._hovered_key = new_key
            self.update()

        if rect is not None:
            tip = self._tooltip_for(rect.key)
            if tip:
                QToolTip.showText(event.globalPosition().toPoint(), tip, self)
        else:
            QToolTip.hideText()

    def mousePressEvent(self, event: Any) -> None:
        """Handle left-click zoom, back-button unzoom, and right-click context menu."""
        if event.button() == Qt.MouseButton.BackButton:
            if self._zoomed_group is not None:
                self.set_zoomed_group(None)
            return

        rect = self._rect_at(event.position())
        if event.button() == Qt.MouseButton.LeftButton:
            if self._zoomed_group is None and rect is not None:
                self.set_zoomed_group(rect.key)
            elif self._zoomed_group == SYSTEM_KEY and rect is not None:
                item = self._find_system_slice(rect.key)
                if (
                    item is not None
                    and item.target_group
                    and self._find_group(item.target_group) is not None
                ):
                    self.set_zoomed_group(item.target_group)
            return

        if event.button() == Qt.MouseButton.RightButton:
            self._show_context_menu(rect, event.globalPosition().toPoint())

    def _show_context_menu(self, rect: TreemapRect | None, global_pos: Any) -> None:
        if self._snapshot is None:
            return
        menu = QMenu(self)

        if self._zoomed_group is None:
            if rect is None:
                return
            if rect.key == SYSTEM_KEY:
                drill_act = menu.addAction("System-/Geteilt-Block aufschlüsseln…")
                if menu.exec(global_pos) == drill_act:
                    self.set_zoomed_group(SYSTEM_KEY)
                return
            group = self._find_group(rect.key)
            if group is None:
                return
            zoom_act = menu.addAction(
                f"Auf „{group.name}“ zoomen ({len(group.processes)} Prozesse)"
            )
            term_act = menu.addAction(
                f"Anwendung „{group.name}“ beenden "
                f"({len(group.processes)} Prozesse, {format_bytes(group.private_ws)})…"
            )
            chosen = menu.exec(global_pos)
            if chosen == zoom_act:
                self.set_zoomed_group(group.name)
            elif chosen == term_act:
                self.terminate_requested.emit(
                    group.name,
                    [proc.pid for proc in group.processes],
                    group.private_ws,
                )
            return

        if self._zoomed_group == SYSTEM_KEY:
            jump_act = None
            target_group: str | None = None
            if rect is not None:
                item = self._find_system_slice(rect.key)
                if (
                    item is not None
                    and item.target_group
                    and self._find_group(item.target_group) is not None
                ):
                    target_group = item.target_group
                    jump_act = menu.addAction(f"Auf „{target_group}“ zoomen")
            back_act = menu.addAction("← Zurück zur Übersicht")
            chosen = menu.exec(global_pos)
            if chosen == back_act:
                self.set_zoomed_group(None)
            elif jump_act is not None and chosen == jump_act and target_group is not None:
                self.set_zoomed_group(target_group)
            return

        term_proc_act = None
        proc: ProcSample | None = None
        if rect is not None:
            group = self._find_group(self._zoomed_group)
            proc = self._find_proc(group, rect.key) if group is not None else None
            if proc is not None:
                term_proc_act = menu.addAction(
                    f"Prozess „{proc.name}“ (PID {proc.pid}, "
                    f"{format_bytes(proc.private_ws)}) beenden…"
                )
        back_act = menu.addAction("← Zurück zur Übersicht")
        chosen = menu.exec(global_pos)
        if chosen is None:
            return
        if chosen == back_act:
            self.set_zoomed_group(None)
        elif chosen == term_proc_act and proc is not None:
            self.terminate_requested.emit(
                f"{proc.name} (PID {proc.pid})",
                [proc.pid],
                proc.private_ws,
            )


class MainWindow(QMainWindow):
    """Main application window for pyRAM."""

    def __init__(self, start_worker: bool = True) -> None:
        super().__init__()
        self._settings = QSettings("pyRAM", "pyRAM")
        self._dark_mode = self._read_bool_setting("dark_mode", True)
        self._show_system_block = self._read_bool_setting("show_system_block", True)
        self._snapshot: Snapshot | None = None

        self.setWindowTitle("pyRAM – Arbeitsspeicher-Landkarte")
        self.resize(1100, 720)

        root = QWidget()
        root.setObjectName("centralRoot")
        layout = QVBoxLayout(root)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(8)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(8)

        self._back_btn = QPushButton("← Alle Anwendungen")
        self._back_btn.setVisible(False)
        self._back_btn.clicked.connect(lambda: self._treemap.set_zoomed_group(None))
        toolbar.addWidget(self._back_btn)

        self._status_label = QLabel("Lade Arbeitsspeicher-Daten…")
        toolbar.addWidget(self._status_label)
        toolbar.addStretch()

        self._system_checkbox = QCheckBox("Systemblock zeigen")
        self._system_checkbox.setChecked(self._show_system_block)
        self._system_checkbox.toggled.connect(self._on_system_block_toggled)
        toolbar.addWidget(self._system_checkbox)

        self._refresh_btn = QPushButton("Aktualisieren")
        toolbar.addWidget(self._refresh_btn)

        self._theme_btn = QPushButton("Hell / Dunkel")
        self._theme_btn.clicked.connect(self.toggle_theme)
        toolbar.addWidget(self._theme_btn)

        self._fullscreen_btn = QPushButton("Vollbild (F11)")
        self._fullscreen_btn.clicked.connect(self.toggle_fullscreen)
        toolbar.addWidget(self._fullscreen_btn)

        layout.addLayout(toolbar)

        self._system_bar = SystemBarWidget()
        layout.addWidget(self._system_bar)

        self._treemap = TreemapWidget()
        self._treemap.set_show_system_block(self._show_system_block)
        self._treemap.zoom_changed.connect(self._on_zoom_changed)
        self._treemap.terminate_requested.connect(self._on_terminate_requested)
        layout.addWidget(self._treemap, stretch=1)

        self.setCentralWidget(root)

        self._worker = SamplerWorker(interval_s=2.0, parent=self)
        self._worker.snapshot_ready.connect(self._on_snapshot)
        self._refresh_btn.clicked.connect(self._worker.request_refresh)

        QShortcut(QKeySequence(Qt.Key.Key_F11), self, self.toggle_fullscreen)
        QShortcut(QKeySequence(Qt.Key.Key_Escape), self, self._handle_escape)
        QShortcut(
            QKeySequence(Qt.Key.Key_Backspace), self, lambda: self._treemap.set_zoomed_group(None)
        )

        self._apply_theme()
        self._restore_geometry()

        if start_worker:
            self._worker.start()

    def _read_bool_setting(self, key: str, default: bool) -> bool:
        value = self._settings.value(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"1", "true", "yes"}
        return bool(value)

    def _restore_geometry(self) -> None:
        geometry = self._settings.value("geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        state = self._settings.value("windowState")
        if state is not None:
            self.restoreState(state)

    def _apply_theme(self) -> None:
        self.setStyleSheet(build_stylesheet(self._dark_mode))
        self._system_bar.set_dark_mode(self._dark_mode)
        self._treemap.set_dark_mode(self._dark_mode)

    def toggle_theme(self) -> None:
        """Toggle between dark and light themes."""
        self._dark_mode = not self._dark_mode
        self._apply_theme()

    def toggle_fullscreen(self) -> None:
        """Toggle between normal window mode and fullscreen mode."""
        if self.isFullScreen():
            self.showNormal()
        else:
            self.showFullScreen()

    def _handle_escape(self) -> None:
        if self._treemap.zoomed_group is not None:
            self._treemap.set_zoomed_group(None)
        elif self.isFullScreen():
            self.showNormal()

    def _on_system_block_toggled(self, checked: bool) -> None:
        self._show_system_block = checked
        self._treemap.set_show_system_block(checked)

    def _on_zoom_changed(self, group_name: str | None) -> None:
        self._back_btn.setVisible(group_name is not None)
        self._update_status_label()

    def _on_snapshot(self, snapshot: Snapshot) -> None:
        self._snapshot = snapshot
        self._system_bar.set_snapshot(snapshot)
        self._treemap.set_snapshot(snapshot)
        self._update_status_label()

    def _update_status_label(self) -> None:
        if self._snapshot is None:
            self._status_label.setText("Lade Arbeitsspeicher-Daten…")
            return
        zoomed = self._treemap.zoomed_group
        if zoomed is None:
            total_procs = sum(len(group.processes) for group in self._snapshot.groups)
            self._status_label.setText(
                f"Übersicht: {len(self._snapshot.groups)} Anwendungen ({total_procs} Prozesse)"
            )
            return

        if zoomed == SYSTEM_KEY:
            self._status_label.setText(
                f"Ansicht: System / Geteilt / Kernel ({format_bytes(self._snapshot.unattributed_ram)}) "
                "– Klick auf „Geteilt: …“ öffnet die Anwendung"
            )
            return

        for group in self._snapshot.groups:
            if group.name == zoomed:
                self._status_label.setText(
                    f"Ansicht: {group.name} ({len(group.processes)} Prozesse, "
                    f"{format_bytes(group.private_ws)})"
                )
                return
        self._status_label.setText(f"Ansicht: {zoomed}")

    def _on_terminate_requested(self, label: str, pids: list[int], bytes_used: int) -> None:
        if not pids:
            return
        if len(pids) == 1:
            question = (
                f"Soll der Prozess „{label}“ ({format_bytes(bytes_used)}) wirklich beendet "
                "werden?\n\nUngespeicherte Daten in diesem Prozess gehen verloren."
            )
        else:
            question = (
                f"Sollen alle {len(pids)} Prozesse der Anwendung „{label}“ "
                f"({format_bytes(bytes_used)}) wirklich beendet werden?\n\n"
                "Ungespeicherte Daten gehen verloren."
            )

        reply = QMessageBox.question(
            self,
            "Prozess beenden",
            question,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )
        if reply != QMessageBox.StandardButton.Yes:
            return

        _, errors = terminate_processes(pids)
        if errors:
            QMessageBox.warning(self, "Beenden unvollständig", "\n".join(errors))
        self._worker.request_refresh()

    def closeEvent(self, event: Any) -> None:
        """Persist window geometry/preferences and stop the sampler thread cleanly."""
        self._settings.setValue("geometry", self.saveGeometry())
        self._settings.setValue("windowState", self.saveState())
        self._settings.setValue("dark_mode", self._dark_mode)
        self._settings.setValue("show_system_block", self._show_system_block)
        self._worker.stop()
        super().closeEvent(event)


def main() -> None:
    """Launch the pyRAM desktop GUI."""
    app = QApplication(sys.argv)
    app.setApplicationName("pyRAM")
    app.setOrganizationName("pyRAM")
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
