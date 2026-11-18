"""Process memory sampling, grouping, treemap layout, and background worker for pyRAM."""

from __future__ import annotations

import ctypes
import logging
import os
import sys
import threading
import time
from collections import defaultdict
from collections.abc import Sequence
from dataclasses import dataclass

import psutil
from PySide6.QtCore import QObject, QThread, Signal

SYSTEM_PROCESS_INFORMATION_CLASS = 5
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004
_LOGGER = logging.getLogger(__name__)

# Processes that launch unrelated applications; the ancestor walk stops below them.
LAUNCHERS = {
    "",
    "system",
    "system idle process",
    "registry",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "winlogon.exe",
    "services.exe",
    "svchost.exe",
    "explorer.exe",
    "userinit.exe",
    "sihost.exe",
    "runtimebroker.exe",
    "taskhostw.exe",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "windowsterminal.exe",
    "openconsole.exe",
    "conhost.exe",
    "systemd",
    "init",
    "launchd",
    "bash",
    "zsh",
    "sh",
}


class UnicodeString(ctypes.Structure):
    """Windows UNICODE_STRING structure."""

    _fields_ = [
        ("Length", ctypes.c_uint16),
        ("MaximumLength", ctypes.c_uint16),
        ("Buffer", ctypes.c_void_p),
    ]


class SystemProcessInformation(ctypes.Structure):
    """SYSTEM_PROCESS_INFORMATION (64-bit layout), up to the fields needed for RAM sampling."""

    _fields_ = [
        ("NextEntryOffset", ctypes.c_uint32),
        ("NumberOfThreads", ctypes.c_uint32),
        ("WorkingSetPrivateSize", ctypes.c_int64),
        ("HardFaultCount", ctypes.c_uint32),
        ("NumberOfThreadsHighWatermark", ctypes.c_uint32),
        ("CycleTime", ctypes.c_uint64),
        ("CreateTime", ctypes.c_int64),
        ("UserTime", ctypes.c_int64),
        ("KernelTime", ctypes.c_int64),
        ("ImageName", UnicodeString),
        ("BasePriority", ctypes.c_int32),
        ("UniqueProcessId", ctypes.c_void_p),
        ("InheritedFromUniqueProcessId", ctypes.c_void_p),
        ("HandleCount", ctypes.c_uint32),
        ("SessionId", ctypes.c_uint32),
        ("UniqueProcessKey", ctypes.c_size_t),
        ("PeakVirtualSize", ctypes.c_size_t),
        ("VirtualSize", ctypes.c_size_t),
        ("PageFaultCount", ctypes.c_uint32),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
        ("PrivatePageCount", ctypes.c_size_t),
    ]


class MemoryStatusEx(ctypes.Structure):
    """Windows MEMORYSTATUSEX structure."""

    _fields_ = [
        ("dwLength", ctypes.c_uint32),
        ("dwMemoryLoad", ctypes.c_uint32),
        ("ullTotalPhys", ctypes.c_uint64),
        ("ullAvailPhys", ctypes.c_uint64),
        ("ullTotalPageFile", ctypes.c_uint64),
        ("ullAvailPageFile", ctypes.c_uint64),
        ("ullTotalVirtual", ctypes.c_uint64),
        ("ullAvailVirtual", ctypes.c_uint64),
        ("ullAvailExtendedVirtual", ctypes.c_uint64),
    ]


@dataclass(slots=True)
class ProcSample:
    """Memory and identity sample for a single OS process."""

    pid: int
    ppid: int
    name: str
    created: int
    private_ws: int
    working_set: int
    private_bytes: int


@dataclass(slots=True)
class AppGroup:
    """Aggregated memory usage of processes belonging to one application."""

    name: str
    private_ws: int
    working_set: int
    private_bytes: int
    processes: list[ProcSample]


@dataclass(slots=True)
class Snapshot:
    """Complete system and application RAM snapshot at a point in time."""

    timestamp: float
    total_ram: int
    used_ram: int
    app_ram: int
    unattributed_ram: int
    groups: list[AppGroup]


@dataclass(slots=True)
class TreemapRect:
    """Layout rectangle produced by squarify."""

    key: str
    x: float
    y: float
    w: float
    h: float


def _is_win64() -> bool:
    return sys.platform == "win32" and ctypes.sizeof(ctypes.c_void_p) == 8


class NativeSampler:
    """Reads all processes in one native call on 64-bit Windows, with a psutil fallback."""

    def __init__(self) -> None:
        self._native = _is_win64()
        if self._native:
            self._ntdll = ctypes.WinDLL("ntdll")
            self._query = self._ntdll.NtQuerySystemInformation
            self._query.restype = ctypes.c_uint32
            self._query.argtypes = [
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.POINTER(ctypes.c_uint32),
            ]
            self._size = 1024 * 1024
            self._buffer = ctypes.create_string_buffer(self._size)

    def sample(self) -> dict[int, ProcSample]:
        """Collect a dictionary of PID -> ProcSample for all visible processes."""
        if not self._native:
            return _sample_via_psutil()

        needed = ctypes.c_uint32(0)
        while True:
            status = self._query(
                SYSTEM_PROCESS_INFORMATION_CLASS,
                self._buffer,
                self._size,
                ctypes.byref(needed),
            )
            if status != STATUS_INFO_LENGTH_MISMATCH:
                break
            self._size = max(self._size * 2, needed.value + 64 * 1024)
            self._buffer = ctypes.create_string_buffer(self._size)
        if status != 0:
            raise OSError(f"NtQuerySystemInformation failed with status 0x{status:08X}")

        result: dict[int, ProcSample] = {}
        offset = 0
        while True:
            entry = SystemProcessInformation.from_buffer(self._buffer, offset)
            pid = entry.UniqueProcessId or 0
            if entry.ImageName.Buffer and entry.ImageName.Length:
                name = ctypes.wstring_at(entry.ImageName.Buffer, entry.ImageName.Length // 2)
            else:
                name = "System Idle Process" if pid == 0 else f"PID {pid}"
            result[pid] = ProcSample(
                pid=pid,
                ppid=entry.InheritedFromUniqueProcessId or 0,
                name=name,
                created=entry.CreateTime,
                private_ws=max(0, int(entry.WorkingSetPrivateSize)),
                working_set=max(0, int(entry.WorkingSetSize)),
                private_bytes=max(0, int(entry.PrivatePageCount)),
            )
            if entry.NextEntryOffset == 0:
                break
            offset += entry.NextEntryOffset
        return result


def _sample_via_psutil() -> dict[int, ProcSample]:
    """Cross-platform fallback sampler using psutil."""
    result: dict[int, ProcSample] = {}
    attrs = ["pid", "ppid", "name", "create_time", "memory_info"]
    for proc in psutil.process_iter(attrs, ad_value=None):
        info = proc.info
        pid = info["pid"]
        mem = info["memory_info"]
        rss = getattr(mem, "rss", 0) if mem else 0
        private = getattr(mem, "private", rss) if mem else 0
        created_s = info["create_time"] or 0.0
        result[pid] = ProcSample(
            pid=pid,
            ppid=info["ppid"] or 0,
            name=info["name"] or f"PID {pid}",
            created=int(created_s * 10_000_000),
            private_ws=max(0, int(rss)),
            working_set=max(0, int(rss)),
            private_bytes=max(0, int(private)),
        )
    return result


def physical_memory() -> tuple[int, int]:
    """Return (total, used) physical memory in bytes."""
    if not _is_win64():
        vm = psutil.virtual_memory()
        return int(vm.total), int(vm.total - vm.available)

    status = MemoryStatusEx()
    status.dwLength = ctypes.sizeof(MemoryStatusEx)
    if not ctypes.WinDLL("kernel32").GlobalMemoryStatusEx(ctypes.byref(status)):
        raise ctypes.WinError()
    return int(status.ullTotalPhys), int(status.ullTotalPhys - status.ullAvailPhys)


def app_root(proc: ProcSample, sample: dict[int, ProcSample]) -> str:
    """Walk up the parent chain until a launcher is reached; return that ancestor's name."""
    current = proc
    seen = {proc.pid}
    while True:
        parent = sample.get(current.ppid)
        if parent is None or parent.pid in seen:
            break
        # A parent created after its child means the parent PID was reused.
        if parent.created > current.created:
            break
        if parent.name.lower() in LAUNCHERS:
            break
        seen.add(parent.pid)
        current = parent
    return current.name or f"PID {current.pid}"


def build_snapshot(
    sample: dict[int, ProcSample],
    total_ram: int,
    used_ram: int,
    timestamp: float | None = None,
) -> Snapshot:
    """Group processes into applications and aggregate RAM totals into a Snapshot."""
    grouped: dict[str, list[ProcSample]] = defaultdict(list)
    for proc in sample.values():
        if proc.pid == 0 or proc.private_ws <= 0:
            continue
        grouped[app_root(proc, sample)].append(proc)

    groups: list[AppGroup] = []
    for name, procs in grouped.items():
        procs.sort(key=lambda item: item.private_ws, reverse=True)
        groups.append(
            AppGroup(
                name=name,
                private_ws=sum(item.private_ws for item in procs),
                working_set=sum(item.working_set for item in procs),
                private_bytes=sum(item.private_bytes for item in procs),
                processes=procs,
            )
        )
    groups.sort(key=lambda group: group.private_ws, reverse=True)

    app_ram = sum(group.private_ws for group in groups)
    unattributed_ram = max(0, used_ram - app_ram)
    return Snapshot(
        timestamp=time.time() if timestamp is None else timestamp,
        total_ram=total_ram,
        used_ram=used_ram,
        app_ram=app_ram,
        unattributed_ram=unattributed_ram,
        groups=groups,
    )


def _worst_ratio(row_areas: Sequence[float], side: float) -> float:
    """Compute the worst aspect ratio for a candidate treemap row."""
    if not row_areas or side <= 0:
        return float("inf")
    total = sum(row_areas)
    if total <= 0:
        return float("inf")
    side2 = side * side
    total2 = total * total
    max_a = max(row_areas)
    min_a = min(row_areas)
    if min_a <= 0:
        return float("inf")
    return max((side2 * max_a) / total2, total2 / (side2 * min_a))


def _layout_row(
    row: Sequence[tuple[str, float]],
    rx: float,
    ry: float,
    rw: float,
    rh: float,
    out: list[TreemapRect],
) -> tuple[float, float, float, float]:
    """Place one row of items along the shorter side and return the remaining rectangle."""
    row_sum = sum(area for _, area in row)
    if row_sum <= 0 or rw <= 0 or rh <= 0:
        return rx, ry, rw, rh

    if rw >= rh:
        strip_w = min(rw, row_sum / rh)
        cur_y = ry
        for key, area in row:
            item_h = (area / row_sum) * rh
            out.append(TreemapRect(key=key, x=rx, y=cur_y, w=strip_w, h=item_h))
            cur_y += item_h
        return rx + strip_w, ry, max(0.0, rw - strip_w), rh

    strip_h = min(rh, row_sum / rw)
    cur_x = rx
    for key, area in row:
        item_w = (area / row_sum) * rw
        out.append(TreemapRect(key=key, x=cur_x, y=ry, w=item_w, h=strip_h))
        cur_x += item_w
    return rx, ry + strip_h, rw, max(0.0, rh - strip_h)


def squarify(
    items: Sequence[tuple[str, float]],
    x: float,
    y: float,
    w: float,
    h: float,
) -> list[TreemapRect]:
    """Compute a squarified treemap layout for (key, value) pairs inside (x, y, w, h)."""
    positive = [(key, float(val)) for key, val in items if val > 0]
    if not positive or w <= 0 or h <= 0:
        return []

    positive.sort(key=lambda item: item[1], reverse=True)
    total_val = sum(val for _, val in positive)
    scale = (w * h) / total_val
    areas = [(key, val * scale) for key, val in positive]

    rects: list[TreemapRect] = []
    rx, ry, rw, rh = float(x), float(y), float(w), float(h)
    row: list[tuple[str, float]] = []

    for key, area in areas:
        if rw <= 0 or rh <= 0:
            break
        side = min(rw, rh)
        if not row:
            row.append((key, area))
            continue

        row_areas = [item_area for _, item_area in row]
        if _worst_ratio([*row_areas, area], side) <= _worst_ratio(row_areas, side):
            row.append((key, area))
        else:
            rx, ry, rw, rh = _layout_row(row, rx, ry, rw, rh, rects)
            row = [(key, area)]

    if row and rw > 0 and rh > 0:
        _layout_row(row, rx, ry, rw, rh, rects)
    return rects


def terminate_processes(pids: Sequence[int]) -> tuple[int, list[str]]:
    """Terminate the given PIDs cleanly, escalating to kill after a short timeout."""
    own_pid = os.getpid()
    success_count = 0
    errors: list[str] = []
    terminating: list[psutil.Process] = []

    for pid in dict.fromkeys(pids):
        if pid == own_pid or pid <= 0:
            continue
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            terminating.append(proc)
        except psutil.NoSuchProcess:
            success_count += 1
        except psutil.AccessDenied:
            errors.append(f"PID {pid}: Zugriff verweigert")
        except psutil.Error as exc:
            errors.append(f"PID {pid}: {exc}")

    if terminating:
        gone, alive = psutil.wait_procs(terminating, timeout=0.3)
        success_count += len(gone)
        for proc in alive:
            try:
                proc.kill()
                success_count += 1
            except psutil.NoSuchProcess:
                success_count += 1
            except psutil.AccessDenied:
                errors.append(f"PID {proc.pid}: Zugriff verweigert")
            except psutil.Error as exc:
                errors.append(f"PID {proc.pid}: {exc}")

    return success_count, errors


class SamplerWorker(QThread):
    """Background worker thread that periodically emits fresh RAM snapshots."""

    snapshot_ready = Signal(object)

    def __init__(self, interval_s: float = 2.0, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self._interval_s = interval_s
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()

    def run(self) -> None:
        """Sample processes at the configured interval until stopped."""
        sampler = NativeSampler()
        while not self._stop_event.is_set():
            self._wake_event.clear()
            try:
                sample = sampler.sample()
                total_ram, used_ram = physical_memory()
                snapshot = build_snapshot(sample, total_ram, used_ram)
                self.snapshot_ready.emit(snapshot)
            except (OSError, psutil.Error) as exc:
                _LOGGER.warning("Failed to sample process memory: %s", exc)

            if self._stop_event.is_set():
                break
            self._wake_event.wait(self._interval_s)

    def request_refresh(self) -> None:
        """Wake the worker to take an immediate sample."""
        self._wake_event.set()

    def stop(self) -> None:
        """Signal the worker thread to exit and wait briefly for cleanup."""
        self._stop_event.set()
        self._wake_event.set()
        self.wait(2000)
