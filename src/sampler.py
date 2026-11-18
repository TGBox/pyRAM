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
from pathlib import Path

import psutil
from PySide6.QtCore import QObject, QThread, Signal

SYSTEM_PROCESS_INFORMATION_CLASS = 5
SYSTEM_MODULE_INFORMATION_CLASS = 11
SYSTEM_FILECACHE_INFORMATION_CLASS = 21
SYSTEM_MEMORY_LIST_INFORMATION_CLASS = 80
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


class PerformanceInformation(ctypes.Structure):
    """Windows PERFORMANCE_INFORMATION structure for GetPerformanceInfo."""

    _fields_ = [
        ("cb", ctypes.c_uint32),
        ("CommitTotal", ctypes.c_size_t),
        ("CommitLimit", ctypes.c_size_t),
        ("CommitPeak", ctypes.c_size_t),
        ("PhysicalTotal", ctypes.c_size_t),
        ("PhysicalAvailable", ctypes.c_size_t),
        ("SystemCache", ctypes.c_size_t),
        ("KernelTotal", ctypes.c_size_t),
        ("KernelPaged", ctypes.c_size_t),
        ("KernelNonpaged", ctypes.c_size_t),
        ("PageSize", ctypes.c_size_t),
        ("HandleCount", ctypes.c_uint32),
        ("ProcessCount", ctypes.c_uint32),
        ("ThreadCount", ctypes.c_uint32),
    ]


class SystemFileCacheInformation(ctypes.Structure):
    """Windows SYSTEM_FILECACHE_INFORMATION structure."""

    _fields_ = [
        ("CurrentSize", ctypes.c_size_t),
        ("PeakSize", ctypes.c_size_t),
        ("PageFaultCount", ctypes.c_uint32),
        ("MinimumWorkingSet", ctypes.c_size_t),
        ("MaximumWorkingSet", ctypes.c_size_t),
        ("CurrentSizeIncludingTransitionInPages", ctypes.c_size_t),
        ("PeakSizeIncludingTransitionInPages", ctypes.c_size_t),
        ("TransitionRePurposeCount", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
    ]


class SystemMemoryListInformation(ctypes.Structure):
    """Windows SYSTEM_MEMORY_LIST_INFORMATION structure."""

    _fields_ = [
        ("ZeroPageCount", ctypes.c_size_t),
        ("FreePageCount", ctypes.c_size_t),
        ("ModifiedPageCount", ctypes.c_size_t),
        ("ModifiedNoWritePageCount", ctypes.c_size_t),
        ("BadPageCount", ctypes.c_size_t),
        ("PageCountByPriority", ctypes.c_size_t * 8),
        ("RepurposedPagesByPriority", ctypes.c_size_t * 8),
        ("ModifiedPageCountPageFile", ctypes.c_size_t),
    ]


class RtlProcessModuleInformation(ctypes.Structure):
    """Windows RTL_PROCESS_MODULE_INFORMATION structure."""

    _fields_ = [
        ("Section", ctypes.c_void_p),
        ("MappedBase", ctypes.c_void_p),
        ("ImageBase", ctypes.c_void_p),
        ("ImageSize", ctypes.c_uint32),
        ("Flags", ctypes.c_uint32),
        ("LoadOrderIndex", ctypes.c_uint16),
        ("InitOrderIndex", ctypes.c_uint16),
        ("LoadCount", ctypes.c_uint16),
        ("OffsetToFileName", ctypes.c_uint16),
        ("FullPathName", ctypes.c_char * 256),
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

    @property
    def shared_ws(self) -> int:
        """Working set pages shared with other processes (non-additive across apps)."""
        return max(0, self.working_set - self.private_ws)


@dataclass(slots=True)
class AppGroup:
    """Aggregated memory usage of processes belonging to one application."""

    name: str
    private_ws: int
    working_set: int
    private_bytes: int
    processes: list[ProcSample]

    @property
    def shared_ws(self) -> int:
        """Sum of shared working set bytes across processes in this group."""
        return max(0, self.working_set - self.private_ws)


@dataclass(slots=True)
class SystemBreakdown:
    """Windows kernel and system memory metrics queried without elevation."""

    kernel_nonpaged: int
    kernel_paged: int
    system_cache: int
    driver_images: int
    top_drivers: list[tuple[str, int]]


@dataclass(slots=True)
class SystemSlice:
    """One sub-tile inside the System / Shared / Kernel treemap drilldown."""

    key: str
    title: str
    bytes_value: int
    category: str
    description: str
    target_group: str | None = None
    raw_shared_ws: int = 0


@dataclass(slots=True)
class Snapshot:
    """Complete system and application RAM snapshot at a point in time."""

    timestamp: float
    total_ram: int
    used_ram: int
    app_ram: int
    unattributed_ram: int
    groups: list[AppGroup]
    system_breakdown: SystemBreakdown
    system_slices: list[SystemSlice]


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


def _format_size_short(num_bytes: int) -> str:
    if num_bytes >= 100 * 1024**2:
        return f"{num_bytes / 1024**3:.2f}".replace(".", ",") + " GB"
    if num_bytes >= 1024**2:
        return f"{num_bytes / 1024**2:.1f}".replace(".", ",") + " MB"
    return f"{num_bytes / 1024:.0f} KB"


def _query_kernel_modules(ntdll: ctypes.WinDLL) -> tuple[int, list[tuple[str, int]]]:
    """Query loaded kernel modules (.sys / ntoskrnl) via SystemModuleInformation."""
    query = ntdll.NtQuerySystemInformation
    size = 256 * 1024
    buf = ctypes.create_string_buffer(size)
    needed = ctypes.c_uint32(0)
    while True:
        status = query(SYSTEM_MODULE_INFORMATION_CLASS, buf, size, ctypes.byref(needed))
        if status != STATUS_INFO_LENGTH_MISMATCH:
            break
        size = max(size * 2, needed.value + 64 * 1024)
        buf = ctypes.create_string_buffer(size)
    if status != 0:
        return 0, []

    count = ctypes.c_uint32.from_buffer(buf, 0).value
    header_offset = ctypes.sizeof(ctypes.c_void_p)
    entry_size = ctypes.sizeof(RtlProcessModuleInformation)
    if header_offset + count * entry_size > len(buf):
        return 0, []

    mods: list[tuple[str, int]] = []
    total_size = 0
    for idx in range(count):
        mod = RtlProcessModuleInformation.from_buffer(buf, header_offset + idx * entry_size)
        raw = bytes(mod.FullPathName)
        nul = raw.find(0)
        path = raw[: nul if nul >= 0 else len(raw)].decode("ascii", errors="replace")
        if mod.OffsetToFileName < len(path):
            name = path[mod.OffsetToFileName :]
        else:
            name = path.rsplit("\\", 1)[-1]
        img_size = int(mod.ImageSize)
        total_size += img_size
        mods.append((name, img_size))

    mods.sort(key=lambda item: item[1], reverse=True)
    return total_size, mods[:6]


def query_system_breakdown() -> SystemBreakdown:
    """Query Windows kernel pools, active system cache, and loaded driver module sizes."""
    if not _is_win64():
        return SystemBreakdown(0, 0, 0, 0, [])

    kernel_nonpaged = 0
    kernel_paged = 0
    system_cache = 0
    driver_images = 0
    top_drivers: list[tuple[str, int]] = []
    page_size = 4096

    try:
        pi = PerformanceInformation()
        pi.cb = ctypes.sizeof(pi)
        if ctypes.WinDLL("psapi").GetPerformanceInfo(ctypes.byref(pi), pi.cb):
            page_size = int(pi.PageSize or 4096)
            kernel_nonpaged = int(pi.KernelNonpaged * page_size)
            kernel_paged = int(pi.KernelPaged * page_size)
            system_cache = int(pi.SystemCache * page_size)
    except OSError:
        pass

    try:
        ntdll = ctypes.WinDLL("ntdll")
        query = ntdll.NtQuerySystemInformation
        query.restype = ctypes.c_uint32
        query.argtypes = [
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.POINTER(ctypes.c_uint32),
        ]

        needed = ctypes.c_uint32(0)
        fc = SystemFileCacheInformation()
        if (
            query(
                SYSTEM_FILECACHE_INFORMATION_CLASS,
                ctypes.byref(fc),
                ctypes.sizeof(fc),
                ctypes.byref(needed),
            )
            == 0
        ):
            active_cache = int(fc.CurrentSize)
            ml = SystemMemoryListInformation()
            if (
                query(
                    SYSTEM_MEMORY_LIST_INFORMATION_CLASS,
                    ctypes.byref(ml),
                    ctypes.sizeof(ml),
                    ctypes.byref(needed),
                )
                == 0
            ):
                active_cache += int(
                    (ml.ModifiedPageCount + ml.ModifiedNoWritePageCount) * page_size
                )
            system_cache = active_cache

        driver_images, top_drivers = _query_kernel_modules(ntdll)
    except OSError:
        pass

    return SystemBreakdown(
        kernel_nonpaged=kernel_nonpaged,
        kernel_paged=kernel_paged,
        system_cache=system_cache,
        driver_images=driver_images,
        top_drivers=top_drivers,
    )


def _scale_slices_to_budget(slices: list[SystemSlice], budget: int) -> list[SystemSlice]:
    """Scale slice sizes proportionally so their total matches budget."""
    total = sum(s.bytes_value for s in slices)
    if total <= 0 or budget <= 0:
        return []
    scaled: list[SystemSlice] = []
    for item in slices:
        val = round(budget * (item.bytes_value / total))
        if val > 0:
            scaled.append(
                SystemSlice(
                    key=item.key,
                    title=item.title,
                    bytes_value=val,
                    category=item.category,
                    description=item.description,
                    target_group=item.target_group,
                    raw_shared_ws=item.raw_shared_ws,
                )
            )
    if not scaled:
        largest = max(slices, key=lambda item: item.bytes_value)
        scaled.append(
            SystemSlice(
                key=largest.key,
                title=largest.title,
                bytes_value=budget,
                category=largest.category,
                description=largest.description,
                target_group=largest.target_group,
                raw_shared_ws=largest.raw_shared_ws,
            )
        )
    else:
        diff = budget - sum(item.bytes_value for item in scaled)
        if diff != 0:
            largest = max(scaled, key=lambda item: item.bytes_value)
            largest.bytes_value = max(1, largest.bytes_value + diff)
    return scaled


def build_system_slices(
    unattributed_ram: int,
    groups: Sequence[AppGroup],
    breakdown: SystemBreakdown,
) -> list[SystemSlice]:
    """Partition unattributed physical RAM into kernel slices and shared application slices."""
    if unattributed_ram <= 0:
        return []

    kernel_slices: list[SystemSlice] = []
    nonpaged_rest = (
        max(0, breakdown.kernel_nonpaged - breakdown.driver_images)
        if breakdown.driver_images > 0
        else breakdown.kernel_nonpaged
    )
    if nonpaged_rest > 0:
        kernel_slices.append(
            SystemSlice(
                key="sys:nonpaged",
                title="Kernel Nonpaged Pool",
                bytes_value=nonpaged_rest,
                category="kernel",
                description=(
                    "Nicht auslagerbarer Kernel- und Treiberspeicher im physischen RAM.\n"
                    "Kann nicht direkt beendet werden — sinkt nur durch Treiber-Updates oder Neustart."
                ),
            )
        )
    if breakdown.kernel_paged > 0:
        kernel_slices.append(
            SystemSlice(
                key="sys:paged",
                title="Kernel Paged Pool",
                bytes_value=breakdown.kernel_paged,
                category="kernel",
                description=(
                    "Auslagerbarer Kernel-Speicher für Registry-Strukturen, Handles und Dateisystem-Metadaten.\n"
                    "Wird von Windows bei Bedarf selbst verwaltet."
                ),
            )
        )
    if breakdown.system_cache > 0:
        kernel_slices.append(
            SystemSlice(
                key="sys:cache",
                title="System-Dateicache & Modified",
                bytes_value=breakdown.system_cache,
                category="kernel",
                description=(
                    "Aktiver Windows-Dateicache und noch nicht auf Datenträger geschriebene Seiten.\n"
                    "Windows gibt diesen Speicher bei Bedarf automatisch wieder frei."
                ),
            )
        )
    if breakdown.driver_images > 0:
        drivers_text = ", ".join(
            f"{name} ({_format_size_short(size)})" for name, size in breakdown.top_drivers
        )
        desc = "Im RAM geladene Programmcode-Images von Windows-Kernel und Treibern."
        if drivers_text:
            desc += f"\nGrößte Module: {drivers_text}"
        kernel_slices.append(
            SystemSlice(
                key="sys:drivers",
                title="Geladene Kernel-Treiber (.sys)",
                bytes_value=breakdown.driver_images,
                category="kernel",
                description=desc,
            )
        )

    kernel_sum = sum(item.bytes_value for item in kernel_slices)
    if kernel_sum > unattributed_ram:
        kernel_slices = _scale_slices_to_budget(kernel_slices, unattributed_ram)
        kernel_sum = sum(item.bytes_value for item in kernel_slices)

    remaining_shared = max(0, unattributed_ram - kernel_sum)
    slices: list[SystemSlice] = list(kernel_slices)

    if remaining_shared > 0:
        shared_groups = [group for group in groups if group.shared_ws > 0]
        total_gross_shared = sum(group.shared_ws for group in shared_groups)
        if shared_groups and total_gross_shared > 0:
            raw_shared_slices: list[SystemSlice] = []
            for group in shared_groups:
                est_bytes = round(remaining_shared * (group.shared_ws / total_gross_shared))
                if est_bytes <= 0:
                    continue
                raw_shared_slices.append(
                    SystemSlice(
                        key=f"shared:{group.name}",
                        title=f"Geteilt: {group.name}",
                        bytes_value=est_bytes,
                        category="shared",
                        target_group=group.name,
                        raw_shared_ws=group.shared_ws,
                        description=(
                            f"Geschätzter Anteil von {group.name} am gemeinsam genutzten RAM "
                            "(DLLs, Chromium/Electron-IPC, Memory-Mapped Files).\n"
                            f"Brutto-Shared-WS dieser Gruppe: {_format_size_short(group.shared_ws)} "
                            "(zwischen mehreren Prozessen geteilt).\n"
                            "Linksklick: Zu dieser Anwendung springen."
                        ),
                    )
                )
            if raw_shared_slices:
                slices.extend(_scale_slices_to_budget(raw_shared_slices, remaining_shared))
            else:
                slices.append(
                    SystemSlice(
                        key="sys:shared_other",
                        title="Geteilter Systemspeicher & DLLs",
                        bytes_value=remaining_shared,
                        category="kernel",
                        description=(
                            "Gemeinsam genutzte Programmbibliotheken (DLLs) und Memory-Mapped Files,\n"
                            "die von Windows keinem einzelnen Prozess exklusiv zugerechnet werden."
                        ),
                    )
                )
        else:
            slices.append(
                SystemSlice(
                    key="sys:shared_other",
                    title="Geteilter Systemspeicher & DLLs",
                    bytes_value=remaining_shared,
                    category="kernel",
                    description=(
                        "Gemeinsam genutzte Programmbibliotheken (DLLs) und System-Ressourcen\n"
                        "außerhalb privater Prozess-Working-Sets."
                    ),
                )
            )

    slices = [item for item in slices if item.bytes_value > 0]
    slices.sort(key=lambda item: item.bytes_value, reverse=True)
    return slices


def build_snapshot(
    sample: dict[int, ProcSample],
    total_ram: int,
    used_ram: int,
    timestamp: float | None = None,
    breakdown: SystemBreakdown | None = None,
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
    sys_breakdown = breakdown or SystemBreakdown(0, 0, 0, 0, [])
    sys_slices = build_system_slices(unattributed_ram, groups, sys_breakdown)
    return Snapshot(
        timestamp=time.time() if timestamp is None else timestamp,
        total_ram=total_ram,
        used_ram=used_ram,
        app_ram=app_ram,
        unattributed_ram=unattributed_ram,
        groups=groups,
        system_breakdown=sys_breakdown,
        system_slices=sys_slices,
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


_CHROMIUM_SUBTYPES = {
    "network.mojom.networkservice": "Netzwerkdienst",
    "storage.mojom.storageservice": "Speicherdienst",
    "audio.mojom.audioservice": "Audio-Dienst",
    "node.mojom.nodeservice": "Node-Service",
    "data_decoder.mojom.datadecoderservice": "Daten-Decoder",
    "unzip.mojom.unzipper": "Entpacker",
}

_CHROMIUM_TYPES = {
    "gpu-process": "GPU-Prozess",
    "renderer": "Renderer",
    "extensionhost": "Extension-Host",
    "ptyhost": "Terminal-Host (PTY)",
    "filewatcher": "File-Watcher",
    "crashpad-handler": "Crashpad-Handler",
}

_FIREFOX_ROLES = {
    "gpu": "GPU-Prozess",
    "rdd": "Media-Decoder (RDD)",
    "socket": "Netzwerk-Socket",
    "extension": "Erweiterungen",
    "utility": "Utility-Prozess",
}

_SCRIPT_SUFFIXES = (".py", ".js", ".mjs", ".cjs", ".ts", ".ps1")


def parse_process_role(
    proc_name: str,
    group_name: str,
    cmdline: Sequence[str],
    services: Sequence[str] = (),
) -> str:
    """Derive a concise German role or service label from process services and command line."""
    if services:
        shown = ", ".join(services[:2])
        if len(services) > 2:
            return f"{shown} (+{len(services) - 2})"
        return shown

    proc_type = ""
    utility_sub = ""
    script_label = ""
    is_firefox_content = False

    for arg in cmdline[1:]:
        lower = arg.lower()
        if lower == "-contentproc":
            is_firefox_content = True
        elif lower.startswith("--utility-sub-type="):
            utility_sub = arg.split("=", 1)[1]
        elif lower.startswith("--type="):
            proc_type = arg.split("=", 1)[1]
        elif not arg.startswith(("-", "/")) and lower.endswith(_SCRIPT_SUFFIXES):
            filename = Path(arg.replace("\\", "/")).name
            stem = filename.lower()
            if "extensionhost" in stem:
                script_label = "Extension-Host"
            elif "ptyhost" in stem:
                script_label = "Terminal-Host (PTY)"
            elif "watcherservice" in stem or "filewatcher" in stem:
                script_label = "File-Watcher"
            elif "sharedprocess" in stem:
                script_label = "Shared-Process"
            elif not script_label:
                script_label = filename

    if utility_sub:
        mapped = _CHROMIUM_SUBTYPES.get(utility_sub.lower())
        if mapped:
            return mapped
        return f"Utility ({utility_sub.rsplit('.', 1)[-1]})"

    if proc_type:
        mapped = _CHROMIUM_TYPES.get(proc_type.lower())
        if mapped:
            return mapped
        if proc_type.lower() == "utility":
            return "Utility-Prozess"
        return proc_type

    if is_firefox_content and cmdline:
        kind = cmdline[-1].lower()
        if kind == "tab":
            tab_id = cmdline[-2] if len(cmdline) >= 2 and cmdline[-2].isdigit() else ""
            return f"Tab #{tab_id}" if tab_id else "Browser-Tab"
        return _FIREFOX_ROLES.get(kind, f"Content ({cmdline[-1]})" if cmdline[-1] else "Content")

    if script_label:
        return script_label

    if proc_name.lower() != group_name.lower():
        return proc_name

    if len(cmdline) == 1:
        return "Hauptprozess"
    return ""


class ProcessDetailResolver:
    """Lazily resolves and caches process roles, command lines, and Windows service names."""

    def __init__(self) -> None:
        self._cache: dict[tuple[int, int], tuple[str, str, tuple[str, ...]]] = {}
        self._services_by_pid: dict[int, tuple[str, ...]] = {}
        self._services_loaded_at = 0.0

    def _refresh_services_if_needed(self) -> None:
        if sys.platform != "win32":
            return
        now = time.monotonic()
        if now - self._services_loaded_at < 10.0:
            return
        mapping: dict[int, list[str]] = defaultdict(list)
        try:
            for svc in psutil.win_service_iter():
                try:
                    pid = svc.pid()
                    if pid:
                        mapping[int(pid)].append(svc.display_name() or svc.name())
                except (psutil.Error, OSError):
                    continue
        except (psutil.Error, OSError):
            pass
        self._services_by_pid = {pid: tuple(names) for pid, names in mapping.items()}
        self._services_loaded_at = now

    def resolve(self, proc: ProcSample, group_name: str) -> tuple[str, str, tuple[str, ...]]:
        """Return (role_label, short_cmdline, service_names) for a process, cached by (pid, created)."""
        key = (proc.pid, proc.created)
        cached = self._cache.get(key)
        if cached is not None:
            return cached

        services: tuple[str, ...] = ()
        if proc.name.lower() == "svchost.exe":
            self._refresh_services_if_needed()
            services = self._services_by_pid.get(proc.pid, ())

        cmdline: list[str] = []
        try:
            cmdline = psutil.Process(proc.pid).cmdline()
        except (psutil.Error, OSError):
            cmdline = []

        role = parse_process_role(proc.name, group_name, cmdline, services)
        short_cmd = " ".join(cmdline)
        if len(short_cmd) > 220:
            short_cmd = short_cmd[:217] + "…"

        if len(self._cache) > 2000:
            self._cache.clear()
        result = (role, short_cmd, services)
        self._cache[key] = result
        return result


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
                breakdown = query_system_breakdown()
                snapshot = build_snapshot(sample, total_ram, used_ram, breakdown=breakdown)
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
