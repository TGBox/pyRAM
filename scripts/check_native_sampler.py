"""Throwaway check #2 for pyRAM: sample all processes with one native Windows call.

Measures whether NtQuerySystemInformation is fast enough for a background sampler and
whether the private working set adds up to something close to the physical RAM in use.

Run with:  uv run python scripts/check_native_sampler.py
"""

from __future__ import annotations

import ctypes
import sys
import time
from collections import defaultdict
from dataclasses import dataclass

TOP_N = 15
SAMPLE_PASSES = 10
SAMPLE_INTERVAL_S = 2.0

SYSTEM_PROCESS_INFORMATION_CLASS = 5
STATUS_INFO_LENGTH_MISMATCH = 0xC0000004

# Processes that launch unrelated things; the ancestor walk stops below them.
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
}


class UnicodeString(ctypes.Structure):
    _fields_ = [
        ("Length", ctypes.c_uint16),
        ("MaximumLength", ctypes.c_uint16),
        ("Buffer", ctypes.c_void_p),
    ]


class SystemProcessInformation(ctypes.Structure):
    """SYSTEM_PROCESS_INFORMATION (64-bit layout), up to the fields needed here."""

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


@dataclass
class ProcSample:
    pid: int
    ppid: int
    name: str
    created: int
    private_ws: int  # physical RAM owned by this process alone
    working_set: int  # physical RAM incl. shared pages
    private_bytes: int  # committed, incl. paged-out pages


class NativeSampler:
    """Reads every process with a single system call and a reusable buffer."""

    def __init__(self) -> None:
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
        needed = ctypes.c_uint32(0)
        while True:
            status = self._query(
                SYSTEM_PROCESS_INFORMATION_CLASS, self._buffer, self._size, ctypes.byref(needed)
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
                private_ws=entry.WorkingSetPrivateSize,
                working_set=entry.WorkingSetSize,
                private_bytes=entry.PrivatePageCount,
            )
            if entry.NextEntryOffset == 0:
                break
            offset += entry.NextEntryOffset
        return result


def physical_memory() -> tuple[int, int]:
    """Return (total, used) physical memory in bytes."""
    status = MemoryStatusEx()
    status.dwLength = ctypes.sizeof(MemoryStatusEx)
    if not ctypes.WinDLL("kernel32").GlobalMemoryStatusEx(ctypes.byref(status)):
        raise ctypes.WinError()
    return status.ullTotalPhys, status.ullTotalPhys - status.ullAvailPhys


def app_root(proc: ProcSample, sample: dict[int, ProcSample]) -> str:
    """Walk up the parent chain until a launcher is reached; return that ancestor's name."""
    current = proc
    seen = {proc.pid}
    while True:
        parent = sample.get(current.ppid)
        if parent is None or parent.pid in seen:
            break
        # A parent created after its child means the PID was reused.
        if parent.created > current.created:
            break
        if parent.name.lower() in LAUNCHERS:
            break
        seen.add(parent.pid)
        current = parent
    return current.name


def gib(value: float) -> str:
    return f"{value / 1024**3:6.2f} GB"


def main() -> None:
    if sys.platform != "win32" or ctypes.sizeof(ctypes.c_void_p) != 8:
        sys.exit("Dieses Skript braucht 64-Bit-Python unter Windows.")

    sampler = NativeSampler()
    durations: list[float] = []
    sample: dict[int, ProcSample] = {}
    for _ in range(SAMPLE_PASSES):
        start = time.perf_counter()
        sample = sampler.sample()
        durations.append(time.perf_counter() - start)

    print("=== Kosten des nativen Samplers ===")
    print("  Durchlaeufe (ms): " + "  ".join(f"{d * 1000:.1f}" for d in durations))
    average = sum(durations) / len(durations)
    print(
        f"  Mittel: {average * 1000:.1f} ms"
        f" -> ca. {average / SAMPLE_INTERVAL_S * 100:.2f} % eines Kerns"
        f" bei {SAMPLE_INTERVAL_S:.0f} s Intervall"
    )

    total, used = physical_memory()
    sum_private_ws = sum(p.private_ws for p in sample.values())
    sum_working_set = sum(p.working_set for p in sample.values())
    sum_private_bytes = sum(p.private_bytes for p in sample.values())
    print("\n=== Welche Metrik passt zum physischen RAM? ===")
    print(f"  Prozesse:                      {len(sample)}")
    print(f"  Belegt laut System:            {gib(used)} von {gib(total)}")
    print(f"  Summe privates Working Set:    {gib(sum_private_ws)}")
    print(f"  Summe Working Set (mit Shared):{gib(sum_working_set)}")
    print(f"  Summe Private Bytes (Commit):  {gib(sum_private_bytes)}")

    groups: dict[str, list[int]] = defaultdict(lambda: [0, 0, 0])
    for proc in sample.values():
        entry = groups[app_root(proc, sample)]
        entry[0] += proc.private_ws
        entry[1] += proc.private_bytes
        entry[2] += 1
    ranked = sorted(groups.items(), key=lambda item: item[1][0], reverse=True)

    print("\n=== Top-Gruppen nach privatem Working Set ===")
    print("   Privat-WS   Priv. Bytes  Prozesse  Gruppe")
    for name, (private_ws, private_bytes, count) in ranked[:TOP_N]:
        print(f"  {gib(private_ws)}   {gib(private_bytes)}     {count:3d}    {name}")
    rest = sum(values[0] for _, values in ranked[TOP_N:])
    print(f"  {gib(rest)}                          Rest ({max(len(ranked) - TOP_N, 0)} Gruppen)")


if __name__ == "__main__":
    main()
