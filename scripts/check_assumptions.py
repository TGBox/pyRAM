"""Throwaway check for the pyRAM assumptions in docs/ideas/pyram.md.

Answers three questions before any GUI code is written:
1. Does grouping by exe name plus parent process produce sensible "applications"?
2. How much stays invisible without admin rights?
3. How expensive is one sampling pass?

Run with:  uv run python scripts/check_assumptions.py
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass

import psutil

TOP_N = 15
SAMPLE_PASSES = 5
SAMPLE_INTERVAL_S = 2.0

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
    # Non-Windows, only so the script also runs elsewhere.
    "systemd",
    "init",
    "launchd",
    "bash",
    "zsh",
    "sh",
}


@dataclass
class ProcSample:
    pid: int
    ppid: int
    name: str
    created: float
    private: int | None  # None = access denied


def take_sample() -> dict[int, ProcSample]:
    """Read all processes once."""
    sample: dict[int, ProcSample] = {}
    attrs = ["pid", "ppid", "name", "create_time", "memory_info"]
    for proc in psutil.process_iter(attrs, ad_value=None):
        info = proc.info
        mem = info["memory_info"]
        # Private bytes are additive; working set (rss) double-counts shared pages.
        private = getattr(mem, "private", None) if mem else None
        if mem and private is None:
            private = mem.rss  # non-Windows fallback
        sample[info["pid"]] = ProcSample(
            pid=info["pid"],
            ppid=info["ppid"] or 0,
            name=info["name"] or "",
            created=info["create_time"] or 0.0,
            private=private,
        )
    return sample


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
    return current.name or f"PID {current.pid}"


def group(sample: dict[int, ProcSample], by_ancestor: bool) -> dict[str, tuple[int, int]]:
    """Return {group name: (private bytes, process count)}."""
    totals: dict[str, list[int]] = defaultdict(lambda: [0, 0])
    for proc in sample.values():
        if proc.private is None:
            continue
        key = app_root(proc, sample) if by_ancestor else (proc.name or f"PID {proc.pid}")
        totals[key][0] += proc.private
        totals[key][1] += 1
    return {name: (values[0], values[1]) for name, values in totals.items()}


def gib(value: float) -> str:
    return f"{value / 1024**3:6.2f} GB"


def print_top(title: str, groups: dict[str, tuple[int, int]]) -> None:
    print(f"\n{title}")
    print("-" * len(title))
    ranked = sorted(groups.items(), key=lambda item: item[1][0], reverse=True)
    for name, (private, count) in ranked[:TOP_N]:
        print(f"  {gib(private)}  {count:3d} Prozesse  {name}")
    rest = sum(private for _, (private, _) in ranked[TOP_N:])
    print(f"  {gib(rest)}  Rest ({max(len(ranked) - TOP_N, 0)} weitere Gruppen)")


def main() -> None:
    durations: list[float] = []
    sample: dict[int, ProcSample] = {}
    for _ in range(SAMPLE_PASSES):
        start = time.perf_counter()
        sample = take_sample()
        durations.append(time.perf_counter() - start)

    by_name = group(sample, by_ancestor=False)
    by_ancestor = group(sample, by_ancestor=True)

    print("=== Annahme 1: Gruppierung ===")
    print_top("Nur nach Exe-Name", by_name)
    print_top("Nach Exe-Name plus Elternprozess", by_ancestor)
    print(f"\n  Gruppen: {len(by_name)} nach Name, {len(by_ancestor)} mit Elternprozess")

    denied = [proc for proc in sample.values() if proc.private is None]
    visible = sum(proc.private for proc in sample.values() if proc.private is not None)
    vm = psutil.virtual_memory()
    print("\n=== Annahme 2: Sichtbarkeit ohne Adminrechte ===")
    print(f"  Prozesse gesamt:           {len(sample)}")
    print(f"  davon ohne Speicherwert:   {len(denied)}")
    if denied:
        names = sorted({proc.name or f"PID {proc.pid}" for proc in denied})
        print(f"  betroffen: {', '.join(names)}")
    print(f"  Summe Private Bytes sichtbar: {gib(visible)}")
    print(f"  Belegt laut System:           {gib(vm.used)} von {gib(vm.total)}")
    print("  (Grober Vergleich: Private Bytes enthalten auch ausgelagerte Seiten,")
    print("   'belegt' enthaelt zusaetzlich Kernel und gemeinsam genutzte Seiten.)")

    average = sum(durations) / len(durations)
    print("\n=== Annahme 3: Kosten des Samplers ===")
    print(f"  Ein Durchlauf: {average * 1000:.0f} ms im Mittel ({SAMPLE_PASSES} Durchlaeufe)")
    print(
        f"  Bei {SAMPLE_INTERVAL_S:.0f} s Intervall: ca. {average / SAMPLE_INTERVAL_S * 100:.1f} %"
        " eines CPU-Kerns"
    )


if __name__ == "__main__":
    main()
