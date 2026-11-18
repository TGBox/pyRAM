# pyRAM

## Problemstellung

Wie könnten wir auf einen Blick zeigen, wohin der RAM gerade geht und wie er sich entwickelt, sodass ich gezielt eingreifen kann, statt im Task-Manager Zeilen zu sortieren?

## Empfohlene Richtung

pyRAM ist eine Live-Landkarte des Arbeitsspeichers: eine Treemap, in der jede Anwendung eine Fläche proportional zu ihrem Verbrauch bekommt. Zusammengehörige Prozesse werden zu einem Block zusammengefasst, ein Klick zoomt auf die Einzelprozesse, ein Rechtsklick beendet.

Die Flächen basieren auf Private Bytes, weil sich nur diese Größe sauber addieren lässt. Ein schmaler Balken über der Karte zeigt die systemweite Aufteilung, damit „90 % belegt" nicht mit „90 % gebraucht" verwechselt wird.

In der zweiten Stufe kommt ein Recorder dazu, der Snapshots in SQLite schreibt und eine Zeitleiste zum Zurückspulen bietet. Der Sampler läuft deshalb von Anfang an in einem Worker-Thread und liefert Snapshots als eigene Datenstruktur.

## Zu prüfende Annahmen

- [ ] Exe-Name plus Elternprozess reicht, um Prozesse zu Anwendungen zu gruppieren. Test: 30-Zeilen-Skript mit `psutil` auf dem eigenen Rechner, Ergebnis mit dem Task-Manager vergleichen.
- [ ] Ohne Adminrechte bleibt genug sichtbar. Test: im selben Skript zählen, wie viel RAM auf Prozesse mit „Zugriff verweigert" entfällt.
- [ ] Ein Abtastintervall von 2 Sekunden kostet unter 1 % CPU. Test: Sampler eine Stunde laufen lassen und messen.
- [ ] Die Landkarte zeigt mehr als „Browser und IDE". Test: eine Woche benutzen, danach entscheiden, ob Stufe 2 vorgezogen wird.

## MVP-Umfang

**Drin:**

- Sampler im Worker-Thread
- Gruppierung zu Anwendungen
- Treemap mit Zoom und Tooltip
- Systembalken (belegt / verfügbar)
- „Prozess beenden" mit Rückfrage
- grauer Block für nicht einsehbare Systemprozesse
- Build als .exe

**Draußen:** alles aus Stufe 2 (Recorder, Zeitleiste, Leak-Erkennung, Tray-Betrieb).

## Nicht tun (und warum)

- **Speicher freigeben (Working Sets, Standby-Cache leeren):** unter Windows überwiegend Kosmetik, die Zahl sinkt, der Rechner wird nicht schneller.
- **Warnungen und Limits:** brauchen den Verlauf als Grundlage. Sinnvoll erst nach Stufe 2.
- **Prozessliste als Tabelle:** die hat der Task-Manager schon.
- **Detailansicht für Standby und geänderte Seiten:** RAMMap kann das besser.
- **macOS und Linux:** ein Nutzer, ein Windows-Rechner.

## Offene Fragen

- Soll die Treemap selbst gezeichnet werden (etwa 50 Zeilen Squarify-Algorithmus mit `QPainter`) oder über eine Bibliothek kommen?
- Wie werden `svchost`-Dienste dargestellt: als ein Block „Windows-Dienste" oder nach Dienstname aufgelöst?
- Soll „beenden" bei Anwendungsblöcken alle zugehörigen Prozesse treffen oder nur nach dem Zoom einzelne?

## Rahmen

- Zielgruppe: nur für mich, Windows, Weitergabe als .exe
- Läuft ohne Adminrechte
- Stack: PySide6, uv, PyInstaller; `psutil` als neue Abhängigkeit

---

## Erweiterung: Block-Drilldown & System-Aufschlüsselung

## Problemstellung (2)

Wie könnten wir beim Klick auf jeden Block – insbesondere auf den großen grauen Block „System / Geteilt / Kernel“, auf `svchost.exe` und auf Multi-Prozess-Anwendungen – sofort verständlich zeigen, wofür der Speicher konkret verbraucht wird und ob man eingreifen kann?

## Empfohlene Richtung (2)

Jeder Block in der Treemap wird zoombar – auch „System / Geteilt / Kernel“.
Ein Klick auf den Systemblock öffnet eine Unter-Treemap, die den unzugeordneten physischen RAM in zwei klar unterscheidbare Kategorien zerlegt:

1. **Echter Kernel- & System-Speicher** (aus `GetPerformanceInfo` und `NtQuerySystemInformation`):
   - *Kernel Nonpaged Pool* (nicht auslagerbarer Kernel-/Treiberspeicher)
   - *Kernel Paged Pool* (auslagerbarer Kernel-Speicher)
   - *System-Dateicache & Geänderte Seiten* (aktiver Datei-Cache & Modified List)
   - *Geladene Kernel-Treiber* (`SystemModuleInformation`, inkl. Top-Treibern im Tooltip)
2. **Geteilter Anwendungsspeicher (Shared Working Set)**:
   - Der verbleibende Differenzbetrag entsteht durch Speicherseiten, die von mehreren Prozessen gemeinsam genutzt werden (DLLs, Chromium/Electron Shared Memory). Er wird anteilig nach dem Shared Working Set (`working_set - private_ws`) der Anwendungen aufgeschlüsselt (z. B. „Geteilt: Antigravity IDE.exe“, „Geteilt: firefox.exe“). Ein Klick darauf führt direkt zum jeweiligen Anwendungs-Zoom.

Beim Zoom in **Anwendungsblöcke** werden Einzelprozesse intelligent beschriftet (lazy beim Zoomen geladen und per `(pid, created)` gecacht):

- **`svchost.exe`**: Löst über den Windows Service Manager (`psutil.win_service_iter`) die enthaltenen Dienste auf (z. B. „Windows Update“, „DNS-Client“, „Windows-Audio“).
- **Multi-Prozess-Apps (Browser, Electron, Python/Node)**: Extrahiert aus den Startargumenten (`cmdline`) die lesbare Rolle (`GPU-Prozess`, `Renderer`, `Extension-Host`, `Netzwerkdienst`, `Audio-Service`, `Hauptprozess` oder den Skriptnamen).
- **Shared-RAM-Sichtbarkeit**: Jede App- und Prozesskachel zeigt im Tooltip (und optional als Zusatzinfo) neben dem Private Working Set auch ihren geteilten Speicher (`Shared WS = Working Set - Private WS`).

## Geprüfte Annahmen

- [x] Kernel-Pools, Dateicache, Modified List und Treiber-Module lassen sich ohne Adminrechte in < 1 ms abfragen (getestet via `psapi` und `ntdll`).
- [x] Windows-Dienste (`win_service_iter`) lassen sich ohne Adminrechte ihren `svchost`-PIDs zuordnen (~34 ms einmalig beim Zoomen).
- [ ] Die proportionale Zuordnung des Shared-RAM-Rests nach `working_set - private_ws` deckt sich für den Nutzer nachvollziehbar mit den laufenden Großanwendungen.

## MVP-Umfang (2)

**Drin:**

- Klick-Zoom in den Block „System / Geteilt / Kernel“ mit Aufschlüsselung in Kernel-Pools, System-Cache/Modified, Kernel-Treiber-Images und anteiligen Shared-RAM pro Anwendung
- Erklärende Tooltips im System-Zoom („Was ist das?“ + „Kann ich etwas tun?“)
- Dienstnamen-Auflösung für `svchost.exe`-Prozesse im Gruppen-Zoom
- Rollen-Erkennung aus Startargumenten (`--type=...`, Skriptpfade) für Anwendungs-Unterprozesse mit `(pid, created)`-Cache
- Ausweis des geteilten Working Sets (`working_set - private_ws`) in Gruppen- und Prozess-Tooltips

**Draußen (Nicht tun – und warum):**

- **Einzelne `.sys`-Treiber als 150 Mini-Kacheln:** Liefert ohne Admin-Pool-Tagging nur Datei-Image-Größen statt echter Treiber-Allokationen; Top-Treiber gehören in den Tooltip der Treiber-Kachel.
- **Prozess-Beenden-Aktion auf Kernel-/System-Kacheln:** Kernel-Pools und Caches sind keine beendbaren Prozesse; ein Klick auf „Geteilt: `<App>`“ wechselt stattdessen in den Zoom dieser App.
- **Abfrage von `cmdline()` und Diensten alle 2 Sekunden für alle 400 Prozesse:** Unnötige CPU-Last; wird nur bei Bedarf (im Zoom) abgefragt und über `(pid, created)` gecacht.
