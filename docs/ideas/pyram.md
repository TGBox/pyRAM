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
