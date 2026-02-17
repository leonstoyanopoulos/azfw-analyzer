# azfw-analyzer

Eine kleine CLI-Applikation zur Analyse von **Azure Firewall Rules** (JSON-Export).

## Features

- Extrahiert Rules aus `collectionGroups` / `ruleCollectionGroups`
- Erkennt doppelte Rule-Namen
- Erkennt inhaltlich doppelte Rule-Definitionen
- Meldet potenziell "shadowed" Rules (frühere, allgemeinere Rule kann spätere überdecken)

## Voraussetzungen

- Python 3.10+

## Verwendung

```bash
python azfw_analyzer.py <input.json>
```

Optional mit Ausgabedatei:

```bash
python azfw_analyzer.py <input.json> --output report.txt
```

## Beispielausgabe

```text
Azure Firewall Rule Analysis
============================
Total rules: 128
Duplicate names: 3
Duplicate signatures: 8
Potentially shadowed rules: 5
```

## Hinweise

- Die Shadowing-Analyse ist heuristisch und sollte als Hinweis verstanden werden.
- Für Production-Use können weitere Prüfungen ergänzt werden (z. B. DNAT/NAT-spezifische Semantik, Action-Order, Threat-Intel-Mode).
