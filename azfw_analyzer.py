#!/usr/bin/env python3
"""CLI tool to analyze Azure Firewall rules exported as JSON."""

from __future__ import annotations

import argparse
import html
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class RuleRecord:
    collection_group: str
    collection: str
    collection_priority: int
    name: str
    rule_type: str
    section: str
    source_addresses: tuple[str, ...]
    destination_addresses: tuple[str, ...]
    destination_ports: tuple[str, ...]
    protocols: tuple[str, ...]


def _ensure_list(value: Any, fallback: str = "*") -> tuple[str, ...]:
    if value is None:
        return (fallback,)
    if isinstance(value, list):
        return tuple(str(v) for v in value if v is not None) or (fallback,)
    return (str(value),)


def _normalize_protocols(rule: dict[str, Any]) -> tuple[str, ...]:
    if "ipProtocols" in rule:
        return tuple(p.upper() for p in _ensure_list(rule.get("ipProtocols"), "ANY"))
    protocols = rule.get("protocols")
    if isinstance(protocols, list):
        out: list[str] = []
        for proto in protocols:
            if isinstance(proto, dict) and "protocolType" in proto:
                out.append(str(proto["protocolType"]).upper())
            else:
                out.append(str(proto).upper())
        return tuple(out) or ("ANY",)
    return ("ANY",)




def _classify_rule_section(collection_rule_type: str, rule: dict[str, Any]) -> str:
    collection_type_lower = collection_rule_type.lower()
    rule_type_lower = str(rule.get("ruleType", "")).lower()

    if "dnat" in collection_type_lower or "nat" in rule_type_lower:
        return "DNAT"
    if "application" in collection_type_lower or "application" in rule_type_lower:
        return "Application"
    if "network" in collection_type_lower or "network" in rule_type_lower:
        return "Network"

    if rule.get("translatedAddress") is not None or rule.get("translatedPort") is not None:
        return "DNAT"
    if any(
        rule.get(key) is not None
        for key in ("targetFqdns", "destinationFqdns", "targetUrls", "fqdnTags", "webCategories")
    ):
        return "Application"
    return "Network"

def load_rules(input_file: Path) -> list[RuleRecord]:
    data = json.loads(input_file.read_text(encoding="utf-8"))
    if isinstance(data, list):
        groups = data
    elif isinstance(data, dict):
        groups = data.get("collectionGroups") or data.get("ruleCollectionGroups") or []
    else:
        raise ValueError("Unsupported JSON format: expected object or list of collection groups")

    records: list[RuleRecord] = []

    for group in groups:
        group_name = group.get("name", "<unknown-group>")
        collections = group.get("ruleCollections") or []
        for collection in collections:
            collection_name = collection.get("name", "<unknown-collection>")
            priority = int(collection.get("priority", 65000))
            action = (
                (collection.get("action") or {}).get("type")
                if isinstance(collection.get("action"), dict)
                else collection.get("action")
            )
            collection_rule_type = str(collection.get("ruleCollectionType", action or "Unknown"))
            for rule in collection.get("rules", []):
                rule_type = str(rule.get("ruleType") or collection_rule_type)
                records.append(
                    RuleRecord(
                        collection_group=group_name,
                        collection=collection_name,
                        collection_priority=priority,
                        name=str(rule.get("name", "<unnamed-rule>")),
                        rule_type=rule_type,
                        section=_classify_rule_section(collection_rule_type, rule),
                        source_addresses=_ensure_list(rule.get("sourceAddresses") or rule.get("sourceIpGroups")),
                        destination_addresses=_ensure_list(
                            rule.get("destinationAddresses")
                            or rule.get("targetFqdns")
                            or rule.get("destinationFqdns")
                        ),
                        destination_ports=_ensure_list(rule.get("destinationPorts"), "*") ,
                        protocols=_normalize_protocols(rule),
                    )
                )
    return records


def _is_superset(candidate: tuple[str, ...], target: tuple[str, ...]) -> bool:
    cand = set(candidate)
    targ = set(target)
    if "*" in cand or "ANY" in cand:
        return True
    return targ.issubset(cand)


def find_duplicate_names(rules: list[RuleRecord]) -> list[tuple[str, list[RuleRecord]]]:
    by_name: dict[str, list[RuleRecord]] = {}
    for rule in rules:
        by_name.setdefault(rule.name, []).append(rule)
    return [(name, items) for name, items in by_name.items() if len(items) > 1]


def find_duplicate_signatures(rules: list[RuleRecord]) -> list[list[RuleRecord]]:
    signatures: dict[tuple[Any, ...], list[RuleRecord]] = {}
    for rule in rules:
        key = (
            tuple(sorted(rule.source_addresses)),
            tuple(sorted(rule.destination_addresses)),
            tuple(sorted(rule.destination_ports)),
            tuple(sorted(rule.protocols)),
            rule.rule_type,
        )
        signatures.setdefault(key, []).append(rule)
    return [items for items in signatures.values() if len(items) > 1]


def find_shadowed_rules(rules: list[RuleRecord]) -> list[tuple[RuleRecord, RuleRecord]]:
    shadowed: list[tuple[RuleRecord, RuleRecord]] = []
    sorted_rules = sorted(rules, key=lambda r: r.collection_priority)
    for i, earlier in enumerate(sorted_rules):
        for later in sorted_rules[i + 1 :]:
            if _is_superset(earlier.source_addresses, later.source_addresses) and _is_superset(
                earlier.destination_addresses, later.destination_addresses
            ) and _is_superset(earlier.destination_ports, later.destination_ports) and _is_superset(
                earlier.protocols, later.protocols
            ):
                shadowed.append((earlier, later))
    return shadowed


def render_report(rules: list[RuleRecord]) -> str:
    duplicates_by_name = find_duplicate_names(rules)
    duplicate_signatures = find_duplicate_signatures(rules)
    shadowed_rules = find_shadowed_rules(rules)

    lines = [
        "Azure Firewall Rule Analysis",
        "=" * 28,
        f"Total rules: {len(rules)}",
        f"Duplicate names: {len(duplicates_by_name)}",
        f"Duplicate signatures: {len(duplicate_signatures)}",
        f"Potentially shadowed rules: {len(shadowed_rules)}",
        "",
    ]

    if duplicates_by_name:
        lines.append("Duplicate rule names")
        lines.append("-" * 20)
        for name, items in duplicates_by_name:
            lines.append(f"- {name} ({len(items)}x)")
            for item in items:
                lines.append(
                    f"  • {item.collection_group}/{item.collection} (priority {item.collection_priority})"
                )
        lines.append("")

    if duplicate_signatures:
        lines.append("Duplicate rule definitions")
        lines.append("-" * 27)
        for items in duplicate_signatures:
            first = items[0]
            lines.append(
                f"- Signature {first.protocols} {first.source_addresses} -> {first.destination_addresses}:{first.destination_ports}"
            )
            for item in items:
                lines.append(
                    f"  • {item.name} in {item.collection_group}/{item.collection} (priority {item.collection_priority})"
                )
        lines.append("")

    if shadowed_rules:
        lines.append("Potentially shadowed rules")
        lines.append("-" * 25)
        for earlier, later in shadowed_rules:
            lines.append(
                f"- {later.name} ({later.collection_priority}) may be shadowed by {earlier.name} ({earlier.collection_priority})"
            )

    return "\n".join(lines).strip() + "\n"


def _render_rules_html_section(title: str, rules: list[RuleRecord]) -> str:
    section_id = title.lower().replace(" ", "-")
    sorted_rules = sorted(rules, key=lambda rule: (rule.collection_priority, rule.name.lower()))

    rows: list[str] = []
    for rule in sorted_rules:
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(rule.collection_priority))}</td>"
            f"<td>{html.escape(rule.collection_group)}</td>"
            f"<td>{html.escape(rule.collection)}</td>"
            f"<td>{html.escape(rule.name)}</td>"
            f"<td>{html.escape(rule.rule_type)}</td>"
            f"<td>{html.escape(', '.join(rule.source_addresses))}</td>"
            f"<td>{html.escape(', '.join(rule.destination_addresses))}</td>"
            f"<td>{html.escape(', '.join(rule.destination_ports))}</td>"
            f"<td>{html.escape(', '.join(rule.protocols))}</td>"
            "</tr>"
        )

    body_rows = "\n".join(rows) if rows else '<tr><td colspan="9">No rules found</td></tr>'
    return (
        f"<h2>{html.escape(title)}</h2>\n"
        f"<label for=\"filter-{section_id}\">Filter {html.escape(title)} rules (fuzzy):</label>\n"
        f"<input id=\"filter-{section_id}\" data-fuzzy-filter=\"{html.escape(section_id)}\" type=\"search\" placeholder=\"Type to fuzzy filter...\">\n"
        f"<table border=\"1\" data-fuzzy-table=\"{html.escape(section_id)}\">\n"
        "<thead><tr><th>Priority</th><th>Collection Group</th><th>Collection</th><th>Rule Name</th><th>Type</th><th>Source Addresses</th><th>Destination Addresses</th><th>Destination Ports</th><th>Protocols</th></tr></thead>\n"
        f"<tbody>\n{body_rows}\n</tbody>\n"
        "</table>\n"
    )


def render_rules_html(rules: list[RuleRecord]) -> str:
    dnat_rules = [rule for rule in rules if rule.section == "DNAT"]
    network_rules = [rule for rule in rules if rule.section == "Network"]
    application_rules = [rule for rule in rules if rule.section == "Application"]

    return (
        "<html>\n"
        "<body>\n"
        "<h1>Azure Firewall Rules (sorted by priority)</h1>\n"
        f"{_render_rules_html_section('DNAT', dnat_rules)}"
        f"{_render_rules_html_section('Network', network_rules)}"
        f"{_render_rules_html_section('Application', application_rules)}"
        "<script>\n"
        "const fuzzyMatch = (query, text) => {\n"
        "  if (!query) return true;\n"
        "  let queryIndex = 0;\n"
        "  for (const char of text) {\n"
        "    if (char === query[queryIndex]) queryIndex += 1;\n"
        "    if (queryIndex === query.length) return true;\n"
        "  }\n"
        "  return false;\n"
        "};\n"
        "\n"
        "document.querySelectorAll('[data-fuzzy-filter]').forEach((input) => {\n"
        "  const section = input.dataset.fuzzyFilter;\n"
        "  const table = document.querySelector(`[data-fuzzy-table='${section}']`);\n"
        "  if (!table) return;\n"
        "  const rows = Array.from(table.querySelectorAll('tbody tr'));\n"
        "\n"
        "  const applyFilter = () => {\n"
        "    const query = input.value.trim().toLowerCase();\n"
        "    rows.forEach((row) => {\n"
        "      const text = row.textContent.toLowerCase();\n"
        "      row.style.display = fuzzyMatch(query, text) ? '' : 'none';\n"
        "    });\n"
        "  };\n"
        "\n"
        "  input.addEventListener('input', applyFilter);\n"
        "});\n"
        "</script>\n"
        "</body>\n"
        "</html>\n"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Analyze Azure Firewall rule exports")
    parser.add_argument("input", type=Path, help="Path to Azure Firewall JSON export")
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Optional output file for the generated report",
    )
    parser.add_argument(
        "--html-output",
        type=Path,
        help="Optional HTML output file with rules sorted by priority",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    rules = load_rules(args.input)
    report = render_report(rules)
    html_report = render_rules_html(rules)

    if args.output:
        args.output.write_text(report, encoding="utf-8")
    else:
        print(report, end="")

    if args.html_output:
        args.html_output.write_text(html_report, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
