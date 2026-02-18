from azfw_analyzer import load_rules, render_report, render_rules_html


def test_render_report_detects_duplicates_and_shadowing(tmp_path):
    fixture = {
        "collectionGroups": [
            {
                "name": "cg-1",
                "ruleCollections": [
                    {
                        "name": "allow-all",
                        "priority": 100,
                        "ruleCollectionType": "NetworkRuleCollection",
                        "rules": [
                            {
                                "name": "rule-a",
                                "sourceAddresses": ["*"],
                                "destinationAddresses": ["10.0.0.1"],
                                "destinationPorts": ["443"],
                                "ipProtocols": ["TCP"],
                            }
                        ],
                    },
                    {
                        "name": "allow-specific",
                        "priority": 200,
                        "ruleCollectionType": "NetworkRuleCollection",
                        "rules": [
                            {
                                "name": "rule-a",
                                "sourceAddresses": ["10.1.0.0/24"],
                                "destinationAddresses": ["10.0.0.1"],
                                "destinationPorts": ["443"],
                                "ipProtocols": ["TCP"],
                            },
                            {
                                "name": "rule-c",
                                "sourceAddresses": ["10.1.0.0/24"],
                                "destinationAddresses": ["10.0.0.1"],
                                "destinationPorts": ["443"],
                                "ipProtocols": ["TCP"],
                            },
                        ],
                    },
                ],
            }
        ]
    }

    input_file = tmp_path / "rules.json"
    input_file.write_text(__import__("json").dumps(fixture), encoding="utf-8")

    rules = load_rules(input_file)
    report = render_report(rules)

    assert "Total rules: 3" in report
    assert "Duplicate names: 1" in report
    assert "Duplicate signatures: 1" in report
    assert "Potentially shadowed rules" in report


def test_load_rules_supports_top_level_list(tmp_path):
    fixture = [
        {
            "name": "cg-1",
            "ruleCollections": [
                {
                    "name": "allow-web",
                    "priority": 100,
                    "ruleCollectionType": "NetworkRuleCollection",
                    "rules": [
                        {
                            "name": "rule-a",
                            "sourceAddresses": ["10.0.0.0/24"],
                            "destinationAddresses": ["20.0.0.10"],
                            "destinationPorts": ["443"],
                            "ipProtocols": ["TCP"],
                        }
                    ],
                }
            ],
        }
    ]

    input_file = tmp_path / "rules-list.json"
    input_file.write_text(__import__("json").dumps(fixture), encoding="utf-8")

    rules = load_rules(input_file)

    assert len(rules) == 1
    assert rules[0].collection_group == "cg-1"
    assert rules[0].name == "rule-a"


def test_render_rules_html_creates_dnat_network_and_application_sections(tmp_path):
    fixture = {
        "collectionGroups": [
            {
                "name": "cg-1",
                "ruleCollections": [
                    {
                        "name": "network-low-priority",
                        "priority": 200,
                        "ruleCollectionType": "NetworkRuleCollection",
                        "rules": [
                            {
                                "name": "network-late",
                                "sourceAddresses": ["10.1.0.0/24"],
                                "destinationAddresses": ["10.0.0.1"],
                                "destinationPorts": ["443"],
                                "ipProtocols": ["TCP"],
                            }
                        ],
                    },
                    {
                        "name": "network-high-priority",
                        "priority": 100,
                        "ruleCollectionType": "NetworkRuleCollection",
                        "rules": [
                            {
                                "name": "network-early",
                                "sourceAddresses": ["*"],
                                "destinationAddresses": ["10.0.0.1"],
                                "destinationPorts": ["443"],
                                "ipProtocols": ["TCP"],
                            }
                        ],
                    },
                    {
                        "name": "dnat-collection",
                        "priority": 110,
                        "ruleCollectionType": "DnatRuleCollection",
                        "rules": [
                            {
                                "name": "dnat-rule",
                                "sourceAddresses": ["*"],
                                "destinationAddresses": ["40.0.0.10"],
                                "destinationPorts": ["443"],
                                "ipProtocols": ["TCP"],
                            }
                        ],
                    },
                    {
                        "name": "application-collection",
                        "priority": 120,
                        "ruleCollectionType": "ApplicationRuleCollection",
                        "rules": [
                            {
                                "name": "app-rule",
                                "sourceAddresses": ["10.2.0.0/24"],
                                "destinationFqdns": ["example.org"],
                                "destinationPorts": ["443"],
                                "protocols": [{"protocolType": "Https"}],
                            }
                        ],
                    },
                ],
            }
        ]
    }

    input_file = tmp_path / "rules.json"
    input_file.write_text(__import__("json").dumps(fixture), encoding="utf-8")

    rules = load_rules(input_file)
    html = render_rules_html(rules)

    assert "<h2>DNAT</h2>" in html
    assert "<h2>Network</h2>" in html
    assert "<h2>Application</h2>" in html
    assert html.index("network-early") < html.index("network-late")


def test_render_rules_html_handles_generic_collection_types(tmp_path):
    fixture = {
        "collectionGroups": [
            {
                "name": "cg-generic",
                "ruleCollections": [
                    {
                        "name": "generic-filter",
                        "priority": 100,
                        "ruleCollectionType": "FirewallPolicyFilterRuleCollection",
                        "action": {"type": "Allow"},
                        "rules": [
                            {
                                "name": "generic-network",
                                "ruleType": "NetworkRule",
                                "sourceAddresses": ["10.0.0.0/24"],
                                "destinationAddresses": ["20.0.0.10"],
                                "destinationPorts": ["443"],
                                "ipProtocols": ["TCP"],
                            },
                            {
                                "name": "generic-application",
                                "ruleType": "ApplicationRule",
                                "sourceAddresses": ["10.0.0.0/24"],
                                "destinationFqdns": ["example.org"],
                                "protocols": [{"protocolType": "Https"}],
                            },
                        ],
                    },
                    {
                        "name": "generic-nat",
                        "priority": 110,
                        "ruleCollectionType": "FirewallPolicyNatRuleCollection",
                        "action": {"type": "Dnat"},
                        "rules": [
                            {
                                "name": "generic-dnat",
                                "ruleType": "NatRule",
                                "sourceAddresses": ["*"],
                                "destinationAddresses": ["40.0.0.10"],
                                "destinationPorts": ["443"],
                                "translatedAddress": "10.0.1.10",
                                "translatedPort": "443",
                                "ipProtocols": ["TCP"],
                            }
                        ],
                    },
                ],
            }
        ]
    }

    input_file = tmp_path / "rules-generic.json"
    input_file.write_text(__import__("json").dumps(fixture), encoding="utf-8")

    rules = load_rules(input_file)
    html = render_rules_html(rules)

    assert "generic-dnat" in html
    assert "generic-network" in html
    assert "generic-application" in html


def test_render_rules_html_includes_fuzzy_filters(tmp_path):
    fixture = {
        "collectionGroups": [
            {
                "name": "cg-1",
                "ruleCollections": [
                    {
                        "name": "network",
                        "priority": 100,
                        "ruleCollectionType": "NetworkRuleCollection",
                        "rules": [
                            {
                                "name": "allow-web",
                                "sourceAddresses": ["10.0.0.0/24"],
                                "destinationAddresses": ["20.0.0.10"],
                                "destinationPorts": ["443"],
                                "ipProtocols": ["TCP"],
                            }
                        ],
                    }
                ],
            }
        ]
    }

    input_file = tmp_path / "rules-filter.json"
    input_file.write_text(__import__("json").dumps(fixture), encoding="utf-8")

    rules = load_rules(input_file)
    html = render_rules_html(rules)

    assert 'data-fuzzy-filter="network"' in html
    assert 'data-fuzzy-table="network"' in html
    assert 'const fuzzyMatch = (query, text) => {' in html
