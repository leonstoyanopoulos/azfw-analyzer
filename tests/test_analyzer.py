from azfw_analyzer import load_rules, render_report


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
