# azfw-analyzer

A small CLI application for analyzing **Azure Firewall Rules** from a JSON export.

## Features

- Extracts rules from `collectionGroups` / `ruleCollectionGroups`
- Detects duplicate rule names
- Detects duplicate rule definitions (same signature)
- Reports potentially shadowed rules (an earlier, broader rule may shadow a later one)
- Can export an HTML table with rules sorted by priority (no CSS)

## Requirements

- Python 3.10+

## Where do I get the JSON file?

You can export it directly from Azure, for example with Azure CLI:

```bash
az network firewall policy rule-collection-group list \
  --resource-group <RESOURCE_GROUP> \
  --policy-name <FIREWALL_POLICY_NAME> \
  --output json > rules.json
```

If you only want to export **one** Rule Collection Group:

```bash
az network firewall policy rule-collection-group show \
  --resource-group <RESOURCE_GROUP> \
  --policy-name <FIREWALL_POLICY_NAME> \
  --name <RULE_COLLECTION_GROUP_NAME> \
  --output json > rules.json
```

Alternatively via PowerShell:

```powershell
Get-AzFirewallPolicyRuleCollectionGroup \
  -ResourceGroupName <RESOURCE_GROUP> \
  -AzureFirewallPolicyName <FIREWALL_POLICY_NAME> |
  ConvertTo-Json -Depth 100 |
  Out-File -Encoding utf8 rules.json
```

## How do I find Resource Group and Policy Name?

### Azure CLI

List all Resource Groups:

```bash
az group list --query "[].name" -o tsv
```

List all Firewall Policies in a Resource Group:

```bash
az network firewall policy list \
  --resource-group <RESOURCE_GROUP> \
  --query "[].name" -o tsv
```

(Optional) List policies across all Resource Groups including RG name:

```bash
az network firewall policy list \
  --query "[].{policy:name,resourceGroup:resourceGroup}" -o table
```

### PowerShell

All Resource Groups:

```powershell
Get-AzResourceGroup | Select-Object -ExpandProperty ResourceGroupName
```

All Firewall Policies in one Resource Group:

```powershell
Get-AzFirewallPolicy -ResourceGroupName <RESOURCE_GROUP> |
  Select-Object -ExpandProperty Name
```

Policies including Resource Group:

```powershell
Get-AzFirewallPolicy |
  Select-Object Name, ResourceGroupName
```

> Note: The tool accepts both a wrapper object with `collectionGroups`/`ruleCollectionGroups` **and** a top-level JSON list of Rule Collection Groups.

## Usage

```bash
python azfw_analyzer.py <input.json>
```

Optional text output file:

```bash
python azfw_analyzer.py <input.json> --output report.txt
```

Optional HTML output (rules sorted by priority):

```bash
python azfw_analyzer.py <input.json> --html-output rules.html
```

You can also combine both outputs:

```bash
python azfw_analyzer.py <input.json> --output report.txt --html-output rules.html
```

## Example output

```text
Azure Firewall Rule Analysis
============================
Total rules: 128
Duplicate names: 3
Duplicate signatures: 8
Potentially shadowed rules: 5
```

## Notes

- Shadowing analysis is heuristic and should be treated as guidance.
- For production usage, you can extend checks (e.g., DNAT/NAT-specific semantics, action ordering, threat intel mode).
