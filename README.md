# azfw-analyzer

Eine kleine CLI-Applikation zur Analyse von **Azure Firewall Rules** (JSON-Export).

## Features

- Extrahiert Rules aus `collectionGroups` / `ruleCollectionGroups`
- Erkennt doppelte Rule-Namen
- Erkennt inhaltlich doppelte Rule-Definitionen
- Meldet potenziell "shadowed" Rules (frühere, allgemeinere Rule kann spätere überdecken)

## Voraussetzungen

- Python 3.10+

## Woher bekomme ich die JSON-Datei?

Du kannst die Datei direkt aus Azure ziehen, z. B. über Azure CLI:

```bash
az network firewall policy rule-collection-group list \
  --resource-group <RESOURCE_GROUP> \
  --policy-name <FIREWALL_POLICY_NAME> \
  --output json > rules.json
```

Wenn du nur **eine** Rule Collection Group exportieren willst:

```bash
az network firewall policy rule-collection-group show \
  --resource-group <RESOURCE_GROUP> \
  --policy-name <FIREWALL_POLICY_NAME> \
  --name <RULE_COLLECTION_GROUP_NAME> \
  --output json > rules.json
```

Alternativ per PowerShell:

```powershell
Get-AzFirewallPolicyRuleCollectionGroup \
  -ResourceGroupName <RESOURCE_GROUP> \
  -AzureFirewallPolicyName <FIREWALL_POLICY_NAME> |
  ConvertTo-Json -Depth 100 |
  Out-File -Encoding utf8 rules.json
```

## Wie finde ich Resource Group und Policy Name?

### Azure CLI

Alle Resource Groups anzeigen:

```bash
az group list --query "[].name" -o tsv
```

Alle Firewall Policies in einer Resource Group anzeigen:

```bash
az network firewall policy list \
  --resource-group <RESOURCE_GROUP> \
  --query "[].name" -o tsv
```

(Optional) Policies über alle RGs mit RG-Namen anzeigen:

```bash
az network firewall policy list \
  --query "[].{policy:name,resourceGroup:resourceGroup}" -o table
```

### PowerShell

Alle Resource Groups:

```powershell
Get-AzResourceGroup | Select-Object -ExpandProperty ResourceGroupName
```

Alle Firewall Policies in einer Resource Group:

```powershell
Get-AzFirewallPolicy -ResourceGroupName <RESOURCE_GROUP> |
  Select-Object -ExpandProperty Name
```

Policies inklusive RG:

```powershell
Get-AzFirewallPolicy |
  Select-Object Name, ResourceGroupName
```

> Hinweis: Falls dein Export nicht direkt `collectionGroups` enthält, kannst du das JSON ggf. in ein Wrapper-Objekt mit `collectionGroups` oder `ruleCollectionGroups` packen.

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
