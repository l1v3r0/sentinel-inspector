# Sentinel Workspace Inspector

**Author:** [l1v3r](https://github.com/l1v3r0)  
**Code reviewed & validated by:** Claude (Anthropic)

A CLI tool to inspect Microsoft Sentinel workspaces and validate analytics rules against the target environment — no app registration or secrets required.

---

## Features

| # | Check | Description |
|---|-------|-------------|
| 1 | Table existence | Verifies all referenced tables exist in the workspace |
| 2 | Function existence | Checks custom/ASIM functions are deployed, validates their bodies |
| 3 | Field existence | Confirms field references exist in the actual table schemas |
| 4 | Dry-run | Executes the rule KQL with `\| limit 1` against live data |
| 5 | Data presence | Detects tables/parsers with 0 rows in last 30 days |
| 6 | Schedule gap | Flags rules where `queryFrequency > queryPeriod` |
| 7 | Rule state | Reports disabled rules |
| 8 | External refs | Detects missing watchlists, config tables, lookup tables |

**Verdicts:** `WILL WORK` · `WILL FAIL` · `NO DATA` · `SCHEDULE GAP` · `DISABLED` · `UNCERTAIN`

---

## Requirements

- Python 3.8+
- Azure CLI (`azure-cli`)
- `pip3 install requests`

---

## Usage

```bash
python3 sentinel_inspector.py
```

On first run:
1. Checks / installs Azure CLI
2. Opens browser for `az login`
3. Lists subscriptions — pick one
4. Lists workspaces — pick one
5. Interactive menu

---

## Menu

```
1  List all tables
2  Inspect table fields
3  List saved functions
4  Validate rule KQL (paste manually)
5  Search and validate rule by ID or name
6  Auto-validate rules modified last 30 days
7  Validate ALL deployed rules
8  List all rules and validate one
```

---

## Auth

Uses Azure CLI device code / browser flow — no app registration, no client secrets, no hardcoded credentials. Tokens are cached in memory for the session duration.

Your account needs **Log Analytics Reader** RBAC on the workspace.

---

## Platform support

| Platform | Notes |
|----------|-------|
| macOS | Full — auto-installs Azure CLI via Homebrew if missing |
| Windows | Full — prompts to install Azure CLI via MSI if missing |
| Linux | Full — provides install command if Azure CLI missing |

---

## KQL parsing

The validator understands:
- Inline `let`-defined functions and tabular expressions (not flagged as missing)
- ASIM unified parsers (`imNetworkSession`, `imAuthentication`, etc.)
- Multiline `union isfuzzy=true (datatable(...)[]), (RealTable | ...)` patterns
- `join`, `lookup`, `union` subquery table references
- `toscalar(Table | ...)` and `lookup Table on field` external references
- BvisionSOC-style `BV_CONFIG`, `bv_rba_*`, `bv_desc_*` config tables

---

## Disclaimer

This tool executes read-only queries against live workspaces (`| limit 1`). No data is modified.
