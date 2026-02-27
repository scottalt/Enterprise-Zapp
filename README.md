# Enterprise-Zapp

**Zap the stale. Secure the rest.**

Enterprise-Zapp is a free, open-source tool that scans your Microsoft Entra ID tenant for enterprise app hygiene issues — expired credentials, stale apps, orphaned registrations, and over-privileged service principals — and produces a detailed HTML + CSV + PDF report.

> **Strictly read-only.** Enterprise-Zapp never modifies your tenant. It collects data, surfaces risks, and tells you what to fix. Your team makes the call.

---

## What It Finds

| Signal | Severity |
|--------|----------|
| Apps with no sign-in activity in 90+ days | High |
| Apps that have never been used | High |
| Apps with no owners defined | High |
| Owners who are disabled/deleted accounts | High |
| Expired client secrets or certificates | Critical |
| Secrets/certs expiring within 30 days | High |
| High-privilege permissions on stale apps | Critical |
| Service principals disabled but not deleted | Medium |
| Apps with no user/group assignments | Medium |
| Long-lived client secrets (>1 year) | Low |

Each app receives a **risk score (0–100)** and a **risk band** (Critical / High / Medium / Low / Clean), with a prioritised recommendation for remediation.

---

## What It Does NOT Do

- Does **not** modify, disable, or delete any app registration or service principal
- Does **not** revoke credentials or permissions
- Does **not** send data to any external service
- Does **not** require persistent infrastructure or a deployed application

---

## Prerequisites

| Requirement | Notes |
|-------------|-------|
| PowerShell 7+ | For `setup.ps1` — one-time app registration |
| Microsoft.Graph PowerShell module | Auto-installed by `setup.ps1` |
| Global Admin or Privileged Role Admin | Required for `setup.ps1` only |
| Python 3.10+ | For the scan tool |
| pip | For Python dependencies |

---

## Quick Start

### Step 1 — Create the temporary app registration (30 seconds)

Open PowerShell as a **Global Admin or Privileged Role Admin** and run:

```powershell
.\setup.ps1
```

This creates a temporary, read-only app registration in your tenant, grants admin consent for the required permissions, and saves the configuration to `enterprise_zapp_config.json`.

### Step 2 — Install Python dependencies

```bash
pip install -r requirements.txt
```

Or after `pip install .`:

```bash
pip install enterprise-zapp
```

### Step 3 — Run the scan

```bash
python -m src.cli
```

Or if installed as a package:

```bash
enterprise-zapp
```

You'll be prompted to authenticate via Microsoft's device code flow:

```
Open your browser and go to:
  https://microsoft.com/devicelogin

Enter the code:
  ABCD-1234
```

After authentication, the tool fetches data, analyzes it, and writes your reports to `./output/`.

### Step 4 — Clean up the app registration (optional)

```powershell
.\setup.ps1 -Cleanup
```

This deletes the temporary app registration from your tenant.

---

## CLI Options

```
Usage: enterprise-zapp [OPTIONS]

Options:
  -t, --tenant TENANT_ID       Entra tenant ID or domain. Reads from config if omitted.
  -c, --client-id CLIENT_ID    Azure app registration client ID. Reads from config if omitted.
  --config PATH                Path to enterprise_zapp_config.json.
  --stale-days DAYS            Days without sign-in before an app is stale. [default: 90]
  -o, --output DIR             Output directory for reports. [default: ./output]
  --from-cache CACHE_FILE      Re-use collected data without re-querying Graph API.
  --skip-pdf                   Skip PDF generation.
  -V, --version                Show version.
  --help                       Show help.
```

### Examples

```bash
# Adjust staleness threshold to 60 days
enterprise-zapp --stale-days 60

# Write reports to a timestamped folder
enterprise-zapp --output ./reports/2026-02-27/

# Re-generate reports from cached data (instant, no auth needed)
enterprise-zapp --from-cache ./output/raw_contoso_2026-02-27.json

# Supply tenant and client ID directly (no config file)
enterprise-zapp --tenant contoso.onmicrosoft.com --client-id <app-id>
```

---

## Output Files

| File | Description |
|------|-------------|
| `enterprise_zapp_<tenant>_<date>.html` | Self-contained HTML report (works offline) |
| `enterprise_zapp_<tenant>_<date>.csv` | Flat CSV for Excel / ticketing systems |
| `enterprise_zapp_<tenant>_<date>.pdf` | PDF for audit / executive delivery |
| `raw_<tenant>_<date>.json` | Raw collected data (for `--from-cache` re-runs) |

The HTML report includes:
- Executive summary with risk distribution
- Sortable, filterable full app inventory
- Sections for stale apps, credential issues, orphaned apps, and over-privileged apps
- Per-app signal breakdown and remediation recommendation

---

## Permissions Used

Enterprise-Zapp requests the following **delegated, read-only** Microsoft Graph permissions:

| Permission | Purpose |
|------------|---------|
| `Application.Read.All` | Read enterprise app and service principal data |
| `Directory.Read.All` | Read users, groups, and org structure |
| `AuditLog.Read.All` | Read sign-in logs for staleness detection |
| `Reports.Read.All` | Read service principal sign-in activity reports |
| `Policy.Read.All` | Read conditional access and policy data |

All permissions are **delegated** (not application-level), scoped to what the authenticated user can see. All calls are read-only GET requests.

---

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

---

## Project Structure

```
enterprise-zapp/
├── setup.ps1                  # PowerShell: create temp app registration
├── src/
│   ├── auth.py                # MSAL device code authentication
│   ├── graph.py               # Graph API client (pagination + retry)
│   ├── collector.py           # Data collection orchestration
│   ├── analyzer.py            # Signal evaluation + risk scoring
│   ├── reporter.py            # HTML / CSV / PDF generation
│   └── cli.py                 # Click CLI entrypoint
├── templates/
│   └── report.html.j2         # Jinja2 HTML report template
├── tests/
│   ├── test_analyzer.py       # Unit tests (no network calls)
│   └── fixtures/              # Sample data for tests
├── requirements.txt
├── pyproject.toml
└── LICENSE                    # MIT
```

---

## Frequently Asked Questions

**Does this tool require a persistent app registration?**
No. `setup.ps1` creates a temporary, named registration (e.g. `Enterprise-Zapp-Scan-2026-02-27`) that can be deleted immediately after the scan with `setup.ps1 -Cleanup`.

**Can this be run against Azure Government or other sovereign clouds?**
The current version targets the commercial Azure cloud (`graph.microsoft.com`). Sovereign cloud support is planned.

**How long does a scan take?**
For a tenant with ~100 apps, expect 1–2 minutes. For 500+ apps, 4–8 minutes. A progress bar is shown throughout.

**Can I re-run the report without re-authenticating?**
Yes. Use `--from-cache ./output/raw_<tenant>_<date>.json` to re-render the report from previously collected data.

**What happens if I don't have `Reports.Read.All`?**
The scan still runs, but sign-in activity data will be unavailable. Staleness signals will be limited to apps that have never had activity recorded. The report notes which data was skipped.

---

## Contributing

Contributions are welcome. Please open an issue before submitting a large pull request.

- Bug reports: [GitHub Issues](https://github.com/scottalt/Enterprise-Zapp/issues)
- Feature requests: Open an issue with the `enhancement` label

---

## License

[MIT License](LICENSE) — free to use, modify, and distribute. Attribution appreciated.

---

## Disclaimer

Enterprise-Zapp is provided as-is for informational purposes. It does not constitute security advice. Always validate findings in your environment and follow your organisation's change management processes before taking remediation actions.
