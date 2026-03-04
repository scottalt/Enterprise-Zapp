# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Enterprise-Zapp, please report it responsibly by emailing the maintainers directly rather than opening a public issue.

We will acknowledge receipt within 48 hours and aim to provide a fix or mitigation within 7 days for critical issues.

## Permissions & Least Privilege

Enterprise-Zapp follows the principle of least privilege. The tool requests **read-only** Microsoft Graph permissions and never modifies tenant data during a scan.

### Required Permissions (4 scopes)

| Permission | Why it's needed |
|---|---|
| `Application.Read.All` | Enumerate service principals, app registrations, and role assignments |
| `Directory.Read.All` | Read organization info, SP owners, oauth2 permission grants, and disabled user accounts |
| `Reports.Read.All` | Fetch service principal sign-in activity (beta endpoint). Gracefully skipped if denied |
| `Policy.Read.All` | Read Conditional Access policies for coverage analysis |

### Cleanup-only Permission

| Permission | Why it's needed |
|---|---|
| `Application.ReadWrite.All` | Only requested by `--cleanup` to delete the Enterprise-Zapp app registration. Never requested during normal scans |

### What is NOT requested

- No write permissions during scans (read-only)
- No `AuditLog.Read.All` (not needed)
- No `User.Read.All` (covered by `Directory.Read.All`)
- No `Mail.*`, `Files.*`, or any other sensitive scopes

## Data Handling

- **Access tokens** are held in memory only and never written to disk.
- **Raw scan data** is saved to `output/raw_<tenant>_<date>.json` for `--from-cache` replay. This file contains tenant metadata and service principal configurations. Treat it as confidential.
- **HTML/CSV reports** contain app names, risk scores, credential expiry dates, and permission details. Treat as confidential.
- **No telemetry** is collected. No data is sent to any external service beyond Microsoft Graph.

## CSV Injection Protection

All CSV exports sanitize cell values that begin with `=`, `+`, `-`, `@`, `\t`, or `\r` to prevent formula injection when opened in spreadsheet applications.

## Dependencies

The tool depends on well-maintained packages (`msal`, `requests`, `jinja2`, `rich`, `click`). Pin versions in `pyproject.toml` and review updates for security advisories.

## Supported Versions

Security fixes are applied to the latest release only. There is no long-term support for older versions.
