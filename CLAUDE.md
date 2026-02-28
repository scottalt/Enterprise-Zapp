# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install in editable mode (registers the `enterprise-zapp` CLI command)
pip install -e .

# Run the tool directly without installing
python -m src.cli

# Run all tests
pytest tests/ -v

# Run a single test file or class
pytest tests/test_analyzer.py::TestRiskBand -v
pytest tests/test_analyzer.py::TestExpiredSecret::test_expired_secret_detected -v
```

PDF generation is not built in. Open the HTML report in any browser and use Ctrl+P → Save as PDF.

## Architecture

The tool follows a linear pipeline: **Auth → Collect → Analyze → Report**

```
cli.py          Entrypoint + Click CLI. Orchestrates the pipeline. Exits with code
                1/2/3 based on highest risk band (medium/high/critical).

auth.py         MSAL device code flow. Reads client_id/tenant_id from
                enterprise_zapp_config.json (created by setup.ps1) or CLI flags.
                Token is in-memory only.

graph.py        Read-only Graph API client. Handles pagination ($top=999,
                @odata.nextLink), 429 retry (Retry-After header), and
                exponential backoff on 5xx. Sign-in activity uses the beta
                endpoint. get_conditional_access_policies() returns None (not [])
                when permission is denied, to distinguish from zero policies.

collector.py    Orchestrates all Graph calls and returns a raw_data dict:
                { tenant, apps (enriched SPs), ca_policies,
                  ca_permission_granted, collected_at, skipped }.
                Enriches each SP with _assignments, _owners, _delegatedGrants,
                _appPermissions, _signInActivity, _disabledOwnerIds.
                Saves raw JSON cache to output/raw_<tenant>_<date>.json.

analyzer.py     Pure functions, no I/O. analyze_app(sp) evaluates a single
                enriched SP dict and returns AppResult with risk_score (0–100),
                risk_band, and a list of Signal objects. analyze_all() runs
                all SPs and sorts by descending score. Microsoft first-party apps
                (identified by appOwnerOrganizationId in MICROSOFT_TENANT_IDS)
                skip staleness and ownership signals.

ca_analyzer.py  Conditional Access cross-reference. analyze_ca_coverage() maps
                CA policies to apps, determining which are covered by at least
                one enforced policy. Called inside reporter.py before HTML render.

reporter.py     Jinja2 HTML template rendering and CSV export.
                generate_all() is the main orchestrator. The HTML report is
                fully self-contained (inline CSS/JS). _csv_safe() prefixes
                formula-triggering characters for spreadsheet safety.

templates/
  report.html.j2   Single Jinja2 template that renders the complete HTML report.
                   All CSS and JS are inline.
```

### Data flow for `--from-cache`

When `--from-cache` is passed, `cli.py` loads the raw JSON directly and skips auth + collection entirely. The raw JSON must have an `apps` key.

### Risk scoring

Scores are additive and capped at 100. Risk bands: ≥75=critical, ≥50=high, ≥25=medium, >0=low, 0=clean. Signal score contributions are defined inline in `analyze_app()` — see `analyzer.py` for the full list.

### Adding a new signal

1. Add the signal in `analyze_app()` in `analyzer.py` with a unique `key`, `severity`, `title`, `detail`, and `score_contribution`.
2. Add a recommendation string to `_recommendation_for_signal()` for that key.
3. Update the Jinja2 template (`templates/report.html.j2`) to surface the signal in the report if needed.
4. Add unit tests in `tests/test_analyzer.py` using `BASE_SP` as the baseline fixture.

### Testing approach

`test_analyzer.py` contains all unit tests — no network calls. Tests use `BASE_SP` (a zero-signal SP dict) spread with `{**BASE_SP, ...}` to override specific fields. Fixture SPs are in `tests/fixtures/sample_sps.json`.
