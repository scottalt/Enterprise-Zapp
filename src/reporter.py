"""
Report generation for Enterprise-Zapp.

Produces:
  - Self-contained HTML report (inline CSS/JS, works offline)
  - CSV export (one row per app)
"""

from __future__ import annotations

import csv
import io
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console

from . import __version__
from .analyzer import AppResult, band_counts
from .ca_analyzer import AppCoverage, PolicySummary

console = Console()

TEMPLATES_DIR = Path(__file__).parent.parent / "templates"


# ── Jinja2 filters ─────────────────────────────────────────────────────────────


def _format_date(value: str | None) -> str:
    if not value:
        return "—"
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return value


def _tenant_slug(display_name: str) -> str:
    """Sanitize a tenant display name for use in file paths."""
    return re.sub(r"[^\w\-]", "_", display_name).lower()


def _build_jinja_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        # Include "html.j2" and "j2" so templates named *.html.j2 are also escaped
        autoescape=select_autoescape(["html", "html.j2", "j2"]),
    )
    env.filters["format_date"] = _format_date
    return env


# ── Top recommendations derivation ─────────────────────────────────────────────


def _top_recommendations(results: list[AppResult]) -> list[dict]:
    """Derive 3 high-level recommendations from the result set."""
    counts = band_counts(results)
    recs = []

    crit_high = counts["critical"] + counts["high"]
    if crit_high > 0:
        recs.append({
            "text": f"Prioritise review of {crit_high} Critical/High risk apps",
            "sub": f"{counts['critical']} critical and {counts['high']} high risk apps detected. "
                   "Start with apps that are stale and hold high-privilege permissions.",
        })

    expired_cred_apps = sum(1 for r in results if r.has_expired_secret or r.has_expired_cert)
    if expired_cred_apps > 0:
        recs.append({
            "text": f"Rotate or remove expired credentials on {expired_cred_apps} app(s)",
            "sub": "Expired secrets and certificates should be removed immediately — they may indicate "
                   "abandoned apps or missed rotation cycles.",
        })

    # Exclude Microsoft first-party apps — ownership is managed by Microsoft
    # and cannot be meaningfully assigned by tenant admins.
    orphaned = sum(1 for r in results if r.owner_count == 0 and not r.is_microsoft_first_party)
    if orphaned > 0:
        recs.append({
            "text": f"Assign owners to {orphaned} ownerless app(s)",
            "sub": "Apps without owners lack accountability for rotation, decommission, and incident response.",
        })

    stale = sum(1 for r in results if any(s.key in ("stale", "never_signed_in") for s in r.signals))
    if stale > 0 and len(recs) < 3:
        recs.append({
            "text": f"Decommission or verify {stale} stale or never-used app(s)",
            "sub": "Each unused app represents unnecessary attack surface. Work with app owners to confirm "
                   "necessity and disable/delete those no longer required.",
        })

    if not recs:
        recs.append({
            "text": "Maintain regular hygiene reviews",
            "sub": "Your tenant is in good shape. Schedule periodic scans to catch drift early.",
        })

    return recs[:3]


# ── HTML report ────────────────────────────────────────────────────────────────


def generate_html(
    results: list[AppResult],
    raw_data: dict,
    stale_days: int,
    output_path: Path,
    hide_microsoft: bool = False,
    filter_band: str = "all",
    total_scanned: int | None = None,
    ca_app_coverages: list[AppCoverage] | None = None,
    ca_policy_summaries: list[PolicySummary] | None = None,
) -> Path:
    """Render the HTML report and write to output_path."""
    env = _build_jinja_env()
    try:
        template = env.get_template("report.html.j2")
    except Exception as exc:
        console.print(f"[red]Error loading report template: {exc}[/red]")
        raise

    tenant = raw_data.get("tenant", {})

    # Count Microsoft first-party apps before any filtering
    microsoft_app_count = sum(1 for r in results if r.is_microsoft_first_party)

    # Optionally filter out Microsoft first-party apps for all downstream lists
    if hide_microsoft:
        results = [r for r in results if not r.is_microsoft_first_party]

    bands = band_counts(results)

    critical_high = [r for r in results if r.risk_band in ("critical", "high")]
    stale_apps = sorted(
        [r for r in results if any(s.key in ("stale", "never_signed_in") for s in r.signals)],
        key=lambda r: (r.days_since_sign_in or 999999),
        reverse=True,
    )
    credential_apps = [r for r in results if r.has_expired_secret or r.has_expired_cert or r.has_near_expiry_secret or r.has_near_expiry_cert]
    orphaned_apps = [r for r in results if r.owner_count == 0 or any(s.key == "disabled_owner" for s in r.signals)]
    high_privilege_apps = [r for r in results if r.has_high_privilege and any(s.key in ("stale", "never_signed_in") for s in r.signals)]
    tool_artifact_apps = [r for r in results if r.is_tool_artifact]

    collected_at_raw = raw_data.get("collected_at", "")
    try:
        collected_at_dt = datetime.fromisoformat(collected_at_raw.replace("Z", "+00:00"))
        # Convert to local time so the report reflects when the scan ran locally
        collected_at = collected_at_dt.astimezone().strftime("%Y-%m-%d %H:%M %Z")
    except (ValueError, TypeError):
        collected_at = collected_at_raw

    # ── Conditional Access coverage ─────────────────────────────────────────
    # ca_in_cache distinguishes new cache files (which have this key) from old
    # cache files that predate CA support entirely.
    ca_in_cache = "ca_permission_granted" in raw_data
    # ca_permission_granted: True = permission granted, False = explicitly denied,
    # None = old cache format that did not record this field.
    ca_permission_granted = raw_data.get("ca_permission_granted", None)
    ca_app_coverages = ca_app_coverages or []
    ca_policy_summaries = ca_policy_summaries or []
    # ca_available only when permission was explicitly granted (True); treat
    # False (denied) and None (old cache) the same for coverage calculation.
    ca_available = ca_permission_granted is True
    if ca_available:
        covered_count = sum(1 for c in ca_app_coverages if c.is_covered)
        ca_coverage_pct = round(covered_count / len(ca_app_coverages) * 100) if ca_app_coverages else 0
    else:
        covered_count = 0
        ca_coverage_pct = 0

    html_content = template.render(
        tenant_name=tenant.get("displayName", "Unknown Tenant"),
        tenant_id=tenant.get("id", ""),
        collected_at=collected_at,
        version=__version__,
        total_apps=len(results),
        total_scanned=total_scanned if total_scanned is not None else len(results),
        filter_band=filter_band,
        band_counts=bands,
        top_recommendations=_top_recommendations(results),
        critical_high_apps=critical_high,
        stale_apps=stale_apps,
        credential_apps=credential_apps,
        orphaned_apps=orphaned_apps,
        high_privilege_apps=high_privilege_apps,
        all_apps=results,
        skipped=raw_data.get("skipped", []),
        stale_days=stale_days,
        hide_microsoft=hide_microsoft,
        microsoft_app_count=microsoft_app_count,
        tool_artifact_apps=tool_artifact_apps,
        ca_available=ca_available,
        ca_permission_granted=ca_permission_granted,
        ca_in_cache=ca_in_cache,
        ca_app_coverages=ca_app_coverages,
        ca_policy_summaries=ca_policy_summaries,
        ca_covered_count=covered_count,
        ca_coverage_pct=ca_coverage_pct,
    )

    output_path.write_text(html_content, encoding="utf-8")
    return output_path


# ── CSV export ─────────────────────────────────────────────────────────────────


def _csv_safe(value: str) -> str:
    """Prefix formula-triggering characters so spreadsheets treat them as literals."""
    if value and value[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def generate_csv(results: list[AppResult], output_path: Path) -> Path:
    """Write a flat CSV with one row per app."""
    fieldnames = [
        "app_name",
        "app_id",
        "object_id",
        "account_enabled",
        "sp_type",
        "created_at",
        "last_sign_in",
        "days_since_sign_in",
        "risk_score",
        "risk_band",
        "owner_count",
        "assignment_count",
        "has_expired_secret",
        "earliest_secret_expiry",
        "has_expired_cert",
        "earliest_cert_expiry",
        "has_near_expiry_secret",
        "has_near_expiry_cert",
        "has_high_privilege",
        "is_microsoft_first_party",
        "is_tool_artifact",
        "signal_keys",
        "signal_count",
        "primary_recommendation",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            # Derive earliest expiry dates from credential lists
            secret_expiries = [
                c["endDateTime"] for c in r.password_credentials if c.get("endDateTime")
            ]
            cert_expiries = [
                c["endDateTime"] for c in r.key_credentials if c.get("endDateTime")
            ]
            earliest_secret = min(secret_expiries) if secret_expiries else ""
            earliest_cert = min(cert_expiries) if cert_expiries else ""

            writer.writerow(
                {
                    "app_name": _csv_safe(r.display_name),
                    "app_id": r.app_id,
                    "object_id": r.sp_id,
                    "account_enabled": "yes" if r.account_enabled else "no",
                    "sp_type": r.sp_type,
                    "created_at": r.created_datetime or "",
                    "last_sign_in": r.last_sign_in or "",
                    "days_since_sign_in": r.days_since_sign_in if r.days_since_sign_in is not None else "",
                    "risk_score": r.risk_score,
                    "risk_band": r.risk_band,
                    "owner_count": r.owner_count,
                    "assignment_count": r.assignment_count,
                    "has_expired_secret": "yes" if r.has_expired_secret else "no",
                    "earliest_secret_expiry": earliest_secret,
                    "has_expired_cert": "yes" if r.has_expired_cert else "no",
                    "earliest_cert_expiry": earliest_cert,
                    "has_near_expiry_secret": "yes" if r.has_near_expiry_secret else "no",
                    "has_near_expiry_cert": "yes" if r.has_near_expiry_cert else "no",
                    "has_high_privilege": "yes" if r.has_high_privilege else "no",
                    "is_microsoft_first_party": "yes" if r.is_microsoft_first_party else "no",
                    "is_tool_artifact": "yes" if r.is_tool_artifact else "no",
                    "signal_keys": "|".join(s.key for s in r.signals),
                    "signal_count": len(r.signals),
                    "primary_recommendation": _csv_safe(r.primary_recommendation),
                }
            )

    return output_path


# ── Orchestrator ───────────────────────────────────────────────────────────────


def generate_all(
    results: list[AppResult],
    raw_data: dict,
    stale_days: int,
    output_dir: Path,
    hide_microsoft: bool = False,
    skip_html: bool = False,
    skip_csv: bool = False,
    filter_band: str = "all",
    total_scanned: int | None = None,
    ca_app_coverages: list[AppCoverage] | None = None,
    ca_policy_summaries: list[PolicySummary] | None = None,
) -> dict[str, Path | None]:
    """Generate HTML and CSV reports. Returns dict of format → output path."""
    output_dir.mkdir(parents=True, exist_ok=True)

    tenant = raw_data.get("tenant", {})
    tenant_slug = _tenant_slug(tenant.get("displayName", "tenant"))
    date_slug = datetime.now().strftime("%Y-%m-%d")  # local date for filename
    base = output_dir / f"enterprise_zapp_{tenant_slug}_{date_slug}"

    html_path = Path(str(base) + ".html")
    csv_path = Path(str(base) + ".csv")

    if skip_html:
        html_out = None
    else:
        console.print("[cyan]Generating HTML report...[/cyan]")
        html_out = generate_html(
            results, raw_data, stale_days, html_path,
            hide_microsoft=hide_microsoft,
            filter_band=filter_band,
            total_scanned=total_scanned,
            ca_app_coverages=ca_app_coverages,
            ca_policy_summaries=ca_policy_summaries,
        )
        console.print(f"[green]HTML:[/green] {html_out}")

    if skip_csv:
        csv_out = None
    else:
        console.print("[cyan]Generating CSV export...[/cyan]")
        csv_out = generate_csv(results, csv_path)
        console.print(f"[green]CSV: [/green] {csv_out}")

    return {"html": html_out, "csv": csv_out}
