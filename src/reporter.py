"""
Report generation for Enterprise-Zapp.

Produces:
  - Self-contained HTML report (inline CSS/JS, works offline)
  - CSV export (one row per app)
  - PDF export (rendered from the HTML template via weasyprint)
"""

from __future__ import annotations

import csv
import io
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape
from rich.console import Console

from . import __version__
from .analyzer import AppResult, band_counts

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


def _build_jinja_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATES_DIR)),
        autoescape=select_autoescape(["html"]),
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

    orphaned = sum(1 for r in results if r.owner_count == 0)
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
) -> Path:
    """Render the HTML report and write to output_path."""
    env = _build_jinja_env()
    template = env.get_template("report.html.j2")

    tenant = raw_data.get("tenant", {})
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

    collected_at_raw = raw_data.get("collected_at", "")
    try:
        collected_at_dt = datetime.fromisoformat(collected_at_raw.replace("Z", "+00:00"))
        collected_at = collected_at_dt.strftime("%Y-%m-%d %H:%M UTC")
    except (ValueError, TypeError):
        collected_at = collected_at_raw

    html_content = template.render(
        tenant_name=tenant.get("displayName", "Unknown Tenant"),
        tenant_id=tenant.get("id", ""),
        collected_at=collected_at,
        version=__version__,
        total_apps=len(results),
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
    )

    output_path.write_text(html_content, encoding="utf-8")
    return output_path


# ── CSV export ─────────────────────────────────────────────────────────────────


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
        "has_expired_cert",
        "has_near_expiry_secret",
        "has_near_expiry_cert",
        "has_high_privilege",
        "signal_keys",
        "signal_count",
        "primary_recommendation",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for r in results:
            writer.writerow(
                {
                    "app_name": r.display_name,
                    "app_id": r.app_id,
                    "object_id": r.sp_id,
                    "account_enabled": r.account_enabled,
                    "sp_type": r.sp_type,
                    "created_at": r.created_datetime or "",
                    "last_sign_in": r.last_sign_in or "",
                    "days_since_sign_in": r.days_since_sign_in if r.days_since_sign_in is not None else "",
                    "risk_score": r.risk_score,
                    "risk_band": r.risk_band,
                    "owner_count": r.owner_count,
                    "assignment_count": r.assignment_count,
                    "has_expired_secret": r.has_expired_secret,
                    "has_expired_cert": r.has_expired_cert,
                    "has_near_expiry_secret": r.has_near_expiry_secret,
                    "has_near_expiry_cert": r.has_near_expiry_cert,
                    "has_high_privilege": r.has_high_privilege,
                    "signal_keys": "|".join(s.key for s in r.signals),
                    "signal_count": len(r.signals),
                    "primary_recommendation": r.primary_recommendation,
                }
            )

    return output_path


# ── PDF export ─────────────────────────────────────────────────────────────────


def generate_pdf(html_path: Path, pdf_path: Path) -> Path | None:
    """Render PDF from the HTML report. Returns path on success, None if weasyprint unavailable."""
    try:
        from weasyprint import HTML  # type: ignore
    except ImportError:
        console.print("[yellow]weasyprint not installed — skipping PDF generation. Run: pip install weasyprint[/yellow]")
        return None

    try:
        HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        return pdf_path
    except Exception as exc:
        console.print(f"[yellow]PDF generation failed: {exc}[/yellow]")
        return None


# ── Orchestrator ───────────────────────────────────────────────────────────────


def generate_all(
    results: list[AppResult],
    raw_data: dict,
    stale_days: int,
    output_dir: Path,
) -> dict[str, Path | None]:
    """Generate HTML, CSV, and PDF reports. Returns dict of format → output path."""
    output_dir.mkdir(parents=True, exist_ok=True)

    tenant = raw_data.get("tenant", {})
    tenant_slug = tenant.get("displayName", "tenant").replace(" ", "_").lower()
    date_slug = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    base = output_dir / f"enterprise_zapp_{tenant_slug}_{date_slug}"

    html_path = Path(str(base) + ".html")
    csv_path = Path(str(base) + ".csv")
    pdf_path = Path(str(base) + ".pdf")

    console.print("[cyan]Generating HTML report...[/cyan]")
    html_out = generate_html(results, raw_data, stale_days, html_path)
    console.print(f"[green]HTML:[/green] {html_out}")

    console.print("[cyan]Generating CSV export...[/cyan]")
    csv_out = generate_csv(results, csv_path)
    console.print(f"[green]CSV: [/green] {csv_out}")

    console.print("[cyan]Generating PDF export...[/cyan]")
    pdf_out = generate_pdf(html_path, pdf_path)
    if pdf_out:
        console.print(f"[green]PDF: [/green] {pdf_out}")

    return {"html": html_out, "csv": csv_out, "pdf": pdf_out}
