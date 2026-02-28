"""
Enterprise-Zapp CLI entrypoint.

Usage:
    enterprise-zapp [OPTIONS]
    python -m src.cli [OPTIONS]
"""

from __future__ import annotations

import json
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .analyzer import analyze_all, band_counts
from .auth import get_token
from .ca_analyzer import analyze_ca_coverage
from .collector import collect
from .graph import GraphClient
from .reporter import WEASYPRINT_AVAILABLE, generate_all, _top_recommendations

console = Console()

BANNER = f"""[bold]
  ███████╗ ███╗  ██╗ ████████╗ ███████╗ ██████╗  ██████╗ ██╗ ███████╗ ███████╗
  ██╔════╝ ████╗ ██║ ╚══██╔══╝ ██╔════╝ ██╔══██╗ ██╔══██╗██║ ██╔════╝ ██╔════╝
  █████╗   ██╔██╗██║    ██║    █████╗   ██████╔╝ ██████╔╝██║ ███████╗ █████╗
  ██╔══╝   ██║╚████║    ██║    ██╔══╝   ██╔══██╗ ██╔═══╝ ██║ ╚════██║ ██╔══╝
  ███████╗ ██║ ╚███║    ██║    ███████╗ ██║  ██║ ██║     ██║ ███████║ ███████╗
  ╚══════╝ ╚═╝  ╚══╝    ╚═╝    ╚══════╝ ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝ ╚══════╝
[/bold][bold green]
                     ███████╗  █████╗  ██████╗  ██████╗
                     ╚════██║ ██╔══██╗ ██╔══██╗ ██╔══██╗
                         ██╔╝ ███████║ ██████╔╝ ██████╔╝
                        ██╔╝  ██╔══██║ ██╔═══╝  ██╔═══╝
                     ███████╗ ██║  ██║ ██║      ██║
                     ╚══════╝ ╚═╝  ╚═╝ ╚═╝      ╚═╝
[/bold green]
[dim]  Entra ID Enterprise App Hygiene Scanner  ·  v{__version__}[/dim]
[bold green]  Read-Only. No changes will be made to your Entra ID tenant.[/bold green]
[dim]  By Scott Altiparmak · https://www.linkedin.com/in/scottaltiparmak/[/dim]
"""


@click.command()
@click.option(
    "--tenant", "-t",
    default=None,
    metavar="TENANT_ID",
    help="Entra tenant ID or domain (e.g. contoso.onmicrosoft.com). Reads from config file if omitted.",
)
@click.option(
    "--client-id", "-c",
    default=None,
    metavar="CLIENT_ID",
    help="Azure app registration client ID. Reads from config file if omitted.",
)
@click.option(
    "--config",
    default=None,
    type=click.Path(exists=False, path_type=Path),
    metavar="PATH",
    help="Path to enterprise_zapp_config.json (default: ./enterprise_zapp_config.json).",
)
@click.option(
    "--stale-days",
    default=90,
    show_default=True,
    type=click.IntRange(min=1, max=3650),
    metavar="DAYS",
    help="Number of days without sign-in before an app is considered stale.",
)
@click.option(
    "--output", "-o",
    default="./output",
    show_default=True,
    type=click.Path(path_type=Path),
    metavar="DIR",
    help="Directory to write reports and raw data cache.",
)
@click.option(
    "--from-cache",
    default=None,
    type=click.Path(exists=True, path_type=Path),
    metavar="CACHE_FILE",
    help="Re-use a previously collected raw JSON data file. Skips Graph API calls.",
)
@click.option(
    "--skip-pdf",
    is_flag=True,
    default=False,
    help="Skip PDF generation (useful if weasyprint is not installed).",
)
@click.option(
    "--hide-microsoft/--show-microsoft",
    default=False,
    show_default=True,
    help="Exclude Microsoft first-party apps (Teams, SharePoint, etc.) from the report.",
)
@click.option(
    "--output-format",
    default="all",
    show_default=True,
    type=click.Choice(["all", "html", "csv", "pdf"], case_sensitive=False),
    help="Report format(s) to generate.",
)
@click.option(
    "--filter-band",
    default="all",
    show_default=True,
    type=click.Choice(["all", "critical", "high", "medium", "low", "clean"], case_sensitive=False),
    help="Only include apps at or above this risk band in the report.",
)
@click.option(
    "--quiet",
    is_flag=True,
    default=False,
    help="Suppress banner, disclaimer, and decorative output. Only print errors and output paths.",
)
@click.option(
    "--json-output",
    "json_output",
    is_flag=True,
    default=False,
    help="Print a structured JSON summary to stdout after the scan.",
)
@click.version_option(__version__, "--version", "-V")
def main(
    tenant: str | None,
    client_id: str | None,
    config: Path | None,
    stale_days: int,
    output: Path,
    from_cache: Path | None,
    skip_pdf: bool,
    hide_microsoft: bool,
    output_format: str,
    filter_band: str,
    quiet: bool,
    json_output: bool,
) -> None:
    """
    Enterprise-Zapp — Entra ID Enterprise App Hygiene Scanner.

    Authenticates to your Microsoft Entra tenant via device code flow,
    collects enterprise app data from the Microsoft Graph API,
    and produces an HTML + CSV + PDF hygiene report.

    Run setup.ps1 first to create the required app registration.

    Exit codes:
      0  All apps are clean or low risk only
      1  At least one medium-risk app detected
      2  At least one high-risk app detected
      3  At least one critical-risk app detected
    """
    _scan_start = time.monotonic()

    if not quiet:
        console.print(BANNER)

        console.print(
            Panel(
                "[bold yellow]This tool is strictly read-only.[/bold yellow]\n"
                "It collects data from the Microsoft Graph API and produces a report.\n"
                "[bold]No changes will be made to your Entra ID tenant.[/bold]",
                border_style="yellow",
            )
        )

        console.print(
            Panel(
                "[bold red]DISCLAIMER[/bold red]\n"
                "This tool is provided [bold]as-is[/bold], without warranty of any kind.\n"
                "[bold]Scott Altiparmak[/bold] ([cyan]linkedin.com/in/scottaltiparmak[/cyan]) "
                "accepts [bold red]no responsibility or liability[/bold red] for any issues, "
                "damages, or consequences arising from running this tool in your environment.\n"
                "[dim]Use entirely at your own risk. Validate all findings before taking action.[/dim]",
                border_style="red",
                title="[bold red]Use At Your Own Risk[/bold red]",
            )
        )

    # ── Authenticate ────────────────────────────────────────────────────────
    if from_cache:
        console.print(f"[cyan]Cache mode — loading data from {from_cache}[/cyan]")
        try:
            raw_data = json.loads(from_cache.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError) as exc:
            console.print(f"[red]Error reading cache file: {exc}[/red]")
            sys.exit(1)
        if "apps" not in raw_data:
            console.print(
                "[red]Error: cache file does not look like an Enterprise-Zapp data file "
                "(missing 'apps' key). Pass the raw_<tenant>_<date>.json file.[/red]"
            )
            sys.exit(1)
        tenant_name = raw_data.get("tenant", {}).get("displayName", "cached tenant")
        console.print(f"[green]Loaded cache for:[/green] {tenant_name}")
    else:
        token, auth_config = get_token(tenant, client_id, config)
        tenant_name = auth_config.get("tenant_name", auth_config.get("tenant_id", ""))
        console.print(f"[green]Connected to:[/green] {tenant_name}")

        # ── Collect data ────────────────────────────────────────────────────
        client = GraphClient(access_token=token)
        output_path = Path(output)
        raw_data = collect(client, output_dir=output_path)

    # ── Analyze ─────────────────────────────────────────────────────────────
    console.print("\n[cyan]Analyzing apps...[/cyan]")
    results = analyze_all(raw_data, stale_days=stale_days)
    ca_app_coverages, ca_policy_summaries = analyze_ca_coverage(
        raw_data.get("ca_policies", []), raw_data.get("apps", [])
    )

    total_scanned = len(results)
    full_bands = band_counts(results)
    if filter_band != "all":
        band_order = ["clean", "low", "medium", "high", "critical"]
        min_idx = band_order.index(filter_band)
        results = [r for r in results if band_order.index(r.risk_band) >= min_idx]

    bands = band_counts(results)

    # ── Terminal summary ─────────────────────────────────────────────────────
    summary_table = Table(title=f"Risk Summary — {len(results)} apps scanned", show_header=True, header_style="bold")
    summary_table.add_column("Risk Band", style="bold")
    summary_table.add_column("Count", justify="right")
    summary_table.add_column("Apps", style="dim")

    band_styles = {
        "critical": "bold red",
        "high": "bold yellow",
        "medium": "yellow",
        "low": "green",
        "clean": "dim green",
    }
    for band in ("critical", "high", "medium", "low", "clean"):
        count = bands[band]
        style = band_styles[band]
        names = ", ".join(r.display_name for r in results if r.risk_band == band)[:80]
        summary_table.add_row(band.title(), str(count), names, style=style if count > 0 else "dim")

    console.print(summary_table)

    top_recs = _top_recommendations(results)
    if top_recs:
        console.print("\n[bold]Top Actions:[/bold]")
        for i, rec in enumerate(top_recs, 1):
            console.print(f"  [cyan]{i}.[/cyan] {rec['text']}")

    # ── Generate reports ─────────────────────────────────────────────────────
    console.print("\n[cyan]Generating reports...[/cyan]")
    output_dir = Path(output)

    want_pdf = (output_format in ("all", "pdf")) and not skip_pdf
    if want_pdf and not WEASYPRINT_AVAILABLE:
        console.print(
            "[yellow]PDF generation skipped — weasyprint native libraries are not available on this system.[/yellow]\n"
            "[dim]Tip: Open the HTML report in your browser and use Ctrl+P → Save as PDF instead.[/dim]"
        )

    outputs = generate_all(
        results, raw_data, stale_days, output_dir,
        hide_microsoft=hide_microsoft,
        skip_pdf=(output_format not in ("all", "pdf")) or skip_pdf or not WEASYPRINT_AVAILABLE,
        skip_html=(output_format not in ("all", "html")),
        skip_csv=(output_format not in ("all", "csv")),
        filter_band=filter_band,
        total_scanned=total_scanned,
        ca_app_coverages=ca_app_coverages,
        ca_policy_summaries=ca_policy_summaries,
    )

    # ── Final summary ────────────────────────────────────────────────────────
    elapsed = time.monotonic() - _scan_start
    elapsed_str = f"{int(elapsed // 60)}m {int(elapsed % 60)}s" if elapsed >= 60 else f"{elapsed:.1f}s"

    console.print(
        Panel(
            "\n".join(
                [
                    "[bold green]Scan complete![/bold green]",
                    "",
                    f"[bold]HTML:[/bold] {outputs.get('html', '—')}",
                    f"[bold]CSV: [/bold] {outputs.get('csv', '—')}",
                    f"[bold]PDF: [/bold] {outputs.get('pdf') or 'skipped'}",
                    "",
                    f"[dim]Total apps: {len(results)} · "
                    f"Critical: {bands['critical']} · High: {bands['high']} · "
                    f"Medium: {bands['medium']} · Low: {bands['low']} · Clean: {bands['clean']}[/dim]",
                    f"[dim]Completed in {elapsed_str}[/dim]",
                ]
            ),
            title="[bold cyan]Enterprise-Zapp[/bold cyan]",
            border_style="cyan",
        )
    )

    # ── JSON output ──────────────────────────────────────────────────────────
    if json_output:
        import json as json_module
        summary = {
            "tenant": tenant_name,
            "scanned_at": datetime.now(timezone.utc).isoformat(),
            "total_apps": total_scanned,
            "filtered_to": filter_band,
            "bands": bands,
            "outputs": {k: str(v) if v else None for k, v in outputs.items()},
        }
        click.echo(json_module.dumps(summary, indent=2))

    # ── Cleanup offer ────────────────────────────────────────────────────────
    if not from_cache:
        console.print(
            "\n[dim]Tip: To remove the temporary app registration created by setup.ps1, run:[/dim]\n"
            "  [cyan].\\setup.ps1 -Cleanup[/cyan]"
        )

    # Exit with meaningful code so pipelines can branch on severity.
    # Use full_bands (pre-filter) so --filter-band critical cannot suppress exit codes.
    if full_bands["critical"] > 0:
        sys.exit(3)
    elif full_bands["high"] > 0:
        sys.exit(2)
    elif full_bands["medium"] > 0:
        sys.exit(1)
    # else exit 0 (default)


if __name__ == "__main__":
    main()
