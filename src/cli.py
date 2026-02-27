"""
Enterprise-Zapp CLI entrypoint.

Usage:
    enterprise-zapp [OPTIONS]
    python -m src.cli [OPTIONS]
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .analyzer import analyze_all, band_counts
from .auth import get_token
from .collector import collect
from .graph import GraphClient
from .reporter import generate_all

console = Console()

BANNER = f"""
[bold]
  ███████╗ ███╗  ██╗ ████████╗ ███████╗ ██████╗  ██████╗ ██╗ ███████╗ ███████╗
  ██╔════╝ ████╗ ██║ ╚══██╔══╝ ██╔════╝ ██╔══██╗ ██╔══██╗██║ ██╔════╝ ██╔════╝
  █████╗   ██╔██╗██║    ██║    █████╗   ██████╔╝ ██████╔╝██║ ███████╗ █████╗
  ██╔══╝   ██║╚████║    ██║    ██╔══╝   ██╔══██╗ ██╔═══╝ ██║ ╚════██║ ██╔══╝
  ███████╗ ██║ ╚███║    ██║    ███████╗ ██║  ██║ ██║     ██║ ███████║ ███████╗
  ╚══════╝ ╚═╝  ╚══╝    ╚═╝    ╚══════╝ ╚═╝  ╚═╝ ╚═╝     ╚═╝ ╚══════╝ ╚══════╝
[/bold]
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
@click.version_option(__version__, "--version", "-V")
def main(
    tenant: str | None,
    client_id: str | None,
    config: Path | None,
    stale_days: int,
    output: Path,
    from_cache: Path | None,
    skip_pdf: bool,
) -> None:
    """
    Enterprise-Zapp — Entra ID Enterprise App Hygiene Scanner.

    Authenticates to your Microsoft Entra tenant via device code flow,
    collects enterprise app data from the Microsoft Graph API,
    and produces an HTML + CSV + PDF hygiene report.

    Run setup.ps1 first to create the required app registration.
    """
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

    # ── Generate reports ─────────────────────────────────────────────────────
    console.print("\n[cyan]Generating reports...[/cyan]")
    output_dir = Path(output)

    if skip_pdf:
        from .reporter import generate_html, generate_csv
        from datetime import datetime, timezone
        from . import __version__ as ver
        output_dir.mkdir(parents=True, exist_ok=True)
        tenant_obj = raw_data.get("tenant", {})
        slug = tenant_obj.get("displayName", "tenant").replace(" ", "_").lower()
        date_slug = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        base = output_dir / f"enterprise_zapp_{slug}_{date_slug}"
        html_out = generate_html(results, raw_data, stale_days, Path(str(base) + ".html"))
        csv_out = generate_csv(results, Path(str(base) + ".csv"))
        outputs = {"html": html_out, "csv": csv_out, "pdf": None}
    else:
        outputs = generate_all(results, raw_data, stale_days, output_dir)

    # ── Final summary ────────────────────────────────────────────────────────
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
                ]
            ),
            title="[bold cyan]Enterprise-Zapp[/bold cyan]",
            border_style="cyan",
        )
    )

    # ── Cleanup offer ────────────────────────────────────────────────────────
    if not from_cache:
        console.print(
            "\n[dim]Tip: To remove the temporary app registration created by setup.ps1, run:[/dim]\n"
            "  [cyan].\\setup.ps1 -Cleanup[/cyan]"
        )


if __name__ == "__main__":
    main()
