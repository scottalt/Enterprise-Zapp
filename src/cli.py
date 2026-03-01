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
from .auth import get_token, DEFAULT_CONFIG_FILE
from .ca_analyzer import analyze_ca_coverage
from .collector import collect
from .graph import GraphClient
from .reporter import generate_all, _top_recommendations

console = Console()

_GRAPH_BASE = "https://graph.microsoft.com/v1.0"
_CLEANUP_SCOPES = ["https://graph.microsoft.com/Application.ReadWrite.All"]


def _perform_cleanup(config_path: Path, dry_run: bool = False) -> None:
    """
    Re-authenticate as Application Administrator and delete the Enterprise-Zapp
    app registration via Microsoft Graph, then remove the local config file.

    Uses a fresh device code flow requesting Application.ReadWrite.All.
    The signed-in account must hold Application Administrator or Global Administrator.

    If dry_run is True, looks up and displays the app registration but does not delete it.
    """
    import msal
    import requests

    if not config_path.exists():
        console.print(
            Panel(
                "[yellow]Config file not found.[/yellow]\n"
                "The app registration may already have been deleted, or setup.ps1 was not run.",
                title="[yellow]Nothing to Clean Up[/yellow]",
                border_style="yellow",
            )
        )
        return

    try:
        cfg = json.loads(config_path.read_text(encoding="utf-8-sig"))
    except (json.JSONDecodeError, OSError) as exc:
        console.print(Panel(f"[red]Could not read config file: {exc}[/red]", border_style="red"))
        return

    app_client_id = cfg.get("client_id")
    tenant_id = cfg.get("tenant_id")
    if not app_client_id or not tenant_id:
        console.print(Panel("[red]Config file is missing client_id or tenant_id.[/red]", border_style="red"))
        return

    if dry_run:
        console.print(
            Panel(
                f"[bold yellow]Dry run — no changes will be made.[/bold yellow]\n\n"
                f"Would delete app registration:\n"
                f"  [bold]Name:[/bold]   {cfg.get('app_name', 'Enterprise-Zapp')}\n"
                f"  [bold]App ID:[/bold] {app_client_id}\n"
                f"  [bold]Tenant:[/bold] {cfg.get('tenant_name', tenant_id)} ({tenant_id})\n\n"
                "Re-run without [cyan]--cleanup-dry-run[/cyan] to delete for real.",
                title="[yellow]Cleanup Dry Run[/yellow]",
                border_style="yellow",
            )
        )
        return

    console.print(
        "\n[cyan]Cleanup requires a separate sign-in with elevated permissions.[/cyan]\n"
        "[dim]Sign in with an account that has Application Administrator or Global Administrator role.[/dim]\n"
    )

    msal_app = msal.PublicClientApplication(
        client_id=app_client_id,
        authority=f"https://login.microsoftonline.com/{tenant_id}",
    )

    flow = msal_app.initiate_device_flow(scopes=_CLEANUP_SCOPES)
    if "user_code" not in flow:
        console.print(f"[red]Failed to start sign-in: {flow.get('error_description', 'unknown error')}[/red]")
        return

    console.print(
        Panel(
            f"[bold yellow]Open your browser and go to:[/bold yellow]\n\n"
            f"  [cyan underline]https://microsoft.com/devicelogin[/cyan underline]\n\n"
            f"[bold yellow]Enter the code:[/bold yellow]\n\n"
            f"  [bold white on blue]  {flow['user_code']}  [/bold white on blue]\n\n"
            f"[dim]Sign in with Application Administrator or Global Administrator credentials.[/dim]\n"
            f"[dim]Waiting... (expires in {flow.get('expires_in', 900) // 60} minutes)[/dim]",
            title="[bold cyan]Cleanup Authentication[/bold cyan]",
            border_style="cyan",
        )
    )

    result = msal_app.acquire_token_by_device_flow(flow)
    if "access_token" not in result:
        error = result.get("error_description") or result.get("error") or "unknown error"
        console.print(f"[red]Authentication failed: {error}[/red]")
        return

    headers = {
        "Authorization": f"Bearer {result['access_token']}",
        "Content-Type": "application/json",
    }

    # Look up the app's object ID by appId
    resp = requests.get(
        f"{_GRAPH_BASE}/applications",
        headers=headers,
        params={"$filter": f"appId eq '{app_client_id}'", "$select": "id,displayName"},
        timeout=30,
    )

    if resp.status_code == 403:
        console.print(
            "[red]Permission denied. The signed-in account does not have "
            "Application Administrator or Global Administrator role.[/red]"
        )
        return

    if resp.status_code != 200:
        console.print(f"[red]Failed to look up app registration: HTTP {resp.status_code}[/red]")
        return

    apps = resp.json().get("value", [])
    if not apps:
        config_path.unlink(missing_ok=True)
        console.print(
            Panel(
                "[yellow]App registration not found — it may have already been deleted.[/yellow]\n"
                "[green]Config file removed.[/green]",
                title="[yellow]Already Gone[/yellow]",
                border_style="yellow",
            )
        )
        return

    obj_id = apps[0]["id"]
    display_name = apps[0].get("displayName", "Enterprise-Zapp")

    del_resp = requests.delete(
        f"{_GRAPH_BASE}/applications/{obj_id}",
        headers=headers,
        timeout=30,
    )

    if del_resp.status_code == 204:
        config_path.unlink(missing_ok=True)
        console.print(
            Panel(
                f"[bold green]App registration deleted successfully.[/bold green]\n\n"
                f"  [bold]Name:[/bold]   {display_name}\n"
                f"  [bold]App ID:[/bold] {app_client_id}\n\n"
                "[green]Config file removed.[/green]",
                title="[bold green]Cleanup Complete[/bold green]",
                border_style="green",
            )
        )
    elif del_resp.status_code == 403:
        console.print(
            Panel(
                "[red]Permission denied.[/red] The signed-in account does not have "
                "[bold]Application Administrator[/bold] or [bold]Global Administrator[/bold] role.\n\n"
                "Ask your Global Administrator to delete the app registration manually, or sign in "
                "with a higher-privileged account and re-run [cyan]--cleanup-after[/cyan].",
                title="[red]Permission Denied[/red]",
                border_style="red",
            )
        )
    else:
        try:
            err_msg = del_resp.json().get("error", {}).get("message", del_resp.text)
        except Exception:
            err_msg = del_resp.text
        console.print(
            Panel(
                f"[red]Failed to delete app registration.[/red]\n\n"
                f"HTTP {del_resp.status_code}: {err_msg}\n\n"
                "You can delete it manually in the [cyan]Entra admin center → App registrations[/cyan].",
                title="[red]Deletion Failed[/red]",
                border_style="red",
            )
        )


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
[bold green]  Scan is read-only · Setup creates one app registration · Cleanup deletes it[/bold green]
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
    "--hide-microsoft/--show-microsoft",
    default=False,
    show_default=True,
    help="Exclude Microsoft first-party apps (Teams, SharePoint, etc.) from the report.",
)
@click.option(
    "--output-format",
    default="all",
    show_default=True,
    type=click.Choice(["all", "html", "csv"], case_sensitive=False),
    help="Report format(s) to generate.",
)
@click.option(
    "--filter-band",
    default="all",
    show_default=True,
    type=click.Choice(["all", "critical", "high", "medium", "low", "clean"], case_sensitive=False),
    help=(
        "Only include apps at or above this risk band in the report. "
        "Exit codes always reflect the full pre-filter results — a critical app "
        "not shown in the report will still produce exit code 3."
    ),
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
@click.option(
    "--cleanup-after",
    "cleanup_after",
    is_flag=True,
    default=False,
    help=(
        "After generating the report, prompt to delete the Enterprise-Zapp app registration. "
        "Requires a second sign-in as Application Administrator or Global Administrator."
    ),
)
@click.option(
    "--cleanup-dry-run",
    "cleanup_dry_run",
    is_flag=True,
    default=False,
    help=(
        "Show what the cleanup would delete (app name, ID, tenant) without making any changes. "
        "Use to verify before running --cleanup-after."
    ),
)
@click.version_option(__version__, "--version", "-V")
def main(
    tenant: str | None,
    client_id: str | None,
    config: Path | None,
    stale_days: int,
    output: Path,
    from_cache: Path | None,
    hide_microsoft: bool,
    output_format: str,
    filter_band: str,
    quiet: bool,
    json_output: bool,
    cleanup_after: bool,
    cleanup_dry_run: bool,
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
                "[bold green]The scan is read-only.[/bold green] "
                "No changes will be made to your Entra ID tenant.\n\n"
                "[bold yellow]Note:[/bold yellow] [bold]setup.ps1[/bold] created an [bold]Enterprise-Zapp[/bold] "
                "app registration in your tenant. It only holds read-only Graph permissions, "
                "but you should delete it when your audit is complete.\n\n"
                "Delete options:\n"
                "  [cyan].\\setup.ps1 -Cleanup[/cyan]          [dim]run manually after the scan[/dim]\n"
                "  [cyan]enterprise-zapp --cleanup-after[/cyan]  [dim]prompts at the end of this run[/dim]",
                border_style="cyan",
                title="[bold cyan]Scan Scope[/bold cyan]",
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

    outputs = generate_all(
        results, raw_data, stale_days, output_dir,
        hide_microsoft=hide_microsoft,
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
                    "[dim]PDF: open the HTML report in your browser and use Ctrl+P → Save as PDF[/dim]",
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

    # ── Cleanup ──────────────────────────────────────────────────────────────
    config_path = config or DEFAULT_CONFIG_FILE
    if cleanup_dry_run:
        _perform_cleanup(config_path, dry_run=True)
    elif cleanup_after:
        if click.confirm(
            "\nDelete the Enterprise-Zapp app registration now?",
            default=False,
        ):
            _perform_cleanup(config_path)
        else:
            console.print(
                "[dim]Skipped. Run [cyan].\\setup.ps1 -Cleanup[/cyan] "
                "(Application Administrator) when ready.[/dim]"
            )
    elif not quiet:
        console.print(
            Panel(
                "[bold]Cleanup reminder[/bold]\n"
                "Setup created an [bold]Enterprise-Zapp[/bold] app registration in your tenant.\n"
                "Once you are done with your audit, delete it:\n\n"
                "  [cyan bold].\\setup.ps1 -Cleanup[/cyan bold]                  [dim]manual cleanup[/dim]\n"
                "  [cyan bold]enterprise-zapp --cleanup-after[/cyan bold]  [dim]prompts at end of next scan[/dim]\n\n"
                "[dim]Requires Application Administrator or Global Administrator.[/dim]",
                border_style="yellow",
                title="[bold yellow]Action Required After Audit[/bold yellow]",
            )
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
