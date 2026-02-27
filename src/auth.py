"""
MSAL device code flow authentication for Enterprise-Zapp.

Reads client_id and tenant_id from enterprise_zapp_config.json or accepts
them as explicit arguments. The access token is held only in memory and
never written to disk.
"""

import json
import sys
from pathlib import Path

import msal
from rich.console import Console
from rich.panel import Panel

console = Console()

GRAPH_SCOPES = [
    "https://graph.microsoft.com/Application.Read.All",
    "https://graph.microsoft.com/Directory.Read.All",
    "https://graph.microsoft.com/AuditLog.Read.All",
    "https://graph.microsoft.com/Reports.Read.All",
    "https://graph.microsoft.com/Policy.Read.All",
]

DEFAULT_CONFIG_FILE = Path(__file__).parent.parent / "enterprise_zapp_config.json"


def load_config(config_path: Path | None = None) -> dict:
    """Load client_id and tenant_id from the JSON config produced by setup.ps1."""
    path = config_path or DEFAULT_CONFIG_FILE
    if not path.exists():
        console.print(
            Panel(
                "[bold red]Config file not found.[/bold red]\n\n"
                "Run [cyan]setup.ps1[/cyan] first to create an app registration,\n"
                "or pass [cyan]--tenant[/cyan] and [cyan]--client-id[/cyan] flags directly.",
                title="[red]Setup Required[/red]",
                border_style="red",
            )
        )
        sys.exit(1)
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        console.print(f"[red]Error reading config file {path}: {exc}[/red]")
        sys.exit(1)


def acquire_token(tenant_id: str, client_id: str) -> str:
    """
    Run MSAL device code flow and return an access token string.

    Prompts the user to visit https://microsoft.com/devicelogin and enter a code.
    Token is returned as a plain string and never cached to disk.
    """
    authority = f"https://login.microsoftonline.com/{tenant_id}"
    app = msal.PublicClientApplication(client_id=client_id, authority=authority)

    flow = app.initiate_device_flow(scopes=GRAPH_SCOPES)
    if "user_code" not in flow:
        console.print(f"[red]Failed to create device flow: {flow.get('error_description', 'unknown error')}[/red]")
        sys.exit(1)

    console.print(
        Panel(
            f"[bold yellow]Open your browser and go to:[/bold yellow]\n\n"
            f"  [cyan underline]https://microsoft.com/devicelogin[/cyan underline]\n\n"
            f"[bold yellow]Enter the code:[/bold yellow]\n\n"
            f"  [bold white on blue]  {flow['user_code']}  [/bold white on blue]\n\n"
            f"[dim]Waiting for authentication... (expires in {flow.get('expires_in', 900) // 60} minutes)[/dim]",
            title="[bold cyan]Microsoft Authentication Required[/bold cyan]",
            border_style="cyan",
        )
    )

    result = app.acquire_token_by_device_flow(flow)

    if "access_token" not in result:
        error = result.get("error_description") or result.get("error") or "Unknown error"
        console.print(f"[red]Authentication failed: {error}[/red]")
        sys.exit(1)

    console.print("[green]Authentication successful.[/green]")
    return result["access_token"]


def get_token(tenant_id: str | None, client_id: str | None, config_path: Path | None = None) -> tuple[str, dict]:
    """
    Resolve configuration and return (access_token, config_dict).

    If tenant_id or client_id are not provided, loads them from the config file.
    """
    if tenant_id and client_id:
        config = {"tenant_id": tenant_id, "client_id": client_id, "tenant_name": tenant_id}
    else:
        config = load_config(config_path)
        if tenant_id:
            config["tenant_id"] = tenant_id
        if client_id:
            config["client_id"] = client_id

    token = acquire_token(config["tenant_id"], config["client_id"])
    return token, config
