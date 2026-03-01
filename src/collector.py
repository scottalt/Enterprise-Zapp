"""
Data collection orchestration for Enterprise-Zapp.

Fetches all required data from Microsoft Graph and assembles a list of
enriched service principal records ready for analysis.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path

from rich.console import Console
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)

from . import __version__
from .graph import GraphClient

console = Console()


def collect(client: GraphClient, output_dir: Path, cache_path: Path | None = None) -> dict:
    """
    Collect all data required for the hygiene report.

    Returns a dict with keys:
        tenant       – organization info
        apps         – list of enriched SP dicts
        collected_at – ISO timestamp
        skipped      – list of data categories that could not be fetched
    """
    if cache_path and cache_path.exists():
        console.print(f"[cyan]Loading cached data from {cache_path}...[/cyan]")
        return json.loads(cache_path.read_text(encoding="utf-8"))

    skipped: list[str] = []

    # ── Step 1: tenant info ─────────────────────────────────────────────────
    with console.status("[cyan]Fetching tenant information..."):
        tenant = client.get_organization()
    console.print(f"[green]Tenant:[/green] {tenant.get('displayName', 'Unknown')} ({tenant.get('id', '')})")

    # ── Step 2: sign-in activity (fetch once, keyed by appId) ──────────────
    with console.status("[cyan]Fetching service principal sign-in activity (this may take a moment)..."):
        sign_in_map = client.get_sign_in_activities()
    if not sign_in_map:
        skipped.append("sign_in_activities")
        console.print("[yellow]Sign-in activity unavailable — staleness detection will be limited.[/yellow]")
    else:
        console.print(f"[green]Sign-in records:[/green] {len(sign_in_map):,}")

    # ── Step 2b: Application credentials ───────────────────────────────────
    # Credentials (passwordCredentials, keyCredentials) and implicit-grant
    # settings live on the Application registration, not on the Service
    # Principal. Fetch all app registrations and build a lookup by appId.
    app_cred_map: dict[str, dict] = {}
    try:
        with console.status("[cyan]Fetching application credential data..."):
            for app in client.get_applications():
                if app_id_key := app.get("appId"):
                    web = app.get("web") or {}
                    implicit = web.get("implicitGrantSettings") or {}
                    app_cred_map[app_id_key] = {
                        "passwordCredentials": app.get("passwordCredentials") or [],
                        "keyCredentials": app.get("keyCredentials") or [],
                        "oauth2AllowImplicitFlow": implicit.get("enableAccessTokenIssuance", False),
                        "oauth2AllowIdTokenIssuance": implicit.get("enableIdTokenIssuance", False),
                    }
        console.print(f"[green]App registrations found:[/green] {len(app_cred_map):,}")
    except (PermissionError, RuntimeError) as exc:
        skipped.append("app_credentials")
        console.print(f"[yellow]App credential data unavailable ({exc}). Credential signals will be limited.[/yellow]")

    # ── Step 3: disabled users (for orphan detection) ──────────────────────
    with console.status("[cyan]Fetching disabled user list..."):
        disabled_user_ids = client.get_disabled_users()

    # ── Step 4: service principals ─────────────────────────────────────────
    console.print("[cyan]Fetching enterprise app list...[/cyan]")
    all_sps = list(client.get_service_principals())
    console.print(f"[green]Enterprise apps found:[/green] {len(all_sps):,}")

    # ── Step 5: per-SP enrichment ──────────────────────────────────────────
    enriched: list[dict] = []

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Enriching app data...", total=len(all_sps))

        for sp in all_sps:
            sp_id = sp.get("id", "")
            app_id = sp.get("appId", "")

            if not sp_id:
                console.print("[yellow]Warning: skipping SP with missing id field[/yellow]")
                progress.advance(task)
                continue

            app_role_assignments = client.get_sp_app_role_assignments(sp_id)
            owners = client.get_sp_owners(sp_id)
            delegated_grants = client.get_sp_oauth2_permission_grants(sp_id)
            app_permissions = client.get_sp_app_role_assigned_to(sp_id)
            sign_in = sign_in_map.get(app_id, {})

            # Merge credential + auth data from the linked Application registration.
            # These fields are not returned on the SP endpoint — they live on the
            # Application object and must be overlaid here.
            app_cred = app_cred_map.get(app_id, {})

            enriched.append(
                {
                    **sp,
                    # Application-sourced fields (override SP values when the app
                    # registration was found). Use key presence, not truthiness,
                    # so an empty list [] from the Application object is respected
                    # rather than falling through to stale SP-level data.
                    "passwordCredentials": app_cred["passwordCredentials"] if "passwordCredentials" in app_cred else (sp.get("passwordCredentials") or []),
                    "keyCredentials": app_cred["keyCredentials"] if "keyCredentials" in app_cred else (sp.get("keyCredentials") or []),
                    "oauth2AllowImplicitFlow": app_cred.get("oauth2AllowImplicitFlow", sp.get("oauth2AllowImplicitFlow", False)),
                    "oauth2AllowIdTokenIssuance": app_cred.get("oauth2AllowIdTokenIssuance", sp.get("oauth2AllowIdTokenIssuance", False)),
                    # SP-sourced enrichment keys
                    "_assignments": app_role_assignments,
                    "_owners": owners,
                    "_delegatedGrants": delegated_grants,
                    "_appPermissions": app_permissions,
                    "_signInActivity": sign_in,
                    "_disabledOwnerIds": [
                        o.get("id") for o in owners if o.get("id") in disabled_user_ids
                    ],
                }
            )
            progress.advance(task)

    # ── Step 6: Conditional Access policies ────────────────────────────────────
    with console.status("[cyan]Fetching Conditional Access policies..."):
        ca_policies_result = client.get_conditional_access_policies()

    ca_permission_granted = ca_policies_result is not None
    ca_policies = ca_policies_result if ca_permission_granted else []

    if not ca_permission_granted:
        skipped.append("ca_policies")
    elif ca_policies:
        console.print(f"[green]CA policies found:[/green] {len(ca_policies):,}")
    else:
        console.print("[dim]CA policies: none configured in this tenant.[/dim]")

    result = {
        "schema_version": __version__,
        "tenant": tenant,
        "apps": enriched,
        "ca_policies": ca_policies,
        "ca_permission_granted": ca_permission_granted,
        "collected_at": datetime.now(timezone.utc).isoformat(),
        "skipped": skipped,
    }

    # ── Save raw cache ──────────────────────────────────────────────────────
    output_dir.mkdir(parents=True, exist_ok=True)
    tenant_slug = re.sub(r"[^\w\-]", "_", tenant.get("displayName", "tenant")).lower()
    date_slug = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    cache_file = output_dir / f"raw_{tenant_slug}_{date_slug}.json"
    cache_file.write_text(json.dumps(result, indent=2, default=str), encoding="utf-8")
    console.print(f"[dim]Raw data cached to {cache_file}[/dim]")

    return result
