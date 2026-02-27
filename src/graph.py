"""
Microsoft Graph API client with automatic pagination and retry logic.

All methods are read-only GET requests. No POST/PATCH/DELETE calls are made.
Respects Retry-After headers on 429 responses and retries up to MAX_RETRIES times.
"""

import time
from typing import Any, Generator

import requests
from rich.console import Console

console = Console()

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
MAX_RETRIES = 5
RETRY_BACKOFF_BASE = 2  # seconds; doubles each retry


class GraphClient:
    """Thin read-only wrapper around the Microsoft Graph REST API."""

    def __init__(self, access_token: str) -> None:
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {access_token}",
                "Content-Type": "application/json",
                "ConsistencyLevel": "eventual",  # required for $count / $search on some endpoints
            }
        )

    def _get(self, url: str, params: dict | None = None) -> dict:
        """Single GET request with retry on 429 / transient errors."""
        for attempt in range(MAX_RETRIES):
            try:
                resp = self._session.get(url, params=params, timeout=30)
            except requests.RequestException as exc:
                if attempt < MAX_RETRIES - 1:
                    wait = RETRY_BACKOFF_BASE ** attempt
                    console.print(f"[yellow]Network error ({exc}). Retrying in {wait}s...[/yellow]")
                    time.sleep(wait)
                    continue
                raise

            if resp.status_code == 200:
                return resp.json()

            if resp.status_code == 429:
                retry_after = int(resp.headers.get("Retry-After", RETRY_BACKOFF_BASE ** attempt))
                console.print(f"[yellow]Rate limited. Waiting {retry_after}s...[/yellow]")
                time.sleep(retry_after)
                continue

            if resp.status_code in (401, 403):
                try:
                    msg = resp.json().get("error", {}).get("message", resp.text)
                except Exception:
                    msg = resp.text
                raise PermissionError(f"Graph API access denied ({resp.status_code}): {msg}")

            if resp.status_code in (500, 502, 503, 504) and attempt < MAX_RETRIES - 1:
                wait = RETRY_BACKOFF_BASE ** attempt
                console.print(f"[yellow]Server error {resp.status_code}. Retrying in {wait}s...[/yellow]")
                time.sleep(wait)
                continue

            try:
                err = resp.json().get("error", {}).get("message", resp.text)
            except Exception:
                err = resp.text
            raise RuntimeError(f"Graph API error {resp.status_code}: {err}")

        raise RuntimeError(f"Graph API request failed after {MAX_RETRIES} retries: {url}")

    def get_paged(self, path: str, params: dict | None = None) -> Generator[dict, None, None]:
        """
        Yield individual items from a paged Graph API collection.

        Automatically follows @odata.nextLink until all pages are consumed.
        """
        url = f"{GRAPH_BASE}{path}"
        query = {"$top": 999, **(params or {})}

        while url:
            data = self._get(url, params=query if url.startswith(GRAPH_BASE) else None)
            # On nextLink pages, params are already encoded in the URL
            query = None
            for item in data.get("value", []):
                yield item
            url = data.get("@odata.nextLink")

    def get_one(self, path: str, params: dict | None = None) -> dict:
        """Fetch a single object (not a collection)."""
        return self._get(f"{GRAPH_BASE}{path}", params=params)

    # ── Convenience methods ──────────────────────────────────────────────────

    def get_organization(self) -> dict:
        """Return the first organization object (tenant details)."""
        data = self._get(f"{GRAPH_BASE}/organization")
        orgs = data.get("value", [data])
        return orgs[0] if orgs else {}

    def get_service_principals(self) -> Generator[dict, None, None]:
        """Yield all service principals (enterprise apps) in the tenant."""
        yield from self.get_paged(
            "/servicePrincipals",
            params={
                "$select": (
                    "id,appId,displayName,description,accountEnabled,servicePrincipalType,"
                    "tags,appRoles,oauth2PermissionScopes,"
                    "passwordCredentials,keyCredentials,createdDateTime,"
                    "appOwnerOrganizationId,homepage,replyUrls,notes"
                )
            },
        )

    def get_sp_app_role_assignments(self, sp_id: str) -> list[dict]:
        """Users and groups assigned to this service principal."""
        return list(self.get_paged(f"/servicePrincipals/{sp_id}/appRoleAssignments"))

    def get_sp_owners(self, sp_id: str) -> list[dict]:
        """Owners of this service principal."""
        try:
            return list(
                self.get_paged(
                    f"/servicePrincipals/{sp_id}/owners",
                    params={"$select": "id,displayName,accountEnabled,userPrincipalName,deletedDateTime"},
                )
            )
        except (PermissionError, RuntimeError):
            return []

    def get_sp_oauth2_permission_grants(self, sp_id: str) -> list[dict]:
        """Delegated permission grants for this service principal."""
        try:
            return list(self.get_paged(f"/servicePrincipals/{sp_id}/oauth2PermissionGrants"))
        except (PermissionError, RuntimeError):
            return []

    def get_sp_app_role_assigned_to(self, sp_id: str) -> list[dict]:
        """Application role assignments granted TO this SP (app permissions it holds)."""
        try:
            return list(self.get_paged(f"/servicePrincipals/{sp_id}/appRoleAssignedTo"))
        except (PermissionError, RuntimeError):
            return []

    def get_sign_in_activities(self) -> dict[str, dict]:
        """
        Return a dict keyed by appId → sign-in activity record.

        Uses the servicePrincipalSignInActivities report endpoint.
        Returns empty dict if the caller lacks Reports.Read.All.
        """
        try:
            activities: dict[str, dict] = {}
            for item in self.get_paged("/reports/servicePrincipalSignInActivities"):
                activities[item["appId"]] = item
            return activities
        except (PermissionError, RuntimeError) as exc:
            console.print(f"[yellow]Warning: Could not fetch sign-in activity data ({exc}). Staleness signals will be limited.[/yellow]")
            return {}

    def get_disabled_users(self) -> set[str]:
        """Return a set of object IDs for disabled/soft-deleted users (for orphan detection)."""
        try:
            disabled_ids: set[str] = set()
            for user in self.get_paged(
                "/users",
                params={"$filter": "accountEnabled eq false", "$select": "id"},
            ):
                disabled_ids.add(user["id"])
            return disabled_ids
        except (PermissionError, RuntimeError):
            return set()
