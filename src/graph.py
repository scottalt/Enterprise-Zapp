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
GRAPH_BETA = "https://graph.microsoft.com/beta"
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
                try:
                    retry_after = int(resp.headers.get("Retry-After", RETRY_BACKOFF_BASE ** attempt))
                except ValueError:
                    retry_after = RETRY_BACKOFF_BASE ** attempt
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
        # Spread caller params first so our $top=999 default always wins
        query: dict | None = {**(params or {}), "$top": 999}

        while url:
            data = self._get(url, params=query)
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
                    "createdDateTime,appOwnerOrganizationId,homepage,replyUrls,notes,"
                    "signInAudience"
                )
            },
        )

    def get_applications(self) -> Generator[dict, None, None]:
        """
        Yield all application registrations owned by this tenant.

        Credentials (passwordCredentials, keyCredentials) and implicit-grant
        settings live on the Application object, NOT on the linked Service
        Principal, so they must be fetched here and merged during enrichment.
        Requires Application.Read.All.
        """
        yield from self.get_paged(
            "/applications",
            params={"$select": "appId,passwordCredentials,keyCredentials,web"},
        )

    def get_sp_app_role_assignments(self, sp_id: str) -> list[dict]:
        """
        App role assignments granted TO this service principal — i.e. the API
        permissions this SP holds on other resources (e.g. Graph app roles).
        """
        try:
            return list(self.get_paged(f"/servicePrincipals/{sp_id}/appRoleAssignments"))
        except (PermissionError, RuntimeError):
            return []

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
        """
        Users, groups, and service principals that have been assigned roles IN
        this app — i.e. the user/group assignments visible in the Enterprise App
        blade.
        """
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
            # This endpoint is beta-only — not available on v1.0
            url = f"{GRAPH_BETA}/reports/servicePrincipalSignInActivities"
            query: dict | None = {"$top": 999}
            while url:
                data = self._get(url, params=query)
                query = None
                for item in data.get("value", []):
                    if app_id := item.get("appId"):
                        activities[app_id] = item
                url = data.get("@odata.nextLink")
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
                if uid := user.get("id"):
                    disabled_ids.add(uid)
            return disabled_ids
        except (PermissionError, RuntimeError):
            return set()

    def get_conditional_access_policies(self) -> list[dict] | None:
        """
        Return all Conditional Access policies. Requires Policy.Read.All.

        Returns:
            list[dict]  — policies fetched (may be empty if none are configured)
            None        — permission denied or endpoint unreachable
        """
        try:
            return list(self.get_paged(
                "/identity/conditionalAccess/policies",
                params={
                    "$select": (
                        "id,displayName,state,conditions,createdDateTime,modifiedDateTime"
                    )
                },
            ))
        except (PermissionError, RuntimeError) as exc:
            console.print(
                f"[yellow]CA policies unavailable ({exc}). "
                "Grant Policy.Read.All to enable Conditional Access coverage analysis.[/yellow]"
            )
            return None
