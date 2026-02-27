"""
Signal evaluation and risk scoring for Enterprise-Zapp.

Each enterprise app (service principal) is evaluated against a set of
hygiene signals. A risk score (0-100) and risk band are computed.

This module contains pure functions with no I/O — it is fully unit-testable
with mock data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

# ── Constants ─────────────────────────────────────────────────────────────────

DEFAULT_STALE_DAYS = 90
NEAR_EXPIRY_DAYS = 30
NEAR_EXPIRY_WARN_DAYS = 90

# Microsoft's well-known tenant ID — used to identify Microsoft first-party apps
MICROSOFT_TENANT_ID = "f8cdef31-a31e-4b4a-93e4-5f571e91255a"

# Application permission IDs that are considered high-privilege
# (Microsoft Graph well-known role IDs)
HIGH_PRIVILEGE_ROLE_IDS: set[str] = {
    "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8",  # RoleManagement.ReadWrite.Directory
    "62a82d76-70ea-41e2-9197-370581804d09",  # Group.ReadWrite.All
    "1bfefb4e-e0b5-418b-a88f-73c46d2cc8e9",  # Application.ReadWrite.All
    "9492366f-7969-46a4-8d15-ed1a20078fff",  # Sites.ReadWrite.All
    "741f803b-c850-494e-b5df-cde7c675a1ca",  # User.ReadWrite.All
    "e1fe6dd8-ba31-4d61-89e7-88639da4683d",  # User.Read.All (app)
    "df021288-bdef-4463-88db-98f22de89214",  # User.Read.All
    "19dbc75e-c2e2-444c-a770-ec69d8559fc7",  # Directory.ReadWrite.All
    "06b708a9-e830-4db3-a914-8e69da51d44f",  # AppRoleAssignment.ReadWrite.All
    "50483e42-d915-4231-9212-7c7c36c48b57",  # UserAuthenticationMethod.ReadWrite.All
    "c79f8feb-a9db-4090-85f9-90d820caa0eb",  # Application.Read.All (used as proxy for sensitivity)
}

# ── Data classes ──────────────────────────────────────────────────────────────


@dataclass
class Signal:
    key: str
    severity: str          # "critical" | "high" | "medium" | "low" | "info"
    title: str
    detail: str
    score_contribution: int


@dataclass
class AppResult:
    sp_id: str
    app_id: str
    display_name: str
    account_enabled: bool
    sp_type: str
    created_datetime: str | None
    last_sign_in: str | None
    days_since_sign_in: int | None
    owner_count: int
    assignment_count: int
    has_expired_secret: bool
    has_expired_cert: bool
    has_near_expiry_secret: bool
    has_near_expiry_cert: bool
    has_high_privilege: bool
    signals: list[Signal]
    risk_score: int
    risk_band: str          # "critical" | "high" | "medium" | "low" | "clean"
    primary_recommendation: str
    tags: list[str]

    # Classification flags
    is_microsoft_first_party: bool = False
    is_tool_artifact: bool = False

    # Informational metadata (no score impact)
    description: str | None = None
    notes: str | None = None

    # Raw data for report drill-down
    owners: list[dict] = field(default_factory=list)
    password_credentials: list[dict] = field(default_factory=list)
    key_credentials: list[dict] = field(default_factory=list)
    delegated_grants: list[dict] = field(default_factory=list)
    app_permissions: list[dict] = field(default_factory=list)


# ── Helpers ───────────────────────────────────────────────────────────────────


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    try:
        # Graph returns ISO 8601 with trailing Z or +00:00
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc)
    except (ValueError, TypeError):
        return None


def _days_since(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    delta = _utcnow() - dt
    return delta.days


def _days_until(dt: datetime | None) -> int | None:
    if dt is None:
        return None
    delta = dt - _utcnow()
    return delta.days


def _risk_band(score: int) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    if score > 0:
        return "low"
    return "clean"


def _primary_recommendation(signals: list[Signal], account_enabled: bool) -> str:
    if not signals:
        return "No issues detected. Periodic review recommended."
    # Most severe signal drives the recommendation
    severity_order = ["critical", "high", "medium", "low", "info"]
    for sev in severity_order:
        for sig in signals:
            if sig.severity == sev:
                return _recommendation_for_signal(sig.key, account_enabled)
    return "Review flagged signals and remediate as appropriate."


def _recommendation_for_signal(key: str, account_enabled: bool) -> str:
    recs = {
        "never_signed_in": "Review whether this app was ever needed. If not in use, disable then delete.",
        "stale": "Verify with the app owner whether this is still in use. If unused, disable and plan for removal.",
        "no_owners": "Assign at least two owners to this app to ensure accountability.",
        "disabled_owner": "Update app ownership — current owners are disabled accounts.",
        "no_assignments": "If this app requires user/group access, add assignments. Otherwise consider whether it is still needed.",
        "disabled_sp": "If the app is intentionally decommissioned, delete the service principal to reduce attack surface.",
        "expired_secret": "Rotate or remove expired client secrets immediately.",
        "expired_cert": "Rotate or remove expired certificates immediately.",
        "near_expiry_secret": "Rotate client secret before expiry to avoid service disruption.",
        "near_expiry_cert": "Rotate certificate before expiry to avoid service disruption.",
        "high_privilege_stale": "High-privilege app with no recent sign-in activity — investigate necessity and disable if unused.",
        "long_lived_secret": "Replace long-lived secrets with shorter-lived credentials to reduce breach impact.",
    }
    return recs.get(key, "Review and remediate flagged issues.")


# ── Core analysis ─────────────────────────────────────────────────────────────


def analyze_app(sp: dict, stale_days: int = DEFAULT_STALE_DAYS) -> AppResult:
    """
    Evaluate a single enriched service principal record and return an AppResult.

    `sp` must include the enrichment keys added by collector.py:
        _assignments, _owners, _delegatedGrants, _appPermissions,
        _signInActivity, _disabledOwnerIds
    """
    now = _utcnow()
    signals: list[Signal] = []
    score = 0

    sp_id = sp.get("id", "")
    app_id = sp.get("appId", "")
    display_name = sp.get("displayName", "Unknown")
    account_enabled = sp.get("accountEnabled", True)
    sp_type = sp.get("servicePrincipalType", "")
    created_dt = _parse_dt(sp.get("createdDateTime"))

    # ── Classification flags ───────────────────────────────────────────────
    is_microsoft_first_party = (
        sp.get("appOwnerOrganizationId") == MICROSOFT_TENANT_ID
    )
    is_tool_artifact = display_name.startswith("Enterprise-Zapp-Scan-")

    owners: list[dict] = sp.get("_owners", [])
    assignments: list[dict] = sp.get("_assignments", [])
    delegated_grants: list[dict] = sp.get("_delegatedGrants", [])
    app_permissions: list[dict] = sp.get("_appPermissions", [])
    disabled_owner_ids: list[str] = sp.get("_disabledOwnerIds", [])
    sign_in: dict = sp.get("_signInActivity", {})

    password_creds: list[dict] = sp.get("passwordCredentials", [])
    key_creds: list[dict] = sp.get("keyCredentials", [])

    # ── Signal: last sign-in / staleness ──────────────────────────────────
    last_sign_in_raw = (
        sign_in.get("lastSignInActivity", {}).get("lastSignInDateTime")
        or sign_in.get("lastDelegatedSignInActivity", {}).get("lastSignInDateTime")
        or sign_in.get("lastApplicationSignInActivity", {}).get("lastSignInDateTime")
    )
    last_sign_in_dt = _parse_dt(last_sign_in_raw)
    days_since = _days_since(last_sign_in_dt)

    if last_sign_in_dt is None and sign_in:
        # Sign-in data available but app has never signed in
        signals.append(Signal(
            key="never_signed_in",
            severity="high",
            title="Never signed in",
            detail="This app has sign-in activity tracking but has never authenticated.",
            score_contribution=35,
        ))
        score += 35
    elif days_since is not None and days_since > stale_days:
        signals.append(Signal(
            key="stale",
            severity="high",
            title=f"Stale — last sign-in {days_since} days ago",
            detail=f"No sign-in activity detected in the past {stale_days} days (last seen: {last_sign_in_raw}).",
            score_contribution=30,
        ))
        score += 30

    # ── Signal: no owners ─────────────────────────────────────────────────
    if len(owners) == 0:
        signals.append(Signal(
            key="no_owners",
            severity="high",
            title="No owners defined",
            detail="This app has no assigned owners. There is no clear accountability for its lifecycle.",
            score_contribution=20,
        ))
        score += 20
    elif disabled_owner_ids:
        signals.append(Signal(
            key="disabled_owner",
            severity="high",
            title=f"Owner(s) are disabled accounts ({len(disabled_owner_ids)} of {len(owners)})",
            detail="One or more app owners are disabled/deleted users — effectively orphaned.",
            score_contribution=15,
        ))
        score += 15

    # ── Signal: no assignments ────────────────────────────────────────────
    if len(assignments) == 0 and account_enabled:
        signals.append(Signal(
            key="no_assignments",
            severity="medium",
            title="No user/group assignments",
            detail="No users or groups have been assigned to this app.",
            score_contribution=10,
        ))
        score += 10

    # ── Signal: disabled SP ───────────────────────────────────────────────
    if not account_enabled:
        signals.append(Signal(
            key="disabled_sp",
            severity="medium",
            title="Service principal is disabled",
            detail="The service principal is disabled but has not been deleted. Disabled apps can be re-enabled without audit visibility.",
            score_contribution=10,
        ))
        score += 10

    # ── Signal: credentials ───────────────────────────────────────────────
    has_expired_secret = False
    has_near_expiry_secret = False
    for cred in password_creds:
        end_dt = _parse_dt(cred.get("endDateTime"))
        days_left = _days_until(end_dt)
        if days_left is not None:
            if days_left < 0:
                has_expired_secret = True
            elif days_left <= NEAR_EXPIRY_DAYS:
                has_near_expiry_secret = True

    has_expired_cert = False
    has_near_expiry_cert = False
    for cred in key_creds:
        end_dt = _parse_dt(cred.get("endDateTime"))
        days_left = _days_until(end_dt)
        if days_left is not None:
            if days_left < 0:
                has_expired_cert = True
            elif days_left <= NEAR_EXPIRY_DAYS:
                has_near_expiry_cert = True

    if has_expired_secret:
        signals.append(Signal(
            key="expired_secret",
            severity="critical",
            title="Expired client secret(s)",
            detail="One or more client secrets have passed their expiry date.",
            score_contribution=25,
        ))
        score += 25

    if has_expired_cert:
        signals.append(Signal(
            key="expired_cert",
            severity="critical",
            title="Expired certificate(s)",
            detail="One or more certificates have passed their expiry date.",
            score_contribution=25,
        ))
        score += 25

    if has_near_expiry_secret and not has_expired_secret:
        signals.append(Signal(
            key="near_expiry_secret",
            severity="high",
            title=f"Client secret expiring within {NEAR_EXPIRY_DAYS} days",
            detail="A client secret is nearing expiry — rotate before it causes authentication failures.",
            score_contribution=15,
        ))
        score += 15

    if has_near_expiry_cert and not has_expired_cert:
        signals.append(Signal(
            key="near_expiry_cert",
            severity="high",
            title=f"Certificate expiring within {NEAR_EXPIRY_DAYS} days",
            detail="A certificate is nearing expiry — rotate before it causes authentication failures.",
            score_contribution=15,
        ))
        score += 15

    # ── Signal: long-lived secrets (>1 year) ──────────────────────────────
    long_lived = [
        c for c in password_creds
        if (end_dt := _parse_dt(c.get("endDateTime")))
        and (start_dt := _parse_dt(c.get("startDateTime")))
        and (end_dt - start_dt).days > 365
    ]
    if long_lived:
        signals.append(Signal(
            key="long_lived_secret",
            severity="low",
            title=f"Long-lived client secret(s) — {len(long_lived)} credential(s) valid >1 year",
            detail="Secrets with lifetimes over one year increase the blast radius of a credential compromise.",
            score_contribution=5,
        ))
        score += 5

    # ── Signal: high-privilege + stale ────────────────────────────────────
    has_high_privilege = any(
        perm.get("appRoleId") in HIGH_PRIVILEGE_ROLE_IDS
        for perm in app_permissions
    )
    stale_signal = any(s.key in ("stale", "never_signed_in") for s in signals)
    if has_high_privilege and stale_signal:
        signals.append(Signal(
            key="high_privilege_stale",
            severity="critical",
            title="High-privilege permissions on a stale app",
            detail=(
                "This app holds elevated Microsoft Graph permissions (e.g., Directory.ReadWrite.All, "
                "User.ReadWrite.All) but shows no recent sign-in activity. This is a significant "
                "security risk if the app or its credentials are compromised."
            ),
            score_contribution=25,
        ))
        score += 25

    # ── Signal: tool artifact ─────────────────────────────────────────────
    if is_tool_artifact:
        signals.append(Signal(
            key="tool_artifact",
            severity="info",
            title="Enterprise-Zapp scan app",
            detail=(
                "This app was created by Enterprise-Zapp's setup.ps1 script. "
                "Remember to delete it after your audit is complete to avoid "
                "leaving unused credentials in your tenant."
            ),
            score_contribution=0,
        ))

    # Cap score at 100
    score = min(score, 100)

    return AppResult(
        sp_id=sp_id,
        app_id=app_id,
        display_name=display_name,
        account_enabled=account_enabled,
        sp_type=sp_type,
        created_datetime=sp.get("createdDateTime"),
        last_sign_in=last_sign_in_raw,
        days_since_sign_in=days_since,
        owner_count=len(owners),
        assignment_count=len(assignments),
        has_expired_secret=has_expired_secret,
        has_expired_cert=has_expired_cert,
        has_near_expiry_secret=has_near_expiry_secret,
        has_near_expiry_cert=has_near_expiry_cert,
        has_high_privilege=has_high_privilege,
        signals=signals,
        risk_score=score,
        risk_band=_risk_band(score),
        primary_recommendation=_primary_recommendation(signals, account_enabled),
        tags=sp.get("tags", []),
        is_microsoft_first_party=is_microsoft_first_party,
        is_tool_artifact=is_tool_artifact,
        description=sp.get("description") or None,
        notes=sp.get("notes") or None,
        owners=owners,
        password_credentials=password_creds,
        key_credentials=key_creds,
        delegated_grants=delegated_grants,
        app_permissions=app_permissions,
    )


def analyze_all(raw_data: dict, stale_days: int = DEFAULT_STALE_DAYS) -> list[AppResult]:
    """Analyze all apps from collected raw data. Returns sorted list (highest risk first)."""
    results = [analyze_app(sp, stale_days) for sp in raw_data.get("apps", [])]
    return sorted(results, key=lambda r: (-r.risk_score, r.display_name.lower()))


def band_counts(results: list[AppResult]) -> dict[str, int]:
    """Return a dict of risk band → count."""
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0}
    for r in results:
        counts[r.risk_band] = counts.get(r.risk_band, 0) + 1
    return counts
