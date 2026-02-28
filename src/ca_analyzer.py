"""
Conditional Access coverage analysis for Enterprise-Zapp.

Cross-references enabled CA policies against the tenant's enterprise apps
to determine which apps are protected by at least one enforced CA policy.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class PolicySummary:
    """Summarised view of a single CA policy."""

    policy_id: str
    display_name: str
    state: str  # enabled | disabled | enabledForReportingButNotEnforced
    includes_all_apps: bool
    included_app_ids: list[str]
    excluded_app_ids: list[str]
    created_datetime: str | None
    modified_datetime: str | None

    @property
    def is_enforced(self) -> bool:
        return self.state == "enabled"

    @property
    def state_label(self) -> str:
        return {
            "enabled": "Enabled",
            "disabled": "Disabled",
            "enabledForReportingButNotEnforced": "Report-only",
        }.get(self.state, self.state)

    @property
    def state_css(self) -> str:
        return {
            "enabled": "ca-state-enabled",
            "disabled": "ca-state-disabled",
            "enabledForReportingButNotEnforced": "ca-state-report",
        }.get(self.state, "")


@dataclass
class AppCoverage:
    """CA coverage status for a single enterprise application."""

    app_id: str
    display_name: str
    is_covered: bool
    policy_names: list[str] = field(default_factory=list)


def _parse_policies(ca_policies: list[dict]) -> list[PolicySummary]:
    """Convert raw Graph CA policy dicts into PolicySummary objects."""
    summaries = []
    for p in ca_policies:
        conditions = p.get("conditions", {})
        apps_cond = conditions.get("applications", {})
        include_apps: list[str] = apps_cond.get("includeApplications", [])
        exclude_apps: list[str] = apps_cond.get("excludeApplications", [])
        includes_all = any(a.lower() in ("all",) for a in include_apps)
        summaries.append(
            PolicySummary(
                policy_id=p.get("id", ""),
                display_name=p.get("displayName", "(unnamed)"),
                state=p.get("state", "disabled"),
                includes_all_apps=includes_all,
                included_app_ids=[a.lower() for a in include_apps if a.lower() not in ("all", "none")],
                excluded_app_ids=[a.lower() for a in exclude_apps],
                created_datetime=p.get("createdDateTime"),
                modified_datetime=p.get("modifiedDateTime"),
            )
        )
    return summaries


def analyze_ca_coverage(
    ca_policies: list[dict],
    apps: list[dict],
) -> tuple[list[AppCoverage], list[PolicySummary]]:
    """
    Analyse CA coverage for each enterprise app.

    Parameters
    ----------
    ca_policies:
        Raw CA policy objects from the Graph API (may be empty if permission absent).
    apps:
        Enriched service principal dicts from the collector.

    Returns
    -------
    app_coverages:
        Per-app coverage results for all apps.
    policy_summaries:
        Parsed and summarised policy objects (all states).
    """
    policy_summaries = _parse_policies(ca_policies)
    enforced = [p for p in policy_summaries if p.is_enforced]

    app_coverages: list[AppCoverage] = []
    for app in apps:
        app_id = app.get("appId", "").lower()
        display_name = app.get("displayName", "(unnamed)")
        covering: list[str] = []

        for policy in enforced:
            # Determine whether this app falls inside the policy's include set
            if policy.includes_all_apps:
                included = True
            else:
                included = app_id in policy.included_app_ids

            if not included:
                continue

            # Skip if the app is explicitly excluded
            if app_id in policy.excluded_app_ids:
                continue

            covering.append(policy.display_name)

        app_coverages.append(
            AppCoverage(
                app_id=app_id,
                display_name=display_name,
                is_covered=bool(covering),
                policy_names=covering,
            )
        )

    return app_coverages, policy_summaries
