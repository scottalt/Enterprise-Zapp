"""
Unit tests for src/ca_analyzer.py.

No mocks needed — ca_analyzer.py contains pure functions only.
"""

import pytest

from src.ca_analyzer import (
    analyze_ca_coverage,
    PolicySummary,
    AppCoverage,
    _parse_policies,
)


# ── Fixtures ───────────────────────────────────────────────────────────────────


def _make_policy(
    *,
    policy_id: str = "policy-1",
    display_name: str = "Test Policy",
    state: str = "enabled",
    include_apps: list | None = None,
    exclude_apps: list | None = None,
) -> dict:
    """Return a minimal CA policy dict suitable for testing."""
    return {
        "id": policy_id,
        "displayName": display_name,
        "state": state,
        "conditions": {
            "applications": {
                "includeApplications": include_apps if include_apps is not None else ["All"],
                "excludeApplications": exclude_apps if exclude_apps is not None else [],
            }
        },
        "createdDateTime": "2024-01-01T00:00:00Z",
        "modifiedDateTime": "2024-06-01T00:00:00Z",
    }


def _make_app(*, app_id: str = "app-aaa", display_name: str = "Test App") -> dict:
    """Return a minimal enriched SP dict suitable for testing."""
    return {
        "appId": app_id,
        "displayName": display_name,
    }


# ── analyze_ca_coverage ────────────────────────────────────────────────────────


class TestIncludeAllApps:
    """Policy with includeApplications: ['All'] covers every app."""

    def test_all_apps_covered_by_include_all(self):
        policy = _make_policy(state="enabled", include_apps=["All"])
        apps = [
            _make_app(app_id="app-001", display_name="First App"),
            _make_app(app_id="app-002", display_name="Second App"),
        ]
        coverages, _ = analyze_ca_coverage([policy], apps)
        assert len(coverages) == 2
        assert all(c.is_covered for c in coverages)

    def test_policy_name_captured_for_covered_apps(self):
        policy = _make_policy(display_name="Global Policy", state="enabled", include_apps=["All"])
        apps = [_make_app(app_id="app-001")]
        coverages, _ = analyze_ca_coverage([policy], apps)
        assert "Global Policy" in coverages[0].policy_names


class TestExcludeApplications:
    """Apps in excludeApplications must not be counted as covered, even if 'All' is in include."""

    def test_excluded_app_not_covered(self):
        excluded_id = "app-excluded"
        policy = _make_policy(
            state="enabled",
            include_apps=["All"],
            exclude_apps=[excluded_id],
        )
        apps = [
            _make_app(app_id=excluded_id, display_name="Excluded App"),
            _make_app(app_id="app-other", display_name="Other App"),
        ]
        coverages, _ = analyze_ca_coverage([policy], apps)
        by_id = {c.app_id: c for c in coverages}
        assert not by_id[excluded_id].is_covered
        assert by_id["app-other"].is_covered

    def test_excluded_app_has_empty_policy_names(self):
        excluded_id = "app-excluded"
        policy = _make_policy(
            state="enabled",
            include_apps=["All"],
            exclude_apps=[excluded_id],
        )
        apps = [_make_app(app_id=excluded_id)]
        coverages, _ = analyze_ca_coverage([policy], apps)
        assert coverages[0].policy_names == []


class TestDisabledPolicy:
    """A disabled policy must not contribute coverage."""

    def test_disabled_policy_does_not_cover_apps(self):
        policy = _make_policy(state="disabled", include_apps=["All"])
        apps = [_make_app(app_id="app-001")]
        coverages, _ = analyze_ca_coverage([policy], apps)
        assert not coverages[0].is_covered

    def test_disabled_policy_still_appears_in_summaries(self):
        policy = _make_policy(state="disabled", include_apps=["All"])
        _, summaries = analyze_ca_coverage([policy], [])
        assert len(summaries) == 1
        assert summaries[0].state == "disabled"
        assert not summaries[0].is_enforced


class TestReportOnlyPolicy:
    """A report-only (enabledForReportingButNotEnforced) policy must not contribute coverage."""

    def test_report_only_does_not_cover_apps(self):
        policy = _make_policy(
            state="enabledForReportingButNotEnforced",
            include_apps=["All"],
        )
        apps = [_make_app(app_id="app-001")]
        coverages, _ = analyze_ca_coverage([policy], apps)
        assert not coverages[0].is_covered

    def test_report_only_still_appears_in_summaries(self):
        policy = _make_policy(state="enabledForReportingButNotEnforced")
        _, summaries = analyze_ca_coverage([policy], [])
        assert len(summaries) == 1
        assert not summaries[0].is_enforced


class TestSpecificAppIds:
    """Enabled policy with specific app IDs only covers listed apps."""

    def test_listed_app_is_covered(self):
        covered_id = "app-covered"
        policy = _make_policy(state="enabled", include_apps=[covered_id])
        apps = [_make_app(app_id=covered_id)]
        coverages, _ = analyze_ca_coverage([policy], apps)
        assert coverages[0].is_covered

    def test_unlisted_app_is_not_covered(self):
        covered_id = "app-covered"
        other_id = "app-other"
        policy = _make_policy(state="enabled", include_apps=[covered_id])
        apps = [
            _make_app(app_id=covered_id, display_name="Covered App"),
            _make_app(app_id=other_id, display_name="Other App"),
        ]
        coverages, _ = analyze_ca_coverage([policy], apps)
        by_id = {c.app_id: c for c in coverages}
        assert by_id[covered_id].is_covered
        assert not by_id[other_id].is_covered


class TestEmptyPolicies:
    """Empty ca_policies list produces zero coverage for all apps."""

    def test_no_policies_means_no_coverage(self):
        apps = [
            _make_app(app_id="app-001"),
            _make_app(app_id="app-002"),
        ]
        coverages, summaries = analyze_ca_coverage([], apps)
        assert len(coverages) == 2
        assert all(not c.is_covered for c in coverages)
        assert summaries == []


class TestMultiplePoliciesCoverage:
    """App covered by multiple policies has all covering policy names listed."""

    def test_multiple_policy_names_captured(self):
        policy_a = _make_policy(policy_id="pol-a", display_name="Policy A", state="enabled", include_apps=["All"])
        policy_b = _make_policy(policy_id="pol-b", display_name="Policy B", state="enabled", include_apps=["All"])
        apps = [_make_app(app_id="app-001")]
        coverages, _ = analyze_ca_coverage([policy_a, policy_b], apps)
        assert coverages[0].is_covered
        assert "Policy A" in coverages[0].policy_names
        assert "Policy B" in coverages[0].policy_names
        assert len(coverages[0].policy_names) == 2


class TestCaseInsensitiveAppIdMatching:
    """App IDs are matched case-insensitively."""

    def test_uppercase_include_matches_lowercase_app_id(self):
        # Policy has uppercase app ID; app dict has lowercase
        app_id_upper = "APP-CASE-001"
        app_id_lower = "app-case-001"
        policy = _make_policy(state="enabled", include_apps=[app_id_upper])
        apps = [_make_app(app_id=app_id_lower, display_name="Case App")]
        coverages, _ = analyze_ca_coverage([policy], apps)
        assert coverages[0].is_covered

    def test_mixed_case_exclude_matches_lowercase_app_id(self):
        app_id_upper = "APP-EXCLUDE-001"
        app_id_lower = "app-exclude-001"
        policy = _make_policy(
            state="enabled",
            include_apps=["All"],
            exclude_apps=[app_id_upper],
        )
        apps = [_make_app(app_id=app_id_lower)]
        coverages, _ = analyze_ca_coverage([policy], apps)
        assert not coverages[0].is_covered


class TestEmptyApps:
    """Empty apps list returns empty coverage list."""

    def test_no_apps_returns_empty_coverage(self):
        policy = _make_policy(state="enabled", include_apps=["All"])
        coverages, summaries = analyze_ca_coverage([policy], [])
        assert coverages == []
        assert len(summaries) == 1  # policy is still parsed


# ── PolicySummary properties ───────────────────────────────────────────────────


class TestPolicySummaryProperties:
    """state_label and state_css return correct values."""

    def _make_summary(self, state: str) -> PolicySummary:
        return PolicySummary(
            policy_id="test-id",
            display_name="Test",
            state=state,
            includes_all_apps=True,
            included_app_ids=[],
            excluded_app_ids=[],
            created_datetime=None,
            modified_datetime=None,
        )

    def test_enabled_state_label(self):
        s = self._make_summary("enabled")
        assert s.state_label == "Enabled"

    def test_enabled_state_css(self):
        s = self._make_summary("enabled")
        assert s.state_css == "ca-state-enabled"

    def test_disabled_state_label(self):
        s = self._make_summary("disabled")
        assert s.state_label == "Disabled"

    def test_disabled_state_css(self):
        s = self._make_summary("disabled")
        assert s.state_css == "ca-state-disabled"

    def test_report_only_state_label(self):
        s = self._make_summary("enabledForReportingButNotEnforced")
        assert s.state_label == "Report-only"

    def test_report_only_state_css(self):
        s = self._make_summary("enabledForReportingButNotEnforced")
        assert s.state_css == "ca-state-report"

    def test_unknown_state_label_falls_back_to_state_value(self):
        s = self._make_summary("unknownState")
        assert s.state_label == "unknownState"

    def test_unknown_state_css_returns_empty_string(self):
        s = self._make_summary("unknownState")
        assert s.state_css == ""

    def test_is_enforced_true_for_enabled(self):
        s = self._make_summary("enabled")
        assert s.is_enforced is True

    def test_is_enforced_false_for_disabled(self):
        s = self._make_summary("disabled")
        assert s.is_enforced is False

    def test_is_enforced_false_for_report_only(self):
        s = self._make_summary("enabledForReportingButNotEnforced")
        assert s.is_enforced is False
