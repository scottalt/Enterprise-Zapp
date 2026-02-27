"""
Unit tests for src/analyzer.py.

Uses mock SP data from tests/fixtures/sample_sps.json.
No network calls are made.
"""

import json
from pathlib import Path

import pytest

from src.analyzer import (
    analyze_app,
    analyze_all,
    band_counts,
    AppResult,
    _risk_band,
    _days_since,
    _days_until,
    _parse_dt,
)

FIXTURES = Path(__file__).parent / "fixtures" / "sample_sps.json"

# A minimal but complete SP dict that produces zero signals when passed to analyze_app.
# New test classes build on this by spreading it and overriding specific fields.
BASE_SP: dict = {
    "id": "test-sp-id",
    "appId": "test-app-id",
    "displayName": "Test App",
    "accountEnabled": True,
    "servicePrincipalType": "Application",
    "tags": [],
    "createdDateTime": "2024-01-01T00:00:00Z",
    "passwordCredentials": [],
    "keyCredentials": [],
    "replyUrls": [],
    "_assignments": [{"id": "assign-test", "principalType": "User"}],
    "_owners": [{"id": "owner-1", "displayName": "Test Owner", "accountEnabled": True}],
    "_delegatedGrants": [],
    "_appPermissions": [],
    # Empty sign-in block with no lastSignInActivity — avoids never_signed_in trigger
    "_signInActivity": {},
    "_disabledOwnerIds": [],
}


@pytest.fixture
def sample_sps():
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


@pytest.fixture
def healthy_app(sample_sps):
    return sample_sps[0]  # "Healthy App"


@pytest.fixture
def stale_no_owners(sample_sps):
    return sample_sps[1]  # "Stale App With No Owners"


@pytest.fixture
def expired_secret_app(sample_sps):
    return sample_sps[2]  # "App With Expired Secret"


@pytest.fixture
def high_privilege_stale(sample_sps):
    return sample_sps[3]  # "High Privilege Stale App"


@pytest.fixture
def never_signed_in(sample_sps):
    return sample_sps[4]  # "Never Signed In App"


@pytest.fixture
def disabled_sp(sample_sps):
    return sample_sps[5]  # "Disabled SP Not Deleted"


# ── _risk_band ─────────────────────────────────────────────────────────────────


class TestRiskBand:
    def test_critical_boundary(self):
        assert _risk_band(75) == "critical"
        assert _risk_band(100) == "critical"

    def test_high_boundary(self):
        assert _risk_band(50) == "high"
        assert _risk_band(74) == "high"

    def test_medium_boundary(self):
        assert _risk_band(25) == "medium"
        assert _risk_band(49) == "medium"

    def test_low_boundary(self):
        assert _risk_band(1) == "low"
        assert _risk_band(24) == "low"

    def test_clean(self):
        assert _risk_band(0) == "clean"


# ── _parse_dt ──────────────────────────────────────────────────────────────────


class TestParseDt:
    def test_iso_with_z(self):
        dt = _parse_dt("2025-01-01T00:00:00Z")
        assert dt is not None
        assert dt.year == 2025

    def test_iso_with_offset(self):
        dt = _parse_dt("2025-06-15T12:30:00+00:00")
        assert dt is not None
        assert dt.month == 6

    def test_none_input(self):
        assert _parse_dt(None) is None

    def test_empty_string(self):
        assert _parse_dt("") is None

    def test_invalid_format(self):
        assert _parse_dt("not-a-date") is None


# ── Healthy app ────────────────────────────────────────────────────────────────


class TestHealthyApp:
    def test_no_signals(self, healthy_app):
        result = analyze_app(healthy_app, stale_days=90)
        assert result.risk_score == 0
        assert result.risk_band == "clean"
        assert result.signals == []
        assert result.has_expired_secret is False
        assert result.has_expired_cert is False

    def test_has_owner(self, healthy_app):
        result = analyze_app(healthy_app, stale_days=90)
        assert result.owner_count == 1

    def test_has_assignment(self, healthy_app):
        result = analyze_app(healthy_app, stale_days=90)
        assert result.assignment_count == 1


# ── Stale app with no owners ───────────────────────────────────────────────────


class TestStaleNoOwners:
    def test_stale_signal_present(self, stale_no_owners):
        result = analyze_app(stale_no_owners, stale_days=90)
        signal_keys = {s.key for s in result.signals}
        assert "stale" in signal_keys

    def test_no_owners_signal(self, stale_no_owners):
        result = analyze_app(stale_no_owners, stale_days=90)
        signal_keys = {s.key for s in result.signals}
        assert "no_owners" in signal_keys

    def test_score_elevated(self, stale_no_owners):
        result = analyze_app(stale_no_owners, stale_days=90)
        assert result.risk_score >= 50  # stale(30) + no_owners(20)

    def test_no_assignments_signal(self, stale_no_owners):
        result = analyze_app(stale_no_owners, stale_days=90)
        signal_keys = {s.key for s in result.signals}
        assert "no_assignments" in signal_keys


# ── Expired secret ─────────────────────────────────────────────────────────────


class TestExpiredSecret:
    def test_expired_secret_detected(self, expired_secret_app):
        result = analyze_app(expired_secret_app, stale_days=90)
        assert result.has_expired_secret is True

    def test_expired_secret_signal(self, expired_secret_app):
        result = analyze_app(expired_secret_app, stale_days=90)
        signal_keys = {s.key for s in result.signals}
        assert "expired_secret" in signal_keys

    def test_score_includes_expired(self, expired_secret_app):
        result = analyze_app(expired_secret_app, stale_days=90)
        assert result.risk_score >= 25

    def test_signal_severity_critical(self, expired_secret_app):
        result = analyze_app(expired_secret_app, stale_days=90)
        expired_sigs = [s for s in result.signals if s.key == "expired_secret"]
        assert expired_sigs[0].severity == "critical"


# ── High privilege stale ───────────────────────────────────────────────────────


class TestHighPrivilegeStale:
    def test_high_privilege_flag(self, high_privilege_stale):
        result = analyze_app(high_privilege_stale, stale_days=90)
        assert result.has_high_privilege is True

    def test_combined_signal(self, high_privilege_stale):
        result = analyze_app(high_privilege_stale, stale_days=90)
        signal_keys = {s.key for s in result.signals}
        assert "high_privilege_stale" in signal_keys

    def test_critical_band(self, high_privilege_stale):
        result = analyze_app(high_privilege_stale, stale_days=90)
        assert result.risk_band in ("critical", "high")


# ── Never signed in ────────────────────────────────────────────────────────────


class TestNeverSignedIn:
    def test_never_signed_in_signal(self, never_signed_in):
        result = analyze_app(never_signed_in, stale_days=90)
        signal_keys = {s.key for s in result.signals}
        assert "never_signed_in" in signal_keys

    def test_last_sign_in_is_none(self, never_signed_in):
        result = analyze_app(never_signed_in, stale_days=90)
        assert result.last_sign_in is None or result.last_sign_in == ""

    def test_disabled_owner_signal(self, never_signed_in):
        result = analyze_app(never_signed_in, stale_days=90)
        signal_keys = {s.key for s in result.signals}
        assert "disabled_owner" in signal_keys


# ── Disabled SP ───────────────────────────────────────────────────────────────


class TestDisabledSP:
    def test_disabled_sp_signal(self, disabled_sp):
        result = analyze_app(disabled_sp, stale_days=90)
        signal_keys = {s.key for s in result.signals}
        assert "disabled_sp" in signal_keys

    def test_account_enabled_false(self, disabled_sp):
        result = analyze_app(disabled_sp, stale_days=90)
        assert result.account_enabled is False

    def test_no_assignments_not_flagged_when_disabled(self, disabled_sp):
        # When disabled, no_assignments signal should NOT fire (it's irrelevant)
        result = analyze_app(disabled_sp, stale_days=90)
        signal_keys = {s.key for s in result.signals}
        assert "no_assignments" not in signal_keys


# ── analyze_all ────────────────────────────────────────────────────────────────


class TestAnalyzeAll:
    def test_returns_all_apps(self, sample_sps):
        raw = {"apps": sample_sps}
        results = analyze_all(raw)
        assert len(results) == len(sample_sps)

    def test_sorted_by_risk_desc(self, sample_sps):
        raw = {"apps": sample_sps}
        results = analyze_all(raw)
        scores = [r.risk_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_empty_apps(self):
        results = analyze_all({"apps": []})
        assert results == []


# ── band_counts ────────────────────────────────────────────────────────────────


class TestBandCounts:
    def test_counts_sum_to_total(self, sample_sps):
        raw = {"apps": sample_sps}
        results = analyze_all(raw)
        counts = band_counts(results)
        total = sum(counts.values())
        assert total == len(sample_sps)

    def test_all_bands_present(self, sample_sps):
        raw = {"apps": sample_sps}
        results = analyze_all(raw)
        counts = band_counts(results)
        for band in ("critical", "high", "medium", "low", "clean"):
            assert band in counts

    def test_no_results_gives_zeros(self):
        counts = band_counts([])
        assert all(v == 0 for v in counts.values())


# ── Score cap ──────────────────────────────────────────────────────────────────


class TestScoreCap:
    def test_score_never_exceeds_100(self, sample_sps):
        raw = {"apps": sample_sps}
        results = analyze_all(raw)
        for r in results:
            assert r.risk_score <= 100

    def test_score_never_negative(self, sample_sps):
        raw = {"apps": sample_sps}
        results = analyze_all(raw)
        for r in results:
            assert r.risk_score >= 0


# ── Near expiry credentials ────────────────────────────────────────────────────


class TestNearExpiry:
    def _make_sp_with_secret(self, days_until_expiry: int) -> dict:
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=30)
        end = now + timedelta(days=days_until_expiry)
        return {
            **BASE_SP,
            "passwordCredentials": [
                {
                    "keyId": "test-key",
                    "displayName": "test-secret",
                    "startDateTime": start.isoformat(),
                    "endDateTime": end.isoformat(),
                }
            ],
        }

    def test_near_expiry_secret_within_30_days(self):
        sp = self._make_sp_with_secret(15)
        result = analyze_app(sp)
        assert result.has_near_expiry_secret
        assert any(s.key == "near_expiry_secret" for s in result.signals)
        assert any(s.severity == "high" for s in result.signals if s.key == "near_expiry_secret")

    def test_expiry_warning_secret_30_to_90_days(self):
        sp = self._make_sp_with_secret(60)
        result = analyze_app(sp)
        assert result.has_expiry_warning_secret
        assert any(s.key == "expiry_warning_secret" for s in result.signals)
        assert any(s.severity == "medium" for s in result.signals if s.key == "expiry_warning_secret")
        assert not result.has_near_expiry_secret

    def test_no_expiry_signal_when_far_future(self):
        sp = self._make_sp_with_secret(120)
        result = analyze_app(sp)
        assert not result.has_near_expiry_secret
        assert not result.has_expiry_warning_secret
        assert not result.has_expired_secret


# ── Long-lived secrets ─────────────────────────────────────────────────────────


class TestLongLivedSecret:
    def test_long_lived_secret_detected(self):
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=400)
        end = now + timedelta(days=100)
        sp = {
            **BASE_SP,
            "passwordCredentials": [
                {
                    "keyId": "test-key",
                    "displayName": "old-secret",
                    "startDateTime": start.isoformat(),
                    "endDateTime": end.isoformat(),
                }
            ],
        }
        result = analyze_app(sp)
        assert any(s.key == "long_lived_secret" for s in result.signals)
        assert any(s.severity == "low" for s in result.signals if s.key == "long_lived_secret")
        assert any(s.score_contribution == 15 for s in result.signals if s.key == "long_lived_secret")

    def test_short_lived_secret_not_flagged(self):
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=30)
        end = now + timedelta(days=60)
        sp = {
            **BASE_SP,
            "passwordCredentials": [
                {
                    "keyId": "test-key",
                    "displayName": "fresh-secret",
                    "startDateTime": start.isoformat(),
                    "endDateTime": end.isoformat(),
                }
            ],
        }
        result = analyze_app(sp)
        assert not any(s.key == "long_lived_secret" for s in result.signals)


# ── Microsoft first-party apps ─────────────────────────────────────────────────


class TestMicrosoftFirstParty:
    def test_microsoft_app_flagged(self):
        sp = {**BASE_SP, "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a"}
        result = analyze_app(sp)
        assert result.is_microsoft_first_party

    def test_non_microsoft_app_not_flagged(self):
        sp = {**BASE_SP, "appOwnerOrganizationId": "some-other-tenant-id"}
        result = analyze_app(sp)
        assert not result.is_microsoft_first_party


# ── Tool artifact apps ─────────────────────────────────────────────────────────


class TestToolArtifact:
    def test_tool_artifact_detected(self):
        sp = {**BASE_SP, "displayName": "Enterprise-Zapp-Scan-2026-01-01"}
        result = analyze_app(sp)
        assert result.is_tool_artifact
        assert any(s.key == "tool_artifact" for s in result.signals)
        assert any(s.severity == "info" for s in result.signals if s.key == "tool_artifact")
        # Tool artifact signal has no score contribution
        assert any(s.score_contribution == 0 for s in result.signals if s.key == "tool_artifact")

    def test_non_artifact_not_flagged(self):
        sp = {**BASE_SP, "displayName": "My Normal App"}
        result = analyze_app(sp)
        assert not result.is_tool_artifact


# ── Stale days parameter ───────────────────────────────────────────────────────


class TestStaleDaysParameter:
    def _make_sp_with_last_signin(self, days_ago: int) -> dict:
        from datetime import datetime, timezone, timedelta
        last_signin = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
        return {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": last_signin}
            },
        }

    def test_stale_at_default_threshold(self):
        sp = self._make_sp_with_last_signin(100)
        result = analyze_app(sp, stale_days=90)
        assert any(s.key == "stale" for s in result.signals)

    def test_not_stale_within_threshold(self):
        sp = self._make_sp_with_last_signin(80)
        result = analyze_app(sp, stale_days=90)
        assert not any(s.key == "stale" for s in result.signals)

    def test_custom_stale_days_tighter(self):
        sp = self._make_sp_with_last_signin(40)
        result_tight = analyze_app(sp, stale_days=30)
        result_loose = analyze_app(sp, stale_days=90)
        assert any(s.key == "stale" for s in result_tight.signals)
        assert not any(s.key == "stale" for s in result_loose.signals)


# ── Owner signal mutual exclusivity ───────────────────────────────────────────


class TestOwnerSignals:
    def test_no_owners_and_disabled_owner_mutually_exclusive(self):
        """no_owners and disabled_owner signals should never both fire for the same app."""
        # App with no owners at all
        sp_no_owners = {**BASE_SP, "_owners": [], "_disabledOwnerIds": []}
        result_no_owners = analyze_app(sp_no_owners)
        has_no_owners = any(s.key == "no_owners" for s in result_no_owners.signals)
        has_disabled = any(s.key == "disabled_owner" for s in result_no_owners.signals)
        assert has_no_owners
        assert not has_disabled

        # App with one disabled owner
        sp_disabled_owner = {
            **BASE_SP,
            "_owners": [{"id": "dead-user-id", "displayName": "Gone User", "accountEnabled": False}],
            "_disabledOwnerIds": ["dead-user-id"],
        }
        result_disabled = analyze_app(sp_disabled_owner)
        has_no_owners_2 = any(s.key == "no_owners" for s in result_disabled.signals)
        has_disabled_2 = any(s.key == "disabled_owner" for s in result_disabled.signals)
        assert not has_no_owners_2
        assert has_disabled_2
