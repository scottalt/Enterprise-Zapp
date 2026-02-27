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
        assert result.risk_band == "clean" or result.risk_score < 25
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
