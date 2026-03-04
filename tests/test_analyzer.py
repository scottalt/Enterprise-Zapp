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
    "_assignments": [],
    "_owners": [{"id": "owner-1", "displayName": "Test Owner", "accountEnabled": True}],
    "_delegatedGrants": [],
    "_appPermissions": [{"id": "assign-test", "principalType": "User"}],
    # Empty sign-in block with no lastSignInActivity — avoids never_signed_in trigger
    "_signInActivity": {},
    "_disabledOwnerIds": [],
}


@pytest.fixture
def sample_sps():
    return json.loads(FIXTURES.read_text(encoding="utf-8"))


@pytest.fixture
def healthy_app(sample_sps):
    from datetime import datetime, timezone, timedelta
    app = dict(sample_sps[0])
    app["_signInActivity"] = {
        "lastSignInActivity": {
            "lastSignInDateTime": (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        }
    }
    return app


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
        sp = {**BASE_SP, "displayName": "Enterprise-Zapp"}
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

    def test_not_stale_at_exact_boundary(self):
        # Condition is strict `>`, so exactly stale_days ago is NOT stale.
        stale_days = 90
        sp = self._make_sp_with_last_signin(stale_days)
        result = analyze_app(sp, stale_days=stale_days)
        assert not any(s.key == "stale" for s in result.signals)

    def test_stale_one_day_past_boundary(self):
        # stale_days + 1 days ago IS stale.
        stale_days = 90
        sp = self._make_sp_with_last_signin(stale_days + 1)
        result = analyze_app(sp, stale_days=stale_days)
        assert any(s.key == "stale" for s in result.signals)


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


# ── Redirect URIs ──────────────────────────────────────────────────────────────


class TestRedirectURI:
    def test_localhost_redirect_flagged(self):
        sp = {**BASE_SP, "replyUrls": ["http://localhost/callback"]}
        result = analyze_app(sp)
        assert result.has_wildcard_redirect
        assert any(s.key == "wildcard_redirect_uri" for s in result.signals)

    def test_wildcard_redirect_flagged(self):
        sp = {**BASE_SP, "replyUrls": ["https://app.com/*"]}
        result = analyze_app(sp)
        assert result.has_wildcard_redirect
        assert any(s.key == "wildcard_redirect_uri" for s in result.signals)

    def test_no_reply_urls_with_credentials(self):
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        sp = {
            **BASE_SP,
            "replyUrls": [],
            "passwordCredentials": [
                {
                    "keyId": "cred-1",
                    "displayName": "test secret",
                    "startDateTime": (now - timedelta(days=30)).isoformat(),
                    "endDateTime": (now + timedelta(days=60)).isoformat(),
                }
            ],
        }
        result = analyze_app(sp)
        assert result.has_no_reply_urls
        assert any(s.key == "no_reply_urls" for s in result.signals)

    def test_no_reply_urls_without_credentials(self):
        # No creds, no replyUrls — should NOT fire no_reply_urls signal
        sp = {**BASE_SP, "replyUrls": [], "passwordCredentials": [], "keyCredentials": []}
        result = analyze_app(sp)
        assert not result.has_no_reply_urls
        assert not any(s.key == "no_reply_urls" for s in result.signals)

    def test_clean_redirect_uri(self):
        sp = {**BASE_SP, "replyUrls": ["https://app.contoso.com/callback"]}
        result = analyze_app(sp)
        assert not result.has_wildcard_redirect
        assert not any(s.key == "wildcard_redirect_uri" for s in result.signals)


# ── Delegated permissions ──────────────────────────────────────────────────────


class TestDelegatedPermissions:
    def test_excessive_delegated_non_stale(self):
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": recent}
            },
            "_delegatedGrants": [
                {"scope": "Directory.ReadWrite.All openid profile"}
            ],
        }
        result = analyze_app(sp)
        assert result.has_excessive_delegated
        delegated_sigs = [s for s in result.signals if s.key == "excessive_delegated_permissions"]
        assert len(delegated_sigs) == 1
        assert delegated_sigs[0].severity == "high"

    def test_excessive_delegated_stale(self):
        from datetime import datetime, timezone, timedelta
        stale = (datetime.now(timezone.utc) - timedelta(days=120)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": stale}
            },
            "_delegatedGrants": [
                {"scope": "Directory.ReadWrite.All"}
            ],
        }
        result = analyze_app(sp, stale_days=90)
        assert result.has_excessive_delegated
        delegated_sigs = [s for s in result.signals if s.key == "excessive_delegated_permissions"]
        assert len(delegated_sigs) == 1
        assert delegated_sigs[0].severity == "critical"

    def test_non_privileged_delegated_not_flagged(self):
        sp = {
            **BASE_SP,
            "_delegatedGrants": [
                {"scope": "User.Read openid profile email"}
            ],
        }
        result = analyze_app(sp)
        assert not result.has_excessive_delegated
        assert not any(s.key == "excessive_delegated_permissions" for s in result.signals)


# ── Implicit grant ─────────────────────────────────────────────────────────────


class TestImplicitGrant:
    def test_oauth2_allow_implicit_flow_flagged(self):
        sp = {**BASE_SP, "oauth2AllowImplicitFlow": True}
        result = analyze_app(sp)
        assert result.has_implicit_grant
        assert any(s.key == "implicit_grant_enabled" for s in result.signals)

    def test_id_token_issuance_flagged(self):
        sp = {**BASE_SP, "oauth2AllowIdTokenIssuance": True}
        result = analyze_app(sp)
        assert result.has_implicit_grant
        assert any(s.key == "implicit_grant_enabled" for s in result.signals)

    def test_no_implicit_grant_clean(self):
        sp = {**BASE_SP, "oauth2AllowImplicitFlow": False, "oauth2AllowIdTokenIssuance": False}
        result = analyze_app(sp)
        assert not result.has_implicit_grant
        assert not any(s.key == "implicit_grant_enabled" for s in result.signals)


# ── Multi-tenant apps ──────────────────────────────────────────────────────────


class TestMultiTenant:
    def test_multi_tenant_medium(self):
        sp = {**BASE_SP, "signInAudience": "AzureADMultipleOrgs"}
        result = analyze_app(sp)
        assert result.is_multi_tenant
        multi_sigs = [s for s in result.signals if s.key == "multi_tenant_app"]
        assert len(multi_sigs) == 1
        assert multi_sigs[0].severity == "medium"

    def test_multi_tenant_high_with_privileges(self):
        # AzureADMultipleOrgs + a high-privilege app permission → high severity
        sp = {
            **BASE_SP,
            "signInAudience": "AzureADMultipleOrgs",
            "_assignments": [
                {
                    "appRoleId": "19dbc75e-c2e2-444c-a770-ec69d8559fc7",  # Directory.ReadWrite.All
                    "resourceDisplayName": "Microsoft Graph",
                }
            ],
        }
        result = analyze_app(sp)
        assert result.is_multi_tenant
        assert result.has_high_privilege
        multi_sigs = [s for s in result.signals if s.key == "multi_tenant_app"]
        assert len(multi_sigs) == 1
        assert multi_sigs[0].severity == "high"

    def test_single_tenant_not_flagged(self):
        sp = {**BASE_SP, "signInAudience": "AzureADMyOrg"}
        result = analyze_app(sp)
        assert not result.is_multi_tenant
        assert not any(s.key == "multi_tenant_app" for s in result.signals)

    def test_microsoft_first_party_multi_tenant_not_flagged(self):
        # Microsoft-owned first-party apps are inherently multi-tenant — signal must NOT fire
        sp = {
            **BASE_SP,
            "signInAudience": "AzureADMultipleOrgs",
            "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
        }
        result = analyze_app(sp)
        assert result.is_microsoft_first_party
        assert not any(s.key == "multi_tenant_app" for s in result.signals)


# ── Mixed credentials ──────────────────────────────────────────────────────────


class TestMixedCredentials:
    def _make_secret(self):
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        return {
            "keyId": "secret-1",
            "displayName": "Test Secret",
            "startDateTime": (now - timedelta(days=30)).isoformat(),
            "endDateTime": (now + timedelta(days=60)).isoformat(),
        }

    def _make_cert(self):
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        return {
            "keyId": "cert-1",
            "displayName": "Test Cert",
            "startDateTime": (now - timedelta(days=30)).isoformat(),
            "endDateTime": (now + timedelta(days=60)).isoformat(),
        }

    def test_mixed_credentials_flagged(self):
        sp = {
            **BASE_SP,
            "replyUrls": ["https://app.contoso.com/callback"],
            "passwordCredentials": [self._make_secret()],
            "keyCredentials": [self._make_cert()],
        }
        result = analyze_app(sp)
        assert result.has_mixed_credentials
        assert any(s.key == "mixed_credential_types" for s in result.signals)

    def test_only_secrets_not_mixed(self):
        sp = {
            **BASE_SP,
            "replyUrls": ["https://app.contoso.com/callback"],
            "passwordCredentials": [self._make_secret()],
            "keyCredentials": [],
        }
        result = analyze_app(sp)
        assert not result.has_mixed_credentials
        assert not any(s.key == "mixed_credential_types" for s in result.signals)

    def test_only_certs_not_mixed(self):
        sp = {
            **BASE_SP,
            "replyUrls": ["https://app.contoso.com/callback"],
            "passwordCredentials": [],
            "keyCredentials": [self._make_cert()],
        }
        result = analyze_app(sp)
        assert not result.has_mixed_credentials
        assert not any(s.key == "mixed_credential_types" for s in result.signals)


# ── Staleness: multi-activity-type detection ─────────────────────────────────


class TestStalenessMultiActivity:
    """Staleness should use the most recent sign-in across ALL activity types."""

    def _make_sp_with_sign_in(self, sign_in_activity: dict) -> dict:
        return {
            **BASE_SP,
            "_signInActivity": sign_in_activity,
        }

    def test_non_interactive_prevents_stale(self):
        """App with old interactive but recent non-interactive sign-in is NOT stale."""
        from datetime import datetime, timezone, timedelta
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        sp = self._make_sp_with_sign_in({
            "lastSignInActivity": {
                "lastSignInDateTime": old,
                "lastNonInteractiveSignInDateTime": recent,
            },
        })
        result = analyze_app(sp, stale_days=90)
        assert not any(s.key == "stale" for s in result.signals)
        assert result.days_since_sign_in is not None
        assert result.days_since_sign_in < 90

    def test_app_auth_client_prevents_stale(self):
        """App with recent client_credentials sign-in is NOT stale."""
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = self._make_sp_with_sign_in({
            "lastSignInActivity": {},
            "applicationAuthenticationClientSignInActivity": {
                "lastSignInDateTime": recent,
            },
        })
        result = analyze_app(sp, stale_days=90)
        assert not any(s.key == "stale" for s in result.signals)
        assert not any(s.key == "never_signed_in" for s in result.signals)

    def test_app_auth_resource_prevents_stale(self):
        """App acting as resource with recent activity is NOT stale."""
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=15)).isoformat()
        sp = self._make_sp_with_sign_in({
            "lastSignInActivity": {},
            "applicationAuthenticationResourceSignInActivity": {
                "lastSignInDateTime": recent,
            },
        })
        result = analyze_app(sp, stale_days=90)
        assert not any(s.key == "stale" for s in result.signals)

    def test_delegated_client_prevents_stale(self):
        """App with recent delegated client sign-in is NOT stale."""
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=20)).isoformat()
        sp = self._make_sp_with_sign_in({
            "lastSignInActivity": {},
            "delegatedClientSignInActivity": {
                "lastSignInDateTime": recent,
            },
        })
        result = analyze_app(sp, stale_days=90)
        assert not any(s.key == "stale" for s in result.signals)

    def test_all_activity_old_is_stale(self):
        """App where ALL activity types are old IS stale."""
        from datetime import datetime, timezone, timedelta
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        sp = self._make_sp_with_sign_in({
            "lastSignInActivity": {
                "lastSignInDateTime": old,
                "lastNonInteractiveSignInDateTime": old,
            },
            "applicationAuthenticationClientSignInActivity": {
                "lastSignInDateTime": old,
            },
        })
        result = analyze_app(sp, stale_days=90)
        assert any(s.key == "stale" for s in result.signals)

    def test_picks_most_recent_across_types(self):
        """The most recent date across all types should win."""
        from datetime import datetime, timezone, timedelta
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        medium = (datetime.now(timezone.utc) - timedelta(days=100)).isoformat()
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = self._make_sp_with_sign_in({
            "lastSignInActivity": {
                "lastSignInDateTime": old,
                "lastNonInteractiveSignInDateTime": medium,
            },
            "applicationAuthenticationClientSignInActivity": {
                "lastSignInDateTime": recent,
            },
        })
        result = analyze_app(sp, stale_days=90)
        assert not any(s.key == "stale" for s in result.signals)
        assert result.days_since_sign_in is not None
        assert result.days_since_sign_in < 20


# ── Daemon app detection ─────────────────────────────────────────────────────


class TestDaemonApp:
    """Apps with only application-authentication activity are daemon apps."""

    def test_daemon_app_detected(self):
        """App with only applicationAuthentication activity is flagged as daemon."""
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "_owners": [{"id": "owner-1", "displayName": "Test Owner", "accountEnabled": True}],
            "_appPermissions": [],  # no user assignments
            "_signInActivity": {
                "lastSignInActivity": {},
                "applicationAuthenticationClientSignInActivity": {
                    "lastSignInDateTime": recent,
                },
            },
        }
        result = analyze_app(sp)
        assert result.is_daemon_app

    def test_daemon_app_no_assignments_suppressed(self):
        """Daemon apps should NOT get the no_assignments signal."""
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "_owners": [{"id": "owner-1", "displayName": "Test Owner", "accountEnabled": True}],
            "_appPermissions": [],  # no user assignments
            "_signInActivity": {
                "lastSignInActivity": {},
                "applicationAuthenticationClientSignInActivity": {
                    "lastSignInDateTime": recent,
                },
            },
        }
        result = analyze_app(sp)
        assert result.is_daemon_app
        assert not any(s.key == "no_assignments" for s in result.signals)

    def test_daemon_app_no_reply_urls_suppressed(self):
        """Daemon apps should NOT get the no_reply_urls signal."""
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "replyUrls": [],
            "passwordCredentials": [{
                "keyId": "cred-1",
                "displayName": "daemon secret",
                "startDateTime": (now - timedelta(days=30)).isoformat(),
                "endDateTime": (now + timedelta(days=60)).isoformat(),
            }],
            "_signInActivity": {
                "lastSignInActivity": {},
                "applicationAuthenticationClientSignInActivity": {
                    "lastSignInDateTime": recent,
                },
            },
        }
        result = analyze_app(sp)
        assert result.is_daemon_app
        assert not result.has_no_reply_urls
        assert not any(s.key == "no_reply_urls" for s in result.signals)

    def test_non_daemon_app_not_flagged(self):
        """App with delegated activity is NOT a daemon app."""
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {
                    "lastSignInDateTime": recent,
                },
                "applicationAuthenticationClientSignInActivity": {
                    "lastSignInDateTime": recent,
                },
            },
        }
        result = analyze_app(sp)
        assert not result.is_daemon_app

    def test_no_activity_not_daemon(self):
        """App with no sign-in data at all is NOT classified as daemon."""
        sp = {**BASE_SP, "_signInActivity": {}}
        result = analyze_app(sp)
        assert not result.is_daemon_app


# ── Tiered staleness ─────────────────────────────────────────────────────────


class TestTieredStaleness:
    """Staleness tiers: 90-180 medium, 180-365 high, 365+ critical."""

    def _make_sp_stale(self, days_ago: int) -> dict:
        from datetime import datetime, timezone, timedelta
        last_signin = (datetime.now(timezone.utc) - timedelta(days=days_ago)).isoformat()
        return {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": last_signin}
            },
        }

    def test_90_to_180_is_medium(self):
        sp = self._make_sp_stale(120)
        result = analyze_app(sp, stale_days=90)
        stale_sigs = [s for s in result.signals if s.key == "stale"]
        assert len(stale_sigs) == 1
        assert stale_sigs[0].severity == "medium"
        assert stale_sigs[0].score_contribution == 20

    def test_180_to_365_is_high(self):
        sp = self._make_sp_stale(250)
        result = analyze_app(sp, stale_days=90)
        stale_sigs = [s for s in result.signals if s.key == "stale"]
        assert len(stale_sigs) == 1
        assert stale_sigs[0].severity == "high"
        assert stale_sigs[0].score_contribution == 30

    def test_365_plus_is_critical(self):
        sp = self._make_sp_stale(400)
        result = analyze_app(sp, stale_days=90)
        stale_sigs = [s for s in result.signals if s.key == "stale"]
        assert len(stale_sigs) == 1
        assert stale_sigs[0].severity == "critical"
        assert stale_sigs[0].score_contribution == 40

    def test_abandoned_title_contains_abandoned(self):
        sp = self._make_sp_stale(400)
        result = analyze_app(sp, stale_days=90)
        stale_sigs = [s for s in result.signals if s.key == "stale"]
        assert "Abandoned" in stale_sigs[0].title


# ── Creation-age-aware never_signed_in ────────────────────────────────────────


class TestNeverSignedInGracePeriod:
    """Apps created recently get a lower-severity never_signed_in signal."""

    def test_new_app_gets_low_severity(self):
        from datetime import datetime, timezone, timedelta
        recent_created = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "createdDateTime": recent_created,
            "_signInActivity": {
                "lastSignInActivity": {}
            },
        }
        result = analyze_app(sp)
        nsi = [s for s in result.signals if s.key == "never_signed_in"]
        assert len(nsi) == 1
        assert nsi[0].severity == "low"
        assert nsi[0].score_contribution == 5

    def test_old_app_gets_high_severity(self):
        from datetime import datetime, timezone, timedelta
        old_created = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        sp = {
            **BASE_SP,
            "createdDateTime": old_created,
            "_signInActivity": {
                "lastSignInActivity": {}
            },
        }
        result = analyze_app(sp)
        nsi = [s for s in result.signals if s.key == "never_signed_in"]
        assert len(nsi) == 1
        assert nsi[0].severity == "high"
        assert nsi[0].score_contribution == 35

    def test_grace_period_boundary(self):
        from datetime import datetime, timezone, timedelta
        # Exactly at grace period (30 days) — still within grace
        boundary = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        sp = {
            **BASE_SP,
            "createdDateTime": boundary,
            "_signInActivity": {
                "lastSignInActivity": {}
            },
        }
        result = analyze_app(sp)
        nsi = [s for s in result.signals if s.key == "never_signed_in"]
        assert nsi[0].severity == "low"


# ── Expired creds on stale apps ───────────────────────────────────────────────


class TestExpiredCredsOnStaleApps:
    """Expired credentials on stale/abandoned apps are downgraded to info."""

    def test_expired_secret_on_stale_app_is_info(self):
        from datetime import datetime, timezone, timedelta
        old_signin = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": old_signin}
            },
            "passwordCredentials": [{
                "keyId": "old-key",
                "displayName": "expired secret",
                "startDateTime": (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
                "endDateTime": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
            }],
        }
        result = analyze_app(sp, stale_days=90)
        expired = [s for s in result.signals if s.key == "expired_secret"]
        assert len(expired) == 1
        assert expired[0].severity == "info"
        assert expired[0].score_contribution == 0

    def test_expired_secret_on_active_app_is_critical(self):
        from datetime import datetime, timezone, timedelta
        recent_signin = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": recent_signin}
            },
            "passwordCredentials": [{
                "keyId": "old-key",
                "displayName": "expired secret",
                "startDateTime": (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
                "endDateTime": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
            }],
        }
        result = analyze_app(sp, stale_days=90)
        expired = [s for s in result.signals if s.key == "expired_secret"]
        assert len(expired) == 1
        assert expired[0].severity == "critical"
        assert expired[0].score_contribution == 25

    def test_expired_cert_on_never_signed_in_is_info(self):
        from datetime import datetime, timezone, timedelta
        sp = {
            **BASE_SP,
            "createdDateTime": (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(),
            "_signInActivity": {
                "lastSignInActivity": {}
            },
            "keyCredentials": [{
                "keyId": "old-cert",
                "displayName": "expired cert",
                "startDateTime": (datetime.now(timezone.utc) - timedelta(days=400)).isoformat(),
                "endDateTime": (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
            }],
        }
        result = analyze_app(sp, stale_days=90)
        expired = [s for s in result.signals if s.key == "expired_cert"]
        assert len(expired) == 1
        assert expired[0].severity == "info"


# ── Credential sprawl ────────────────────────────────────────────────────────


class TestCredentialSprawl:
    """Apps with 3+ client secrets get a credential_sprawl signal."""

    def _make_secret(self, key_id: str) -> dict:
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        return {
            "keyId": key_id,
            "displayName": f"secret-{key_id}",
            "startDateTime": (now - timedelta(days=30)).isoformat(),
            "endDateTime": (now + timedelta(days=60)).isoformat(),
        }

    def test_three_secrets_triggers_sprawl(self):
        sp = {
            **BASE_SP,
            "replyUrls": ["https://app.contoso.com/callback"],
            "passwordCredentials": [
                self._make_secret("1"),
                self._make_secret("2"),
                self._make_secret("3"),
            ],
        }
        result = analyze_app(sp)
        assert result.credential_count == 3
        sprawl = [s for s in result.signals if s.key == "credential_sprawl"]
        assert len(sprawl) == 1
        assert sprawl[0].severity == "medium"

    def test_two_secrets_no_sprawl(self):
        sp = {
            **BASE_SP,
            "replyUrls": ["https://app.contoso.com/callback"],
            "passwordCredentials": [
                self._make_secret("1"),
                self._make_secret("2"),
            ],
        }
        result = analyze_app(sp)
        assert not any(s.key == "credential_sprawl" for s in result.signals)

    def test_credential_count_includes_certs(self):
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        sp = {
            **BASE_SP,
            "replyUrls": ["https://app.contoso.com/callback"],
            "passwordCredentials": [self._make_secret("1")],
            "keyCredentials": [{
                "keyId": "cert-1",
                "displayName": "cert",
                "startDateTime": (now - timedelta(days=30)).isoformat(),
                "endDateTime": (now + timedelta(days=60)).isoformat(),
            }],
        }
        result = analyze_app(sp)
        assert result.credential_count == 2


# ── Action tags ───────────────────────────────────────────────────────────────


class TestActionTags:
    """Action tags tell the practitioner what to DO."""

    def test_abandoned_app_gets_delete_tag(self):
        from datetime import datetime, timezone, timedelta
        old = (datetime.now(timezone.utc) - timedelta(days=400)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": old}
            },
        }
        result = analyze_app(sp, stale_days=90)
        assert "delete" in result.action_tags

    def test_never_signed_in_gets_delete_tag(self):
        from datetime import datetime, timezone, timedelta
        sp = {
            **BASE_SP,
            "createdDateTime": (datetime.now(timezone.utc) - timedelta(days=200)).isoformat(),
            "_signInActivity": {
                "lastSignInActivity": {}
            },
        }
        result = analyze_app(sp)
        assert "delete" in result.action_tags

    def test_disabled_sp_gets_delete_tag(self):
        sp = {**BASE_SP, "accountEnabled": False}
        result = analyze_app(sp)
        assert "delete" in result.action_tags

    def test_active_app_expired_cred_gets_rotate_tag(self):
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        recent = (now - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": recent}
            },
            "passwordCredentials": [{
                "keyId": "old-key",
                "displayName": "expired",
                "startDateTime": (now - timedelta(days=400)).isoformat(),
                "endDateTime": (now - timedelta(days=30)).isoformat(),
            }],
        }
        result = analyze_app(sp, stale_days=90)
        assert "rotate" in result.action_tags
        assert "delete" not in result.action_tags

    def test_stale_app_expired_cred_gets_delete_not_rotate(self):
        """Stale app with expired creds should get 'delete', not 'rotate'."""
        from datetime import datetime, timezone, timedelta
        now = datetime.now(timezone.utc)
        old = (now - timedelta(days=400)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": old}
            },
            "passwordCredentials": [{
                "keyId": "old-key",
                "displayName": "expired",
                "startDateTime": (now - timedelta(days=500)).isoformat(),
                "endDateTime": (now - timedelta(days=30)).isoformat(),
            }],
        }
        result = analyze_app(sp, stale_days=90)
        assert "delete" in result.action_tags
        # expired_secret on stale app is info/0-score, so no rotate tag
        # but the signal key is still there
        assert "rotate" not in result.action_tags

    def test_no_owners_gets_assign_owner_tag(self):
        sp = {**BASE_SP, "_owners": [], "_disabledOwnerIds": []}
        result = analyze_app(sp)
        assert "assign_owner" in result.action_tags

    def test_implicit_grant_gets_review_config_tag(self):
        sp = {**BASE_SP, "oauth2AllowImplicitFlow": True}
        result = analyze_app(sp)
        assert "review_config" in result.action_tags

    def test_clean_app_has_no_action_tags(self):
        result = analyze_app(BASE_SP)
        assert result.action_tags == []


# ── Sign-in activity breakdown and no_sign_in_data ───────────────────────


class TestNoSignInData:
    """When Graph returns no sign-in record (empty dict), flag it."""

    def test_no_sign_in_data_signal(self):
        sp = {**BASE_SP, "_signInActivity": {}}
        result = analyze_app(sp)
        assert any(s.key == "no_sign_in_data" for s in result.signals)
        assert not result.sign_in_data_available

    def test_no_sign_in_data_score(self):
        sp = {**BASE_SP, "_signInActivity": {}}
        result = analyze_app(sp)
        sig = next(s for s in result.signals if s.key == "no_sign_in_data")
        assert sig.score_contribution == 5
        assert sig.severity == "low"

    def test_microsoft_first_party_skips_no_sign_in_data(self):
        sp = {
            **BASE_SP,
            "_signInActivity": {},
            "appOwnerOrganizationId": "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
        }
        result = analyze_app(sp)
        assert not any(s.key == "no_sign_in_data" for s in result.signals)

    def test_sign_in_record_present_does_not_fire(self):
        """When Graph returns a sign-in record (even with empty activity), no_sign_in_data should not fire."""
        sp = {
            **BASE_SP,
            "_signInActivity": {"lastSignInActivity": {}},
        }
        result = analyze_app(sp)
        assert result.sign_in_data_available
        assert not any(s.key == "no_sign_in_data" for s in result.signals)


class TestSignInBreakdown:
    """Verify individual sign-in type fields are populated correctly."""

    def test_interactive_only(self):
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=5)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": recent},
            },
        }
        result = analyze_app(sp)
        assert result.last_interactive_sign_in == recent
        assert result.last_non_interactive_sign_in is None
        assert result.last_app_auth_client_sign_in is None
        assert not result.is_daemon_app

    def test_stale_detail_includes_breakdown(self):
        from datetime import datetime, timezone, timedelta
        old = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": old},
            },
        }
        result = analyze_app(sp)
        stale_sig = next((s for s in result.signals if s.key == "stale"), None)
        assert stale_sig is not None
        assert "Activity breakdown:" in stale_sig.detail
        assert "Interactive:" in stale_sig.detail
        assert "Non-interactive: none" in stale_sig.detail

    def test_never_signed_in_detail_includes_breakdown(self):
        sp = {
            **BASE_SP,
            "_signInActivity": {"lastSignInActivity": {}},
        }
        result = analyze_app(sp)
        sig = next((s for s in result.signals if s.key == "never_signed_in"), None)
        assert sig is not None
        assert "Activity breakdown:" in sig.detail
        assert "Interactive: none" in sig.detail
        assert "App-only (client): none" in sig.detail


# ── SAML app detection ──────────────────────────────────────────────────────


class TestSamlDetection:
    """Apps with preferredSingleSignOnMode=saml are detected and handled specially."""

    def test_saml_app_detected(self):
        sp = {**BASE_SP, "preferredSingleSignOnMode": "saml", "_signInActivity": {}}
        result = analyze_app(sp)
        assert result.is_saml_app
        assert result.preferred_sso_mode == "saml"

    def test_saml_app_no_sign_in_data_is_info(self):
        """SAML app with no sign-in data gets info severity, not low."""
        sp = {**BASE_SP, "preferredSingleSignOnMode": "saml", "_signInActivity": {}}
        result = analyze_app(sp)
        sig = next(s for s in result.signals if s.key == "no_sign_in_data")
        assert sig.severity == "info"
        assert sig.score_contribution == 0
        assert "SAML" in sig.title

    def test_saml_detail_mentions_entra_logs(self):
        """SAML no_sign_in_data detail should mention checking Entra ID logs."""
        sp = {**BASE_SP, "preferredSingleSignOnMode": "saml", "_signInActivity": {}}
        result = analyze_app(sp)
        sig = next(s for s in result.signals if s.key == "no_sign_in_data")
        assert "Entra ID sign-in logs" in sig.detail

    def test_non_saml_app_no_sign_in_data_is_low(self):
        """Non-SAML app with no sign-in data still gets low severity."""
        sp = {**BASE_SP, "_signInActivity": {}}
        result = analyze_app(sp)
        sig = next(s for s in result.signals if s.key == "no_sign_in_data")
        assert sig.severity == "low"
        assert sig.score_contribution == 5

    def test_saml_sso_variant_detected(self):
        """preferredSingleSignOnMode=samlsso is also detected."""
        sp = {**BASE_SP, "preferredSingleSignOnMode": "samlsso", "_signInActivity": {}}
        result = analyze_app(sp)
        assert result.is_saml_app

    def test_non_saml_mode_not_flagged(self):
        """preferredSingleSignOnMode=password is NOT SAML."""
        sp = {**BASE_SP, "preferredSingleSignOnMode": "password", "_signInActivity": {}}
        result = analyze_app(sp)
        assert not result.is_saml_app

    def test_saml_app_with_sign_in_data_no_special_handling(self):
        """SAML app that HAS sign-in data doesn't get no_sign_in_data signal."""
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "preferredSingleSignOnMode": "saml",
            "_signInActivity": {
                "lastSignInActivity": {"lastSignInDateTime": recent},
            },
        }
        result = analyze_app(sp)
        assert result.is_saml_app
        assert not any(s.key == "no_sign_in_data" for s in result.signals)


# ── lastSuccessfulSignInDateTime preference ─────────────────────────────────


class TestSuccessfulSignInPreference:
    """Staleness should use lastSuccessfulSignInDateTime over lastSignInDateTime."""

    def test_successful_timestamp_preferred(self):
        """When both timestamps exist, the successful one is used."""
        from datetime import datetime, timezone, timedelta
        # lastSignInDateTime is recent (includes failed attempts)
        recent_any = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        # lastSuccessfulSignInDateTime is old
        old_success = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {
                    "lastSignInDateTime": recent_any,
                    "lastSuccessfulSignInDateTime": old_success,
                },
            },
        }
        result = analyze_app(sp, stale_days=90)
        # The successful timestamp is preferred, so app should be stale
        assert any(s.key == "stale" for s in result.signals)

    def test_fallback_to_any_when_no_successful(self):
        """When lastSuccessfulSignInDateTime is absent, lastSignInDateTime is used."""
        from datetime import datetime, timezone, timedelta
        recent = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {
                    "lastSignInDateTime": recent,
                    # no lastSuccessfulSignInDateTime
                },
            },
        }
        result = analyze_app(sp, stale_days=90)
        assert not any(s.key == "stale" for s in result.signals)

    def test_successful_recent_not_stale(self):
        """When successful timestamp is recent, app is not stale."""
        from datetime import datetime, timezone, timedelta
        old_any = (datetime.now(timezone.utc) - timedelta(days=200)).isoformat()
        recent_success = (datetime.now(timezone.utc) - timedelta(days=10)).isoformat()
        sp = {
            **BASE_SP,
            "_signInActivity": {
                "lastSignInActivity": {
                    "lastSignInDateTime": old_any,
                    "lastSuccessfulSignInDateTime": recent_success,
                },
            },
        }
        result = analyze_app(sp, stale_days=90)
        assert not any(s.key == "stale" for s in result.signals)


# ── CA policy cross-reference ──────────────────────────────────────────────


class TestCaPolicyCrossReference:
    """CA policy targeting signal."""

    def _make_ca_policy(self, name: str, include_app_ids: list[str], state: str = "enabled") -> dict:
        return {
            "id": f"policy-{name}",
            "displayName": name,
            "state": state,
            "conditions": {
                "applications": {
                    "includeApplications": include_app_ids,
                    "excludeApplications": [],
                },
            },
        }

    def test_app_targeted_by_ca_policy(self):
        ca = [self._make_ca_policy("Block External", ["test-app-id"])]
        result = analyze_app(BASE_SP, ca_policies=ca)
        sig = next((s for s in result.signals if s.key == "ca_policy_target"), None)
        assert sig is not None
        assert sig.severity == "info"
        assert sig.score_contribution == 0
        assert "Block External" in sig.detail

    def test_app_not_targeted_no_signal(self):
        ca = [self._make_ca_policy("Block External", ["other-app-id"])]
        result = analyze_app(BASE_SP, ca_policies=ca)
        assert not any(s.key == "ca_policy_target" for s in result.signals)

    def test_disabled_policy_ignored(self):
        ca = [self._make_ca_policy("Block External", ["test-app-id"], state="disabled")]
        result = analyze_app(BASE_SP, ca_policies=ca)
        assert not any(s.key == "ca_policy_target" for s in result.signals)

    def test_excluded_app_not_targeted(self):
        ca = [{
            "id": "policy-1",
            "displayName": "Block All",
            "state": "enabled",
            "conditions": {
                "applications": {
                    "includeApplications": ["test-app-id"],
                    "excludeApplications": ["test-app-id"],
                },
            },
        }]
        result = analyze_app(BASE_SP, ca_policies=ca)
        assert not any(s.key == "ca_policy_target" for s in result.signals)

    def test_multiple_policies_targeting_app(self):
        ca = [
            self._make_ca_policy("MFA Policy", ["test-app-id"]),
            self._make_ca_policy("Location Policy", ["test-app-id"]),
        ]
        result = analyze_app(BASE_SP, ca_policies=ca)
        sig = next(s for s in result.signals if s.key == "ca_policy_target")
        assert "2" in sig.title
        assert "policies" in sig.title
        assert "MFA Policy" in sig.detail
        assert "Location Policy" in sig.detail

    def test_no_ca_policies_no_signal(self):
        """When ca_policies is None, no CA signal fires."""
        result = analyze_app(BASE_SP, ca_policies=None)
        assert not any(s.key == "ca_policy_target" for s in result.signals)

    def test_case_insensitive_matching(self):
        """App IDs should match case-insensitively."""
        sp = {**BASE_SP, "appId": "TEST-APP-ID"}
        ca = [self._make_ca_policy("MFA", ["test-app-id"])]
        result = analyze_app(sp, ca_policies=ca)
        assert any(s.key == "ca_policy_target" for s in result.signals)


# ── analyze_all passes ca_policies ──────────────────────────────────────────


class TestAnalyzeAllCaPolicies:
    """analyze_all should pass ca_policies from raw_data to analyze_app."""

    def test_ca_policies_passed_through(self):
        ca = [{
            "id": "p1",
            "displayName": "Test Policy",
            "state": "enabled",
            "conditions": {
                "applications": {
                    "includeApplications": ["test-app-id"],
                    "excludeApplications": [],
                },
            },
        }]
        raw_data = {"apps": [BASE_SP], "ca_policies": ca}
        results = analyze_all(raw_data)
        assert any(s.key == "ca_policy_target" for s in results[0].signals)


class TestBuildOwnerGroups:
    """Tests for the _build_owner_groups function in reporter.py."""

    def test_single_owner_single_app(self):
        from src.reporter import _build_owner_groups

        result = analyze_app(BASE_SP)
        groups = _build_owner_groups([result])
        assert len(groups) == 1
        assert groups[0]["owner_name"] == "Test Owner"
        assert groups[0]["app_count"] == 1
        assert groups[0]["apps"][0].app_id == "test-app-id"

    def test_unowned_app_grouped(self):
        from src.reporter import _build_owner_groups

        sp = {**BASE_SP, "_owners": [], "_disabledOwnerIds": []}
        result = analyze_app(sp)
        groups = _build_owner_groups([result])
        assert any(g["owner_name"] == "Unowned" for g in groups)

    def test_unowned_group_sorted_first(self):
        from src.reporter import _build_owner_groups

        owned = analyze_app(BASE_SP)
        unowned = analyze_app({**BASE_SP, "appId": "unowned-app", "_owners": [], "_disabledOwnerIds": []})
        groups = _build_owner_groups([owned, unowned])
        assert groups[0]["owner_name"] == "Unowned"

    def test_multi_owner_app_appears_in_each_group(self):
        from src.reporter import _build_owner_groups

        sp = {**BASE_SP, "_owners": [
            {"id": "owner-1", "displayName": "Alice", "accountEnabled": True},
            {"id": "owner-2", "displayName": "Bob", "accountEnabled": True},
        ]}
        result = analyze_app(sp)
        groups = _build_owner_groups([result])
        assert len(groups) == 2
        names = {g["owner_name"] for g in groups}
        assert names == {"Alice", "Bob"}
        # The app should appear in both groups
        for g in groups:
            assert len(g["apps"]) == 1

    def test_disabled_owner_flag(self):
        from src.reporter import _build_owner_groups

        sp = {**BASE_SP, "_owners": [
            {"id": "owner-1", "displayName": "Disabled User", "accountEnabled": False},
        ]}
        result = analyze_app(sp)
        groups = _build_owner_groups([result])
        assert groups[0]["owner_enabled"] is False

    def test_groups_sorted_by_risk(self):
        from src.reporter import _build_owner_groups

        # Create a high-risk app (no owners triggers signals)
        high_risk_sp = {**BASE_SP, "appId": "high-risk",
                        "_owners": [{"id": "o-hr", "displayName": "HighRiskOwner", "accountEnabled": True}],
                        "passwordCredentials": [{"endDateTime": "2020-01-01T00:00:00Z", "displayName": "old"}]}
        low_risk_sp = {**BASE_SP, "appId": "low-risk",
                       "_owners": [{"id": "o-lr", "displayName": "LowRiskOwner", "accountEnabled": True}]}
        results = [analyze_app(high_risk_sp), analyze_app(low_risk_sp)]
        groups = _build_owner_groups(results)
        assert groups[0]["owner_name"] == "HighRiskOwner"
        assert groups[0]["max_risk_score"] >= groups[1]["max_risk_score"]
