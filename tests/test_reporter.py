"""
Unit tests for src/reporter.py.

Covers pure helper functions, CSV generation, HTML generation, and the
generate_all orchestrator. No network calls or weasyprint dependency required.
"""

import csv
from pathlib import Path

import pytest

from src.analyzer import AppResult, Signal
from src.ca_analyzer import AppCoverage, PolicySummary
from src.reporter import (
    _csv_safe,
    _format_date,
    _tenant_slug,
    _top_recommendations,
    generate_all,
    generate_csv,
    generate_html,
)


# ── Helpers ────────────────────────────────────────────────────────────────────


def _make_result(
    *,
    sp_id: str = "sp-1",
    app_id: str = "app-1",
    display_name: str = "Test App",
    account_enabled: bool = True,
    sp_type: str = "Application",
    created_datetime: str | None = "2024-01-01T00:00:00Z",
    last_sign_in: str | None = "2024-06-01T00:00:00Z",
    days_since_sign_in: int | None = 10,
    owner_count: int = 1,
    assignment_count: int = 1,
    has_expired_secret: bool = False,
    has_expired_cert: bool = False,
    has_near_expiry_secret: bool = False,
    has_near_expiry_cert: bool = False,
    has_high_privilege: bool = False,
    signals: list | None = None,
    risk_score: int = 0,
    risk_band: str = "clean",
    primary_recommendation: str = "No action required.",
    tags: list | None = None,
    is_microsoft_first_party: bool = False,
    is_tool_artifact: bool = False,
    password_credentials: list | None = None,
    key_credentials: list | None = None,
) -> AppResult:
    return AppResult(
        sp_id=sp_id,
        app_id=app_id,
        display_name=display_name,
        account_enabled=account_enabled,
        sp_type=sp_type,
        created_datetime=created_datetime,
        last_sign_in=last_sign_in,
        days_since_sign_in=days_since_sign_in,
        owner_count=owner_count,
        assignment_count=assignment_count,
        has_expired_secret=has_expired_secret,
        has_expired_cert=has_expired_cert,
        has_near_expiry_secret=has_near_expiry_secret,
        has_near_expiry_cert=has_near_expiry_cert,
        has_high_privilege=has_high_privilege,
        signals=signals or [],
        risk_score=risk_score,
        risk_band=risk_band,
        primary_recommendation=primary_recommendation,
        tags=tags or [],
        is_microsoft_first_party=is_microsoft_first_party,
        is_tool_artifact=is_tool_artifact,
        password_credentials=password_credentials or [],
        key_credentials=key_credentials or [],
    )


RAW_DATA_BASE: dict = {
    "tenant": {"displayName": "Contoso Ltd", "id": "tenant-abc"},
    "collected_at": "2024-06-15T10:00:00Z",
    "ca_permission_granted": True,
}


# ── _format_date ───────────────────────────────────────────────────────────────


class TestFormatDate:
    def test_none_returns_dash(self):
        assert _format_date(None) == "—"

    def test_empty_string_returns_dash(self):
        assert _format_date("") == "—"

    def test_iso_date_with_z(self):
        assert _format_date("2024-03-15T12:00:00Z") == "2024-03-15"

    def test_iso_date_with_offset(self):
        assert _format_date("2024-03-15T12:00:00+00:00") == "2024-03-15"

    def test_invalid_string_returned_as_is(self):
        assert _format_date("not-a-date") == "not-a-date"


# ── _tenant_slug ───────────────────────────────────────────────────────────────


class TestTenantSlug:
    def test_spaces_replaced(self):
        assert _tenant_slug("Contoso Ltd") == "contoso_ltd"

    def test_special_chars_replaced(self):
        assert " " not in _tenant_slug("Acme & Co.")
        assert _tenant_slug("Acme & Co.").islower()

    def test_already_clean(self):
        assert _tenant_slug("contoso") == "contoso"

    def test_hyphen_preserved(self):
        assert _tenant_slug("my-org") == "my-org"

    def test_lowercased(self):
        assert _tenant_slug("UPPER") == "upper"


# ── _csv_safe ──────────────────────────────────────────────────────────────────


class TestCsvSafe:
    def test_normal_value_unchanged(self):
        assert _csv_safe("Hello World") == "Hello World"

    def test_empty_string_unchanged(self):
        assert _csv_safe("") == ""

    def test_equals_sign_prefixed(self):
        assert _csv_safe("=SUM(A1)") == "'=SUM(A1)"

    def test_plus_sign_prefixed(self):
        assert _csv_safe("+123") == "'+123"

    def test_minus_sign_prefixed(self):
        assert _csv_safe("-payload") == "'-payload"

    def test_at_sign_prefixed(self):
        assert _csv_safe("@user") == "'@user"

    def test_tab_prefixed(self):
        assert _csv_safe("\tvalue") == "'\tvalue"

    def test_mid_string_formula_not_prefixed(self):
        # Only the first character triggers the guard
        assert _csv_safe("safe=still") == "safe=still"


# ── _top_recommendations ───────────────────────────────────────────────────────


class TestTopRecommendations:
    def test_empty_list_returns_hygiene_rec(self):
        recs = _top_recommendations([])
        assert len(recs) == 1
        assert "hygiene" in recs[0]["text"].lower()

    def test_critical_high_rec_included(self):
        app = _make_result(risk_band="critical", risk_score=80)
        recs = _top_recommendations([app])
        assert any("Critical/High" in r["text"] for r in recs)

    def test_expired_cred_rec_included(self):
        app = _make_result(has_expired_secret=True)
        recs = _top_recommendations([app])
        assert any("expired" in r["text"].lower() for r in recs)

    def test_orphaned_app_rec_included(self):
        app = _make_result(owner_count=0)
        recs = _top_recommendations([app])
        assert any("owner" in r["text"].lower() for r in recs)

    def test_microsoft_first_party_excluded_from_orphan_count(self):
        ms_app = _make_result(owner_count=0, is_microsoft_first_party=True)
        recs = _top_recommendations([ms_app])
        assert not any("owner" in r["text"].lower() for r in recs)

    def test_stale_rec_included_when_slot_available(self):
        stale_signal = Signal(
            key="stale", severity="high", title="Stale",
            detail="App is stale.", score_contribution=30,
        )
        app = _make_result(signals=[stale_signal])
        recs = _top_recommendations([app])
        assert any("stale" in r["text"].lower() for r in recs)

    def test_max_three_recommendations(self):
        stale_signal = Signal(
            key="stale", severity="high", title="Stale",
            detail="App is stale.", score_contribution=30,
        )
        # One app that fires all four possible rec triggers
        app = _make_result(
            risk_band="critical",
            risk_score=80,
            has_expired_secret=True,
            owner_count=0,
            signals=[stale_signal],
        )
        recs = _top_recommendations([app])
        assert len(recs) <= 3

    def test_each_rec_has_text_and_sub(self):
        app = _make_result(risk_band="high", risk_score=50)
        recs = _top_recommendations([app])
        for rec in recs:
            assert "text" in rec and rec["text"]
            assert "sub" in rec and rec["sub"]


# ── generate_csv ───────────────────────────────────────────────────────────────


class TestGenerateCsv:
    def _read_csv(self, path: Path) -> list[dict]:
        with path.open(encoding="utf-8", newline="") as f:
            return list(csv.DictReader(f))

    def test_header_columns_present(self, tmp_path):
        out = tmp_path / "out.csv"
        generate_csv([], out)
        with out.open(encoding="utf-8") as f:
            header = f.readline().strip().split(",")
        for col in ("app_name", "risk_band", "signal_keys", "primary_recommendation"):
            assert col in header

    def test_empty_results_writes_header_only(self, tmp_path):
        out = tmp_path / "out.csv"
        generate_csv([], out)
        rows = self._read_csv(out)
        assert rows == []

    def test_one_row_per_app(self, tmp_path):
        apps = [_make_result(sp_id=f"sp-{i}", app_id=f"app-{i}") for i in range(3)]
        out = tmp_path / "out.csv"
        generate_csv(apps, out)
        assert len(self._read_csv(out)) == 3

    def test_boolean_fields_are_yes_no(self, tmp_path):
        app = _make_result(account_enabled=True, has_expired_secret=True, has_high_privilege=False)
        out = tmp_path / "out.csv"
        generate_csv([app], out)
        row = self._read_csv(out)[0]
        assert row["account_enabled"] == "yes"
        assert row["has_expired_secret"] == "yes"
        assert row["has_high_privilege"] == "no"

    def test_earliest_secret_expiry_derived(self, tmp_path):
        app = _make_result(password_credentials=[
            {"endDateTime": "2025-03-01T00:00:00Z"},
            {"endDateTime": "2024-01-01T00:00:00Z"},
        ])
        out = tmp_path / "out.csv"
        generate_csv([app], out)
        row = self._read_csv(out)[0]
        assert row["earliest_secret_expiry"] == "2024-01-01T00:00:00Z"

    def test_no_credentials_empty_expiry(self, tmp_path):
        out = tmp_path / "out.csv"
        generate_csv([_make_result()], out)
        row = self._read_csv(out)[0]
        assert row["earliest_secret_expiry"] == ""
        assert row["earliest_cert_expiry"] == ""

    def test_signal_keys_pipe_separated(self, tmp_path):
        sigs = [
            Signal(key="stale", severity="high", title="S", detail="", score_contribution=10),
            Signal(key="no_owner", severity="medium", title="O", detail="", score_contribution=5),
        ]
        out = tmp_path / "out.csv"
        generate_csv([_make_result(signals=sigs)], out)
        row = self._read_csv(out)[0]
        assert row["signal_keys"] == "stale|no_owner"
        assert row["signal_count"] == "2"

    def test_csv_injection_sanitised(self, tmp_path):
        out = tmp_path / "out.csv"
        generate_csv([_make_result(display_name="=HYPERLINK()")], out)
        row = self._read_csv(out)[0]
        assert row["app_name"].startswith("'")

    def test_returns_output_path(self, tmp_path):
        out = tmp_path / "out.csv"
        assert generate_csv([], out) == out


# ── generate_html ──────────────────────────────────────────────────────────────


class TestGenerateHtml:
    def test_writes_file(self, tmp_path):
        out = tmp_path / "report.html"
        generate_html([], RAW_DATA_BASE, 90, out)
        assert out.exists()
        assert out.stat().st_size > 0

    def test_returns_output_path(self, tmp_path):
        out = tmp_path / "report.html"
        assert generate_html([], RAW_DATA_BASE, 90, out) == out

    def test_tenant_name_in_output(self, tmp_path):
        out = tmp_path / "report.html"
        generate_html([], RAW_DATA_BASE, 90, out)
        assert "Contoso Ltd" in out.read_text(encoding="utf-8")

    def test_hide_microsoft_keeps_non_ms_apps(self, tmp_path):
        ms_app = _make_result(display_name="Microsoft App", is_microsoft_first_party=True)
        normal_app = _make_result(sp_id="sp-2", app_id="app-2", display_name="Contoso App")
        out = tmp_path / "report.html"
        generate_html([ms_app, normal_app], RAW_DATA_BASE, 90, out, hide_microsoft=True)
        assert "Contoso App" in out.read_text(encoding="utf-8")

    def test_ca_permission_denied_renders(self, tmp_path):
        raw = {**RAW_DATA_BASE, "ca_permission_granted": False}
        out = tmp_path / "report.html"
        generate_html([], raw, 90, out)
        assert out.exists()

    def test_old_cache_without_ca_key_renders(self, tmp_path):
        raw = {"tenant": RAW_DATA_BASE["tenant"], "collected_at": "2024-06-15T10:00:00Z"}
        out = tmp_path / "report.html"
        generate_html([], raw, 90, out)
        assert out.exists()

    def test_ca_coverage_data_accepted(self, tmp_path):
        coverages = [
            AppCoverage(app_id="a1", display_name="App1", is_covered=True),
            AppCoverage(app_id="a2", display_name="App2", is_covered=False),
        ]
        out = tmp_path / "report.html"
        generate_html([], RAW_DATA_BASE, 90, out, ca_app_coverages=coverages)
        assert out.exists()

    def test_missing_collected_at_handled(self, tmp_path):
        raw = {**RAW_DATA_BASE, "collected_at": ""}
        out = tmp_path / "report.html"
        generate_html([], raw, 90, out)
        assert out.exists()

    def test_unknown_tenant_fallback(self, tmp_path):
        raw = {"tenant": {}, "collected_at": "", "ca_permission_granted": True}
        out = tmp_path / "report.html"
        generate_html([], raw, 90, out)
        assert "Unknown Tenant" in out.read_text(encoding="utf-8")


# ── generate_all ───────────────────────────────────────────────────────────────


class TestGenerateAll:
    def test_skip_html_returns_none(self, tmp_path):
        result = generate_all([], RAW_DATA_BASE, 90, tmp_path, skip_html=True)
        assert result["html"] is None
        assert result["csv"] is not None

    def test_skip_csv_returns_none(self, tmp_path):
        result = generate_all([], RAW_DATA_BASE, 90, tmp_path, skip_csv=True)
        assert result["csv"] is None
        assert result["html"] is not None

    def test_skip_all_returns_all_none(self, tmp_path):
        result = generate_all(
            [], RAW_DATA_BASE, 90, tmp_path,
            skip_html=True, skip_csv=True,
        )
        assert result == {"html": None, "csv": None}

    def test_output_dir_created(self, tmp_path):
        new_dir = tmp_path / "reports" / "nested"
        generate_all([], RAW_DATA_BASE, 90, new_dir)
        assert new_dir.exists()

    def test_filename_contains_tenant_slug(self, tmp_path):
        result = generate_all([], RAW_DATA_BASE, 90, tmp_path)
        assert result["html"] is not None
        assert "contoso_ltd" in result["html"].name

    def test_html_and_csv_written_to_disk(self, tmp_path):
        result = generate_all([], RAW_DATA_BASE, 90, tmp_path)
        assert result["html"].exists()
        assert result["csv"].exists()
