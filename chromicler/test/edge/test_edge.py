#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for Edge Handler - Microsoft Edge security workflow
"""

import json
import pytest
from pathlib import Path
import tempfile
import os

from handlers.edge_handler import EdgeHandler
from version_utils import VersionUtils


@pytest.fixture
def mock_bugzilla_client(mocker):
    """Mock BugzillaClient for testing."""
    client = mocker.Mock()
    client.find_chromium_security_bugs.return_value = []
    client.get_cves_from_bug_alias.return_value = []
    client.update_bug.return_value = True
    # Edge handler now uses VersionUtils to detect constraints; keep default behavior
    client.bzapi.getbug.return_value = mocker.Mock(
        id=12345,
        summary="Security issue in www-client/microsoft-edge",
        alias=["CVE-2025-10200"],
    )
    return client


@pytest.fixture
def mock_logger(mocker):
    """Mock logger for testing."""
    return mocker.Mock()


@pytest.fixture
def edge_handler(mock_bugzilla_client, mock_logger, mocker):
    """EdgeHandler instance for testing."""
    handler = EdgeHandler(
        api_key_file="./bugzilla_api_key",
        logger=mock_logger,
        version_utils=VersionUtils(),
    )
    # Mock the bugzilla property to return our mock
    mocker.patch.object(
        type(handler),
        "bugzilla",
        new_callable=mocker.PropertyMock,
        return_value=mock_bugzilla_client,
    )
    return handler


@pytest.fixture
def sample_cvrf_data():
    """Load sample CVRF data for testing."""
    cvrf_file = Path(__file__).parent.parent / "data" / "edge_cvrf_2025_sep.xml"
    return cvrf_file.read_text()


@pytest.fixture
def sample_msrc_api_response():
    """Sample MSRC API response for CVE lookup."""
    return {
        "@odata.context": "https://api.msrc.microsoft.com/$metadata#Updates",
        "value": [
            {
                "ID": "2025-Sep",
                "Alias": "2025-Sep",
                "DocumentTitle": "September 2025 Security Updates",
                "Severity": None,
                "InitialReleaseDate": "2025-09-09T07:00:00Z",
                "CurrentReleaseDate": "2025-09-19T07:00:24Z",
                "CvrfUrl": "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/2025-Sep",
            }
        ],
    }


class TestEdgeHandlerMSRCAPI:
    """Test Edge handler MSRC API integration."""

    def test_get_msrc_data_for_cve_success(
        self, edge_handler, sample_msrc_api_response, mocker
    ):
        """Test successful MSRC API CVE lookup."""
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_msrc_api_response
        mock_get.return_value = mock_response

        result = edge_handler._get_msrc_data_for_cve("CVE-2025-10200")

        assert result == "2025-Sep"
        mock_get.assert_called_once_with(
            "https://api.msrc.microsoft.com/cvrf/v3.0/updates/CVE-2025-10200",
            timeout=30,
        )

    def test_get_msrc_data_for_cve_not_found(self, edge_handler, mocker):
        """Test MSRC API CVE lookup when CVE not found."""
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        mock_response = mocker.Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        result = edge_handler._get_msrc_data_for_cve("CVE-2025-99999")

        assert result is None

    def test_get_msrc_data_for_cve_empty_response(self, edge_handler, mocker):
        """Test MSRC API CVE lookup with empty response."""
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"value": []}
        mock_get.return_value = mock_response

        result = edge_handler._get_msrc_data_for_cve("CVE-2025-12345")

        assert result is None

    def test_get_msrc_data_for_cve_network_error(self, edge_handler, mocker):
        """Test MSRC API CVE lookup with network error."""
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        mock_get.side_effect = ConnectionError("Network error")

        result = edge_handler._get_msrc_data_for_cve("CVE-2025-10200")

        assert result is None


class TestEdgeHandlerCVRFParsing:
    """Test Edge handler CVRF document parsing."""

    def test_get_edge_cves_for_month_success(
        self, edge_handler, sample_cvrf_data, mocker
    ):
        """Test successful CVRF parsing for Edge CVEs."""
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.text = sample_cvrf_data
        mock_get.return_value = mock_response

        # Cache is automatically skipped during testing
        result = edge_handler.get_edge_cves_for_month(2025, "Sep")

        assert len(result) == 3

        # Verify CVE data structure
        cve_ids = [cve_data["cve"] for cve_data in result]
        assert "CVE-2025-53791" in cve_ids
        assert "CVE-2025-10585" in cve_ids
        assert "CVE-2025-10200" in cve_ids

        # Check specific CVE details
        cve_53791 = next(cve for cve in result if cve["cve"] == "CVE-2025-53791")
        assert (
            cve_53791["title"]
            == "Microsoft Edge (Chromium-based) Security Feature Bypass Vulnerability"
        )
        assert cve_53791["fixed_version"] == "140.0.3485.54"

        cve_10585 = next(cve for cve in result if cve["cve"] == "CVE-2025-10585")
        assert cve_10585["title"] == "Chromium: CVE-2025-10585 Type Confusion in V8"
        assert cve_10585["fixed_version"] == "140.0.3485.52"

    def test_get_edge_cves_for_month_http_error(self, edge_handler, mocker):
        """Test CVRF parsing with HTTP error."""
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        mock_response = mocker.Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response

        # Cache is automatically skipped during testing
        result = edge_handler.get_edge_cves_for_month(2025, "Sep")

        assert result == []

    def test_get_edge_cves_for_month_invalid_xml(self, edge_handler, mocker):
        """Test CVRF parsing with invalid XML."""
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.text = "Invalid XML content"
        mock_get.return_value = mock_response

        # Cache is automatically skipped during testing
        result = edge_handler.get_edge_cves_for_month(2025, "Sep")

        assert result == []


class TestEdgeHandlerCaching:
    """Test Edge handler caching functionality."""

    def test_cache_file_path_generation(self, edge_handler):
        """Test cache file path generation."""
        cache_path = edge_handler._get_cache_file_path(2025, "Sep")
        assert "edge_cves_2025_Sep.json" in cache_path

    def test_is_cache_valid_fresh_cache(self, edge_handler):
        """Test cache validity with fresh cache file."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("[]")
            tmp_path = tmp.name

        try:
            # File just created, should be valid
            assert edge_handler._is_cache_valid(tmp_path, max_age_hours=1) is True
        finally:
            os.unlink(tmp_path)

    def test_is_cache_valid_nonexistent_file(self, edge_handler):
        """Test cache validity with nonexistent file."""
        assert edge_handler._is_cache_valid("/nonexistent/file.json") is False

    def test_load_from_cache_success(self, edge_handler):
        """Test successful cache loading."""
        test_data = [
            {
                "cve": "CVE-2025-10200",
                "title": "Test CVE",
                "fixed_version": "140.0.3485.58",
            }
        ]

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            json.dump(test_data, tmp)
            tmp_path = tmp.name

        try:
            result = edge_handler._load_from_cache(tmp_path)
            assert result == test_data
        finally:
            os.unlink(tmp_path)

    def test_load_from_cache_invalid_json(self, edge_handler):
        """Test cache loading with invalid JSON."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp.write("invalid json")
            tmp_path = tmp.name

        try:
            result = edge_handler._load_from_cache(tmp_path)
            assert result is None
        finally:
            os.unlink(tmp_path)

    def test_save_to_cache_success(self, edge_handler):
        """Test successful cache saving."""
        test_data = [
            {
                "cve": "CVE-2025-10200",
                "title": "Test CVE",
                "fixed_version": "140.0.3485.58",
            }
        ]

        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            edge_handler._save_to_cache(tmp_path, test_data)

            # Verify file was created and contains correct data
            with open(tmp_path, "r") as f:
                saved_data = json.load(f)
            assert saved_data == test_data
        finally:
            os.unlink(tmp_path)


def test_caching_disabled_during_testing(edge_handler, mocker):
    """Test that caching is disabled during testing regardless of other conditions."""

    # Patch the testing flag directly (pytest-mock auto-cleans up at test end)
    _mock_is_testing = mocker.patch.object(
        edge_handler, "_is_testing", return_value=True
    )

    # Cache should be considered invalid during testing
    with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp:
        tmp.write("[]")
        tmp_path = tmp.name

    try:
        # Even with a fresh cache file, should be valid
        assert (
            edge_handler._is_cache_valid(tmp_path, max_age_hours=1) is True
        )  # Cache file is valid

        # But the method should skip cache loading during testing
        mock_get = mocker.patch("handlers.edge_handler.requests.get")
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.text = "<test>xml</test>"
        mock_get.return_value = mock_response

        mock_save_cache = mocker.patch.object(edge_handler, "_save_to_cache")
        # This should fetch fresh data, not use cache, and not save cache
        edge_handler.get_edge_cves_for_month(2025, "Sep")

        # Should have attempted to fetch fresh data
        mock_get.assert_called_once()
        # Should NOT save to cache during testing
        mock_save_cache.assert_not_called()
    finally:
        os.unlink(tmp_path)


def test_caching_enabled_during_dry_run(edge_handler, mocker):
    """Test that caching works normally when not in testing mode (e.g., dry-run)."""

    # Simulate non-testing environment (production or dry-run)
    mock_get = mocker.patch("handlers.edge_handler.requests.get")

    # Patch the testing flag directly (pytest-mock auto-cleans up at test end)
    _mock_is_testing = mocker.patch.object(
        edge_handler, "_is_testing", return_value=False
    )

    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.text = "<test>xml</test>"
    mock_get.return_value = mock_response

    mock_save_cache = mocker.patch.object(edge_handler, "_save_to_cache")
    mocker.patch.object(edge_handler, "_is_cache_valid", return_value=False)

    # Force fresh fetch
    edge_handler.get_edge_cves_for_month(2025, "Sep")

    # Should have fetched fresh data
    mock_get.assert_called_once()
    # Should save to cache when not testing
    mock_save_cache.assert_called_once()


class TestEdgeHandlerVersionUtils:
    """Test Edge handler version utilities."""

    def test_get_latest_version_single_version(self, edge_handler):
        """Test getting latest version with single version."""
        versions = ["140.0.3485.54"]
        result = edge_handler._get_latest_version(versions)
        assert result == "140.0.3485.54"

    def test_get_latest_version_multiple_versions(self, edge_handler):
        """Test getting latest version with multiple versions."""
        versions = ["140.0.3485.52", "140.0.3485.58", "140.0.3485.54"]
        result = edge_handler._get_latest_version(versions)
        assert result == "140.0.3485.58"

    def test_get_latest_version_different_major_versions(self, edge_handler):
        """Test getting latest version across major versions."""
        versions = ["139.0.2415.23", "140.0.3485.52", "138.0.2357.81"]
        result = edge_handler._get_latest_version(versions)
        assert result == "140.0.3485.52"

    def test_add_edge_constraint_to_title_success(self, edge_handler):
        """Test adding Edge version constraint to bug title."""
        original_title = "Security issue in www-client/microsoft-edge package"
        version = "140.0.3485.54"
        expected = "Security issue in <www-client/microsoft-edge-140.0.3485.54 package"

        result = edge_handler._add_edge_constraint_to_title(original_title, version)
        assert result == expected

    def test_add_edge_constraint_to_title_no_match(self, edge_handler):
        """Test adding Edge constraint when no microsoft-edge found."""
        original_title = "Security issue in other package"
        version = "140.0.3485.54"

        result = edge_handler._add_edge_constraint_to_title(original_title, version)
        # Should remain unchanged
        assert result == original_title


class TestEdgeHandlerCVEQueries:
    """Test Edge handler CVE query functionality."""

    def test_query_edge_cves_with_specific_cves(
        self, edge_handler, sample_msrc_api_response, sample_cvrf_data, mocker
    ):
        """Test querying Edge CVEs with specific CVE list."""
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        # Mock MSRC API response for CVE lookup
        mock_msrc_response = mocker.Mock()
        mock_msrc_response.status_code = 200
        mock_msrc_response.json.return_value = sample_msrc_api_response

        # Mock CVRF response
        mock_cvrf_response = mocker.Mock()
        mock_cvrf_response.status_code = 200
        mock_cvrf_response.text = sample_cvrf_data

        mock_get.side_effect = [mock_msrc_response, mock_cvrf_response]

        # Cache is automatically skipped during testing
        result = edge_handler.query_edge_cves(cves=["CVE-2025-10200"])

        assert len(result) == 1
        assert result[0]["cve"] == "CVE-2025-10200"
        assert result[0]["fixed_version"] == "140.0.3485.58"

    def test_query_edge_cves_with_year_month(
        self, edge_handler, sample_cvrf_data, mocker
    ):
        """Test querying Edge CVEs with year and month."""
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.text = sample_cvrf_data
        mock_get.return_value = mock_response

        # Cache is automatically skipped during testing
        result = edge_handler.query_edge_cves(year=2025, month="Sep")

        assert len(result) == 3

        cve_ids = [cve_data["cve"] for cve_data in result]
        assert "CVE-2025-53791" in cve_ids
        assert "CVE-2025-10585" in cve_ids
        assert "CVE-2025-10200" in cve_ids

    def test_query_edge_cves_with_bugs(
        self, edge_handler, mock_bugzilla_client, mocker
    ):
        """Test querying Edge CVEs with bug IDs."""
        # Mock bug alias lookup
        mock_bugzilla_client.get_cves_from_bug_alias.return_value = ["CVE-2025-10200"]

        # Patch helpers directly (mocker auto-cleans up at test end)
        mocker.patch.object(
            edge_handler, "_get_msrc_data_for_cve", return_value="2025-Sep"
        )
        mock_get_cves = mocker.patch.object(edge_handler, "get_edge_cves_for_month")
        mock_get_cves.return_value = [
            {
                "cve": "CVE-2025-10200",
                "title": "Test CVE",
                "fixed_version": "140.0.3485.58",
            }
        ]

        result = edge_handler.query_edge_cves(bugs=[12345])

        assert len(result) == 1
        assert result[0]["cve"] == "CVE-2025-10200"

    def test_query_edge_cves_default_current_month(
        self, edge_handler, sample_cvrf_data, mocker
    ):
        """Test querying Edge CVEs with default current month."""
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.text = sample_cvrf_data
        mock_get.return_value = mock_response

        # Cache is automatically skipped during testing
        result = edge_handler.query_edge_cves()

        # Should use current month (September 2025) and return our test data
        assert len(result) == 3


class TestEdgeHandlerBugUpdates:
    """Test Edge handler bug update functionality."""

    def test_update_specific_bugs_success(
        self, edge_handler, mock_bugzilla_client, mocker
    ):
        """Test updating specific bugs with Edge version constraints."""
        # Setup mock bug
        mock_bug = mocker.Mock()
        mock_bug.id = 12345
        mock_bug.summary = "Security issue in www-client/microsoft-edge"
        mock_bug.alias = ["CVE-2025-10200"]
        mock_bugzilla_client.bzapi.getbug.return_value = mock_bug
        # Edge handler now uses VersionUtils to detect constraints; keep default behavior

        # Mock CVE data lookup
        mock_query = mocker.patch.object(edge_handler, "query_edge_cves")
        mock_query.return_value = [
            {
                "cve": "CVE-2025-10200",
                "title": "Test CVE",
                "fixed_version": "140.0.3485.58",
            }
        ]

        result = edge_handler._update_specific_bugs([12345], dry_run=False)

        assert result["updated"] == 1
        assert result["skipped"] == 0
        assert result["errors"] == 0
        mock_bugzilla_client.update_bug.assert_called_once()

        # Verify the comment includes MSRC URL
        call_args = mock_bugzilla_client.update_bug.call_args
        comment = call_args[1]["comment"]
        assert "MSRC vulnerability information:" in comment
        assert (
            "CVE-2025-10200: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-10200"
            in comment
        )

    def test_update_specific_bugs_already_constrained(
        self, edge_handler, mock_bugzilla_client, mocker
    ):
        """Test updating bugs that already have Edge constraints."""
        mock_bug = mocker.Mock()
        mock_bug.id = 12345
        mock_bug.summary = "Security issue in <www-client/microsoft-edge-140.0.3485.50"
        mock_bug.alias = ["CVE-2025-10200"]
        mock_bugzilla_client.bzapi.getbug.return_value = mock_bug
        # Patch the handler's VersionUtils to indicate constraints are present
        mocker.patch.object(
            edge_handler.version_utils, "has_version_constraints", return_value=True
        )

        result = edge_handler._update_specific_bugs([12345], dry_run=False)

        assert result["updated"] == 0
        assert result["skipped"] == 1
        assert result["errors"] == 0

    def test_update_specific_bugs_no_cves(
        self, edge_handler, mock_bugzilla_client, mocker
    ):
        """Test updating bugs with no CVE aliases."""
        mock_bug = mocker.Mock()
        mock_bug.id = 12345
        mock_bug.summary = "Security issue in www-client/microsoft-edge"
        mock_bug.alias = []  # No CVEs
        mock_bugzilla_client.bzapi.getbug.return_value = mock_bug
        mocker.patch.object(
            edge_handler.version_utils, "has_version_constraints", return_value=False
        )

        result = edge_handler._update_specific_bugs([12345], dry_run=False)

        assert result["updated"] == 0
        assert result["skipped"] == 1
        assert result["errors"] == 0

    def test_update_specific_bugs_dry_run(
        self, edge_handler, mock_bugzilla_client, mocker
    ):
        """Test updating bugs in dry run mode."""
        mock_bug = mocker.Mock()
        mock_bug.id = 12345
        mock_bug.summary = "Security issue in www-client/microsoft-edge"
        mock_bug.alias = ["CVE-2025-10200"]
        mock_bugzilla_client.bzapi.getbug.return_value = mock_bug
        mocker.patch.object(
            edge_handler.version_utils, "has_version_constraints", return_value=False
        )

        mock_query = mocker.patch.object(edge_handler, "query_edge_cves")
        mock_query.return_value = [
            {
                "cve": "CVE-2025-10200",
                "title": "Test CVE",
                "fixed_version": "140.0.3485.58",
            }
        ]

        result = edge_handler._update_specific_bugs([12345], dry_run=True)

        assert result["updated"] == 0  # No actual updates in dry run
        assert result["skipped"] == 0
        assert result["errors"] == 0
        # Should not call update_bug in dry run mode
        mock_bugzilla_client.update_bug.assert_not_called()

    def test_update_specific_bugs_filters_non_msrc_cves(
        self, edge_handler, mock_bugzilla_client, mocker
    ):
        """Test that only CVEs found in MSRC get MSRC URLs in comment."""
        # Setup mock bug with multiple CVEs
        mock_bug = mocker.Mock()
        mock_bug.id = 12345
        mock_bug.summary = "Security issue in www-client/microsoft-edge"
        mock_bug.alias = ["CVE-2025-10200", "CVE-2025-10201", "CVE-2025-10202"]
        mock_bugzilla_client.bzapi.getbug.return_value = mock_bug

        # Mock query - only 2 of 3 CVEs found in MSRC
        mock_query = mocker.patch.object(edge_handler, "query_edge_cves")
        mock_query.return_value = [
            {
                "cve": "CVE-2025-10200",
                "title": "Test CVE 1",
                "fixed_version": "140.0.3485.58",
            },
            {
                "cve": "CVE-2025-10202",
                "title": "Test CVE 2",
                "fixed_version": "140.0.3485.58",
            },
            # CVE-2025-10201 is NOT in MSRC data
        ]

        result = edge_handler._update_specific_bugs([12345], dry_run=False)

        assert result["updated"] == 1

        # Verify the comment only includes MSRC URLs for CVEs that exist in MSRC
        call_args = mock_bugzilla_client.update_bug.call_args
        comment = call_args[1]["comment"]
        assert "MSRC vulnerability information:" in comment
        assert (
            "CVE-2025-10200: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-10200"
            in comment
        )
        assert (
            "CVE-2025-10202: https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-10202"
            in comment
        )
        assert "CVE-2025-10201" not in comment  # This CVE should NOT be in the comment


class TestEdgeHandlerIntegration:
    """Integration tests for Edge handler."""

    def test_full_workflow_with_real_data_structure(
        self, edge_handler, mock_bugzilla_client, sample_cvrf_data, mocker
    ):
        """Test full workflow from CVE lookup to bug update with realistic data."""
        # Mock a bug that needs Edge version constraint
        mock_bug = mocker.Mock()
        mock_bug.id = 12345
        mock_bug.summary = "Security vulnerability in www-client/microsoft-edge browser"
        mock_bug.alias = ["CVE-2025-53791"]
        mock_bugzilla_client.bzapi.getbug.return_value = mock_bug
        mocker.patch.object(
            edge_handler.version_utils, "has_version_constraints", return_value=False
        )

        # Mock MSRC API and CVRF responses
        mock_get = mocker.patch("handlers.edge_handler.requests.get")

        # First call: MSRC API for CVE lookup
        mock_msrc_response = mocker.Mock()
        mock_msrc_response.status_code = 200
        mock_msrc_response.json.return_value = {"value": [{"ID": "2025-Sep"}]}

        # Second call: CVRF document
        mock_cvrf_response = mocker.Mock()
        mock_cvrf_response.status_code = 200
        mock_cvrf_response.text = sample_cvrf_data

        mock_get.side_effect = [mock_msrc_response, mock_cvrf_response]

        # Cache is automatically skipped during testing
        result = edge_handler.update_edge_versions(bugs=[12345], dry_run=False)

        assert result["updated"] == 1

        # Verify the bug update was called with correct parameters
        call_args = mock_bugzilla_client.update_bug.call_args
        assert call_args[0][0] == 12345  # bug_id
        assert "140.0.3485.54" in call_args[1]["summary"]  # Fixed version in title
        assert "Edge version constraint added" in call_args[1]["comment"]
