#!/usr/bin/env python3

"""
Test Opera RSS feed parsing functionality using local test data.
"""

from pathlib import Path
import pytest
import json
import os
import time

from handlers.opera_handler import OperaHandler
from version_utils import VersionUtils


@pytest.fixture
def test_rss_path():
    """Path to test RSS file."""
    return Path(__file__).parent.parent / "data" / "opera_security.rss"


@pytest.fixture(autouse=True)
def mock_rss_requests(test_rss_path, mocker):
    """Auto-use fixture that patches requests.get to return test RSS content for all tests."""
    # Read the test RSS file content
    with open(test_rss_path, "r", encoding="utf-8") as f:
        rss_content = f.read()

    # Mock the requests.get call to return our test RSS content
    mock_get = mocker.patch("handlers.opera_handler.requests.get")
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.content = rss_content.encode("utf-8")
    mock_response.text = rss_content
    mock_get.return_value = mock_response
    yield mock_get


# Common test data
CVE_VERSION_MAPPINGS = [
    ("CVE-2025-6558", "120.0.5543.93"),
    ("CVE-2025-6554", "120.0.5543.38"),
    ("CVE-2025-5419", "119.0.5497.70"),
    ("CVE-2025-2783", "117.0.5408.163"),
]


@pytest.fixture
def mock_bugs(mocker):
    """Mock bugs that would be found by the handler."""
    return [
        mocker.Mock(
            id=12345,
            summary="www-client/opera: Multiple vulnerabilities",
            alias=["CVE-2025-6558"],
        ),
        mocker.Mock(
            id=12346,
            summary="www-client/opera: Security issue",
            alias=["CVE-2025-6554"],
        ),
        mocker.Mock(
            id=12347,
            summary="www-client/opera: Zero-day vulnerability",
            alias=["CVE-2025-5419"],
        ),
    ]


@pytest.fixture
def rss_content(test_rss_path):
    """Read and return RSS content from test file."""
    with open(test_rss_path, "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def mock_rss_response(rss_content, mocker):
    """Create a mock response object with RSS content."""
    mock_response = mocker.Mock()
    mock_response.status_code = 200
    mock_response.content = rss_content.encode("utf-8")
    mock_response.text = rss_content  # Add the text attribute for caching
    return mock_response


def setup_mock_bugzilla_client(mock_bugzilla_client, mock_bugs):
    """Helper to configure mock bugzilla client with standard responses."""
    mock_bugzilla_client.find_security_bugs_by_packages.return_value = mock_bugs
    mock_bugzilla_client.update_bug.return_value = True


def create_mock_version_finder(rss_content, mocker):
    """Create a mock version finder function that uses test RSS content."""

    def mock_find_version(cves):
        mock_get = mocker.patch("handlers.opera_handler.requests.get")
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = rss_content.encode("utf-8")
        mock_response.text = rss_content  # Add the text attribute for caching
        mock_get.return_value = mock_response

        # We need to create a temporary handler to call the RSS method
        handler = OperaHandler(
            mocker.Mock(), mocker.Mock(), dry_run=True, version_utils=VersionUtils()
        )
        version, urls = handler._get_opera_version_from_rss(cves)
        method = "rss" if version else None
        return version, method, urls

    return mock_find_version


@pytest.mark.parametrize(
    "text,expected_version",
    [
        ("Opera One (120.0.5543.93)", "120.0.5543.93"),
        ("Opera GX (120.0.5543.85)", "120.0.5543.85"),
        ("Opera Air (120.0.5543.86)", "120.0.5543.86"),
        ("Opera browser (119.0.5497.70)", "119.0.5497.70"),
        ("Opera (117.0.5408.163)", "117.0.5408.163"),
        ("Update to Opera v115.0.5322.68", "115.0.5322.68"),
        ("Opera Desktop 114.0.5282.122", "114.0.5282.122"),
        ("No version here", None),
    ],
)
def test_version_extraction_patterns(opera_handler, text, expected_version):
    """Test the version extraction regex patterns."""
    result = opera_handler._extract_opera_version_from_text(text)
    assert result == expected_version


@pytest.mark.parametrize(
    "cves,expected_version",
    [
        (["CVE-2025-6558"], "120.0.5543.93"),
        (["CVE-2025-6554"], "120.0.5543.38"),
        (["CVE-2025-5419"], "119.0.5497.70"),
        (["CVE-2025-2783"], "117.0.5408.163"),
        (["CVE-2025-9999"], None),  # CVE doesn't exist
    ],
)
def test_rss_cve_version_mapping(opera_handler, cves, expected_version):
    """Test parsing the Opera security RSS feed for specific CVE mappings."""
    version, urls = opera_handler._get_opera_version_from_rss(cves)
    assert version == expected_version
    if expected_version is not None:
        # If we found a version, we should also have at least one URL
        assert isinstance(urls, list)
        assert len(urls) > 0
    else:
        # If no version found, URLs list should be empty
        assert urls == []


def test_rss_file_exists(test_rss_path):
    """Ensure the test RSS file exists and is readable."""
    assert test_rss_path.exists(), f"Test RSS file not found: {test_rss_path}"
    assert test_rss_path.is_file(), f"Test RSS path is not a file: {test_rss_path}"


def test_rss_file_content_structure(test_rss_path):
    """Verify the RSS file has the expected XML structure."""
    with open(test_rss_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Basic XML structure checks
    assert '<?xml version="1.0"' in content
    assert '<rss version="2.0"' in content
    assert "<channel>" in content
    assert "<item>" in content

    # Opera-specific content checks
    assert "CVE-" in content, "RSS should contain CVE references"
    assert "Opera" in content, "RSS should contain Opera references"


@pytest.mark.integration
def test_multiple_cve_lookup(opera_handler):
    """Test looking up multiple CVEs at once."""
    # Test with multiple CVEs where we expect to find a version
    cves = ["CVE-2025-6558", "CVE-2025-6554"]
    version, urls = opera_handler._get_opera_version_from_rss(cves)

    # Should find a version for at least one of the CVEs
    assert version is not None
    assert version in ["120.0.5543.93", "120.0.5543.38"]
    assert isinstance(urls, list)
    assert len(urls) > 0


@pytest.mark.integration
def test_nonexistent_cve_returns_none(opera_handler):
    """Test that looking up non-existent CVEs returns None."""
    version, urls = opera_handler._get_opera_version_from_rss(["CVE-9999-9999"])
    assert version is None
    assert urls == []


@pytest.mark.parametrize("cve,expected_version", CVE_VERSION_MAPPINGS)
def test_specific_cve_to_version_mapping(opera_handler, cve, expected_version):
    """Test specific CVE to Opera version mappings from the RSS file."""
    version, urls = opera_handler._get_opera_version_from_rss([cve])
    assert version == expected_version
    if expected_version is not None:
        assert isinstance(urls, list)
        assert len(urls) > 0
    else:
        assert urls == []


@pytest.mark.parametrize("dry_run,should_update", [(True, False), (False, True)])
@pytest.mark.integration
def test_opera_handler_workflow(
    mock_bugzilla_client,
    mock_logger,
    mock_bugs,
    rss_content,
    dry_run,
    should_update,
    mocker,
):
    """Test the full Opera handler workflow in both dry-run and live modes."""
    setup_mock_bugzilla_client(mock_bugzilla_client, mock_bugs)

    handler = OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=dry_run, version_utils=VersionUtils()
    )
    mock_find_version = create_mock_version_finder(rss_content, mocker)

    mocker.patch.object(
        handler, "_find_opera_version_for_cves", side_effect=mock_find_version
    )
    results = handler.update_opera_versions()

    # Verify the results
    assert results["total"] == 3
    assert results["updated"] == 3
    assert results["skipped"] == 0

    # Check if update_bug was called based on dry_run mode
    if should_update:
        assert mock_bugzilla_client.update_bug.call_count == 3
    else:
        mock_bugzilla_client.update_bug.assert_not_called()


@pytest.mark.integration
def test_no_bugs_found_scenario(mock_bugzilla_client, mock_logger):
    """Test scenario where no Opera bugs are found."""

    # Configure mock to return no bugs
    mock_bugzilla_client.find_security_bugs_by_packages.return_value = []

    handler = OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=True, version_utils=VersionUtils()
    )

    results = handler.update_opera_versions()

    assert results["total"] == 0
    assert results["updated"] == 0
    assert results["skipped"] == 0

    # No update_bug calls should be made
    mock_bugzilla_client.update_bug.assert_not_called()


@pytest.mark.integration
def test_handler_with_version_constraint_already_present(
    mock_bugzilla_client, mock_logger, rss_content, mocker
):
    """Test handler behavior when bugs already have version constraints."""

    # Mock bug with version constraint already in title
    mock_bug = mocker.Mock(
        id=12345,
        summary="<www-client/opera-120.0.5543.90: Already has constraint",
        alias=["CVE-2025-6558"],
    )

    mock_bugzilla_client.find_security_bugs_by_packages.return_value = [mock_bug]

    handler = OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=True, version_utils=VersionUtils()
    )
    mock_find_version = create_mock_version_finder(rss_content, mocker)

    mocker.patch.object(
        handler, "_find_opera_version_for_cves", side_effect=mock_find_version
    )
    results = handler.update_opera_versions()

    # Should skip the bug since it already has a constraint
    assert results["total"] == 1
    assert results["updated"] == 0
    assert results["skipped"] == 1

    mock_bugzilla_client.update_bug.assert_not_called()


def make_rss_item(title, link, description="", content_encoded=""):
    parts = []
    parts.append(f"<title>{title}</title>")
    parts.append(f"<link>{link}</link>")
    if description:
        parts.append(f"<description>{description}</description>")
    if content_encoded:
        parts.append(f"<content:encoded>{content_encoded}</content:encoded>")
    return "<item>" + "".join(parts) + "</item>"


def wrap_rss(items_xml):
    return '<?xml version="1.0"?><rss><channel>' + items_xml + "</channel></rss>"


def test_get_opera_version_from_rss_uses_cache(
    tmp_path, opera_handler, monkeypatch, mocker
):
    handler = opera_handler

    cache_file = tmp_path / "opera_security_rss.json"
    rss = wrap_rss(
        make_rss_item(
            "Security update - CVE-2025-0000",
            "https://example.com/post",
            description="Opera One (120.0.5543.93)",
        )
    )
    cache_data = {"content": rss, "cached_at": time.time(), "url": handler.rss_url}
    cache_file.write_text(json.dumps(cache_data))

    monkeypatch.setattr(handler, "_get_rss_cache_file_path", lambda: str(cache_file))
    monkeypatch.setattr(type(handler), "_is_testing", lambda self: False)

    ver, urls = handler._get_opera_version_from_rss(["CVE-2025-0000"])
    assert ver == "120.0.5543.93"
    assert urls == ["https://example.com/post"]


def test_get_opera_version_from_rss_falls_back_to_post(
    opera_handler, monkeypatch, mocker
):
    handler = opera_handler

    rss = wrap_rss(
        make_rss_item("Security update - CVE-2025-0001", "https://example.com/post")
    )

    def fake_get(url, timeout=30):
        resp = mocker.Mock()
        if url == handler.rss_url:
            resp.status_code = 200
            resp.text = rss
            return resp
        elif url == "https://example.com/post":
            resp.status_code = 200
            resp.content = b'<div class="content">Opera One (121.0.5600.1)</div>'
            return resp
        else:
            resp.status_code = 404
            return resp

    monkeypatch.setattr("handlers.opera_handler.requests.get", fake_get)

    ver, urls = handler._get_opera_version_from_rss(["CVE-2025-0001"])
    assert ver == "121.0.5600.1"
    assert urls == ["https://example.com/post"]


def test_get_opera_version_from_rss_malformed_rss_returns_none(
    opera_handler, monkeypatch, mocker
):
    handler = opera_handler

    def fake_get(url, timeout=30):
        resp = mocker.Mock()
        resp.status_code = 200
        resp.text = "this is not xml <rss>"
        return resp

    monkeypatch.setattr("handlers.opera_handler.requests.get", fake_get)

    ver, urls = handler._get_opera_version_from_rss(["CVE-2025-0002"])
    assert ver is None
    assert urls == []


def test_rss_cache_expired_triggers_fetch(tmp_path, opera_handler, monkeypatch, mocker):
    handler = opera_handler

    cache_file = tmp_path / "opera_security_rss.json"
    rss = wrap_rss(
        make_rss_item(
            "Security update - CVE-2025-0003",
            "https://example.com/post",
            description="Opera One (122.0.0.1)",
        )
    )
    cache_data = {
        "content": rss,
        "cached_at": time.time() - 3600 * 24,
        "url": handler.rss_url,
    }
    cache_file.write_text(json.dumps(cache_data))

    monkeypatch.setattr(handler, "_get_rss_cache_file_path", lambda: str(cache_file))
    old_time = time.time() - (3600 * 10)
    os.utime(cache_file, (old_time, old_time))

    calls = {"count": 0}

    def fake_get(url, timeout=30):
        calls["count"] += 1
        resp = mocker.Mock()
        resp.status_code = 200
        resp.text = rss
        return resp

    monkeypatch.setattr("handlers.opera_handler.requests.get", fake_get)
    monkeypatch.setattr(type(handler), "_is_testing", lambda self: False)

    ver, urls = handler._get_opera_version_from_rss(["CVE-2025-0003"])
    assert ver == "122.0.0.1"
    assert calls["count"] >= 1
