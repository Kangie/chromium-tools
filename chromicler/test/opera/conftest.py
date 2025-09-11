"""Shared fixtures for Opera handler tests."""

import pytest
from pathlib import Path

from handlers.opera_handler import OperaHandler
from version_utils import VersionUtils


@pytest.fixture
def opera_handler(mocker):
    """Create OperaHandler instance for testing."""
    mock_bugzilla_client = mocker.Mock()
    mock_logger = mocker.Mock()
    handler = OperaHandler(
        api_key_file="./bugzilla_api_key",
        logger=mock_logger,
        dry_run=True,
        version_utils=VersionUtils(),
    )
    # Mock the bugzilla property
    mocker.patch.object(
        type(handler),
        "bugzilla",
        new_callable=mocker.PropertyMock,
        return_value=mock_bugzilla_client,
    )
    return handler


@pytest.fixture
def test_data_dir():
    """Path to test data directory."""
    return Path(__file__).parent.parent / "data"


@pytest.fixture
def sample_bug(mocker):
    """Sample bug object for testing."""
    bug = mocker.Mock()
    bug.id = 12345
    bug.summary = "Test bug summary"
    bug.alias = []
    bug.status = "NEW"
    bug.whiteboard = ""
    return bug


@pytest.fixture
def sample_rss_content():
    """Sample Opera RSS feed content."""
    return """<?xml version="1.0" encoding="UTF-8"?>
    <rss version="2.0" xmlns:content="http://purl.org/rss/1.0/modules/content/">
        <channel>
            <title>Opera Desktop</title>
            <item>
                <title>Opera 95.0.4635.46</title>
                <description>Latest Opera release</description>
                <content:encoded><![CDATA[
                    <p>Security updates based on Chromium 109.0.5414.74</p>
                    <p>Fixed CVE-2023-0001, CVE-2023-0002</p>
                ]]></content:encoded>
            </item>
            <item>
                <title>Opera 94.0.4606.65</title>
                <description>Previous Opera release</description>
                <content:encoded><![CDATA[
                    <p>Based on Chromium 108.0.5359.125</p>
                ]]></content:encoded>
            </item>
        </channel>
    </rss>
    """


@pytest.fixture
def mock_requests_get(mocker):
    """Mock requests.get for HTTP calls."""
    with mocker.patch("handlers.opera_handler.requests.get") as mock_get:
        yield mock_get


@pytest.fixture
def mock_rss_response(sample_rss_content, mocker):
    """Mock response for RSS requests."""
    mock_response = mocker.Mock()
    mock_response.text = sample_rss_content
    mock_response.status_code = 200
    mock_response.raise_for_status.return_value = None
    return mock_response


@pytest.fixture
def mock_rss_requests(mock_rss_response, mocker):
    """Mock RSS requests (manual fixture, not autouse)."""
    with mocker.patch("handlers.opera_handler.requests.get") as mock_get:
        mock_get.return_value = mock_rss_response
        yield mock_get


@pytest.fixture
def mock_bugzilla_client(mocker):
    """Mock Bugzilla client for testing."""
    mock_client = mocker.patch("handlers.opera_handler.BugzillaClient")
    client_instance = mocker.Mock()
    mock_client.return_value = client_instance
    return client_instance


@pytest.fixture
def version_mapping_data():
    """Sample version mapping data for testing."""
    return {
        "109.0.5414.74": ["95.0.4635.46"],
        "108.0.5359.125": ["94.0.4606.65", "94.0.4606.54"],
        "107.0.5304.87": ["93.0.4585.37"],
    }


@pytest.fixture
def chromium_versions():
    """List of Chromium versions for testing."""
    return ["109.0.5414.74", "108.0.5359.125", "107.0.5304.87", "106.0.5249.119"]


@pytest.fixture
def opera_versions():
    """List of Opera versions for testing."""
    return ["95.0.4635.46", "94.0.4606.65", "94.0.4606.54", "93.0.4585.37"]
