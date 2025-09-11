#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Test fixtures for Chromium Handler tests.
"""

import pytest
from pathlib import Path

from handlers.chromium_handler import ChromiumHandler
from chromicler import BrowserRegistry
from handlers.vivaldi_handler import VivaldiHandler
from handlers.edge_handler import EdgeHandler
from handlers.opera_handler import OperaHandler


@pytest.fixture
def mock_bugzilla_client(mocker):
    """Mock BugzillaClient for testing."""
    client = mocker.Mock()
    client.find_chromium_security_bugs.return_value = []
    client.check_existing_bugs_for_cves.return_value = {}
    client.create_security_bug.return_value = 999999
    client.update_bug.return_value = True
    client.get_bug_comments.return_value = []
    return client


@pytest.fixture
def mock_logger(mocker):
    """Mock logger for testing."""
    return mocker.Mock()


@pytest.fixture
def browser_registry(mock_bugzilla_client, mock_logger, mock_version_utils, mocker):
    """Browser registry with all handlers registered for testing."""
    registry = BrowserRegistry()

    # Create handlers and register their browsers
    chromium_handler = ChromiumHandler(
        api_key_file="./bugzilla_api_key",
        logger=mock_logger,
        dry_run=True,
        browser_registry=None,
        version_utils=mock_version_utils,
    )
    # Mock bugzilla property
    mocker.patch.object(
        type(chromium_handler),
        "bugzilla",
        new_callable=mocker.PropertyMock,
        return_value=mock_bugzilla_client,
    )

    edge_handler = EdgeHandler(
        api_key_file="./bugzilla_api_key",
        logger=mock_logger,
        version_utils=mock_version_utils,
    )
    mocker.patch.object(
        type(edge_handler),
        "bugzilla",
        new_callable=mocker.PropertyMock,
        return_value=mock_bugzilla_client,
    )

    opera_handler = OperaHandler(
        api_key_file="./bugzilla_api_key",
        logger=mock_logger,
        dry_run=True,
        version_utils=mock_version_utils,
    )
    mocker.patch.object(
        type(opera_handler),
        "bugzilla",
        new_callable=mocker.PropertyMock,
        return_value=mock_bugzilla_client,
    )

    vivaldi_handler = VivaldiHandler(
        api_key_file="./bugzilla_api_key",
        logger=mock_logger,
        version_utils=mock_version_utils,
    )
    mocker.patch.object(
        type(vivaldi_handler),
        "bugzilla",
        new_callable=mocker.PropertyMock,
        return_value=mock_bugzilla_client,
    )

    # Register browsers with handlers
    chromium_handler.register_browsers(registry)
    edge_handler.register_browsers(registry)
    opera_handler.register_browsers(registry)
    vivaldi_handler.register_browsers(registry)

    return registry


@pytest.fixture
def chromium_handler(
    mock_bugzilla_client, mock_logger, browser_registry, mock_version_utils, mocker
):
    """ChromiumHandler instance for testing."""
    handler = ChromiumHandler(
        api_key_file="./bugzilla_api_key",
        logger=mock_logger,
        dry_run=True,
        browser_registry=browser_registry,
        version_utils=mock_version_utils,
    )
    mocker.patch.object(
        type(handler),
        "bugzilla",
        new_callable=mocker.PropertyMock,
        return_value=mock_bugzilla_client,
    )
    return handler


@pytest.fixture
def chromium_handler_no_dry_run(
    mock_bugzilla_client, mock_logger, browser_registry, mock_version_utils, mocker
):
    """ChromiumHandler instance for testing without dry run."""
    handler = ChromiumHandler(
        api_key_file="./bugzilla_api_key",
        logger=mock_logger,
        dry_run=False,
        browser_registry=browser_registry,
        version_utils=mock_version_utils,
    )
    mocker.patch.object(
        type(handler),
        "bugzilla",
        new_callable=mocker.PropertyMock,
        return_value=mock_bugzilla_client,
    )
    return handler


@pytest.fixture
def chrome_release_html():
    """Load Chrome release HTML test data."""
    html_file = Path(__file__).parent.parent / "data" / "chrome_release_2025_09_17.html"
    return html_file.read_text()


@pytest.fixture
def chrome_blog_index_html():
    """Load Chrome blog index HTML test data."""
    html_file = (
        Path(__file__).parent.parent / "data" / "chrome_releases_blog_index_sample.html"
    )
    return html_file.read_text()


@pytest.fixture
def larry_comments():
    """Load Larry Git Cow comment test data."""
    comments_file = Path(__file__).parent.parent / "data" / "larry_bugzilla_text"
    return [
        {
            "creator": "infra-gitbot@gentoo.org",
            "text": comments_file.read_text(),
            "time": "2025-09-18T10:00:00Z",
        }
    ]
