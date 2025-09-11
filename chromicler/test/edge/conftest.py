#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Shared fixtures and configuration for Edge handler tests.
"""

import pytest
from pathlib import Path


@pytest.fixture
def edge_test_data_dir():
    """Return path to Edge test data directory."""
    return Path(__file__).parent.parent / "data"


@pytest.fixture
def mock_edge_bug(mocker):
    """Mock bug for Edge testing."""
    bug = mocker.Mock()
    bug.id = 12345
    bug.summary = "Security vulnerability affects www-client/microsoft-edge"
    bug.alias = ["CVE-2025-10200"]
    return bug
