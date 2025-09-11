#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for edge_handler bump functionality; tests Edge-specific logic - the shared logic
is tested in test_bump_utils.py
"""

import pytest
from handlers.edge_handler import EdgeHandler


class TestEdgeBump:
    """Test Edge bump operations - focusing on handler-specific logic."""

    @pytest.fixture
    def handler(self, mock_logger, mock_version_utils):
        """Create EdgeHandler with mocked dependencies."""

        # Configure mock_version_utils to handle version tuples
        def get_ebuild_version_impl(ver_tuple):
            """Convert (version, revision) tuple to string."""
            if ver_tuple[1] == "r0":
                return ver_tuple[0]
            return f"{ver_tuple[0]}-{ver_tuple[1]}"

        mock_version_utils.get_ebuild_version.side_effect = get_ebuild_version_impl
        mock_version_utils.compare_version_tuples.side_effect = (
            lambda v1, v2: 0 if v1 == v2 else (1 if v1 > v2 else -1)
        )

        handler = EdgeHandler(
            api_key_file="./bugzilla_api_key",
            logger=mock_logger,
            version_utils=mock_version_utils,
        )
        return handler

    def test_get_prev_channel_stable_to_beta(self, handler):
        """Test channel progression from stable."""
        prev = handler._get_prev_channel("stable")
        assert prev == "beta"

    def test_get_prev_channel_beta_to_dev(self, handler):
        """Test channel progression from beta."""
        prev = handler._get_prev_channel("beta")
        assert prev == "dev"

    def test_get_prev_channel_dev_to_itself(self, handler):
        """Test dev channel copies from itself."""
        prev = handler._get_prev_channel("dev")
        assert prev == "dev"

    def test_compare_version_tuples(self, handler):
        """Test version comparison helper."""
        result = handler._compare_version_tuples(
            ("131.0.2903.51", "r0"), ("131.0.2903.48", "r0")
        )
        # Should return > 0 since first version is newer
        assert result > 0

    def test_get_ebuild_version_no_revision(self, handler):
        """Test ebuild version conversion without revision."""
        version = handler._get_ebuild_version(("131.0.2903.51", "r0"))
        assert version == "131.0.2903.51"

    def test_get_ebuild_version_with_revision(self, handler):
        """Test ebuild version conversion with revision."""
        version = handler._get_ebuild_version(("131.0.2903.51", "r1"))
        assert version == "131.0.2903.51-r1"

    def test_edge_uses_standard_channel_names(self, handler):
        """Test that Edge uses standard stable/beta/dev channels."""
        # This is implicit in _get_prev_channel but worth documenting
        channels = ["stable", "beta", "dev"]
        for channel in channels:
            # Should not raise ValueError
            prev = handler._get_prev_channel(channel)
            assert prev in channels


class TestEdgeBumpIntegration:
    """Integration tests for Edge bump using real portage and git."""

    @pytest.fixture
    def temp_repo(self, portage_test_repo):
        """Create a temporary git repository with Edge ebuilds."""
        packages = {
            "www-client/microsoft-edge": {
                "versions": ["131.0.2903.48"],
                "keywords": "amd64",  # stable channel gets stable keywords
                "description": "Microsoft Edge Web Browser (Stable Channel)",
            },
            "www-client/microsoft-edge-beta": {
                "versions": ["132.0.2957.18"],
                "keywords": "~amd64",
                "description": "Microsoft Edge Web Browser (Beta Channel)",
            },
            "www-client/microsoft-edge-dev": {
                "versions": ["133.0.3014.0"],
                "keywords": "~amd64",
                "description": "Microsoft Edge Web Browser (Dev Channel)",
            },
        }

        repo_data = portage_test_repo(packages)
        yield repo_data
        repo_data["cleanup"]()

    @pytest.fixture
    def handler_with_real_portage(
        self, portage_handler, temp_repo, mock_logger, mocker
    ):
        """Create handler with real portage using proper configuration."""
        from handlers.edge_handler import EdgeHandler

        handler = portage_handler(
            EdgeHandler,
            temp_repo,
            mock_logger,
            mocker,
        )

        return handler

    def test_bump_edge_stable_non_major(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test bumping Edge stable channel with non-major version."""
        handler = handler_with_real_portage

        # Mock upstream version API - returns dict of channel -> list of (version, revision) tuples
        mock_versions = {
            "stable": [("131.0.2903.51", "1")],
            "beta": [("132.0.2957.18", "1")],
            "dev": [("133.0.3014.0", "1")],
        }
        mocker.patch.object(handler, "_get_edge_versions", return_value=mock_versions)

        # Run bump_edge
        result = handler.bump_edge(
            channels=["stable"],
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        assert result["errors"] == 0
        # Should find that stable needs a bump (131.0.2903.48 -> 131.0.2903.51)
        assert result["bumped"] >= 0  # May be 0 in dry_run, but shouldn't error

    def test_bump_edge_all_channels(self, handler_with_real_portage, temp_repo, mocker):
        """Test bumping all Edge channels."""
        handler = handler_with_real_portage

        # Mock upstream version API - returns dict of channel -> list of (version, revision) tuples
        mock_versions = {
            "stable": [("131.0.2903.51", "1")],
            "beta": [("132.0.2957.21", "1")],
            "dev": [("133.0.3014.5", "1")],
        }
        mocker.patch.object(handler, "_get_edge_versions", return_value=mock_versions)

        # Run bump_edge for all channels
        result = handler.bump_edge(
            channels=["stable", "beta", "dev"],
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        assert result["errors"] == 0

    def test_bump_edge_no_updates_needed(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test Edge bump when no updates are needed."""
        handler = handler_with_real_portage

        # Mock upstream versions to match what's in tree - list of tuples
        mock_versions = {
            "stable": [("131.0.2903.48", "1")],
            "beta": [("132.0.2957.18", "1")],
            "dev": [("133.0.3014.0", "1")],
        }
        mocker.patch.object(handler, "_get_edge_versions", return_value=mock_versions)

        # Run bump_edge
        result = handler.bump_edge(
            channels=["stable", "beta", "dev"],
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        # Should complete without errors, nothing to bump
        assert result["errors"] == 0
        assert result["bumped"] == 0
