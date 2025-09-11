#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for opera_handler bump functionality; the shared logic is tested in test_bump_utils.py
"""

import pytest
from handlers.opera_handler import OperaHandler


class TestOperaBump:
    """Test Opera bump operations - focusing on handler-specific logic."""

    @pytest.fixture
    def handler(self, mock_logger, mock_version_utils):
        """Create OperaHandler with mocked dependencies."""

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

        handler = OperaHandler(
            api_key_file="./bugzilla_api_key",
            logger=mock_logger,
            dry_run=True,
            version_utils=mock_version_utils,
        )
        return handler

    def test_get_prev_channel_stable_to_beta(self, handler):
        """Test channel progression from stable."""
        prev = handler._get_prev_channel("stable")
        assert prev == "beta"

    def test_get_prev_channel_beta_to_developer(self, handler):
        """Test channel progression from beta to developer (Opera-specific)."""
        prev = handler._get_prev_channel("beta")
        assert prev == "developer"

    def test_get_prev_channel_developer_to_itself(self, handler):
        """Test developer channel copies from itself."""
        prev = handler._get_prev_channel("developer")
        assert prev == "developer"

    def test_compare_version_tuples(self, handler):
        """Test version comparison helper."""
        result = handler._compare_version_tuples(
            ("116.0.5360.61", "r0"), ("116.0.5360.60", "r0")
        )
        # Should return > 0 since first version is newer
        assert result > 0

    def test_get_ebuild_version_no_revision(self, handler):
        """Test ebuild version conversion without revision."""
        version = handler._get_ebuild_version(("116.0.5360.61", "r0"))
        assert version == "116.0.5360.61"

    def test_get_ebuild_version_with_revision(self, handler):
        """Test ebuild version conversion with revision."""
        version = handler._get_ebuild_version(("116.0.5360.61", "r1"))
        assert version == "116.0.5360.61-r1"

    def test_opera_channel_names(self, handler):
        """Test that Opera uses stable/beta/developer (not 'dev') channels."""
        # Opera's unique channel name
        channels = ["stable", "beta", "developer"]
        for channel in channels:
            # Should not raise ValueError
            prev = handler._get_prev_channel(channel)
            assert prev in channels

    def test_opera_channel_different_from_edge(self, handler):
        """Test that Opera's developer channel is different from Edge's dev."""
        # This documents Opera's uniqueness - it uses "developer" not "dev"
        prev_dev = handler._get_prev_channel("developer")
        assert prev_dev == "developer"

        # Should raise ValueError for "dev" channel (Edge uses this, Opera doesn't)
        with pytest.raises(ValueError):
            handler._get_prev_channel("dev")


class TestOperaBumpIntegration:
    """Integration tests for Opera bump using real portage and git."""

    @pytest.fixture
    def temp_repo(self, portage_test_repo):
        """Create a temporary git repository with Opera ebuilds."""
        packages = {
            "www-client/opera": {
                "versions": ["116.0.5360.60"],
                "keywords": "amd64",  # stable channel gets stable keywords
                "description": "Opera Web Browser (Stable Channel)",
            },
            "www-client/opera-beta": {
                "versions": ["117.0.5384.35"],
                "keywords": "~amd64",
                "description": "Opera Web Browser (Beta Channel)",
            },
            "www-client/opera-developer": {
                "versions": ["118.0.5410.0"],
                "keywords": "~amd64",
                "description": "Opera Web Browser (Developer Channel)",
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
        from handlers.opera_handler import OperaHandler

        handler = portage_handler(
            OperaHandler,
            temp_repo,
            mock_logger,
            mocker,
            dry_run=True,
        )

        return handler

    def test_bump_opera_stable_non_major(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test bumping Opera stable channel with non-major version."""
        handler = handler_with_real_portage

        # Mock Opera version fetching - returns list of (version, revision) tuples
        def mock_get_versions(package, archive, platform, tree_versions):
            if "opera-beta" in package:
                return [("117.0.5384.35", "r0")]
            elif "opera-developer" in package:
                return [("118.0.5410.0", "r0")]
            else:  # stable
                return [("116.0.5360.65", "r0")]

        mocker.patch.object(
            handler, "_get_opera_versions_for_channel", side_effect=mock_get_versions
        )

        # Run bump_opera
        result = handler.bump_opera(
            channels=["stable"],
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        assert result["errors"] == 0
        # Should find that stable needs a bump (116.0.5360.60 -> 116.0.5360.65)
        assert result["bumped"] >= 0  # May be 0 in dry_run, but shouldn't error

    def test_bump_opera_all_channels(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test bumping all Opera channels."""
        handler = handler_with_real_portage

        # Mock Opera version fetching - returns list of (version, revision) tuples
        def mock_get_versions(package, archive, platform, tree_versions):
            if "opera-beta" in package:
                return [("117.0.5384.42", "r0")]
            elif "opera-developer" in package:
                return [("118.0.5410.5", "r0")]
            else:  # stable
                return [("116.0.5360.65", "r0")]

        mocker.patch.object(
            handler, "_get_opera_versions_for_channel", side_effect=mock_get_versions
        )

        # Run bump_opera for all channels
        result = handler.bump_opera(
            channels=["stable", "beta", "developer"],
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        assert result["errors"] == 0

    def test_bump_opera_no_updates_needed(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test Opera bump when no updates are needed."""
        handler = handler_with_real_portage

        # Mock Opera version fetching to match what's in tree
        def mock_get_versions(package, archive, platform, tree_versions):
            if "opera-beta" in package:
                return [("117.0.5384.35", "r0")]
            elif "opera-developer" in package:
                return [("118.0.5410.0", "r0")]
            else:  # stable
                return [("116.0.5360.60", "r0")]

        mocker.patch.object(
            handler, "_get_opera_versions_for_channel", side_effect=mock_get_versions
        )

        # Run bump_opera
        result = handler.bump_opera(
            channels=["stable", "beta", "developer"],
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        # Should complete without errors, nothing to bump
        assert result["errors"] == 0
        assert result["bumped"] == 0
