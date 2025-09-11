#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for bump_utils - Shared bump operation utilities
"""

import pytest

from bump_utils import (
    is_major_bump,
    get_prev_channel_generic,
    calculate_versions_to_remove,
    limit_new_versions,
    bump_browser_package,
)


class TestIsMajorBump:
    """Test major bump detection logic."""

    def test_major_version_increase(self):
        """Test detection of major version increase (e.g., 140.x -> 141.x)."""

        def get_prev_channel(channel):
            return "beta" if channel == "stable" else "dev"

        result = is_major_bump(
            "140.0.6723.58", "141.0.6778.33", "stable", get_prev_channel
        )
        assert result is True

    def test_minor_version_increase(self):
        """Test that minor version increases are not major bumps."""

        def get_prev_channel(channel):
            return "beta" if channel == "stable" else "dev"

        result = is_major_bump(
            "141.0.6723.58", "141.0.6778.33", "stable", get_prev_channel
        )
        assert result is False

    def test_dev_channel_copies_from_itself(self):
        """Test that dev channel returns False even with major version increase."""

        def get_prev_channel(channel):
            return "dev"  # Dev copies from itself

        result = is_major_bump(
            "140.0.6723.58", "141.0.6778.33", "dev", get_prev_channel
        )
        assert result is False

    def test_invalid_version_format(self):
        """Test handling of invalid version strings."""

        def get_prev_channel(channel):
            return "beta"

        result = is_major_bump("invalid", "141.0.6778.33", "stable", get_prev_channel)
        assert result is False

    def test_same_version(self):
        """Test that same version is not a major bump."""

        def get_prev_channel(channel):
            return "beta"

        result = is_major_bump(
            "141.0.6723.58", "141.0.6723.58", "stable", get_prev_channel
        )
        assert result is False


class TestGetPrevChannelGeneric:
    """Test channel progression logic."""

    def test_stable_to_beta(self):
        """Test stable channel gets beta as previous."""
        channels = ["stable", "beta", "dev"]
        result = get_prev_channel_generic("stable", channels)
        assert result == "beta"

    def test_beta_to_dev(self):
        """Test beta channel gets dev as previous."""
        channels = ["stable", "beta", "dev"]
        result = get_prev_channel_generic("beta", channels)
        assert result == "dev"

    def test_dev_to_itself(self):
        """Test dev channel copies from itself."""
        channels = ["stable", "beta", "dev"]
        result = get_prev_channel_generic("dev", channels)
        assert result == "dev"

    def test_opera_channels(self):
        """Test Opera's channel names (developer instead of dev)."""
        channels = ["stable", "beta", "developer"]
        assert get_prev_channel_generic("stable", channels) == "beta"
        assert get_prev_channel_generic("beta", channels) == "developer"
        assert get_prev_channel_generic("developer", channels) == "developer"

    def test_unknown_channel_raises_error(self):
        """Test that unknown channel raises ValueError."""
        channels = ["stable", "beta", "dev"]
        with pytest.raises(ValueError, match="Unknown channel"):
            get_prev_channel_generic("unknown", channels)


class TestCalculateVersionsToRemove:
    """Test version cleanup calculation logic."""

    def test_no_removal_needed(self):
        """Test when current + new versions <= max_count."""
        current = [("141.0", "r0"), ("140.0", "r0")]
        new = [("142.0", "r0")]
        max_count = 3

        result = calculate_versions_to_remove(current, new, max_count)
        assert result == []

    def test_remove_oldest_version(self):
        """Test removal of oldest version when exceeding limit."""
        current = [("141.0", "r0"), ("140.0", "r0"), ("139.0", "r0")]
        new = [("142.0", "r0")]
        max_count = 3

        result = calculate_versions_to_remove(current, new, max_count)
        assert result == [("139.0", "r0")]

    def test_remove_multiple_old_versions(self):
        """Test removal of multiple old versions."""
        current = [("141.0", "r0"), ("140.0", "r0"), ("139.0", "r0"), ("138.0", "r0")]
        new = [("142.0", "r0"), ("141.5", "r0")]
        max_count = 3

        result = calculate_versions_to_remove(current, new, max_count)
        # Should remove 3 oldest versions to make room for 2 new ones
        # and keep only 3 total (max_count)
        assert result == [("140.0", "r0"), ("139.0", "r0"), ("138.0", "r0")]

    def test_no_new_versions(self):
        """Test with empty new versions list."""
        current = [("141.0", "r0"), ("140.0", "r0")]
        new = []
        max_count = 3

        result = calculate_versions_to_remove(current, new, max_count)
        assert result == []

    def test_exact_limit(self):
        """Test when total equals max_count."""
        current = [("141.0", "r0"), ("140.0", "r0")]
        new = [("142.0", "r0")]
        max_count = 3

        result = calculate_versions_to_remove(current, new, max_count)
        assert result == []


class TestLimitNewVersions:
    """Test new version limiting logic."""

    def test_within_limit(self):
        """Test when new versions are within limit."""
        new = [("142.0", "r0"), ("141.5", "r0")]
        max_count = 3

        result = limit_new_versions(new, max_count)
        assert result == new

    def test_exceeds_limit(self):
        """Test limiting when exceeding max_count."""
        new = [("142.0", "r0"), ("141.5", "r0"), ("141.0", "r0"), ("140.5", "r0")]
        max_count = 2

        result = limit_new_versions(new, max_count)
        assert result == [("142.0", "r0"), ("141.5", "r0")]

    def test_empty_list(self):
        """Test with empty list."""
        result = limit_new_versions([], 3)
        assert result == []


class TestBumpBrowserPackage:
    """Test the shared browser package bump implementation."""

    @pytest.fixture
    def mock_ebuild_mgr(self, mocker):
        """Mock EbuildManager."""
        mgr = mocker.Mock()
        mgr.bump_ebuild = mocker.Mock()
        mgr.repo = mocker.Mock()
        mgr.repo.index = mocker.Mock()
        mgr.repo.git = mocker.Mock()
        return mgr

    @pytest.fixture
    def mock_logger(self, mocker):
        """Mock logger."""
        return mocker.Mock()

    @pytest.fixture
    def mock_repo_path(self, tmp_path):
        """Create a temporary repository structure."""
        repo = tmp_path / "repo"
        repo.mkdir()

        # Create package directories
        for pkg in ["microsoft-edge", "microsoft-edge-beta", "microsoft-edge-dev"]:
            pkg_dir = repo / "www-client" / pkg
            pkg_dir.mkdir(parents=True)

            # Create metadata.xml
            metadata = pkg_dir / "metadata.xml"
            metadata.write_text("<pkgmetadata></pkgmetadata>")

        return repo

    def test_non_major_bump(self, mock_ebuild_mgr, mock_logger, mock_repo_path):
        """Test non-major bump copies from same package."""
        pkg_data = {
            "stable": {
                "pkg": "microsoft-edge",
                "version": [("141.0.3537", "r0")],
                "stable": True,
            }
        }

        def get_ebuild_version(ver_tuple):
            return (
                ver_tuple[0]
                if ver_tuple[1] == "r0"
                else f"{ver_tuple[0]}-{ver_tuple[1]}"
            )

        def get_prev_channel(channel):
            return "beta"

        bump_browser_package(
            atom="www-client/microsoft-edge",
            channel="stable",
            uversion="141.0.3537.71",
            tversion="141.0.3537.44",
            major_bump=False,
            pkg_data=pkg_data,
            ebuild_mgr=mock_ebuild_mgr,
            repo_path=mock_repo_path,
            dry_run=True,
            logger=mock_logger,
            get_ebuild_version_func=get_ebuild_version,
            get_prev_channel_func=get_prev_channel,
            enable_stabilization=False,
        )

        # Verify bump_ebuild was called correctly
        mock_ebuild_mgr.bump_ebuild.assert_called_once()
        call_args = mock_ebuild_mgr.bump_ebuild.call_args

        assert call_args.kwargs["atom"] == "www-client/microsoft-edge"
        assert call_args.kwargs["new_version"] == "141.0.3537.71"
        assert call_args.kwargs["source_atom"] == "www-client/microsoft-edge"
        assert call_args.kwargs["source_version"] == "141.0.3537.44"
        assert call_args.kwargs["keywords"] is None
        assert call_args.kwargs["remove_old"] is False

    def test_major_bump_from_previous_channel(
        self, mock_ebuild_mgr, mock_logger, mock_repo_path
    ):
        """Test major bump copies from previous channel."""
        pkg_data = {
            "stable": {
                "pkg": "microsoft-edge",
                "version": [("140.0.3485", "r0")],
                "stable": True,
            },
            "beta": {
                "pkg": "microsoft-edge-beta",
                "version": [("141.0.3537", "r0")],
                "stable": False,
            },
        }

        def get_ebuild_version(ver_tuple):
            return (
                ver_tuple[0]
                if ver_tuple[1] == "r0"
                else f"{ver_tuple[0]}-{ver_tuple[1]}"
            )

        def get_prev_channel(channel):
            return "beta" if channel == "stable" else "dev"

        bump_browser_package(
            atom="www-client/microsoft-edge",
            channel="stable",
            uversion="141.0.3537.71",
            tversion="140.0.3485.94",
            major_bump=True,
            pkg_data=pkg_data,
            ebuild_mgr=mock_ebuild_mgr,
            repo_path=mock_repo_path,
            dry_run=True,
            logger=mock_logger,
            get_ebuild_version_func=get_ebuild_version,
            get_prev_channel_func=get_prev_channel,
            enable_stabilization=False,
        )

        # Verify source is from beta channel
        call_args = mock_ebuild_mgr.bump_ebuild.call_args
        assert call_args.kwargs["source_atom"] == "www-client/microsoft-edge-beta"
        assert call_args.kwargs["source_version"] == "141.0.3537"
        assert call_args.kwargs["keywords"] == ["~amd64"]

    def test_major_bump_copies_metadata_xml(
        self, mock_ebuild_mgr, mock_logger, mock_repo_path
    ):
        """Test that major bump copies metadata.xml (non-dry-run)."""
        pkg_data = {
            "stable": {
                "pkg": "microsoft-edge",
                "version": [("140.0.3485", "r0")],
                "stable": True,
            },
            "beta": {
                "pkg": "microsoft-edge-beta",
                "version": [("141.0.3537", "r0")],
                "stable": False,
            },
        }

        def get_ebuild_version(ver_tuple):
            return ver_tuple[0]

        def get_prev_channel(channel):
            return "beta"

        bump_browser_package(
            atom="www-client/microsoft-edge",
            channel="stable",
            uversion="141.0.3537.71",
            tversion="140.0.3485.94",
            major_bump=True,
            pkg_data=pkg_data,
            ebuild_mgr=mock_ebuild_mgr,
            repo_path=mock_repo_path,
            dry_run=False,
            logger=mock_logger,
            get_ebuild_version_func=get_ebuild_version,
            get_prev_channel_func=get_prev_channel,
            enable_stabilization=False,
        )

        # Verify metadata.xml was copied
        target_metadata = (
            mock_repo_path / "www-client" / "microsoft-edge" / "metadata.xml"
        )
        assert target_metadata.exists()

        # Verify it was added to git index
        mock_ebuild_mgr.repo.index.add.assert_called()

    def test_stabilization_workflow(
        self, mock_ebuild_mgr, mock_logger, mock_repo_path, mocker
    ):
        """Test two-phase stabilization workflow for stable channel."""
        # Mock subprocess.check_call
        mock_subprocess = mocker.patch("subprocess.check_call")
        # Create ebuild file for testing
        ebuild_file = (
            mock_repo_path
            / "www-client"
            / "microsoft-edge"
            / "microsoft-edge-141.0.3537.71.ebuild"
        )
        ebuild_file.parent.mkdir(parents=True, exist_ok=True)
        ebuild_file.write_text("# test ebuild")

        pkg_data = {
            "stable": {
                "pkg": "microsoft-edge",
                "version": [("140.0.3485", "r0")],
                "stable": True,
            },
            "beta": {
                "pkg": "microsoft-edge-beta",
                "version": [("141.0.3537", "r0")],
                "stable": False,
            },
        }

        def get_ebuild_version(ver_tuple):
            return ver_tuple[0]

        def get_prev_channel(channel):
            return "beta"

        # Mock digestgen and portdbapi
        mocker.patch("portage.package.ebuild.digestgen.digestgen")
        mocker.patch("portage.dbapi.porttree.portdbapi")

        bump_browser_package(
            atom="www-client/microsoft-edge",
            channel="stable",
            uversion="141.0.3537.71",
            tversion="140.0.3485.94",
            major_bump=True,
            pkg_data=pkg_data,
            ebuild_mgr=mock_ebuild_mgr,
            repo_path=mock_repo_path,
            dry_run=False,
            logger=mock_logger,
            get_ebuild_version_func=get_ebuild_version,
            get_prev_channel_func=get_prev_channel,
            enable_stabilization=True,
        )

        # Verify ekeyword was called
        mock_subprocess.assert_called_once()
        assert "ekeyword" in str(mock_subprocess.call_args)
        assert "amd64" in str(mock_subprocess.call_args)

        # Verify git commit was made
        mock_ebuild_mgr.repo.git.commit.assert_called_once()
        commit_args = mock_ebuild_mgr.repo.git.commit.call_args
        assert "amd64 stable" in str(commit_args)

    def test_no_stabilization_for_beta_channel(
        self, mock_ebuild_mgr, mock_logger, mock_repo_path, mocker
    ):
        """Test that stabilization is not performed for non-stable channels."""
        # Mock subprocess.check_call
        mock_subprocess = mocker.patch("subprocess.check_call")

        pkg_data = {
            "beta": {
                "pkg": "microsoft-edge-beta",
                "version": [("141.0.3537", "r0")],
                "stable": False,
            }
        }

        def get_ebuild_version(ver_tuple):
            return ver_tuple[0]

        def get_prev_channel(channel):
            return "dev"

        bump_browser_package(
            atom="www-client/microsoft-edge-beta",
            channel="beta",
            uversion="141.0.3537.71",
            tversion="141.0.3537.44",
            major_bump=False,
            pkg_data=pkg_data,
            ebuild_mgr=mock_ebuild_mgr,
            repo_path=mock_repo_path,
            dry_run=False,
            logger=mock_logger,
            get_ebuild_version_func=get_ebuild_version,
            get_prev_channel_func=get_prev_channel,
            enable_stabilization=True,
        )

        # Verify ekeyword was NOT called
        mock_subprocess.assert_not_called()

    def test_dry_run_no_metadata_copy(
        self, mock_ebuild_mgr, mock_logger, mock_repo_path
    ):
        """Test that metadata.xml is not copied in dry-run mode."""
        pkg_data = {
            "stable": {
                "pkg": "microsoft-edge",
                "version": [("140.0.3485", "r0")],
                "stable": True,
            },
            "beta": {
                "pkg": "microsoft-edge-beta",
                "version": [("141.0.3537", "r0")],
                "stable": False,
            },
        }

        # Remove target metadata to verify it's not created
        target_metadata = (
            mock_repo_path / "www-client" / "microsoft-edge" / "metadata.xml"
        )
        if target_metadata.exists():
            target_metadata.unlink()

        def get_ebuild_version(ver_tuple):
            return ver_tuple[0]

        def get_prev_channel(channel):
            return "beta"

        bump_browser_package(
            atom="www-client/microsoft-edge",
            channel="stable",
            uversion="141.0.3537.71",
            tversion="140.0.3485.94",
            major_bump=True,
            pkg_data=pkg_data,
            ebuild_mgr=mock_ebuild_mgr,
            repo_path=mock_repo_path,
            dry_run=True,
            logger=mock_logger,
            get_ebuild_version_func=get_ebuild_version,
            get_prev_channel_func=get_prev_channel,
            enable_stabilization=False,
        )

        # Verify metadata was not created (dry run)
        assert not target_metadata.exists()
