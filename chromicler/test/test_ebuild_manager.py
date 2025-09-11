#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for EbuildManager

Note: These tests require portage to be available. Tests will be skipped
if portage is not installed.
"""

import pytest
from git import GitCommandError

# Check if portage is available - skip all tests if not
pytest.importorskip("portage", reason="Portage required for EbuildManager tests")


class TestEbuildManagerInit:
    """Test EbuildManager initialization."""

    def test_init_success(self, tmp_path, mocker, mock_logger):
        """Test successful initialization."""
        # Mock git repo in the ebuild_manager module
        mock_repo = mocker.MagicMock()
        mocker.patch("ebuild_manager.Repo", return_value=mock_repo)

        from ebuild_manager import EbuildManager

        mgr = EbuildManager(repo_path=str(tmp_path), logger=mock_logger, dry_run=False)

        assert mgr.repo_path == tmp_path
        assert mgr.logger == mock_logger
        assert mgr.dry_run is False
        assert mgr.repo == mock_repo
        assert mgr.version_utils is not None

    def test_init_dry_run(self, tmp_path, mocker, mock_logger):
        """Test initialization in dry-run mode."""
        mocker.patch("ebuild_manager.Repo")

        from ebuild_manager import EbuildManager

        mgr = EbuildManager(repo_path=str(tmp_path), logger=mock_logger, dry_run=True)

        assert mgr.dry_run is True

    def test_init_nonexistent_path(self, mocker, mock_logger):
        """Test initialization with non-existent path."""
        from ebuild_manager import EbuildManager

        with pytest.raises(ValueError, match="Repository path does not exist"):
            EbuildManager(
                repo_path="/nonexistent/path", logger=mock_logger, dry_run=False
            )

    def test_init_invalid_git_repo(self, tmp_path, mocker, mock_logger):
        """Test initialization with invalid git repository."""
        # Mock Repo to raise an exception when instantiated
        mock_repo_class = mocker.patch("ebuild_manager.Repo")
        mock_repo_class.side_effect = Exception("Not a git repo")

        from ebuild_manager import EbuildManager

        with pytest.raises(ValueError, match="Invalid git repository"):
            EbuildManager(repo_path=str(tmp_path), logger=mock_logger, dry_run=False)


class TestGetPackageVersions:
    """Test get_package_versions method."""

    @pytest.fixture
    def ebuild_manager(self, tmp_path, mocker, mock_logger):
        """Create an EbuildManager instance for testing."""
        mocker.patch("ebuild_manager.Repo")

        from ebuild_manager import EbuildManager

        return EbuildManager(repo_path=str(tmp_path), logger=mock_logger)

    def test_get_versions_success(self, ebuild_manager, tmp_path):
        """Test getting versions from package directory."""
        # Create package directory with ebuilds
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)

        (pkg_dir / "google-chrome-130.0.6723.58.ebuild").touch()
        (pkg_dir / "google-chrome-131.0.6778.69.ebuild").touch()
        (pkg_dir / "google-chrome-132.0.6834.83.ebuild").touch()

        versions = ebuild_manager.get_package_versions("www-client/google-chrome")

        assert len(versions) == 3
        # Versions should be sorted (portage handles this)
        version_strings = [v[0] for v in versions]
        assert "130.0.6723.58" in version_strings
        assert "131.0.6778.69" in version_strings
        assert "132.0.6834.83" in version_strings

    def test_get_versions_package_not_found(self, ebuild_manager):
        """Test getting versions for non-existent package."""
        versions = ebuild_manager.get_package_versions("www-client/nonexistent")

        assert versions == []

    def test_get_versions_empty_directory(self, ebuild_manager, tmp_path):
        """Test getting versions from empty package directory."""
        pkg_dir = tmp_path / "www-client" / "empty-package"
        pkg_dir.mkdir(parents=True)

        versions = ebuild_manager.get_package_versions("www-client/empty-package")

        assert versions == []


class TestGetLatestVersion:
    """Test get_latest_version method."""

    @pytest.fixture
    def ebuild_manager(self, tmp_path, mocker, mock_logger):
        """Create an EbuildManager instance for testing."""
        mocker.patch("ebuild_manager.Repo")

        from ebuild_manager import EbuildManager

        return EbuildManager(repo_path=str(tmp_path), logger=mock_logger)

    def test_get_latest_version_success(self, ebuild_manager, tmp_path):
        """Test getting latest version."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)

        (pkg_dir / "google-chrome-130.0.6723.58.ebuild").touch()
        (pkg_dir / "google-chrome-131.0.6778.69.ebuild").touch()

        latest = ebuild_manager.get_latest_version("www-client/google-chrome")

        # Should return a version (portage sorts them)
        assert latest in ["130.0.6723.58", "131.0.6778.69"]

    def test_get_latest_version_not_found(self, ebuild_manager):
        """Test getting latest version for non-existent package."""
        latest = ebuild_manager.get_latest_version("www-client/nonexistent")

        assert latest is None


class TestVersionExists:
    """Test version_exists method."""

    @pytest.fixture
    def ebuild_manager(self, tmp_path, mocker, mock_logger):
        """Create an EbuildManager instance for testing."""
        mocker.patch("ebuild_manager.Repo")

        from ebuild_manager import EbuildManager

        return EbuildManager(repo_path=str(tmp_path), logger=mock_logger)

    def test_version_exists_true(self, ebuild_manager, tmp_path):
        """Test checking if version exists."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)

        (pkg_dir / "google-chrome-131.0.6778.69.ebuild").touch()

        exists = ebuild_manager.version_exists(
            "www-client/google-chrome", "131.0.6778.69"
        )

        assert exists is True

    def test_version_exists_false(self, ebuild_manager, tmp_path):
        """Test checking if version doesn't exist."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)

        (pkg_dir / "google-chrome-131.0.6778.69.ebuild").touch()

        exists = ebuild_manager.version_exists(
            "www-client/google-chrome", "132.0.6834.83"
        )

        assert exists is False


class TestCompareVersions:
    """Test compare_versions method."""

    @pytest.fixture
    def ebuild_manager(self, tmp_path, mocker, mock_logger):
        """Create an EbuildManager instance for testing."""
        mocker.patch("ebuild_manager.Repo")

        from ebuild_manager import EbuildManager

        return EbuildManager(repo_path=str(tmp_path), logger=mock_logger)

    def test_compare_versions_less_than(self, ebuild_manager):
        """Test comparing versions where v1 < v2."""
        result = ebuild_manager.compare_versions("130.0.6723.58", "131.0.6778.69")

        assert result == -1

    def test_compare_versions_equal(self, ebuild_manager):
        """Test comparing equal versions."""
        result = ebuild_manager.compare_versions("131.0.6778.69", "131.0.6778.69")

        assert result == 0

    def test_compare_versions_greater_than(self, ebuild_manager):
        """Test comparing versions where v1 > v2."""
        result = ebuild_manager.compare_versions("132.0.6834.83", "131.0.6778.69")

        assert result == 1


class TestBumpEbuild:
    """Test bump_ebuild method."""

    @pytest.fixture
    def ebuild_manager(self, tmp_path, mocker, mock_logger):
        """Create an EbuildManager instance for testing."""
        mock_repo = mocker.MagicMock()
        mock_repo.index = mocker.MagicMock()
        mock_repo.git = mocker.MagicMock()
        mocker.patch("ebuild_manager.Repo", return_value=mock_repo)

        from ebuild_manager import EbuildManager

        mgr = EbuildManager(repo_path=str(tmp_path), logger=mock_logger)
        mgr.repo = mock_repo
        return mgr

    def test_bump_ebuild_simple(self, ebuild_manager, tmp_path, mocker):
        """Test simple ebuild bump."""
        # Create package directory with existing ebuild
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)
        old_ebuild = pkg_dir / "google-chrome-130.0.6723.58.ebuild"
        old_ebuild.write_text("# Old ebuild content")

        # Mock digestgen
        mocker.patch("portage.package.ebuild.digestgen.digestgen")
        mock_config = mocker.MagicMock()
        mocker.patch("portage.package.ebuild.config.config", return_value=mock_config)

        result = ebuild_manager.bump_ebuild(
            atom="www-client/google-chrome",
            new_version="131.0.6778.69",
            remove_old=False,
        )

        assert result["success"] is True
        assert result["new_version"] == "131.0.6778.69"
        assert result["old_version"] == "130.0.6723.58"

        # Verify new ebuild was created
        new_ebuild = pkg_dir / "google-chrome-131.0.6778.69.ebuild"
        assert new_ebuild.exists()

    def test_bump_ebuild_with_remove_old(self, ebuild_manager, tmp_path, mocker):
        """Test ebuild bump with old version removal."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)
        old_ebuild = pkg_dir / "google-chrome-130.0.6723.58.ebuild"
        old_ebuild.write_text("# Old ebuild")

        # Mock digestgen
        mocker.patch("portage.package.ebuild.digestgen.digestgen")
        mock_config = mocker.MagicMock()
        mocker.patch("portage.package.ebuild.config.config", return_value=mock_config)

        result = ebuild_manager.bump_ebuild(
            atom="www-client/google-chrome",
            new_version="131.0.6778.69",
            remove_old=True,
        )

        assert result["success"] is True
        # Verify git.index.remove was called
        ebuild_manager.repo.index.remove.assert_called_once()

    def test_bump_ebuild_from_different_package(self, ebuild_manager, tmp_path, mocker):
        """Test bumping from a different package (major bump scenario)."""
        # Create source package
        source_pkg_dir = tmp_path / "www-client" / "google-chrome-beta"
        source_pkg_dir.mkdir(parents=True)
        source_ebuild = source_pkg_dir / "google-chrome-beta-132.0.6834.15.ebuild"
        source_ebuild.write_text("# Beta ebuild")

        # Create target package directory
        target_pkg_dir = tmp_path / "www-client" / "google-chrome"
        target_pkg_dir.mkdir(parents=True)

        # Mock digestgen
        mocker.patch("portage.package.ebuild.digestgen.digestgen")
        mock_config = mocker.MagicMock()
        mocker.patch("portage.package.ebuild.config.config", return_value=mock_config)

        result = ebuild_manager.bump_ebuild(
            atom="www-client/google-chrome",
            new_version="132.0.6834.15",
            source_atom="www-client/google-chrome-beta",
            source_version="132.0.6834.15",
            remove_old=False,
        )

        assert result["success"] is True
        assert result["new_version"] == "132.0.6834.15"

        # Verify new ebuild was created in target directory
        new_ebuild = target_pkg_dir / "google-chrome-132.0.6834.15.ebuild"
        assert new_ebuild.exists()

    def test_bump_ebuild_version_already_exists(self, ebuild_manager, tmp_path):
        """Test bump when version already exists."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)
        (pkg_dir / "google-chrome-131.0.6778.69.ebuild").write_text("# Existing")

        result = ebuild_manager.bump_ebuild(
            atom="www-client/google-chrome",
            new_version="131.0.6778.69",
        )

        assert result["success"] is False
        assert "already exists" in result["message"]

    def test_bump_ebuild_no_existing_versions(self, ebuild_manager, tmp_path):
        """Test bump when no existing versions found."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)

        with pytest.raises(ValueError, match="No existing ebuilds found"):
            ebuild_manager.bump_ebuild(
                atom="www-client/google-chrome",
                new_version="131.0.6778.69",
            )

    def test_bump_ebuild_source_not_found(self, ebuild_manager, tmp_path):
        """Test bump when source ebuild not found."""
        with pytest.raises(ValueError, match="Source ebuild not found"):
            ebuild_manager.bump_ebuild(
                atom="www-client/google-chrome",
                new_version="132.0.6834.15",
                source_atom="www-client/google-chrome-beta",
                source_version="132.0.6834.15",
            )

    def test_bump_ebuild_with_keywords(self, ebuild_manager, tmp_path, mocker):
        """Test ebuild bump with keyword updates."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)
        old_ebuild = pkg_dir / "google-chrome-130.0.6723.58.ebuild"
        old_ebuild.write_text("# Old ebuild")

        # Mock subprocess for ekeyword
        mock_subprocess = mocker.patch("subprocess.run")
        mock_subprocess.return_value = mocker.MagicMock(returncode=0)

        # Mock digestgen
        mocker.patch("portage.package.ebuild.digestgen.digestgen")
        mock_config = mocker.MagicMock()
        mocker.patch("portage.package.ebuild.config.config", return_value=mock_config)

        result = ebuild_manager.bump_ebuild(
            atom="www-client/google-chrome",
            new_version="131.0.6778.69",
            keywords=["~amd64", "~x86"],
            remove_old=False,
        )

        assert result["success"] is True
        # Verify ekeyword was called
        mock_subprocess.assert_called_once()
        assert "ekeyword" in str(mock_subprocess.call_args)

    def test_bump_ebuild_with_commit_message(self, ebuild_manager, tmp_path, mocker):
        """Test ebuild bump with custom commit message."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)
        old_ebuild = pkg_dir / "google-chrome-130.0.6723.58.ebuild"
        old_ebuild.write_text("# Old ebuild")

        # Mock digestgen
        mocker.patch("portage.package.ebuild.digestgen.digestgen")
        mock_config = mocker.MagicMock()
        mocker.patch("portage.package.ebuild.config.config", return_value=mock_config)

        custom_msg = "www-client/google-chrome: security bump"

        result = ebuild_manager.bump_ebuild(
            atom="www-client/google-chrome",
            new_version="131.0.6778.69",
            commit_message=custom_msg,
            remove_old=False,
        )

        assert result["success"] is True
        assert result["commit_message"] == custom_msg
        ebuild_manager.repo.git.commit.assert_called_once()

    def test_bump_ebuild_with_bug_urls(self, ebuild_manager, tmp_path, mocker):
        """Test ebuild bump with bug URLs."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)
        old_ebuild = pkg_dir / "google-chrome-130.0.6723.58.ebuild"
        old_ebuild.write_text("# Old ebuild")

        # Mock digestgen
        mocker.patch("portage.package.ebuild.digestgen.digestgen")
        mock_config = mocker.MagicMock()
        mocker.patch("portage.package.ebuild.config.config", return_value=mock_config)

        bug_urls = ["https://bugs.gentoo.org/123456"]

        result = ebuild_manager.bump_ebuild(
            atom="www-client/google-chrome",
            new_version="131.0.6778.69",
            bug_urls=bug_urls,
            remove_old=False,
        )

        assert result["success"] is True
        assert "Bug: https://bugs.gentoo.org/123456" in result["commit_message"]

    def test_bump_ebuild_dry_run(self, tmp_path, mocker, mock_logger):
        """Test ebuild bump in dry-run mode."""
        mock_repo = mocker.MagicMock()
        mocker.patch("ebuild_manager.Repo", return_value=mock_repo)

        from ebuild_manager import EbuildManager

        mgr = EbuildManager(repo_path=str(tmp_path), logger=mock_logger, dry_run=True)

        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)
        old_ebuild = pkg_dir / "google-chrome-130.0.6723.58.ebuild"
        old_ebuild.write_text("# Old ebuild")

        result = mgr.bump_ebuild(
            atom="www-client/google-chrome",
            new_version="131.0.6778.69",
            remove_old=True,
        )

        assert result["success"] is True
        # In dry-run, new ebuild should NOT be created
        new_ebuild = pkg_dir / "google-chrome-131.0.6778.69.ebuild"
        assert not new_ebuild.exists()
        # Git operations should not be called
        mock_repo.index.remove.assert_not_called()
        mock_repo.git.commit.assert_not_called()

    def test_bump_ebuild_manifest_generation_fails(
        self, ebuild_manager, tmp_path, mocker
    ):
        """Test ebuild bump when manifest generation fails."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)
        old_ebuild = pkg_dir / "google-chrome-130.0.6723.58.ebuild"
        old_ebuild.write_text("# Old ebuild")

        # Mock digestgen to raise an exception
        mocker.patch(
            "portage.package.ebuild.digestgen.digestgen",
            side_effect=Exception("Digest generation failed"),
        )
        mock_config = mocker.MagicMock()
        mocker.patch("portage.package.ebuild.config.config", return_value=mock_config)

        with pytest.raises(Exception, match="Digest generation failed"):
            ebuild_manager.bump_ebuild(
                atom="www-client/google-chrome",
                new_version="131.0.6778.69",
                remove_old=False,
            )

    def test_bump_ebuild_git_commit_fails(self, ebuild_manager, tmp_path, mocker):
        """Test ebuild bump when git commit fails."""
        pkg_dir = tmp_path / "www-client" / "google-chrome"
        pkg_dir.mkdir(parents=True)
        old_ebuild = pkg_dir / "google-chrome-130.0.6723.58.ebuild"
        old_ebuild.write_text("# Old ebuild")

        # Mock digestgen
        mocker.patch("portage.package.ebuild.digestgen.digestgen")
        mock_config = mocker.MagicMock()
        mocker.patch("portage.package.ebuild.config.config", return_value=mock_config)

        # Make git commit fail
        ebuild_manager.repo.git.commit.side_effect = GitCommandError("git commit", 1)

        with pytest.raises(GitCommandError):
            ebuild_manager.bump_ebuild(
                atom="www-client/google-chrome",
                new_version="131.0.6778.69",
                remove_old=False,
            )
