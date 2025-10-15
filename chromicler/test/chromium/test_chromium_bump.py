#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for chromium_handler bump functionality
"""

import pytest
import json
from handlers.chromium_handler import ChromiumHandler


class TestChromiumBump:
    """Test Chrome/Chromium bump operations."""

    @pytest.fixture
    def mock_ebuild_mgr(self, mocker):
        """Mock EbuildManager."""
        mgr = mocker.Mock()
        mgr.bump_ebuild = mocker.Mock()
        mgr.repo = mocker.Mock()
        mgr.repo.git = mocker.Mock()
        mgr.repo.index = mocker.Mock()
        mgr.repo.working_dir = "/tmp/test-repo"
        return mgr

    @pytest.fixture
    def handler(
        self,
        mock_logger,
        mock_bugzilla_client,
        mock_version_utils,
        mock_ebuild_mgr,
        mocker,
    ):
        """Create ChromiumHandler with mocked dependencies."""

        # Configure mock_version_utils to handle version tuples
        def get_ebuild_version_impl(ver_tuple):
            """Convert (version, revision) tuple to string."""
            if ver_tuple[1] == "r0":
                return ver_tuple[0]
            return f"{ver_tuple[0]}-{ver_tuple[1]}"

        mock_version_utils.get_ebuild_version.side_effect = get_ebuild_version_impl

        handler = ChromiumHandler(
            api_key_file="./bugzilla_api_key",
            logger=mock_logger,
            dry_run=True,
            browser_registry=None,
            version_utils=mock_version_utils,
        )
        # Mock bugzilla property
        mocker.patch.object(
            type(handler),
            "bugzilla",
            new_callable=mocker.PropertyMock,
            return_value=mock_bugzilla_client,
        )
        # Mock ebuild manager
        handler.ebuild_mgr = mock_ebuild_mgr
        return handler

    def test_fetch_chrome_version(self, handler, mocker):
        """Test fetching Chrome version from version history API."""
        # Mock JSON response
        mock_response_data = json.dumps(
            {
                "releases": [
                    {
                        "name": "chrome/platforms/linux/channels/stable/versions/141.0.6778.108/releases/1234",
                        "version": "141.0.6778.108",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        # Mock urlopen
        mock_urlopen = mocker.patch("urllib.request.urlopen")
        mock_response = mock_urlopen.return_value
        mock_response.read.return_value = mock_response_data

        version = handler._get_chrome_version_for_channel("stable")

        # Should return newest version
        assert version == "141.0.6778.108"

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

    def test_get_cves_for_chrome_version(self, handler, mocker):
        """Test CVE extraction from release blog."""
        mock_parse = mocker.patch.object(handler, "parse_chrome_releases")
        mock_parse.return_value = [
            {
                "linux_version": "141.0.6778.108",
                "cves": ["CVE-2025-0001", "CVE-2025-0002", "CVE-2025-0003"],
                "title": "Stable Channel Update",
                "date": "2025-01-15",
            }
        ]

        cves = handler._get_cves_for_chrome_version("141.0.6778.108")

        assert "CVE-2025-0001" in cves
        assert "CVE-2025-0002" in cves
        assert "CVE-2025-0003" in cves
        assert len(cves) == 3

    def test_bump_chrome_package_non_major(self, handler, mock_ebuild_mgr):
        """Test non-major bump for chromium package."""
        pkg_data = {
            "www-client": {
                "stable": {
                    "pkg": "google-chrome",
                    "suffix": None,
                    "version": (
                        "141.0.6778.33",
                        "r0",
                    ),  # Just the version string, not a list
                    "stable": True,
                }
            }
        }

        chrome_info = {"stable": "141.0.6778.108"}

        handler._bump_chrome_package(
            category="www-client",
            channel="stable",
            pkg_data=pkg_data,
            chrome_info=chrome_info,
            ebuild_mgr=mock_ebuild_mgr,
            link_bugs=False,
            dry_run=True,
        )

        # Verify bump_ebuild was called
        mock_ebuild_mgr.bump_ebuild.assert_called_once()
        call_args = mock_ebuild_mgr.bump_ebuild.call_args

        assert call_args.kwargs["atom"] == "www-client/google-chrome"
        assert call_args.kwargs["new_version"] == "141.0.6778.108"
        assert call_args.kwargs["source_atom"] == "www-client/google-chrome"
        assert call_args.kwargs["source_version"] == "141.0.6778.33"
        assert call_args.kwargs["keywords"] is None  # Non-major bump uses None

    def test_bump_chrome_package_major(self, handler, mock_ebuild_mgr):
        """Test major bump copies from previous channel."""
        pkg_data = {
            "www-client": {
                "stable": {
                    "pkg": "google-chrome",
                    "suffix": None,
                    "version": ("140.0.6723.58", "r0"),
                    "stable": True,
                },
                "beta": {
                    "pkg": "google-chrome-beta",
                    "suffix": None,
                    "version": ("141.0.6778.33", "r0"),
                    "stable": False,
                },
            }
        }

        chrome_info = {"stable": "141.0.6778.108"}

        handler._bump_chrome_package(
            category="www-client",
            channel="stable",
            pkg_data=pkg_data,
            chrome_info=chrome_info,
            ebuild_mgr=mock_ebuild_mgr,
            link_bugs=False,
            dry_run=True,
        )

        # Verify source is from beta channel
        call_args = mock_ebuild_mgr.bump_ebuild.call_args
        assert call_args.kwargs["source_atom"] == "www-client/google-chrome-beta"
        assert call_args.kwargs["source_version"] == "141.0.6778.33"
        assert call_args.kwargs["keywords"] == ["amd64"]  # Major bump uses amd64

    def test_bump_chrome_binary_plugins_with_suffix(self, handler, mock_ebuild_mgr):
        """Test chrome-binary-plugins with _beta suffix handling."""
        pkg_data = {
            "www-plugins": {
                "beta": {
                    "pkg": "chrome-binary-plugins",
                    "suffix": "beta",
                    "version": ("141.0.6778.33", "r0"),
                    "stable": False,
                }
            }
        }

        chrome_info = {"beta": "141.0.6778.108"}

        handler._bump_chrome_package(
            category="www-plugins",
            channel="beta",
            pkg_data=pkg_data,
            chrome_info=chrome_info,
            ebuild_mgr=mock_ebuild_mgr,
            link_bugs=False,
            dry_run=True,
        )

        # Verify suffix is included in source_version
        call_args = mock_ebuild_mgr.bump_ebuild.call_args
        assert call_args.kwargs["source_atom"] == "www-plugins/chrome-binary-plugins"
        assert call_args.kwargs["source_version"] == "141.0.6778.33_beta"

    def test_bump_chromedriver_copies_from_itself(self, handler, mock_ebuild_mgr):
        """Test chromedriver-bin copies from itself for all channels."""
        pkg_data = {
            "www-apps": {
                "stable": {
                    "pkg": "chromedriver-bin",
                    "suffix": None,
                    "version": ("141.0.6778.33", "r0"),
                    "stable": True,
                },
                "beta": {
                    "pkg": "chromedriver-bin",
                    "suffix": None,
                    "version": ("141.0.6778.33", "r0"),
                    "stable": False,
                },
            }
        }

        chrome_info = {"stable": "141.0.6778.108"}

        handler._bump_chrome_package(
            category="www-apps",
            channel="stable",
            pkg_data=pkg_data,
            chrome_info=chrome_info,
            ebuild_mgr=mock_ebuild_mgr,
            link_bugs=False,
            dry_run=True,
        )

        # Verify source is from same package (chromedriver always copies from itself)
        call_args = mock_ebuild_mgr.bump_ebuild.call_args
        assert call_args.kwargs["source_atom"] == "www-apps/chromedriver-bin"
        assert call_args.kwargs["source_version"] == "141.0.6778.33"


class TestChromiumBumpChromeIntegration:
    """Test full bump_chrome workflow with real portage and git."""

    @pytest.fixture
    def temp_repo(self, portage_test_repo):
        """Create a temporary git repository with Chrome ebuilds."""
        packages = {
            "www-client/google-chrome": {
                "versions": ["140.0.6723.58"],
                "keywords": "~amd64",
                "description": "Google Chrome Web Browser",
            },
            "www-client/google-chrome-beta": {
                "versions": ["141.0.6778.33"],
                "keywords": "~amd64",
                "description": "Google Chrome Web Browser (Beta)",
            },
            "www-client/google-chrome-unstable": {
                "versions": ["142.0.6800.12"],
                "keywords": "~amd64",
                "description": "Google Chrome Web Browser (Dev)",
            },
            "www-plugins/chrome-binary-plugins": {
                "versions": [
                    "140.0.6723.58",
                    "141.0.6778.33_beta",
                    "142.0.6800.12_alpha",
                ],
                "keywords": "~amd64",
                "description": "Chrome binary plugins (Widevine CDM, ...)",
            },
            "www-apps/chromedriver-bin": {
                "versions": ["140.0.6723.58"],
                "keywords": "~amd64",
                "description": "WebDriver for Chrome",
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
        from handlers.chromium_handler import ChromiumHandler

        handler = portage_handler(
            ChromiumHandler,
            temp_repo,
            mock_logger,
            mocker,
            dry_run=True,
            browser_registry=None,
        )

        # Mock bugzilla
        mock_bugzilla = mocker.Mock()
        mock_bugzilla.check_existing_bugs_for_cves.return_value = {}
        mocker.patch.object(
            type(handler),
            "bugzilla",
            new_callable=mocker.PropertyMock,
            return_value=mock_bugzilla,
        )

        return handler

    def test_bump_chrome_stable_non_major(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test bump_chrome for stable channel non-major version bump."""
        handler = handler_with_real_portage

        # Mock upstream version API
        mock_response_stable = json.dumps(
            {
                "releases": [
                    {
                        "version": "140.0.6723.108",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_response_beta = json.dumps(
            {
                "releases": [
                    {
                        "version": "141.0.6778.50",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_response_dev = json.dumps(
            {
                "releases": [
                    {
                        "version": "142.0.6800.20",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_urlopen = mocker.patch("urllib.request.urlopen")
        mock_urlopen.return_value.read.side_effect = [
            mock_response_stable,
            mock_response_beta,
            mock_response_dev,
        ]

        # Mock CVE lookup
        mocker.patch.object(handler, "_get_cves_for_chrome_version", return_value=[])

        # Run bump_chrome
        result = handler.bump_chrome(
            channels=["stable"],
            link_bugs=False,
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        # Should detect bump needed (140.0.6723.58 -> 140.0.6723.108)
        # In dry_run mode, we won't actually create files, but we can verify the logic
        assert result["errors"] == 0

    def test_bump_chrome_major_version_bump(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test bump_chrome for major version bump (stable 140 -> 141)."""
        handler = handler_with_real_portage

        # Mock upstream version API - stable gets bumped to 141
        mock_response_stable = json.dumps(
            {
                "releases": [
                    {
                        "version": "141.0.6778.108",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_response_beta = json.dumps(
            {
                "releases": [
                    {
                        "version": "141.0.6778.50",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_response_dev = json.dumps(
            {
                "releases": [
                    {
                        "version": "142.0.6800.20",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_urlopen = mocker.patch("urllib.request.urlopen")
        mock_urlopen.return_value.read.side_effect = [
            mock_response_stable,
            mock_response_beta,
            mock_response_dev,
        ]

        # Mock CVE lookup
        mocker.patch.object(handler, "_get_cves_for_chrome_version", return_value=[])

        # Run bump_chrome
        result = handler.bump_chrome(
            channels=["stable"],
            link_bugs=False,
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        # Should detect major bump (140 -> 141)
        assert result["errors"] == 0

    def test_bump_chrome_all_channels(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test bump_chrome for all channels."""
        handler = handler_with_real_portage

        # Mock upstream version API
        mock_response_stable = json.dumps(
            {
                "releases": [
                    {
                        "version": "140.0.6723.108",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_response_beta = json.dumps(
            {
                "releases": [
                    {
                        "version": "141.0.6778.108",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_response_dev = json.dumps(
            {
                "releases": [
                    {
                        "version": "142.0.6800.50",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_urlopen = mocker.patch("urllib.request.urlopen")
        mock_urlopen.return_value.read.side_effect = [
            mock_response_stable,
            mock_response_beta,
            mock_response_dev,
        ]

        # Mock CVE lookup
        mocker.patch.object(handler, "_get_cves_for_chrome_version", return_value=[])

        # Run bump_chrome for all channels
        result = handler.bump_chrome(
            channels=["stable", "beta", "dev"],
            link_bugs=False,
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        # All channels should be processed
        assert result["errors"] == 0

    def test_bump_chrome_no_updates_needed(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test bump_chrome when no updates are needed."""
        handler = handler_with_real_portage

        # Mock upstream version API - same as what's in repo
        mock_response_stable = json.dumps(
            {
                "releases": [
                    {
                        "version": "140.0.6723.58",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_response_beta = json.dumps(
            {
                "releases": [
                    {
                        "version": "141.0.6778.33",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_response_dev = json.dumps(
            {
                "releases": [
                    {
                        "version": "142.0.6800.12",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_urlopen = mocker.patch("urllib.request.urlopen")
        mock_urlopen.return_value.read.side_effect = [
            mock_response_stable,
            mock_response_beta,
            mock_response_dev,
        ]

        # Run bump_chrome
        result = handler.bump_chrome(
            channels=["stable", "beta", "dev"],
            link_bugs=False,
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        # No bumps should be needed
        assert result["bumped"] == 0
        assert result["errors"] == 0

    def test_bump_chrome_with_cve_linking(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test bump_chrome with CVE bug linking."""
        handler = handler_with_real_portage

        # Mock upstream version API
        mock_response_stable = json.dumps(
            {
                "releases": [
                    {
                        "version": "140.0.6723.108",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_response_beta = json.dumps(
            {
                "releases": [
                    {
                        "version": "141.0.6778.33",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_response_dev = json.dumps(
            {
                "releases": [
                    {
                        "version": "142.0.6800.12",
                        "serving": {"startTime": "2025-01-15T00:00:00Z"},
                    }
                ]
            }
        ).encode("utf-8")

        mock_urlopen = mocker.patch("urllib.request.urlopen")
        mock_urlopen.return_value.read.side_effect = [
            mock_response_stable,
            mock_response_beta,
            mock_response_dev,
        ]

        # Mock CVE lookup
        mock_cves = ["CVE-2025-0001", "CVE-2025-0002"]
        mocker.patch.object(
            handler, "_get_cves_for_chrome_version", return_value=mock_cves
        )

        # Mock existing bugs
        handler.bugzilla.check_existing_bugs_for_cves.return_value = {
            "CVE-2025-0001": 999999
        }

        # Run bump_chrome with link_bugs enabled
        result = handler.bump_chrome(
            channels=["stable"],
            link_bugs=True,
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        # Should have found CVEs - only called once for chrome itself
        handler.bugzilla.check_existing_bugs_for_cves.assert_called_once_with(mock_cves)
        assert result["errors"] == 0

    def test_bump_chrome_upstream_fetch_failure(
        self, handler_with_real_portage, temp_repo, mocker
    ):
        """Test bump_chrome handles upstream version fetch failures gracefully."""
        handler = handler_with_real_portage

        # Mock upstream version API to fail
        mock_urlopen = mocker.patch("urllib.request.urlopen")
        mock_urlopen.side_effect = Exception("Network error")

        # Run bump_chrome
        result = handler.bump_chrome(
            channels=["stable"],
            link_bugs=False,
            repo_path=temp_repo["repo_path"],
            dry_run=True,
        )

        # Should handle error gracefully
        # Since we can't determine upstream versions, no bumps will happen
        assert result["bumped"] == 0
