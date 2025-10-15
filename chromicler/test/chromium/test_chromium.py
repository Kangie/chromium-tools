#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Tests for Chromium Handler - Chrome security release workflow
"""

from handlers.chromium_handler import ChromiumHandler


class TestChromiumHandlerBlogParsing:
    """Test Chromium handler Chrome blog parsing."""

    def test_parse_chrome_releases_success(
        self, mocker, chromium_handler, chrome_blog_index_html
    ):
        """Test successful parsing of Chrome releases blog index."""
        # Mock the blog index page
        mock_get = mocker.patch("handlers.chromium_handler.requests.get")
        mock_index_response = mocker.Mock()
        mock_index_response.status_code = 200
        mock_index_response.content = chrome_blog_index_html.encode()
        mock_index_response.raise_for_status.return_value = None

        # Mock individual post responses
        mock_post_response = mocker.Mock()
        mock_post_response.status_code = 200
        mock_post_response.content = self._get_sample_post_html()
        mock_post_response.raise_for_status.return_value = None

        # Set up the mock to return different responses for different calls
        def mock_get_side_effect(url, **kwargs):
            if "search/label/Desktop%20Update" in url:
                return mock_index_response
            else:
                return mock_post_response

        mock_get.side_effect = mock_get_side_effect

        result = chromium_handler.parse_chrome_releases(limit_releases=3)

        assert len(result) >= 1
        assert result[0]["title"] == "Stable Channel Update for Desktop"
        assert "140.0.7339.185" in result[0]["linux_version"]
        assert "CVE-2025-9001" in result[0]["cves"]

    def test_parse_individual_release_post(
        self, mocker, chromium_handler, chrome_release_html
    ):
        """Test parsing individual Chrome release post."""
        mock_get = mocker.patch("handlers.chromium_handler.requests.get")
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = chrome_release_html.encode()
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        result = chromium_handler._parse_individual_release_post(
            "https://chromereleases.googleblog.com/2025/09/stable-channel-update-for-desktop_17.html",
            "Stable Channel Update for Desktop",
            "Wednesday, September 17, 2025",
        )

        assert result is not None
        assert result["linux_version"] == "140.0.7339.185"
        assert len(result["cves"]) == 4
        assert "CVE-2025-9001" in result["cves"]
        assert "CVE-2025-9002" in result["cves"]
        assert "CVE-2025-9003" in result["cves"]
        assert "CVE-2025-9004" in result["cves"]

        # Check CVE details
        assert "CVE-2025-9001" in result["cve_details"]
        cve_detail = result["cve_details"]["CVE-2025-9001"]
        assert cve_detail["severity"] == "High"
        assert "Type Confusion in V8" in cve_detail["description"]
        assert "Acme Threat Analysis Team" in cve_detail["reporter"]

        # Check "in the wild" detection
        assert len(result["in_the_wild_lines"]) > 0
        assert any("CVE-2025-9001" in line for line in result["in_the_wild_lines"])

    def test_parse_individual_release_post_no_cves(self, mocker, chromium_handler):
        """Parsing an individual release post that contains no CVE information should yield empty CVE lists."""
        mock_get = mocker.patch("handlers.chromium_handler.requests.get")
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        # Content with no CVE lines but include a Linux version so parser returns a release_info
        mock_response.content = b"""
        <div class=\"post-content\">
            <noscript>
                <p>The Stable channel has been updated to 140.0.7339.185 for Linux...</p>
                <p>No security fixes in this release.</p>
            </noscript>
        </div>
        """
        mock_response.raise_for_status.return_value = None
        mock_get.return_value = mock_response

        result = chromium_handler._parse_individual_release_post(
            "https://example.com/post/no-cves",
            "Minor Update Without CVEs",
            "Monday, January 1, 2025",
        )

        assert result is not None
        # No CVEs should be extracted
        assert result.get("cves") == []
        assert result.get("cve_details") == {}
        # No in-the-wild lines
        assert result.get("in_the_wild_lines") == []

    def _get_sample_post_html(self):
        """Get sample post HTML for testing."""
        return """
        <div class="post-content">
            <noscript>
                <p>The Stable channel has been updated to 140.0.7339.185 for Linux...</p>
                <p>[NA][445380761] High CVE-2025-9001: Type Confusion in V8. Reported by Acme Threat Analysis Team</p>
            </noscript>
        </div>
        """.encode()

    def test_parse_chrome_releases_http_error(self, mocker, chromium_handler):
        """Test Chrome blog parsing with HTTP error."""
        mock_get = mocker.patch("handlers.chromium_handler.requests.get")
        mock_response = mocker.Mock()
        mock_response.status_code = 500
        mock_response.raise_for_status.side_effect = Exception("HTTP 500")
        mock_get.return_value = mock_response

        result = chromium_handler.parse_chrome_releases()

        assert result == []

    def test_parse_chrome_releases_network_error(self, mocker, chromium_handler):
        """Test Chrome blog parsing with network error."""
        mock_get = mocker.patch("handlers.chromium_handler.requests.get")
        mock_get.side_effect = ConnectionError("Network error")

        result = chromium_handler.parse_chrome_releases()

        assert result == []


class TestChromiumHandlerCVEProcessing:
    """Test Chromium handler CVE processing."""

    def test_parse_cve_details_from_text(self, chromium_handler):
        """Test parsing CVE details from release text."""
        content_text = """
        This update includes 4 security fixes.
        
        [NA][445380761] High CVE-2025-9001: Type Confusion in V8. Reported by Acme Threat Analysis Team on 2025-09-16
        [$15000][435875050] High CVE-2025-9002: Use after free in Dawn. Reported by Researcher X (Ji-woo Kim) on 2025-08-03
        [TBD][438038775] High CVE-2025-9004: Heap buffer overflow in ANGLE. Reported by BigCorp Security on 2025-08-12
        
        Acme Threat Analysis Team is aware that an exploit for CVE-2025-9001 exists in the wild.
        """

        cve_details = {}
        in_the_wild_lines = []

        chromium_handler._parse_cve_details_from_text(
            content_text, cve_details, "test_url", in_the_wild_lines
        )

        assert len(cve_details) == 3
        assert "CVE-2025-9001" in cve_details
        assert "CVE-2025-9002" in cve_details
        assert "CVE-2025-9004" in cve_details

        # Check CVE-2025-9001 details
        cve_585 = cve_details["CVE-2025-9001"]
        assert cve_585["severity"] == "High"
        assert "Type Confusion in V8" in cve_585["description"]
        assert "Acme Threat Analysis Team" in cve_585["reporter"]
        assert cve_585["issue_status"] == "NA"
        assert cve_585["bug_id"] == "445380761"

        # Check CVE-2025-9002 details
        cve_500 = cve_details["CVE-2025-9002"]
        assert cve_500["severity"] == "High"
        assert "Use after free in Dawn" in cve_500["description"]
        assert "Researcher X (Ji-woo Kim)" in cve_500["reporter"]
        assert cve_500["bug_id"] == "435875050"

        # Check "in the wild" detection
        assert len(in_the_wild_lines) > 0
        assert any("CVE-2025-9001" in line for line in in_the_wild_lines)

    def test_extract_chromium_issue_urls(self, chromium_handler, chrome_release_html):
        """Test extraction of Chromium issue URLs."""
        from bs4 import BeautifulSoup

        soup = BeautifulSoup(chrome_release_html, "html.parser")
        post_content = soup.find("div", class_="post-content")

        chromium_issues = chromium_handler._extract_chromium_issue_urls(post_content)

        assert len(chromium_issues) == 4
        assert "https://issues.chromium.org/issues/445380761" in chromium_issues
        assert "https://issues.chromium.org/issues/435875050" in chromium_issues
        assert "https://issues.chromium.org/issues/440737137" in chromium_issues
        assert "https://issues.chromium.org/issues/438038775" in chromium_issues


class TestChromiumHandlerBugCreation:
    """Test Chromium handler bug creation."""

    def test_generate_bug_title_single_cve(self, chromium_handler):
        """Test bug title generation for single CVE."""
        release_info = {
            "cve_details": {
                "CVE-2025-9001": {
                    "description": "Type Confusion in V8",
                    "severity": "High",
                }
            }
        }

        title = chromium_handler._generate_bug_title(["CVE-2025-9001"], release_info)

        # Check that all browsers are mentioned (order may vary due to registry implementation)
        expected_browsers = [
            "www-client/chromium",
            "www-client/google-chrome",
            "www-client/microsoft-edge",
            "www-client/opera",
            "www-client/vivaldi",
        ]
        for browser in expected_browsers:
            assert browser in title, f"Browser {browser} not found in title: {title}"
        assert "Type Confusion in V8" in title

    def test_generate_bug_title_multiple_cves(self, chromium_handler):
        """Test bug title generation for multiple CVEs."""
        release_info = {}
        cves = ["CVE-2025-9001", "CVE-2025-9002", "CVE-2025-9003"]

        title = chromium_handler._generate_bug_title(cves, release_info)

        # Check that all browsers are mentioned (order may vary due to registry implementation)
        expected_browsers = [
            "www-client/chromium",
            "www-client/google-chrome",
            "www-client/microsoft-edge",
            "www-client/opera",
            "www-client/vivaldi",
        ]
        for browser in expected_browsers:
            assert browser in title, f"Browser {browser} not found in title: {title}"
        assert "multiple vulnerabilities" in title

    def test_generate_bug_description(self, chromium_handler):
        """Test bug description generation."""
        release_info = {
            "linux_version": "140.0.7339.185",
            "date": "Wednesday, September 17, 2025",
            "url": "https://chromereleases.googleblog.com/2025/09/stable-channel-update-for-desktop_17.html",
            "cve_details": {
                "CVE-2025-9001": {
                    "description": "Type Confusion in V8",
                    "severity": "High",
                    "reporter": "Acme Threat Analysis Team",
                }
            },
            "in_the_wild_lines": [
                "Google is aware that an exploit for CVE-2025-9001 exists in the wild."
            ],
        }

        description = chromium_handler._generate_bug_description(
            ["CVE-2025-9001"], release_info, {"CVE-2025-9002": 123456}
        )

        assert "140.0.7339.185" in description
        assert (
            "CVE-2025-9001 (High): Type Confusion in V8 (Reported by Acme Threat Analysis Team)"
            in description
        )
        assert "⚠️  CVEs being exploited in the wild:" in description
        assert "CVE-2025-9002: bug #123456" in description
        assert "www-client/chromium" in description
        assert "www-client/google-chrome" in description
        assert "www-client/microsoft-edge" in description

    def test_create_chromium_security_bug_success(
        self, chromium_handler_no_dry_run, mock_bugzilla_client
    ):
        """Test successful security bug creation."""
        release_info = {
            "linux_version": "140.0.7339.185",
            "date": "Wednesday, September 17, 2025",
            "url": "https://test.url",
            "cves": ["CVE-2025-9001"],
            "cve_details": {
                "CVE-2025-9001": {
                    "description": "Type Confusion in V8",
                    "severity": "High",
                    "reporter": "Acme Threat Analysis Team",
                }
            },
            "chromium_issues": ["https://issues.chromium.org/issues/445380761"],
        }

        mock_bugzilla_client.check_existing_bugs_for_cves.return_value = {}
        mock_bugzilla_client.create_security_bug.return_value = 999999

        bug_id = chromium_handler_no_dry_run.create_chromium_security_bug(release_info)

        assert bug_id == 999999
        mock_bugzilla_client.create_security_bug.assert_called_once()

        # Verify call arguments
        call_args = mock_bugzilla_client.create_security_bug.call_args
        assert call_args[1]["cves"] == ["CVE-2025-9001"]
        assert call_args[1]["see_also"] == [
            "https://issues.chromium.org/issues/445380761"
        ]

    def test_create_chromium_security_bug_no_cves(
        self, chromium_handler, mock_bugzilla_client
    ):
        """Test bug creation when no CVEs present."""
        release_info = {"linux_version": "140.0.7339.185", "cves": []}

        bug_id = chromium_handler.create_chromium_security_bug(release_info)

        assert bug_id is None
        mock_bugzilla_client.create_security_bug.assert_not_called()

    def test_create_chromium_security_bug_all_exist(
        self, chromium_handler, mock_bugzilla_client
    ):
        """Test bug creation when all CVEs already have bugs."""
        release_info = {
            "linux_version": "140.0.7339.185",
            "cves": ["CVE-2025-9001", "CVE-2025-9002"],
        }

        mock_bugzilla_client.check_existing_bugs_for_cves.return_value = {
            "CVE-2025-9001": 123456,
            "CVE-2025-9002": 123457,
        }

        bug_id = chromium_handler.create_chromium_security_bug(release_info)

        assert bug_id is None
        mock_bugzilla_client.create_security_bug.assert_not_called()

    def test_create_chromium_security_bug_partial_exist(
        self, chromium_handler_no_dry_run, mock_bugzilla_client
    ):
        """Test bug creation when some CVEs already have bugs."""
        release_info = {
            "linux_version": "140.0.7339.185",
            "date": "Wednesday, September 17, 2025",
            "url": "https://test.url",
            "cves": ["CVE-2025-9001", "CVE-2025-9002"],
            "cve_details": {
                "CVE-2025-9001": {
                    "description": "Type Confusion in V8",
                    "severity": "High",
                    "reporter": "Acme Threat Analysis Team",
                },
                "CVE-2025-9002": {
                    "description": "Use after free in Dawn",
                    "severity": "High",
                    "reporter": "Researcher X (Ji-woo Kim)",
                },
            },
        }

        mock_bugzilla_client.check_existing_bugs_for_cves.return_value = {
            "CVE-2025-9002": 123456
        }
        mock_bugzilla_client.create_security_bug.return_value = 999999

        bug_id = chromium_handler_no_dry_run.create_chromium_security_bug(release_info)

        assert bug_id == 999999
        mock_bugzilla_client.create_security_bug.assert_called_once()

        # Verify only new CVE is included
        call_args = mock_bugzilla_client.create_security_bug.call_args
        assert call_args[1]["cves"] == ["CVE-2025-9001"]

        # Verify blocks parameter includes the existing bug ID
        assert call_args[1]["blocks"] == [123456]


class TestChromiumHandlerLarryComments:
    """Test Chromium handler Larry Git Cow comment parsing."""

    def test_parse_larry_comments(self, chromium_handler, larry_comments):
        """Test parsing Larry's Git Cow comments for version information."""
        result = chromium_handler.parse_larry_comments(larry_comments)

        assert "www-client/chromium" in result
        assert "www-client/google-chrome" in result

        # Check that version numbers are extracted correctly
        chromium_version = result.get("www-client/chromium")
        chrome_version = result.get("www-client/google-chrome")

        assert chromium_version is not None
        assert chrome_version is not None
        assert "." in chromium_version  # Should be a version number
        assert "." in chrome_version

    def test_parse_larry_comments_empty(self, chromium_handler):
        """Test parsing empty Larry comments."""
        result = chromium_handler.parse_larry_comments([])

        assert result == {}

    def test_parse_larry_comments_no_versions(self, chromium_handler):
        """Test parsing Larry comments with no version information."""
        comments = [
            {
                "creator": "chromium@gentoo.org",
                "text": "Some random comment without version info",
                "time": "2025-09-18T10:00:00Z",
            }
        ]

        result = chromium_handler.parse_larry_comments(comments)

        assert result == {}


class TestChromiumHandlerVersionConstraints:
    """Test Chromium handler version constraint functionality."""

    def test_has_version_constraints_true(self, chromium_handler):
        """Test detection of existing version constraints in bug title."""
        title_with_constraints = "Security issue in <www-client/chromium-140.0.7339.185"

        result = chromium_handler._has_version_constraints(title_with_constraints)

        assert result is True

    def test_has_version_constraints_false(self, chromium_handler):
        """Test detection when no version constraints in bug title."""
        title_without_constraints = "Security issue in www-client/chromium package"

        result = chromium_handler._has_version_constraints(title_without_constraints)

        assert result is False

    def test_generate_updated_title(self, chromium_handler):
        """Test generation of updated bug title with version constraints."""
        original_title = (
            "www-client/chromium, www-client/google-chrome: there is a security bug"
        )
        fixed_versions = {
            "www-client/chromium": "140.0.7339.185",
            "www-client/google-chrome": "140.0.7339.185",
        }

        new_title = chromium_handler._generate_updated_title(
            original_title, fixed_versions
        )

        assert "<www-client/chromium-140.0.7339.185" in new_title
        assert "<www-client/google-chrome-140.0.7339.185" in new_title


class TestChromiumHandlerIntegration:
    """Integration tests for Chromium handler."""

    def test_full_workflow_fetch_and_process(
        self,
        mocker,
        chromium_handler_no_dry_run,
        chrome_blog_index_html,
        chrome_release_html,
        mock_bugzilla_client,
    ):
        """Test full workflow from blog parsing to bug creation."""
        # Mock blog index response
        mock_get = mocker.patch("handlers.chromium_handler.requests.get")
        mock_index_response = mocker.Mock()
        mock_index_response.status_code = 200
        mock_index_response.content = chrome_blog_index_html.encode()
        mock_index_response.raise_for_status.return_value = None

        # Mock individual post response
        mock_post_response = mocker.Mock()
        mock_post_response.status_code = 200
        mock_post_response.content = chrome_release_html.encode()
        mock_post_response.raise_for_status.return_value = None

        def mock_get_side_effect(url, **kwargs):
            if "search/label/Desktop%20Update" in url:
                return mock_index_response
            else:
                return mock_post_response

        mock_get.side_effect = mock_get_side_effect

        # Mock no existing bugs
        mock_bugzilla_client.check_existing_bugs_for_cves.return_value = {}
        mock_bugzilla_client.create_security_bug.return_value = 999999
        # Fetch vulnerability data - need limit=3 to reach first stable post (at position 3)
        vulnerabilities = chromium_handler_no_dry_run.fetch_vulnerability_data(
            limit_releases=3
        )

        assert len(vulnerabilities) >= 1
        assert vulnerabilities[0]["linux_version"] == "140.0.7339.185"
        assert len(vulnerabilities[0]["cves"]) == 4

        # Process vulnerabilities
        result = chromium_handler_no_dry_run.process_vulnerabilities(vulnerabilities)

        assert result["created"] == 1
        assert result["skipped"] == 0
        mock_bugzilla_client.create_security_bug.assert_called_once()

    def test_full_workflow_no_cves(
        self,
        mocker,
        chromium_handler_no_dry_run,
        chrome_blog_index_html,
        mock_bugzilla_client,
    ):
        """When a fetched blog post contains no CVEs, no security bug should be created."""
        # Mock blog index response to return the index HTML
        mock_get = mocker.patch("handlers.chromium_handler.requests.get")
        mock_index_response = mocker.Mock()
        mock_index_response.status_code = 200
        mock_index_response.content = chrome_blog_index_html.encode()
        mock_index_response.raise_for_status.return_value = None

        # Mock individual post response with content that has no CVEs but does include a linux version
        mock_post_response = mocker.Mock()
        mock_post_response.status_code = 200
        mock_post_response.content = b"""
        <div class=\"post-content\">
            <noscript>
                <p>The Stable channel has been updated to 140.0.7339.185 for Linux...</p>
                <p>No security fixes in this release.</p>
            </noscript>
        </div>
        """
        mock_post_response.raise_for_status.return_value = None

        def mock_get_side_effect(url, **kwargs):
            if "search/label/Desktop%20Update" in url:
                return mock_index_response
            else:
                return mock_post_response

        mock_get.side_effect = mock_get_side_effect

        # Ensure Bugzilla client would create a bug if asked, but it should not be called
        mock_bugzilla_client.check_existing_bugs_for_cves.return_value = {}
        mock_bugzilla_client.create_security_bug.return_value = 999999

        # Fetch vulnerability data (increase limit so the Stable post in the
        # provided index fixture is included)
        vulnerabilities = chromium_handler_no_dry_run.fetch_vulnerability_data(
            limit_releases=3
        )

        # The fetched release should have no CVEs
        assert len(vulnerabilities) >= 1
        assert vulnerabilities[0].get("cves") == []

        # Process vulnerabilities - should create zero bugs
        result = chromium_handler_no_dry_run.process_vulnerabilities(vulnerabilities)

        assert result["created"] == 0
        assert result["skipped"] >= 0
        mock_bugzilla_client.create_security_bug.assert_not_called()

    def test_process_bug_with_larry_comments(
        self, chromium_handler_no_dry_run, larry_comments, mock_bugzilla_client, mocker
    ):
        """Test processing a bug with Larry's Git Cow comments."""
        # Mock bug object
        mock_bug = mocker.Mock()
        mock_bug.id = 123456
        mock_bug.summary = "Security issue in www-client/chromium package"

        # Mock bugzilla methods
        mock_bugzilla_client.get_bug_comments.return_value = larry_comments
        mock_bugzilla_client.update_bug.return_value = True

        result = chromium_handler_no_dry_run.process_bug(mock_bug)

        assert result is True
        mock_bugzilla_client.update_bug.assert_called_once()

        # Verify update call
        call_args = mock_bugzilla_client.update_bug.call_args
        assert call_args[1]["bug_id"] == 123456  # bug_id
        assert "Fixed versions detected:" in call_args[1]["comment"]


class TestChromiumHandlerUtilityMethods:
    """Test utility methods in ChromiumHandler."""

    def test_get_vendor_name(self, chromium_handler):
        """Test get_vendor_name returns Google."""
        assert chromium_handler.get_vendor_name() == "Google"

    def test_register_browsers(self, chromium_handler, mocker):
        """Test register_browsers registers chromium and google-chrome."""
        registry = mocker.Mock()
        chromium_handler.register_browsers(registry)

        # Should register both chromium and google-chrome
        assert registry.register_browser.call_count == 2
        calls = registry.register_browser.call_args_list
        assert mocker.call("chromium", "www-client/chromium") in calls
        assert mocker.call("chromium", "www-client/google-chrome") in calls

    def test_get_affected_browsers_for_chromium(
        self, chromium_handler, browser_registry
    ):
        """Test get_affected_browsers_for_chromium returns all browsers."""
        chromium_handler.browser_registry = browser_registry
        browsers = chromium_handler.get_affected_browsers_for_chromium()

        # Should include all registered browsers (chromium, edge, opera, vivaldi)
        assert "www-client/chromium" in browsers
        assert "www-client/google-chrome" in browsers
        assert len(browsers) > 2  # Should include edge, opera, vivaldi etc

    def test_fetch_vulnerability_data(self, chromium_handler, mocker):
        """Test fetch_vulnerability_data calls parse_chrome_releases."""
        mock_parse = mocker.patch.object(chromium_handler, "parse_chrome_releases")
        mock_parse.return_value = [{"version": "141.0.0.0"}]

        result = chromium_handler.fetch_vulnerability_data(limit_releases=5)

        mock_parse.assert_called_once_with(5)
        assert result == [{"version": "141.0.0.0"}]

    def test_process_vulnerabilities(self, chromium_handler, mocker):
        """Test process_vulnerabilities calls process_chrome_releases."""
        mock_process = mocker.patch.object(chromium_handler, "process_chrome_releases")
        mock_process.return_value = {"created": 1}

        vulnerabilities = [{"version": "141.0.0.0"}]
        result = chromium_handler.process_vulnerabilities(vulnerabilities)

        mock_process.assert_called_once_with(vulnerabilities)
        assert result == {"created": 1}

    def test_compare_versions(self, chromium_handler):
        """Test _compare_versions delegates to version_utils."""
        result = chromium_handler._compare_versions("141.0.0.1", "141.0.0.0")
        assert result > 0  # First version is higher

        result = chromium_handler._compare_versions("141.0.0.0", "141.0.0.1")
        assert result < 0  # First version is lower

        result = chromium_handler._compare_versions("141.0.0.0", "141.0.0.0")
        assert result == 0  # Versions are equal

    def test_get_ebuild_version(self, chromium_handler, mock_version_utils):
        """Test _get_ebuild_version calls version_utils."""
        # _get_ebuild_version delegates to version_utils
        # Configure mock to return expected values
        mock_version_utils.get_ebuild_version.side_effect = [
            "141.0.0.0",
            "141.0.0.0-r1",
        ]

        # Test without revision
        result1 = chromium_handler._get_ebuild_version(("141.0.0.0", "r0"))
        assert result1 == "141.0.0.0"

        # Test with revision
        result2 = chromium_handler._get_ebuild_version(("141.0.0.0", "r1"))
        assert result2 == "141.0.0.0-r1"

        # Verify called correctly
        assert mock_version_utils.get_ebuild_version.call_count == 2

    def test_bugzilla_lazy_loading(self, mock_logger, mocker):
        """Test bugzilla property lazy-loads BugzillaClient."""
        # Create handler without mocked bugzilla property
        handler = ChromiumHandler(
            api_key_file="./bugzilla_api_key",
            logger=mock_logger,
            dry_run=True,
            browser_registry=None,
            version_utils=mocker.Mock(),
        )

        # First access should create client
        assert handler._bugzilla is None

        # Mock BugzillaClient creation
        mock_client_class = mocker.patch("handlers.chromium_handler.BugzillaClient")
        mock_client = mocker.Mock()
        mock_client_class.return_value = mock_client

        # Access bugzilla property
        result = handler.bugzilla

        # Should have created client
        assert result == mock_client
        mock_client_class.assert_called_once_with(
            api_key_file=handler.api_key_file,
            logger=handler.logger,
        )

        # Second access should reuse same client
        result2 = handler.bugzilla
        assert result2 == mock_client
        assert mock_client_class.call_count == 1  # Still only called once


class TestChromiumHandlerUpdateExistingBugs:
    """Test update_existing_bugs functionality."""

    def test_update_existing_bugs_no_bugs(self, chromium_handler, mock_bugzilla_client):
        """Test update_existing_bugs when no bugs found."""
        mock_bugzilla_client.find_chromium_security_bugs.return_value = []

        result = chromium_handler.update_existing_bugs()

        assert result == {"updated": 0, "total": 0}

    def test_update_existing_bugs_processes_bugs(
        self, chromium_handler, mock_bugzilla_client, mocker
    ):
        """Test update_existing_bugs processes found bugs."""
        mock_bug1 = mocker.Mock(id=123)
        mock_bug2 = mocker.Mock(id=456)
        mock_bugzilla_client.find_chromium_security_bugs.return_value = [
            mock_bug1,
            mock_bug2,
        ]

        # Mock process_bug to return True for first bug, False for second
        mock_process = mocker.patch.object(chromium_handler, "process_bug")
        mock_process.side_effect = [True, False]

        result = chromium_handler.update_existing_bugs()

        assert result == {"updated": 1, "total": 2}
        assert mock_process.call_count == 2

    def test_update_existing_bugs_all_updated(
        self, chromium_handler, mock_bugzilla_client, mocker
    ):
        """Test update_existing_bugs when all bugs are updated."""
        mock_bugs = [mocker.Mock(id=i) for i in range(5)]
        mock_bugzilla_client.find_chromium_security_bugs.return_value = mock_bugs

        # Mock process_bug to always return True
        mock_process = mocker.patch.object(chromium_handler, "process_bug")
        mock_process.return_value = True

        result = chromium_handler.update_existing_bugs()

        assert result == {"updated": 5, "total": 5}
        assert mock_process.call_count == 5


class TestChromiumHandlerGetCVEsForVersion:
    """Test _get_cves_for_chrome_version method."""

    def test_get_cves_for_chrome_version_found(self, chromium_handler, mocker):
        """Test getting CVEs when version is found in releases."""
        mock_parse = mocker.patch.object(chromium_handler, "parse_chrome_releases")
        mock_parse.return_value = [
            {
                "linux_version": "141.0.0.0",
                "cves": ["CVE-2025-0001", "CVE-2025-0002"],
            },
            {
                "linux_version": "140.0.0.0",
                "cves": ["CVE-2024-9999"],
            },
        ]

        cves = chromium_handler._get_cves_for_chrome_version("141.0.0.0")

        assert cves == ["CVE-2025-0001", "CVE-2025-0002"]

    def test_get_cves_for_chrome_version_not_found(self, chromium_handler, mocker):
        """Test getting CVEs when version is not found."""
        mock_parse = mocker.patch.object(chromium_handler, "parse_chrome_releases")
        mock_parse.return_value = [
            {"linux_version": "140.0.0.0", "cves": ["CVE-2024-9999"]},
        ]

        cves = chromium_handler._get_cves_for_chrome_version("141.0.0.0")

        assert cves == []

    def test_get_cves_for_chrome_version_no_cves_key(self, chromium_handler, mocker):
        """Test getting CVEs when release has no CVEs key."""
        mock_parse = mocker.patch.object(chromium_handler, "parse_chrome_releases")
        mock_parse.return_value = [
            {"linux_version": "141.0.0.0"},  # No 'cves' key
        ]

        cves = chromium_handler._get_cves_for_chrome_version("141.0.0.0")

        assert cves == []

    def test_get_cves_for_chrome_version_empty_releases(self, chromium_handler, mocker):
        """Test getting CVEs when no releases found."""
        mock_parse = mocker.patch.object(chromium_handler, "parse_chrome_releases")
        mock_parse.return_value = []

        cves = chromium_handler._get_cves_for_chrome_version("141.0.0.0")

        assert cves == []


# Test coverage utility
def test_chromium_handler_coverage():
    """Verify that key Chromium handler methods are covered by tests."""
    from handlers.chromium_handler import ChromiumHandler

    # List of methods that should be tested
    critical_methods = [
        "parse_chrome_releases",
        "_parse_individual_release_post",
        "_parse_cve_details_from_text",
        "_extract_chromium_issue_urls",
        "_generate_bug_title",
        "_generate_bug_description",
        "create_chromium_security_bug",
        "parse_larry_comments",
        "_has_version_constraints",
        "_generate_updated_title",
        "process_bug",
    ]

    # Verify all methods exist
    for method_name in critical_methods:
        assert hasattr(ChromiumHandler, method_name), (
            f"Method {method_name} not found in ChromiumHandler"
        )
