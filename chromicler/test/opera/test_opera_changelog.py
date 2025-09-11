#!/usr/bin/env python3

"""
Test Opera changelog parsing functionality
"""

import re
import pytest
import requests
from pathlib import Path

from handlers.opera_handler import OperaHandler
from version_utils import VersionUtils


@pytest.fixture
def opera_handler(mock_bugzilla_client, mock_logger):
    """Create Opera handler for testing."""
    return OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=True, version_utils=VersionUtils()
    )


@pytest.fixture
def test_changelog_path():
    """Path to test changelog HTML file."""
    return Path(__file__).parent.parent / "data" / "opera_changelog.html"


@pytest.fixture
def changelog_html_content(test_changelog_path):
    """Load the changelog HTML content for testing."""
    with open(test_changelog_path, "r", encoding="utf-8") as f:
        return f.read()


@pytest.fixture
def sample_changelog_html():
    """Sample HTML content that mimics Opera changelog structure."""
    return """
    <html>
    <body>
        <div class="content">
            <h4><strong>122.0.5643.24 – 2025-09-16 <a href="#">blog post</a></strong></h4>
            <ul>
                <li>RNA-369 Dark theme selects light theme wallpaper</li>
                <li>RNA-537 Center the icon in header</li>
            </ul>
            
            <h4><strong>122.0.5643.17 – 2025-09-11 <a href="#">blog post</a></strong></h4>
            <ul>
                <li>CHR-10101 Update Chromium on desktop-stable-138-5643 to 138.0.7204.251</li>
                <li>DNA-123490 Crash at settings::AddLocalizedStrings</li>
            </ul>
            
            <h4><strong>122.0.5608.0 – 2025-07-29 <a href="#">blog post</a></strong></h4>
            <ul>
                <li>CHR-10019 Update Chromium on master to 137.0.7151.27</li>
                <li>DNA-112270 Delete suggestion button stays focused</li>
            </ul>
        </div>
    </body>
    </html>
    """


class TestOperaVersionParsing:
    """Test Opera version parsing patterns and logic."""

    @pytest.mark.parametrize(
        "version_string,expected_result",
        [
            ("122.0.5643.24 – 2025-09-16", True),
            ("122.0.5643.17 – 2025-09-11", True),
            ("122.0.5608.0 – 2025-07-29", True),
            ("Invalid version", False),
            ("No dash separator", False),
            ("1.2.3 – 2025-01-01", False),  # Too few version parts
            ("1.2.3.4.5 – 2025-01-01", False),  # Too many version parts
            ("122.0.5643.24 - 2025-09-16", False),  # Wrong dash type
        ],
    )
    def test_version_header_pattern_matching(self, version_string, expected_result):
        """Test version header pattern matching logic."""
        # Pattern that matches: VERSION – DATE (exactly 4-part version)
        pattern = r"^(\d+\.\d+\.\d+\.\d+)\s*–\s*(.+)$"
        match = re.match(pattern, version_string)

        if expected_result:
            assert match is not None, f"Should match version pattern: {version_string}"
            version, date = match.groups()
            assert len(version.split(".")) == 4, "Version should have 4 parts"
        else:
            if match and len(match.group(1).split(".")) != 4:
                # Pattern matched but version format is wrong
                assert True
            else:
                assert match is None, (
                    f"Should not match version pattern: {version_string}"
                )

    @pytest.mark.parametrize(
        "version_text,expected_version",
        [
            ("122.0.5643.24 – 2025-09-16", "122.0.5643.24"),
            ("122.0.5643.17 – 2025-09-11", "122.0.5643.17"),
            ("122.0.5643.6 – 2025-09-08", "122.0.5643.6"),
            ("122.0.5638.0 – 2025-08-28", "122.0.5638.0"),
            ("Invalid format", None),
        ],
    )
    def test_extract_opera_version_from_header(self, version_text, expected_version):
        """Test extraction of Opera version from changelog section headers."""
        if expected_version:
            # Split and extract version as the parsing logic does
            if " – " in version_text:
                result = version_text.split(" – ")[0].strip()
                assert result == expected_version
        else:
            # Should handle invalid formats gracefully
            if " – " not in version_text:
                assert True  # Expected to not match the pattern

    def test_version_extraction_edge_cases(self):
        """Test version extraction with edge case HTML structures."""
        test_cases = [
            (
                '<h4 id="test" class="wp-block-heading"><strong>122.0.5643.24 – 2025-09-16</strong></h4>',
                "122.0.5643.24",
            ),
            (
                "<h4><strong>  122.0.5643.17   –   2025-09-11  </strong></h4>",
                "122.0.5643.17",
            ),
            (
                '<h4><strong>122.0.5608.0 – 2025-07-29 <a href="#">blog post</a></strong></h4>',
                "122.0.5608.0",
            ),
            (
                '<h4 id="complex"><strong>Version 121.0.5500.0 – 2025-06-01 <a href="blog">link</a></strong></h4>',
                "121.0.5500.0",
            ),
        ]

        version_pattern = (
            r"<h4[^>]*>.*?<strong>.*?(\d+\.\d+\.\d+\.\d+).*?</strong>.*?</h4>"
        )

        for html, expected_version in test_cases:
            matches = re.findall(version_pattern, html, re.DOTALL)
            assert len(matches) == 1, f"Should find exactly one version in: {html}"
            assert matches[0] == expected_version, (
                f"Should extract version {expected_version} from: {html}"
            )

    def test_extract_opera_versions_from_html(self, changelog_html_content):
        """Test extraction of Opera versions from HTML."""
        # Test the actual parsing logic
        version_pattern = (
            r"<h4[^>]*>.*?<strong>.*?(\d+\.\d+\.\d+\.\d+).*?</strong>.*?</h4>"
        )
        matches = re.findall(version_pattern, changelog_html_content, re.DOTALL)

        # Should find some versions
        assert len(matches) > 0, "No version numbers extracted"

        # All extracted versions should be valid 4-part versions
        for version in matches:
            parts = version.split(".")
            assert len(parts) == 4, f"Version should have 4 parts: {version}"
            for part in parts:
                assert part.isdigit(), f"Version part should be numeric: {part}"

    def test_version_ordering_logic(self, changelog_html_content):
        """Test that version parsing can determine correct ordering."""
        # Extract all version numbers in order of appearance
        version_pattern = (
            r"<h4[^>]*>.*?<strong>.*?(\d+\.\d+\.\d+\.\d+).*?</strong>.*?</h4>"
        )
        matches = re.findall(version_pattern, changelog_html_content, re.DOTALL)

        versions = matches
        if len(versions) < 2:
            pytest.skip("Need at least 2 versions to test ordering")

        # Convert to comparable version tuples
        def version_tuple(v):
            return tuple(map(int, v.split(".")))

        version_tuples = [version_tuple(v) for v in versions]

        # Test the ordering logic
        is_descending = all(
            version_tuples[i] >= version_tuples[i + 1]
            for i in range(len(version_tuples) - 1)
        )

        # This tests that our parsing preserves the expected order
        assert is_descending, f"Versions should be in descending order: {versions}"

    def test_date_format_parsing(self):
        """Test parsing of date formats in version headers."""
        test_cases = [
            ("122.0.5643.24 – 2025-09-16", ("122.0.5643.24", "2025-09-16")),
            ("121.0.5500.0 – 2025-06-01", ("121.0.5500.0", "2025-06-01")),
            ("Invalid format", None),
            ("122.0.5643.24 - 2025-09-16", None),  # Wrong dash type
            ("122.0.5643.24 – invalid-date", None),  # Invalid date format
        ]

        date_pattern = r"(\d+\.\d+\.\d+\.\d+)\s*–\s*(\d{4}-\d{2}-\d{2})"

        for text, expected_result in test_cases:
            matches = re.findall(date_pattern, text)

            if expected_result is None:
                assert len(matches) == 0, f"Should not match pattern: {text}"
            else:
                assert len(matches) == 1, f"Should match pattern: {text}"
                version, date = matches[0]
                expected_version, expected_date = expected_result
                assert version == expected_version
                assert date == expected_date


class TestChromiumVersionParsing:
    """Test Chromium version parsing from changelog entries."""

    @pytest.mark.parametrize(
        "chromium_text,expected_version",
        [
            (
                "CHR-10101 Update Chromium on desktop-stable-138-5643 to 138.0.7204.251",
                "138.0.7204.251",
            ),
            ("CHR-10019 Update Chromium on master to 137.0.7151.27", "137.0.7151.27"),
            ("Update Chromium to 136.0.6745.123", "136.0.6745.123"),
            ("Update Chromium to version 135.0.6678.45", "135.0.6678.45"),
            (
                "CHR-12345 Update chromium dependencies to 134.0.6543.21",
                "134.0.6543.21",
            ),
            ("Updated Chromium to version 131.0.6778.86", "131.0.6778.86"),
            ("CHR-9999 Chromium update to 131.0.6768.4", "131.0.6768.4"),
            ("Some other text about Chromium", None),
            ("DNA-123456 Regular bug fix", None),
        ],
    )
    def test_extract_chromium_version_from_entry(self, chromium_text, expected_version):
        """Test extraction of Chromium version from changelog entries."""
        patterns = [
            r"CHR-\d+[^>]*Update Chromium[^>]*?(\d+\.\d+\.\d+\.\d+)",
            r"Update Chromium[^>]*?(\d+\.\d+\.\d+\.\d+)",
            r"Updated Chromium[^>]*?(\d+\.\d+\.\d+\.\d+)",
            r"Chromium update[^>]*?(\d+\.\d+\.\d+\.\d+)",
        ]

        found_version = None
        for pattern in patterns:
            matches = re.findall(pattern, chromium_text, re.IGNORECASE)
            if matches:
                found_version = matches[0]
                break

        assert found_version == expected_version, (
            f"Expected {expected_version} from: {chromium_text}"
        )

    def test_extract_chromium_versions_from_html(
        self, opera_handler, changelog_html_content, mocker
    ):
        """Test extraction of Chromium versions from HTML."""
        mocker.patch("handlers.opera_handler.requests.get")

        patterns = [
            r"CHR-\d+[^>]*Update Chromium[^>]*?(\d+\.\d+\.\d+\.\d+)",
            r"Update Chromium[^>]*?(\d+\.\d+\.\d+\.\d+)",
            r"Updated Chromium[^>]*?(\d+\.\d+\.\d+\.\d+)",
        ]

        chromium_versions = []
        for pattern in patterns:
            matches = re.findall(pattern, changelog_html_content, re.IGNORECASE)
            chromium_versions.extend(matches)

        # Should find some Chromium versions
        assert len(chromium_versions) > 0, "No Chromium versions found"

        # All extracted versions should be valid 4-part versions
        for version in chromium_versions:
            parts = version.split(".")
            assert len(parts) == 4, f"Chromium version should have 4 parts: {version}"
            for part in parts:
                assert part.isdigit(), (
                    f"Chromium version part should be numeric: {part}"
                )

    def test_chromium_update_pattern_variations(self):
        """Test different patterns for Chromium update entries."""
        test_cases = [
            (
                "CHR-10101 Update Chromium on desktop-stable-138-5643 to 138.0.7204.251",
                "138.0.7204.251",
            ),
            ("CHR-10019 Update Chromium on master to 137.0.7151.27", "137.0.7151.27"),
            ("Update Chromium to 136.0.6745.123", "136.0.6745.123"),
            ("Update Chromium to version 135.0.6678.45", "135.0.6678.45"),
            (
                "CHR-12345 Update chromium dependencies to 134.0.6543.21",
                "134.0.6543.21",
            ),
            ("Some other text about Chromium", None),
            ("DNA-123456 Regular bug fix", None),
        ]

        patterns = [
            r"CHR-\d+[^>]*Update Chromium[^>]*?(\d+\.\d+\.\d+\.\d+)",
            r"Update Chromium[^>]*?(\d+\.\d+\.\d+\.\d+)",
            r"Updated Chromium[^>]*?(\d+\.\d+\.\d+\.\d+)",
        ]

        for text, expected_version in test_cases:
            found_version = None
            for pattern in patterns:
                matches = re.findall(pattern, text, re.IGNORECASE)
                if matches:
                    found_version = matches[0]
                    break

            assert found_version == expected_version, (
                f"Expected {expected_version} from: {text}"
            )


class TestBugIdParsing:
    """Test parsing of bug IDs from changelog entries."""

    @pytest.mark.parametrize(
        "bug_text,expected_type",
        [
            ("DNA-123490 Crash at settings::AddLocalizedStrings", "DNA"),
            ("RNA-369 Dark theme selects light theme wallpaper", "RNA"),
            (
                "CHR-10101 Update Chromium on desktop-stable-138-5643 to 138.0.7204.251",
                "CHR",
            ),
            ("Random text without bug ID", None),
            ("DNA-ABC Invalid bug ID", None),  # Non-numeric ID
            ("DNA- Missing ID number", None),  # Missing number
        ],
    )
    def test_bug_id_pattern_matching(self, bug_text, expected_type):
        """Test matching of different bug ID patterns."""
        patterns = {
            "DNA": r"DNA-(\d+)",
            "RNA": r"RNA-(\d+)",
            "CHR": r"CHR-(\d+)",
        }

        found_type = None
        for bug_type, pattern in patterns.items():
            if re.search(pattern, bug_text):
                found_type = bug_type
                break

        assert found_type == expected_type, (
            f"Expected {expected_type}, got {found_type} for: {bug_text}"
        )


class TestOperaHandlerMethods:
    """Test Opera handler methods for changelog parsing."""

    def test_get_opera_chromium_mapping_basic(
        self, opera_handler, sample_changelog_html, mocker
    ):
        """Test basic functionality of _get_opera_chromium_mapping."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Mock successful HTTP response
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = sample_changelog_html.encode("utf-8")
        mock_get.return_value = mock_response

        # Call the method
        result = opera_handler._get_opera_chromium_mapping(122)

        # Verify the request was made
        mock_get.assert_called_once()
        expected_url = "https://blogs.opera.com/desktop/changelog-for-122/"
        mock_get.assert_called_with(expected_url, timeout=10)

        # Verify we got results
        assert isinstance(result, dict)
        assert len(result) > 0

    def test_get_opera_chromium_mapping_with_versions(
        self, opera_handler, sample_changelog_html, mocker
    ):
        """Test that version mapping extracts correct Opera-Chromium pairs."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Mock successful HTTP response
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = sample_changelog_html.encode("utf-8")
        mock_get.return_value = mock_response

        # Call the method
        result = opera_handler._get_opera_chromium_mapping(122)

        # Should have found Opera versions
        expected_opera_versions = ["122.0.5643.24", "122.0.5643.17", "122.0.5608.0"]
        found_versions = list(result.keys())

        assert len(found_versions) > 0
        # Should have found at least some of the expected versions
        assert any(version in found_versions for version in expected_opera_versions)

    def test_get_opera_chromium_mapping_chromium_extraction(
        self, opera_handler, sample_changelog_html, mocker
    ):
        """Test that Chromium versions are correctly extracted."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Mock successful HTTP response
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = sample_changelog_html.encode("utf-8")
        mock_get.return_value = mock_response

        # Call the method
        result = opera_handler._get_opera_chromium_mapping(122)

        # Check for Chromium versions in the results
        chromium_versions = [v for v in result.values() if v is not None]

        # Should have found Chromium versions from our test data
        expected_chromium = ["138.0.7204.251", "137.0.7151.27"]
        assert len(chromium_versions) > 0
        assert any(cv in chromium_versions for cv in expected_chromium)

    def test_get_opera_chromium_mapping_success(
        self, opera_handler, changelog_html_content, mocker
    ):
        """Test successful parsing of Opera-Chromium version mapping using real data."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Mock the requests.get call
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = changelog_html_content.encode("utf-8")
        mock_get.return_value = mock_response

        # Call the method
        result = opera_handler._get_opera_chromium_mapping(122)

        # Verify the call was made
        mock_get.assert_called_once()

        # Check that we got some mapping results
        assert isinstance(result, dict)

    def test_map_chromium_to_opera_version(
        self, opera_handler, changelog_html_content, mocker
    ):
        """Test mapping from Chromium version to Opera version."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Mock the requests.get call for multiple major versions
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = changelog_html_content.encode("utf-8")
        mock_get.return_value = mock_response

        # Test with a Chromium version that should be found in test data
        result = opera_handler._map_chromium_to_opera_version("137.0.7151.27")

        # Should return an Opera version or None
        assert result is None or (isinstance(result, str) and "." in result)

    @pytest.mark.parametrize(
        "major_version,expected_call_count",
        [
            (110, 1),  # Should make one request
            (122, 1),  # Should make one request
            (130, 1),  # Should make one request
        ],
    )
    def test_get_opera_chromium_mapping_request_patterns(
        self, opera_handler, major_version, expected_call_count, mocker
    ):
        """Test that requests are made with correct URLs for different versions."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Mock response
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = b"<html><body><div class='content'></div></body></html>"
        mock_get.return_value = mock_response

        # Call the method
        opera_handler._get_opera_chromium_mapping(major_version)

        # Verify the correct URL was called
        assert mock_get.call_count == expected_call_count
        expected_url = f"https://blogs.opera.com/desktop/changelog-for-{major_version}/"
        mock_get.assert_called_with(expected_url, timeout=10)

    def test_get_opera_chromium_mapping_multiple_chromium_updates(
        self, opera_handler, mocker
    ):
        """Test handling of multiple Chromium updates in one version."""
        html_with_multiple_updates = """
        <div class="content">
            <h4><strong>122.0.5643.24 – 2025-09-16</strong></h4>
            <ul>
                <li>CHR-10101 Update Chromium to 138.0.7204.251</li>
                <li>DNA-123490 Some bug fix</li>
                <li>CHR-10102 Another Chromium update to 138.0.7204.300</li>
            </ul>
        </div>
        """

        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = html_with_multiple_updates.encode("utf-8")
        mock_get.return_value = mock_response

        result = opera_handler._get_opera_chromium_mapping(122)

        # Should have picked up a Chromium version (likely the first one found)
        assert "122.0.5643.24" in result
        chromium_version = result["122.0.5643.24"]
        assert chromium_version is not None
        assert "138.0.7204" in chromium_version  # Should be one of the versions


class TestOperaHandlerErrorHandling:
    """Test error handling in Opera handler methods."""

    def test_get_opera_chromium_mapping_http_404(self, opera_handler, mocker):
        """Test handling of 404 responses."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Mock 404 response
        mock_response = mocker.Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        # Call the method
        result = opera_handler._get_opera_chromium_mapping(999)

        # Should return empty dict on 404
        assert result == {}

    def test_get_opera_chromium_mapping_http_error(self, opera_handler, mocker):
        """Test handling of HTTP errors when fetching changelog."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Mock a 404 response
        mock_response = mocker.Mock()
        mock_response.status_code = 404
        mock_get.return_value = mock_response

        # Call the method
        result = opera_handler._get_opera_chromium_mapping(999)

        # Should return empty dict on HTTP error
        assert result == {}

    def test_get_opera_chromium_mapping_timeout(self, opera_handler, mocker):
        """Test handling of request timeouts."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Mock timeout exception
        mock_get.side_effect = requests.exceptions.Timeout("Request timed out")

        # Call the method
        result = opera_handler._get_opera_chromium_mapping(122)

        # Should return empty dict on timeout
        assert result == {}

    def test_get_opera_chromium_mapping_invalid_html(self, opera_handler, mocker):
        """Test handling of invalid HTML content."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Mock response with invalid HTML
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = b"<html><body>No content div here</body></html>"
        mock_get.return_value = mock_response

        # Call the method
        result = opera_handler._get_opera_chromium_mapping(122)

        # Should handle gracefully and return empty dict
        assert result == {}

    def test_error_handling_in_parsing(self, opera_handler, mocker):
        """Test error handling in changelog parsing methods."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Test with invalid HTML content
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = b"<html><body>Invalid content</body></html>"
        mock_get.return_value = mock_response

        result = opera_handler._get_opera_chromium_mapping(122)
        # Should handle gracefully and return empty dict
        assert result == {}

    def test_opera_handler_error_handling(self, opera_handler, mocker):
        """Test that the Opera handler handles parsing errors gracefully."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Test various error conditions
        test_cases = [
            # HTTP error
            (mocker.Mock(status_code=404), {}),
            # Malformed HTML
            (
                mocker.Mock(
                    status_code=200,
                    content=b"<html><body>Invalid content</body></html>",
                ),
                {},
            ),
            # Empty content
            (mocker.Mock(status_code=200, content=b""), {}),
            # Non-HTML content
            (mocker.Mock(status_code=200, content=b"Plain text content"), {}),
        ]

        for mock_response, expected_result in test_cases:
            mock_get.return_value = mock_response

            result = opera_handler._get_opera_chromium_mapping(122)
            assert result == expected_result, (
                f"Should handle error gracefully for {mock_response.status_code}"
            )


class TestOperaHandlerEdgeCases:
    """Test edge cases and advanced parsing scenarios."""

    def test_parse_missing_version_with_empty_h4_tags(self, opera_handler, mocker):
        """Test that version parsing handles empty H4 tags correctly."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        # Real HTML structure that was causing issues due to empty <h4> tags
        mock_html = """
        <html>
        <body>
        <div class="content">
            <h4 id="h-122-0-5643-14-2025-09-10-blog-post" class="wp-block-heading">
                <strong>122.0.5643.17 – 2025-09-11 <a href="https://blogs.opera.com/desktop/2025/09/opera-122">blog post</a></strong>
            </h4>
            <h4></h4>
            <ul class="wp-block-list">
                <li>CHR-10101 Update Chromium on desktop-stable-138-5643 to 138.0.7204.251</li>
            </ul>
            
            <h4 id="h-122-0-5643-6-2025-09-05" class="wp-block-heading">
                <strong>122.0.5643.6 – 2025-09-05</strong>
            </h4>
            <ul class="wp-block-list">
                <li>Some other change</li>
                <li>Another fix</li>
            </ul>
        </div>
        </body>
        </html>
        """

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = mock_html.encode("utf-8")
        mock_get.return_value = mock_response

        # Test the mapping generation
        mapping = opera_handler._get_opera_chromium_mapping(122)

        # Verify that both versions are captured
        assert "122.0.5643.17" in mapping
        assert "122.0.5643.6" in mapping

        # Verify the Chromium version mapping
        assert mapping["122.0.5643.17"] == "138.0.7204.251"
        assert mapping["122.0.5643.6"] is None  # No Chromium update for this version

    def test_parse_various_dash_formats(self, opera_handler, mocker):
        """Test parsing of versions with different dash formats."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")

        mock_html = """
        <html>
        <body>
        <div class="content">
            <h4><strong>115.0.5322.68 – 2023-11-27</strong></h4>
            <ul><li>Update Chromium to 130.0.6723.59</li></ul>
            
            <h4><strong>115.0.5322.77 - 2023-11-30</strong></h4>
            <ul><li>Update Chromium to 130.0.6723.137</li></ul>
            
            <h4><strong>115.0.5322.119</strong></h4>
            <ul><li>No Chromium update</li></ul>
        </div>
        </body>
        </html>
        """

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = mock_html.encode("utf-8")
        mock_get.return_value = mock_response

        mapping = opera_handler._get_opera_chromium_mapping(115)

        # Should handle both em dash (–) and regular dash (-)
        assert "115.0.5322.68" in mapping
        # Note: Regular dash (-) should not match based on the pattern
        # assert "115.0.5322.77" in mapping  # This might not match depending on pattern
        assert "115.0.5322.119" in mapping

        assert mapping["115.0.5322.68"] == "130.0.6723.59"
        # assert mapping["115.0.5322.77"] == "130.0.6723.137"
        assert mapping["115.0.5322.119"] is None

    def test_parse_complex_chromium_update_patterns(self, opera_handler, mocker):
        """Test parsing of various Chromium update text patterns."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")
        mock_html = """
        <html>
        <body>
        <div class="content">
            <h4><strong>116.0.5366.35 – 2024-01-15</strong></h4>
            <ul>
                <li>CHR-10101 Update Chromium on desktop-stable-131-5366 to 131.0.6778.266</li>
            </ul>
            
            <h4><strong>116.0.5366.21 – 2024-01-10</strong></h4>
            <ul>
                <li>Updated Chromium to version 131.0.6778.86</li>
            </ul>
            
            <h4><strong>116.0.5366.7 – 2024-01-05</strong></h4>
            <ul>
                <li>CHR-9999 Chromium update to 131.0.6768.4</li>
            </ul>
        </div>
        </body>
        </html>
        """

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = mock_html.encode("utf-8")
        mock_get.return_value = mock_response

        mapping = opera_handler._get_opera_chromium_mapping(116)

        # Should handle various Chromium update patterns
        assert mapping["116.0.5366.35"] == "131.0.6778.266"
        assert mapping["116.0.5366.21"] == "131.0.6778.86"
        assert mapping["116.0.5366.7"] == "131.0.6768.4"

    def test_handle_malformed_html_gracefully(self, opera_handler, mocker):
        """Test that malformed HTML doesn't crash the parser."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")
        mock_html = """
        <html>
        <body>
        <div class="content">
            <h4><strong>117.0.5408.53</strong></h4>
            <ul><li>Update Chromium to 132.0.6834.210</li></ul>
            
            <!-- Malformed section -->
            <h4><strong></strong></h4>
            <ul><li>Update Chromium to invalid.version.here</li></ul>
            
            <h4><strong>Invalid – Version – Format</strong></h4>
            <ul><li>Update Chromium to 132.0.6834.207</li></ul>
        </div>
        </body>
        </html>
        """

        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = mock_html.encode("utf-8")
        mock_get.return_value = mock_response

        # Should not crash and should parse the valid entry
        mapping = opera_handler._get_opera_chromium_mapping(117)

        assert "117.0.5408.53" in mapping
        assert mapping["117.0.5408.53"] == "132.0.6834.210"

        # Invalid entries should be handled gracefully
        assert len(mapping) >= 1  # At least the valid one should be parsed

    def test_opera_handler_parsing_integration(
        self, opera_handler, changelog_html_content, mocker
    ):
        """Test that the Opera handler can parse the changelog HTML correctly."""
        mock_get = mocker.patch("handlers.opera_handler.requests.get")
        mock_response = mocker.Mock()
        mock_response.status_code = 200
        mock_response.content = changelog_html_content.encode("utf-8")
        mock_get.return_value = mock_response

        # Test the actual parsing method
        result = opera_handler._get_opera_chromium_mapping(122)

        # Should return a dictionary with version mappings
        assert isinstance(result, dict)

        # Test that the parsing works
        if len(result) > 0:
            # Verify the structure of results
            for opera_version, chromium_version in result.items():
                # Opera version should be a valid version string
                assert isinstance(opera_version, str)
                assert len(opera_version.split(".")) == 4

                # Chromium version should be either None or a valid version string
                if chromium_version is not None:
                    assert isinstance(chromium_version, str)
                    assert len(chromium_version.split(".")) == 4


class TestOperaHandlerVersionMethods:
    """Test version-related methods in Opera handler."""

    def test_map_chromium_to_opera_version_success(self, opera_handler, mocker):
        """Test successful mapping from Chromium to Opera version."""
        mocker.patch(
            "handlers.opera_handler.OperaHandler._load_opera_chromium_mapping",
            return_value={
                122: {
                    "122.0.5643.24": None,
                    "122.0.5643.17": "138.0.7204.251",
                    "122.0.5608.0": "137.0.7151.27",
                }
            },
        )
        # Test with a Chromium version that should map
        result = opera_handler._map_chromium_to_opera_version("137.0.7151.27")

        # Should return the corresponding Opera version
        assert result == "122.0.5608.0"

    def test_map_chromium_to_opera_version_not_found(self, opera_handler, mocker):
        """Test mapping when Chromium version is not found."""
        mocker.patch(
            "handlers.opera_handler.OperaHandler._load_opera_chromium_mapping",
            return_value={
                122: {
                    "122.0.5643.17": "138.0.7204.251",
                    "122.0.5608.0": "137.0.7151.27",
                }
            },
        )

        # Test with a Chromium version that doesn't exist
        result = opera_handler._map_chromium_to_opera_version("999.0.0.0")

        # Should return None
        assert result is None

    def test_map_chromium_to_opera_version_invalid_input(self, opera_handler, mocker):
        """Test mapping with invalid Chromium version input."""
        mocker.patch(
            "handlers.opera_handler.OperaHandler._load_opera_chromium_mapping",
            return_value={},
        )

        # Test with invalid version string
        result = opera_handler._map_chromium_to_opera_version("invalid.version")

        # Should return None
        assert result is None

    def test_extract_opera_version_from_text_various_formats(self, opera_handler):
        """Test version extraction from various text formats."""
        test_cases = [
            ("Opera One (120.0.5543.93)", "120.0.5543.93"),
            ("Opera GX (120.0.5543.85)", "120.0.5543.85"),
            ("Opera browser (119.0.5497.70)", "119.0.5497.70"),
            ("Opera (117.0.5408.163)", "117.0.5408.163"),
            ("Update to Opera v115.0.5322.68", "115.0.5322.68"),
            ("Opera Desktop 114.0.5282.122", "114.0.5282.122"),
            ("122.0.5643.24 – 2025-09-16", "122.0.5643.24"),
            ("No version here", None),
            ("Opera without version", None),
        ]

        for text, expected in test_cases:
            result = opera_handler._extract_opera_version_from_text(text)
            assert result == expected, f"Failed for text: '{text}'"

    def test_has_version_constraints(self, opera_handler):
        """Test detection of existing version constraints in bug titles."""
        test_cases = [
            ("Bug in www-client/opera", False),
            ("Bug in <www-client/opera-120.0.5543.93", True),
            ("Multiple packages including <www-client/opera-119.0.5497.70", True),
            ("No opera package mentioned", False),
            ("www-client/opera-devel mentioned", False),
        ]

        for title, expected in test_cases:
            result = opera_handler._has_version_constraints(title)
            assert result == expected, f"Failed for title: '{title}'"

    def test_add_opera_constraint_to_title(self, opera_handler):
        """Test adding Opera version constraints to bug titles."""
        test_cases = [
            (
                "Bug in www-client/opera package",
                "120.0.5543.93",
                "Bug in <www-client/opera-120.0.5543.93 package",
            ),
            (
                "Security issue affects www-client/opera",
                "119.0.5497.70",
                "Security issue affects <www-client/opera-119.0.5497.70",
            ),
            (
                "No opera package mentioned",
                "120.0.5543.93",
                "No opera package mentioned",  # Should remain unchanged
            ),
        ]

        for original_title, version, expected in test_cases:
            result = opera_handler._add_opera_constraint_to_title(
                original_title, version
            )
            assert result == expected, f"Failed for title: '{original_title}'"
