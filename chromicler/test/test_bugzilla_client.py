"""
Tests for BugzillaClient functionality.
"""

import pytest
from bugzilla_client import BugzillaClient


@pytest.fixture
def client(mocker, mock_logger):
    """Create a BugzillaClient instance for testing."""
    client = BugzillaClient.__new__(BugzillaClient)
    client.logger = mock_logger
    client.bzapi = mocker.Mock()
    return client


class TestBugzillaClientInit:
    """Test BugzillaClient initialization."""

    def test_constructor_success_rest_api(self, mocker, mock_logger):
        """Test BugzillaClient constructor with REST API."""
        # Patch open to return API key
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data="dGVzdF9hcGlfa2V5Cg=="),  # "test_api_key"
        )
        mock_bzapi = mocker.Mock()
        mock_bzapi.bz_ver_major = "5.0"
        mock_bugzilla_class = mocker.patch("bugzilla_client.bugzilla.Bugzilla")
        mock_bugzilla_class.return_value = mock_bzapi

        client = BugzillaClient("test_api_key_file", mock_logger, use_rest=True)

        assert client.logger is mock_logger
        assert client.bzapi is mock_bzapi
        assert client.use_rest is True
        # Verify REST was forced
        mock_bugzilla_class.assert_called_once_with(
            "bugs.gentoo.org", api_key="dGVzdF9hcGlfa2V5Cg==", force_rest=True
        )

    def test_constructor_success_xmlrpc(self, mocker, mock_logger):
        """Test BugzillaClient constructor with XMLRPC."""
        mocker.patch(
            "builtins.open",
            mocker.mock_open(read_data="test_api_key_xmlrpc"),
        )
        mock_bzapi = mocker.Mock()
        mock_bugzilla_class = mocker.patch("bugzilla_client.bugzilla.Bugzilla")
        mock_bugzilla_class.return_value = mock_bzapi

        client = BugzillaClient("test_api_key_file", mock_logger, use_rest=False)

        assert client.use_rest is False
        # Verify XMLRPC was used (no force_rest)
        mock_bugzilla_class.assert_called_once_with(
            "bugs.gentoo.org", api_key="test_api_key_xmlrpc"
        )

    def test_constructor_api_key_file_not_found(self, mocker, mock_logger):
        """Test BugzillaClient constructor when API key file doesn't exist."""
        mocker.patch("builtins.open", side_effect=FileNotFoundError("Not found"))

        with pytest.raises(SystemExit) as exc_info:
            BugzillaClient("nonexistent_file", mock_logger)

        assert exc_info.value.code == 1

    def test_constructor_permission_denied(self, mocker, mock_logger):
        """Test BugzillaClient constructor when API key file has no read permission."""
        mocker.patch("builtins.open", side_effect=PermissionError("Access denied"))

        with pytest.raises(SystemExit) as exc_info:
            BugzillaClient("restricted_file", mock_logger)

        assert exc_info.value.code == 1

    def test_constructor_bugzilla_connection_error(self, mocker, mock_logger):
        """Test BugzillaClient constructor when Bugzilla connection fails."""
        mocker.patch("builtins.open", mocker.mock_open(read_data="test_key"))
        mock_bugzilla_class = mocker.patch("bugzilla_client.bugzilla.Bugzilla")
        mock_bugzilla_class.side_effect = Exception("Connection failed")

        with pytest.raises(SystemExit) as exc_info:
            BugzillaClient("test_api_key_file", mock_logger)

        assert exc_info.value.code == 1


class TestFindChromiumSecurityBugs:
    """Test find_chromium_security_bugs method."""

    def test_find_chromium_security_bugs_success(self, client):
        """Test finding chromium security bugs successfully."""
        mock_bugs = [
            client.bzapi.Mock(id=123, summary="chromium: vulnerability"),
            client.bzapi.Mock(id=456, summary="google-chrome: another issue"),
        ]
        client.bzapi.query.return_value = mock_bugs
        client.bzapi.build_query.return_value = {"base": "query"}

        result = client.find_chromium_security_bugs()

        assert result == mock_bugs
        assert len(result) == 2
        client.bzapi.build_query.assert_called_once()

    def test_find_chromium_security_bugs_exception(self, client):
        """Test finding chromium security bugs when query fails."""
        client.bzapi.query.side_effect = Exception("Query failed")
        client.bzapi.build_query.return_value = {"base": "query"}

        result = client.find_chromium_security_bugs()

        assert result == []


class TestFindSecurityBugsByPackages:
    """Test find_security_bugs_by_packages method."""

    def test_find_security_bugs_by_packages(self, client):
        """Test find_security_bugs_by_packages method."""
        # Mock the query response
        mock_bugs = [
            client.bzapi.Mock(id=123, summary="www-client/opera: vulnerability"),
            client.bzapi.Mock(id=456, summary="www-client/chromium: another vuln"),
        ]
        client.bzapi.query.return_value = mock_bugs
        client.bzapi.build_query.return_value = {"base": "query"}

        # Test the method
        packages = ["www-client/opera", "www-client/chromium"]
        result = client.find_security_bugs_by_packages(packages)

        assert result == mock_bugs
        assert len(result) == 2

        # Verify the query was built correctly
        client.bzapi.build_query.assert_called_once_with(
            product="Gentoo Security",
            component="Vulnerabilities",
            status=["NEW", "ASSIGNED", "CONFIRMED", "IN_PROGRESS"],
            include_fields=["id", "summary", "alias", "status", "assigned_to"],
        )

    def test_find_security_bugs_by_packages_custom_status(self, client):
        """Test find_security_bugs_by_packages with custom status list."""
        client.bzapi.query.return_value = []
        client.bzapi.build_query.return_value = {"base": "query"}

        custom_status = ["RESOLVED", "VERIFIED"]
        client.find_security_bugs_by_packages(
            ["www-client/opera"], status=custom_status
        )

        # Verify custom status was used
        client.bzapi.build_query.assert_called_once_with(
            product="Gentoo Security",
            component="Vulnerabilities",
            status=custom_status,
            include_fields=["id", "summary", "alias", "status", "assigned_to"],
        )

    def test_find_security_bugs_by_packages_exception(self, client):
        """Test find_security_bugs_by_packages when query fails."""
        client.bzapi.build_query.return_value = {"base": "query"}
        client.bzapi.query.side_effect = Exception("Query failed")

        result = client.find_security_bugs_by_packages(["www-client/opera"])

        assert result == []


class TestGetBugComments:
    """Test get_bug_comments method."""

    def test_get_bug_comments_success(self, client):
        """Test getting bug comments successfully."""
        mock_comments = [
            {"id": 1, "text": "First comment"},
            {"id": 2, "text": "Second comment"},
        ]
        client.bzapi.get_comments.return_value = {
            "bugs": {"123": {"comments": mock_comments}}
        }

        result = client.get_bug_comments(123)

        assert result == mock_comments
        client.bzapi.get_comments.assert_called_once_with([123])

    def test_get_bug_comments_exception(self, client):
        """Test getting bug comments when an error occurs."""
        client.bzapi.get_comments.side_effect = Exception("API error")

        result = client.get_bug_comments(123)

        assert result == []


class TestGetCVEsFromBugAlias:
    """Test get_cves_from_bug_alias method."""

    def test_get_cves_from_bug_alias_success(self, client, mocker):
        """Test getting CVEs from bug alias successfully."""
        mock_bug = mocker.Mock()
        mock_bug.alias = ["CVE-2025-1234", "CVE-2025-5678"]
        client.bzapi.getbug.return_value = mock_bug

        result = client.get_cves_from_bug_alias(123)

        assert result == ["CVE-2025-1234", "CVE-2025-5678"]
        client.bzapi.getbug.assert_called_once_with(123)

    def test_get_cves_from_bug_alias_no_alias(self, client, mocker):
        """Test getting CVEs when bug has no alias."""
        mock_bug = mocker.Mock()
        mock_bug.alias = None
        client.bzapi.getbug.return_value = mock_bug

        result = client.get_cves_from_bug_alias(123)

        assert result == []

    def test_get_cves_from_bug_alias_exception(self, client):
        """Test getting CVEs when an error occurs."""
        client.bzapi.getbug.side_effect = Exception("Bug not found")

        result = client.get_cves_from_bug_alias(123)

        assert result == []


class TestCheckExistingBugsForCVEs:
    """Test check_existing_bugs_for_cves method."""

    def test_check_existing_bugs_empty_cves(self, client):
        """Test checking with empty CVE list."""
        result = client.check_existing_bugs_for_cves([])

        assert result == {}
        client.bzapi.query.assert_not_called()

    def test_check_existing_bugs_for_cves_found(self, client, mocker):
        """Test checking for existing bugs when bugs exist."""
        client.bzapi.build_query.return_value = {"base": "query"}

        # Mock bug for CVE-2025-1234
        mock_bug1 = mocker.Mock()
        mock_bug1.id = 123
        mock_bug1.summary = "CVE-2025-1234: vulnerability"

        # Mock bug for CVE-2025-5678
        mock_bug2 = mocker.Mock()
        mock_bug2.id = 456
        mock_bug2.summary = "CVE-2025-5678: another vuln"

        client.bzapi.query.side_effect = [[mock_bug1], [mock_bug2]]

        result = client.check_existing_bugs_for_cves(["CVE-2025-1234", "CVE-2025-5678"])

        assert result == {"CVE-2025-1234": 123, "CVE-2025-5678": 456}
        assert client.bzapi.query.call_count == 2

    def test_check_existing_bugs_for_cves_not_found(self, client):
        """Test checking for existing bugs when no bugs exist."""
        client.bzapi.build_query.return_value = {"base": "query"}
        client.bzapi.query.return_value = []  # No bugs found

        result = client.check_existing_bugs_for_cves(["CVE-2025-9999"])

        assert result == {}

    def test_check_existing_bugs_for_cves_exception(self, client):
        """Test checking for existing bugs when an error occurs."""
        client.bzapi.build_query.side_effect = Exception("Query failed")

        result = client.check_existing_bugs_for_cves(["CVE-2025-1234"])

        assert result == {}


class TestCreateSecurityBug:
    """Test create_security_bug method."""

    def test_create_security_bug_minimal(self, client, mocker):
        """Test creating a security bug with minimal parameters."""
        mock_new_bug = mocker.Mock()
        mock_new_bug.id = 789
        client.bzapi.createbug.return_value = mock_new_bug

        result = client.create_security_bug(
            title="Test vulnerability", description="Test description"
        )

        assert result == 789
        client.bzapi.createbug.assert_called_once()
        call_args = client.bzapi.createbug.call_args[1]
        assert call_args["product"] == "Gentoo Security"
        assert call_args["component"] == "Vulnerabilities"
        assert call_args["summary"] == "Test vulnerability"
        assert call_args["description"] == "Test description"
        assert call_args["assigned_to"] == "security@gentoo.org"
        assert call_args["cc"] == ["chromium@gentoo.org"]

    def test_create_security_bug_with_cves(self, client, mocker):
        """Test creating a security bug with CVEs."""
        mock_new_bug = mocker.Mock()
        mock_new_bug.id = 790
        client.bzapi.createbug.return_value = mock_new_bug

        cves = ["CVE-2025-1111", "CVE-2025-2222"]
        result = client.create_security_bug(
            title="Security issue",
            description="Description",
            cves=cves,
        )

        assert result == 790
        call_args = client.bzapi.createbug.call_args[1]
        assert call_args["alias"] == cves

    def test_create_security_bug_with_all_options(self, client, mocker):
        """Test creating a security bug with all optional parameters."""
        mock_new_bug = mocker.Mock()
        mock_new_bug.id = 791
        client.bzapi.createbug.return_value = mock_new_bug

        result = client.create_security_bug(
            title="Complex bug",
            description="Complex description",
            cves=["CVE-2025-3333"],
            url="https://example.com/advisory",
            see_also=["https://bugs.example.com/123"],
            blocks=[100, 200],
        )

        assert result == 791
        call_args = client.bzapi.createbug.call_args[1]
        assert call_args["alias"] == ["CVE-2025-3333"]
        assert call_args["url"] == "https://example.com/advisory"
        assert call_args["see_also"] == ["https://bugs.example.com/123"]
        assert call_args["blocks"] == [100, 200]

    def test_create_security_bug_exception(self, client):
        """Test creating a security bug when an error occurs."""
        client.bzapi.createbug.side_effect = Exception("Creation failed")

        result = client.create_security_bug(title="Test bug", description="Description")

        assert result is None


class TestUpdateBug:
    """Test update_bug method."""

    def test_update_bug_success(self, client):
        """Test update_bug method with successful update."""
        client.bzapi.build_update.return_value = {"summary": "new title"}

        result = client.update_bug(123, summary="new title", comment="test comment")

        assert result is True
        client.bzapi.build_update.assert_called_once_with(
            summary="new title", comment="test comment"
        )
        client.bzapi.update_bugs.assert_called_once_with(
            [123], {"summary": "new title"}
        )

    def test_update_bug_summary_only(self, client):
        """Test updating only the summary."""
        client.bzapi.build_update.return_value = {"summary": "new summary"}

        result = client.update_bug(123, summary="new summary")

        assert result is True
        client.bzapi.build_update.assert_called_once_with(summary="new summary")

    def test_update_bug_comment_only(self, client):
        """Test updating only with a comment."""
        client.bzapi.build_update.return_value = {"comment": "new comment"}

        result = client.update_bug(123, comment="new comment")

        assert result is True
        client.bzapi.build_update.assert_called_once_with(comment="new comment")

    def test_update_bug_exception(self, client):
        """Test update_bug method when exception occurs."""
        client.bzapi.build_update.return_value = {"summary": "new title"}
        client.bzapi.update_bugs.side_effect = Exception("Update failed")

        result = client.update_bug(123, summary="new title")

        assert result is False
