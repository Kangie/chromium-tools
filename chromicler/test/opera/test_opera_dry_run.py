"""
Test for Opera handler dry-run functionality.

This test specifically verifies that when the Opera handler is run in dry-run mode,
it will not actually update any bugs in Bugzilla.
"""

from handlers.opera_handler import OperaHandler
from version_utils import VersionUtils


class TestOperaDryRun:
    """Test dry-run functionality of OperaHandler."""

    def test_dry_run_mode_does_not_update_bugs(
        self, mock_bugzilla_client, mock_logger, mocker
    ):
        """
        Test that Opera handler in dry-run mode does NOT update bugs.

        This is the critical test to ensure dry-run mode is safe to use.
        """
        # Create a mock bug that would normally be updated
        mock_bug = mocker.Mock(
            id=12345,
            summary="www-client/opera: Multiple vulnerabilities",
            alias=["CVE-2024-1234"],
        )

        # Configure mock bugzilla client
        mock_bugzilla_client.find_security_bugs_by_packages.return_value = [mock_bug]
        mock_bugzilla_client.update_bug.return_value = True

        # Create handler with dry_run=True
        handler = OperaHandler(
            mock_bugzilla_client,
            mock_logger,
            dry_run=True,
            version_utils=VersionUtils(),
        )

        # Mock the version finding to return a version (so update would normally happen)
        mocker.patch.object(
            handler,
            "_find_opera_version_for_cves",
            return_value=(
                "115.0.5678.90",
                "rss",
                ["https://example.com/opera-security"],
            ),
        )

        results = handler.update_opera_versions()

        # CRITICAL ASSERTION: update_bug should NOT be called in dry-run mode
        mock_bugzilla_client.update_bug.assert_not_called()

        # But the operation should still be counted as successful in dry-run
        assert results["updated"] == 1
        assert results["total"] == 1
        assert results["skipped"] == 0

    def test_live_mode_does_update_bugs(
        self, mock_bugzilla_client, mock_logger, mocker
    ):
        """
        Test that Opera handler in live mode DOES update bugs.

        This is the control test to ensure live mode works normally.
        """
        # Create a mock bug that would normally be updated
        mock_bug = mocker.Mock(
            id=12345,
            summary="www-client/opera: Multiple vulnerabilities",
            alias=["CVE-2024-1234"],
        )

        # Configure mock bugzilla client
        mock_bugzilla_client.find_security_bugs_by_packages.return_value = [mock_bug]
        mock_bugzilla_client.update_bug.return_value = True

        # Create handler with dry_run=False (live mode)
        handler = OperaHandler(
            mock_bugzilla_client,
            mock_logger,
            dry_run=False,
            version_utils=VersionUtils(),
        )

        # Mock the version finding to return a version
        mocker.patch.object(
            handler,
            "_find_opera_version_for_cves",
            return_value=(
                "115.0.5678.90",
                "rss",
                ["https://example.com/opera-security"],
            ),
        )

        results = handler.update_opera_versions()

        # ASSERTION: update_bug SHOULD be called in live mode
        mock_bugzilla_client.update_bug.assert_called_once()

        # Check the call arguments
        call_args = mock_bugzilla_client.update_bug.call_args
        assert call_args[0][0] == 12345  # bug_id
        assert "115.0.5678.90" in call_args[1]["summary"]  # version in new summary
        assert "Opera version constraint added" in call_args[1]["comment"]  # comment

        assert results["updated"] == 1
        assert results["total"] == 1
        assert results["skipped"] == 0
