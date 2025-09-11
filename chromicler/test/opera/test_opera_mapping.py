"""
Test cases for Opera duplicate Chromium version handling.

Tests the logic that when a Chromium version appears in multiple Opera versions,
the earliest (lowest) Opera version should be returned.
"""

import pytest

from handlers.opera_handler import OperaHandler
from version_utils import VersionUtils
from bugzilla_client import BugzillaClient


class TestOperaDuplicateHandling:
    """Test Opera handler's duplicate Chromium version handling."""

    @pytest.fixture
    def mock_bugzilla(self, mocker):
        """Create a mock BugzillaClient using pytest-mock."""
        return mocker.Mock(spec=BugzillaClient)

    @pytest.fixture
    def mock_logger(self, mocker):
        """Create a mock logger using pytest-mock."""
        return mocker.Mock()

    @pytest.fixture
    def opera_handler(self, mock_bugzilla, mock_logger, mocker):
        """Create OperaHandler for testing."""
        handler = OperaHandler(
            api_key_file="./bugzilla_api_key",
            logger=mock_logger,
            dry_run=True,
            version_utils=VersionUtils(),
        )
        # Mock the bugzilla property
        mocker.patch.object(
            type(handler),
            "bugzilla",
            new_callable=mocker.PropertyMock,
            return_value=mock_bugzilla,
        )
        return handler

    @pytest.fixture
    def duplicate_test_mapping(self):
        """
        Test mapping data with duplicate Chromium versions.

        Based on real data where:
        - 137.0.7151.27 appears in 121.0.5600.3, 121.0.5600.0, and 122.0.5608.0
        - 137.0.7151.122 appears in 121.0.5600.38 and 121.0.5600.20
        """
        return {
            121: {
                "121.0.5600.38": "137.0.7151.122",
                "121.0.5600.20": "137.0.7151.122",
                "121.0.5600.12": None,
                "121.0.5600.3": "137.0.7151.27",
                "121.0.5600.0": "137.0.7151.27",  # Earliest for 137.0.7151.27
                "121.0.5593.0": None,
                "121.0.5544.0": "135.0.7049.42",
            },
            122: {
                "122.0.5643.51": None,
                "122.0.5643.24": None,
                "122.0.5608.0": "137.0.7151.27",  # Duplicate of 137.0.7151.27
                "122.0.5600.0": None,
            },
        }

    def test_find_chromium_match_in_mapping_exact_match(self, opera_handler):
        """Test exact match with no duplicates."""
        mapping = {
            "121.0.5600.0": "137.0.7151.27",
            "121.0.5593.0": None,
            "121.0.5586.0": "136.0.7100.0",
        }

        result = opera_handler._find_chromium_match_in_mapping(mapping, "137.0.7151.27")
        assert result == "121.0.5600.0"

    def test_find_chromium_match_in_mapping_with_duplicates(self, opera_handler):
        """Test that earliest Opera version is returned when duplicates exist."""
        mapping = {
            "121.0.5600.38": "137.0.7151.122",
            "121.0.5600.20": "137.0.7151.122",  # Earlier version, should be returned
            "121.0.5600.12": None,
            "121.0.5600.3": "137.0.7151.27",
            "121.0.5600.0": "137.0.7151.27",  # Earlier version, should be returned
        }

        # Test the first duplicate case
        result = opera_handler._find_chromium_match_in_mapping(
            mapping, "137.0.7151.122"
        )
        assert result == "121.0.5600.20"

        # Test the second duplicate case
        result = opera_handler._find_chromium_match_in_mapping(mapping, "137.0.7151.27")
        assert result == "121.0.5600.0"

    def test_find_chromium_match_in_mapping_fallback_logic(self, opera_handler):
        """Test fallback logic when no exact match exists."""
        mapping = {
            "121.0.5600.0": "137.0.7151.27",  # Lower than target
            "121.0.5593.0": "136.0.7100.0",  # Much lower than target
            "121.0.5586.0": None,
            "121.0.5580.0": "135.0.7000.0",  # Even lower
        }

        # Looking for 138.0.7200.0 (higher than any in mapping)
        # Should return None because no Opera version has Chromium >= target (security fix not available)
        result = opera_handler._find_chromium_match_in_mapping(mapping, "138.0.7200.0")
        assert result is None

        # Test with a Chromium version that exists in the mapping
        result = opera_handler._find_chromium_match_in_mapping(mapping, "137.0.7151.27")
        assert result == "121.0.5600.0"  # Exact match

        # Test with a Chromium version that should find the first version >= target
        mapping_with_newer = {
            "121.0.5600.0": "137.0.7151.27",  # Lower than target
            "121.0.5610.0": "138.0.7200.0",  # Exactly target
            "121.0.5620.0": "139.0.7300.0",  # Higher than target
        }

        # Looking for 138.0.7200.0 - should return 121.0.5610.0 (first version with >= target)
        result = opera_handler._find_chromium_match_in_mapping(
            mapping_with_newer, "138.0.7200.0"
        )
        assert result == "121.0.5610.0"

        # Looking for 137.5.7180.0 - should return 121.0.5610.0 (first version with >= target)
        result = opera_handler._find_chromium_match_in_mapping(
            mapping_with_newer, "137.5.7180.0"
        )
        assert result == "121.0.5610.0"

    def test_find_global_opera_version_for_chromium_version(
        self, mocker, opera_handler, duplicate_test_mapping
    ):
        """Test global search across major versions for duplicates."""
        # Mock the mapping loading to return our test data
        mock_load_mapping = mocker.patch.object(
            OperaHandler, "_load_opera_chromium_mapping"
        )
        mock_load_mapping.return_value = duplicate_test_mapping

        # Reset the cached mapping so it loads our test data
        opera_handler._opera_chromium_mapping = None

        # Test 137.0.7151.27 which appears in both 121 and 122
        # Should return 121.0.5600.0 (earliest globally)
        result = opera_handler._find_global_opera_version_for_chromium_version(
            "137.0.7151.27"
        )
        assert result == "121.0.5600.0"

        # Test 137.0.7151.122 which appears twice in 121
        # Should return 121.0.5600.20 (earliest)
        result = opera_handler._find_global_opera_version_for_chromium_version(
            "137.0.7151.122"
        )
        assert result == "121.0.5600.20"

        # Test unique version
        result = opera_handler._find_global_opera_version_for_chromium_version(
            "135.0.7049.42"
        )
        assert result == "121.0.5544.0"

        # Test non-existent version
        result = opera_handler._find_global_opera_version_for_chromium_version(
            "999.0.0.0"
        )
        assert result is None

    def test_map_chromium_to_opera_version_with_duplicates(
        self, mocker, opera_handler, duplicate_test_mapping
    ):
        """Test complete mapping flow with duplicate handling."""
        # Mock the mapping loading to return our test data
        mock_load_mapping = mocker.patch.object(
            OperaHandler, "_load_opera_chromium_mapping"
        )
        mock_load_mapping.return_value = duplicate_test_mapping

        # Reset the cached mapping so it loads our test data
        opera_handler._opera_chromium_mapping = None

        # Test that global search is used first and finds earliest version
        result = opera_handler._map_chromium_to_opera_version("137.0.7151.27")
        assert result == "121.0.5600.0"

        # Test another duplicate case
        result = opera_handler._map_chromium_to_opera_version("137.0.7151.122")
        assert result == "121.0.5600.20"

    def test_version_comparison_edge_cases(self, opera_handler):
        """Test version comparison with various edge cases."""
        mapping = {
            "121.0.5600.10": "137.0.7151.27",
            "121.0.5600.9": "137.0.7151.27",  # Should be earliest (9 < 10)
            "121.0.5600.100": "137.0.7151.27",  # Should not be confused as earliest
        }

        result = opera_handler._find_chromium_match_in_mapping(mapping, "137.0.7151.27")
        assert result == "121.0.5600.9"

    def test_empty_and_null_mappings(self, opera_handler):
        """Test handling of empty and null mappings."""
        # Empty mapping
        result = opera_handler._find_chromium_match_in_mapping({}, "137.0.7151.27")
        assert result is None

        # Mapping with only null values
        mapping = {"121.0.5600.0": None, "121.0.5593.0": None}
        result = opera_handler._find_chromium_match_in_mapping(mapping, "137.0.7151.27")
        assert result is None

    def test_documentation_examples(self, opera_handler):
        """Test the specific examples mentioned in the function documentation."""
        # Test case from the docstring
        mapping = {
            "122.0.5643.51": None,
            "122.0.5643.24": None,
            "122.0.5643.17": "138.0.7204.251",
            "122.0.5643.6": None,
            "122.0.5638.0": None,
            "122.0.5629.0": None,
            "122.0.5621.0": None,
            "122.0.5615.0": None,
            "122.0.5608.0": "137.0.7151.27",
        }

        # For version 137.0.7200.0, it should find 122.0.5643.17
        # because that's the first Opera version with Chromium >= 137.0.7200.0 (138.0.7204.251)
        # This is the first version that contains the security fix
        result = opera_handler._find_chromium_match_in_mapping(mapping, "137.0.7200.0")
        assert result == "122.0.5643.17"

        # For a version higher than both, should return None because no version has the fix yet
        result = opera_handler._find_chromium_match_in_mapping(mapping, "139.0.0.0")
        assert result is None

        # For exact match
        result = opera_handler._find_chromium_match_in_mapping(mapping, "137.0.7151.27")
        assert result == "122.0.5608.0"

        result = opera_handler._find_chromium_match_in_mapping(
            mapping, "138.0.7204.251"
        )
        assert result == "122.0.5643.17"


def test_find_chromium_match_in_mapping_exact_and_fallback(
    mock_bugzilla_client, mock_logger
):
    handler = OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=True, version_utils=VersionUtils()
    )

    mapping = {
        "121.0.5600.0": "137.0.7151.27",
        "121.0.5600.3": "137.0.7151.27",
        "121.0.5600.5": "137.0.7151.30",
    }

    # Exact-match: should return the earliest Opera version among exact matches
    exact = handler._find_chromium_match_in_mapping(mapping, "137.0.7151.27")
    assert exact == "121.0.5600.0"

    # Fallback: no exact match for 137.0.7151.28, should return the first Opera version
    # whose Chromium mapping is >= target (121.0.5600.5 -> 137.0.7151.30)
    fallback = handler._find_chromium_match_in_mapping(mapping, "137.0.7151.28")
    assert fallback == "121.0.5600.5"


def test_find_opera_version_for_chromium_version_same_major_and_adjacent(
    mock_bugzilla_client, mock_logger, monkeypatch
):
    handler = OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=True, version_utils=VersionUtils()
    )

    # Prepare a full mapping with two majors
    full_mapping = {
        121: {"121.0.5600.0": "137.0.7151.27"},
        122: {"122.0.5600.0": "138.0.7160.0"},
    }

    # Make the handler load this mapping
    monkeypatch.setattr(
        OperaHandler, "_load_opera_chromium_mapping", lambda self: full_mapping
    )

    # Same-major success
    found = handler._find_opera_version_for_chromium_version(121, "137.0.7151.27")
    assert found == "121.0.5600.0"

    # Adjacent-major fallback: target only present in major 122
    found_adj = handler._find_opera_version_for_chromium_version(121, "138.0.7160.0")
    assert found_adj == "122.0.5600.0"

    # Missing major: when opera_major not present, expect None
    not_found = handler._find_opera_version_for_chromium_version(123, "138.0.7160.0")
    assert not_found is None


def test_map_chromium_to_opera_version_global_and_major_lookup(
    mock_bugzilla_client, mock_logger
):
    handler = OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=True, version_utils=VersionUtils()
    )

    # Provide mapping where same Chromium appears in multiple majors
    mapping = {
        120: {"120.0.0": "136.0.7000.0"},
        121: {"121.0.0": "136.0.7000.0"},
    }

    # Set cached mapping directly so property uses it
    handler._opera_chromium_mapping = mapping

    # Global match should return the earliest Opera version across all majors
    result = handler._map_chromium_to_opera_version("136.0.7000.0")
    assert result == "120.0.0"

    # If no global match, but mapping contains the major mapping, _map_chromium_to_opera_version
    # should find the opera_major via _get_opera_major_from_chromium_major and then lookup
    handler._opera_chromium_mapping = {121: {"121.0.5600.0": "137.0.7151.27"}}
    res2 = handler._map_chromium_to_opera_version("137.0.7151.27")
    assert res2 == "121.0.5600.0"
