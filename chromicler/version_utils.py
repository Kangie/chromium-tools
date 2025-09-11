#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Version comparison and manipulation utilities.
"""

import re
from typing import Tuple, List

try:
    # Prefer portage's version utilities when available for proper Gentoo
    # version comparison semantics
    import portage.versions as portage_versions  # type: ignore

    _HAS_PORTAGE = True
except Exception:
    portage_versions = None
    _HAS_PORTAGE = False


class VersionUtils:
    """Utilities for version comparison and manipulation.

    This class delegates to portage.versions.vercmp when portage is
    available. A minimal fallback implementation is provided for
    environments without portage (useful for tests or non-Gentoo hosts).
    """

    def __init__(self):
        self.version_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
        self.package_pattern = re.compile(
            r"(www-client/(?:chromium|google-chrome))-(\d+(?:\.\d+)*(?:\.\d+)?(?:\.\d+)?)"
        )

    def version_tuple(self, v: str) -> Tuple[int, ...]:
        """Convert version string to tuple for comparison."""
        return tuple(map(int, v.split(".")))

    def compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings.

        Returns:
            1 if v1 > v2, -1 if v1 < v2, 0 if equal
        """
        if _HAS_PORTAGE:
            # portage.versions.vercmp returns -1, 0, 1 (or None on errors)
            try:
                rv = portage_versions.vercmp(v1, v2)
                if rv is not None:
                    return int(rv)
                # Fall back to simple logic if vercmp returns None
            except Exception:
                # Fall back to simple logic on unexpected errors
                pass

        # Fallback behavior when portage isn't available or fails
        try:
            v1_tuple = self.version_tuple(v1)
            v2_tuple = self.version_tuple(v2)

            if v1_tuple > v2_tuple:
                return 1
            elif v1_tuple < v2_tuple:
                return -1
            else:
                return 0
        except Exception:
            # Fallback to string comparison for malformed versions
            return 0 if v1 == v2 else (1 if v1 > v2 else -1)

    def extract_version_from_text(self, text: str) -> str:
        """Extract version number from text."""
        matches = self.version_pattern.findall(text)
        return matches[0] if matches else None

    def has_version_constraints(self, title: str, packages: List[str]) -> bool:
        """Check if a bug title already has version constraints for the
        provided package names.

        `packages` must be provided and should contain strings like
        'www-client/opera' or 'www-client/chromium'. Only constraints for the
        supplied packages will be matched.
        """
        if not packages:
            # Defensive: empty list means no packages to check
            return False

        # Build a pattern for the provided package list. Match strings like
        # "<www-client/opera-<version>" for each package.
        parts = [re.escape(pkg) for pkg in packages]
        pattern = r"|".join(rf"<{p}-[\d.]+" for p in parts)
        version_constraint_pattern = re.compile(pattern)
        return bool(version_constraint_pattern.search(title))

    def generate_constraint_string(self, package: str, version: str) -> str:
        """Generate version constraint string for bug titles."""
        return f"<{package}-{version}"

    def compare_version_tuples(
        self, item1: Tuple[str, str], item2: Tuple[str, str]
    ) -> int:
        """
        Compare two version tuples using portage version comparison.

        This is useful for sorting lists of (version, revision) tuples.

        Args:
            item1: (version, revision) tuple
            item2: (version, revision) tuple

        Returns:
            Negative if item1 < item2, 0 if equal, positive if item1 > item2
        """
        if _HAS_PORTAGE:
            # Use portage vercmp (returns negative/0/positive, we want reverse for sorting)
            result = portage_versions.vercmp(item1[0], item2[0])
            return -result if result is not None else 0

        # Fallback to string comparison
        v1 = f"{item1[0]}-{item1[1]}" if item1[1] != "r0" else item1[0]
        v2 = f"{item2[0]}-{item2[1]}" if item2[1] != "r0" else item2[0]
        if v1 < v2:
            return 1
        elif v1 > v2:
            return -1
        return 0

    def get_ebuild_version(self, version: Tuple[str, str]) -> str:
        """
        Convert a (version, revision) tuple to ebuild version string.

        Args:
            version: (version, revision) tuple

        Returns:
            Ebuild version string (e.g., "131.0.0.0" or "131.0.0.0-r1")
        """
        if version[1] == "r0":
            return version[0]
        return f"{version[0]}-{version[1]}"
