#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Opera Handler - Manages Opera security workflow

This handler combines:
1. Opera security RSS feed parsing for direct CVE-to-version mappings
2. Opera changelog scraping for Chromium-to-Opera version mapping
3. Bug updates with Opera version constraints
"""

import functools
import json
import os
import re
import time
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests
import structlog
import typer
import yaml
from bs4 import BeautifulSoup, Tag
from packaging.version import Version

from bugzilla_client import BugzillaClient
from ebuild_manager import EbuildManager
from version_utils import VersionUtils
from bump_utils import (
    is_major_bump,
    get_prev_channel_generic,
    calculate_versions_to_remove,
    limit_new_versions,
    bump_browser_package,
)


class OperaHandler:
    """Handler for Opera security updates."""

    def __init__(
        self,
        api_key_file: str,
        logger: structlog.BoundLogger,
        version_utils: VersionUtils,
        dry_run: bool = False,
    ):
        self.api_key_file = api_key_file
        self.logger = logger
        self.dry_run = dry_run
        self.version_utils = version_utils
        self._bugzilla = None  # Lazy-loaded

        # Opera security RSS feed
        self.rss_url = "https://blogs.opera.com/security/feed"

        # Set up cache directory
        self.cache_dir = Path.home() / ".cache" / "chromium-security-manager"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Version patterns for parsing
        self.cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
        self.opera_version_pattern = re.compile(
            r"Opera (?:One|GX|Air|Desktop|browser)?\s*(?:\(?v?(\d+(?:\.\d+){3})\)?|(\d+(?:\.\d+){2,3}))",
            re.IGNORECASE,
        )

        # Lazy load Opera-Chromium mapping (only when needed)
        self._opera_chromium_mapping = None

        # Create CLI app for this handler
        self.cli = typer.Typer(
            name="opera",
            help="Opera security workflow",
            no_args_is_help=True,
        )
        self._register_commands()

    @property
    def bugzilla(self) -> BugzillaClient:
        """Lazy-load BugzillaClient only when actually needed."""
        if self._bugzilla is None:
            self._bugzilla = BugzillaClient(
                api_key_file=self.api_key_file,
                logger=self.logger,
            )
        return self._bugzilla

    def _get_ebuild_version(self, version: tuple) -> str:
        """Convert (version, revision) tuple to ebuild version string."""
        return self.version_utils.get_ebuild_version(version)

    def _compare_version_tuples(self, v1: tuple, v2: tuple) -> int:
        """Compare two (version, revision) tuples."""
        return self.version_utils.compare_version_tuples(v1, v2)

    def _register_commands(self):
        """Register CLI commands for this handler."""

        from chromicler import DryRunOption, DebugOption, AppConfig

        handler = self

        @self.cli.command(name="update")
        def update(
            dry_run: bool = DryRunOption(),
            debug: bool = DebugOption(),
        ):
            """Update existing bugs with Opera version constraints"""
            try:
                # Update AppConfig and handler state if local options were explicitly set
                if dry_run:
                    AppConfig.dry_run = dry_run
                    handler.dry_run = dry_run
                if debug:
                    AppConfig.debug = debug

                # Show dry run banner if enabled
                if dry_run or AppConfig.dry_run:
                    handler.logger.info(
                        "Dry run mode enabled - no changes will be made"
                    )

                result = handler.update_opera_versions()

                handler.logger.info(
                    "Update complete",
                    updated=result.get("updated", 0),
                    skipped=result.get("skipped", 0),
                    errors=result.get("errors", 0),
                )

            except KeyboardInterrupt:
                typer.echo("\nOperation cancelled by user")
                raise typer.Exit(0)
            except Exception as e:
                typer.echo(f"Error: {e}")
                if debug or AppConfig.debug:
                    import traceback

                    traceback.print_exc()
                raise typer.Exit(1)

        @self.cli.command(name="update-mapping")
        def update_mapping(
            opera_version: Optional[str] = typer.Argument(
                None, help="Specific Opera version to process"
            ),
            chromium_version: Optional[str] = typer.Option(
                None,
                "--chromium",
                "-c",
                help="Chromium version to map to (required with opera_version)",
            ),
            all_versions: bool = typer.Option(
                False,
                "--all",
                "-a",
                help="Process all available Opera versions from changelog",
            ),
            dry_run: bool = DryRunOption(),
            debug: bool = DebugOption(),
        ):
            """Update the Opera-to-Chromium version mapping file"""
            try:
                # Update AppConfig and handler state if local options were explicitly set
                if dry_run:
                    AppConfig.dry_run = dry_run
                    handler.dry_run = dry_run
                if debug:
                    AppConfig.debug = debug

                # Show dry run banner if enabled
                if dry_run or AppConfig.dry_run:
                    handler.logger.info(
                        "Dry run mode enabled - no changes will be made"
                    )

                if opera_version and chromium_version:
                    # Add a specific mapping - create a dict structure
                    major_version = int(opera_version.split(".")[0])
                    mappings = {major_version: {opera_version: chromium_version}}
                    result = handler.update_mapping_file(mappings=mappings)
                elif all_versions:
                    # Update all mappings from changelog
                    mappings = handler.generate_version_mapping()
                    if mappings:
                        result = handler.update_mapping_file(mappings=mappings)
                    else:
                        typer.echo("No mappings generated")
                        raise typer.Exit(1)
                else:
                    typer.echo(
                        "Error: Either provide both --opera and --chromium, or use --all"
                    )
                    raise typer.Exit(1)

                handler.logger.info("Mapping update complete", file=result)

            except KeyboardInterrupt:
                typer.echo("\nOperation cancelled by user")
                raise typer.Exit(0)
            except Exception as e:
                typer.echo(f"Error: {e}")
                if debug or AppConfig.debug:
                    import traceback

                    traceback.print_exc()
                raise typer.Exit(1)

        @self.cli.command(name="bump")
        def bump(
            channels: List[str] = typer.Option(
                None,
                "--channel",
                "-c",
                help="Specific channels to bump (stable, beta, developer). If not specified, checks all channels.",
            ),
            repo_path: str = typer.Option(
                "/var/db/repos/gentoo",
                "--repo",
                "-r",
                help="Path to Gentoo repository",
            ),
            dry_run: bool = DryRunOption(),
            debug: bool = DebugOption(),
        ):
            """Check for Opera updates and bump ebuilds if needed"""
            try:
                # Update AppConfig and handler state if local options were explicitly set
                if dry_run:
                    AppConfig.dry_run = dry_run
                    handler.dry_run = dry_run
                if debug:
                    AppConfig.debug = debug

                # Show dry run banner if enabled
                if dry_run or AppConfig.dry_run:
                    handler.logger.info(
                        "Dry run mode enabled - no changes will be made"
                    )

                # Default to all channels if none specified
                if not channels:
                    channels = ["stable", "beta", "developer"]

                result = handler.bump_opera(
                    channels=channels,
                    repo_path=repo_path,
                    dry_run=dry_run or AppConfig.dry_run,
                )

                handler.logger.info(
                    "Bump complete",
                    bumped=result.get("bumped", 0),
                    skipped=result.get("skipped", 0),
                    errors=result.get("errors", 0),
                )

            except KeyboardInterrupt:
                typer.echo("\nOperation cancelled by user")
                raise typer.Exit(0)
            except Exception as e:
                typer.echo(f"Error: {e}")
                if debug or AppConfig.debug:
                    import traceback

                    traceback.print_exc()
                raise typer.Exit(1)

    def get_vendor_name(self) -> str:
        """Return the vendor name for this handler."""
        return "Opera Software"

    def register_browsers(self, registry):
        """Register the browsers that this handler impacts."""
        registry.register_browser("opera", "www-client/opera")

    def _is_testing(self) -> bool:
        """
        Check if code is running in a testing environment.

        Returns:
            True if running under pytest, False otherwise
        """
        return os.environ.get("PYTEST_CURRENT_TEST") is not None

    def update_opera_versions(self) -> Dict:
        """
        Update existing bugs with Opera version constraints.

        Returns:
            Dictionary with update statistics
        """
        self.logger.info("Starting Opera version updates")

        # Find all relevant bugs that mention opera
        bugs = self.bugzilla.find_security_bugs_by_packages(["www-client/opera"])
        if not bugs:
            self.logger.info("No Opera bugs found to process")
            return {"updated": 0, "skipped": 0, "total": 0}

        results = {"updated": 0, "skipped": 0, "total": len(bugs)}

        for bug in bugs:
            bug_id = None
            try:
                bug_id = bug.id

                self.logger.debug("Processing Opera bug", bug_id=bug_id)

                # Skip if already has version constraints
                summary = bug.summary or ""
                if self._has_version_constraints(summary):
                    self.logger.debug(
                        "Bug already has version constraints", bug_id=bug_id
                    )
                    results["skipped"] += 1
                    continue

                # Get CVEs from bug aliases
                cves = bug.alias or []
                if not cves:
                    self.logger.warning("No CVE aliases found for bug", bug_id=bug_id)
                    results["skipped"] += 1
                    continue

                # Find Opera version for these CVEs
                opera_version, method, urls = self._find_opera_version_for_cves(cves)
                if not opera_version:
                    self.logger.warning(
                        "No Opera version found", bug_id=bug_id, cves=cves
                    )
                    results["skipped"] += 1
                    continue

                # Update bug title
                new_title = self._add_opera_constraint_to_title(summary, opera_version)
                if new_title == summary:
                    self.logger.debug("No title update needed", bug_id=bug_id)
                    results["skipped"] += 1
                    continue

                self.logger.info(
                    "Updating Opera bug title",
                    bug_id=bug_id,
                    old_title=summary,
                    new_title=new_title,
                    opera_version=opera_version,
                )

                # Update the bug
                method_comment = (
                    "from CVE security advisory analysis"
                    if method == "rss"
                    else "from Opera Release blog scraping"
                )

                comment = f"Opera version constraint added: <www-client/opera-{opera_version} ({method_comment})"

                if method == "rss" and urls:
                    comment += "\n\nRelated Opera Security Advisory URLs:"
                    for i, url in enumerate(urls, 1):
                        comment += f"\n{i}. {url}"

                if self.dry_run:
                    self.logger.info(
                        "DRY RUN: Would update bug",
                        bug_id=bug_id,
                        new_summary=new_title,
                        comment=comment,
                    )
                    results["updated"] += 1
                else:
                    if self.bugzilla.update_bug(
                        bug_id, summary=new_title, comment=comment
                    ):
                        results["updated"] += 1
                    else:
                        results["skipped"] += 1

            except Exception as e:
                self.logger.error(
                    "Error processing Opera bug",
                    bug_id=bug_id if "bug_id" in locals() else "unknown",
                    error=str(e),
                    exc_info=True,
                )
                results["skipped"] += 1

        self.logger.info(
            "Opera version updates complete",
            updated=results["updated"],
            skipped=results["skipped"],
            total=results["total"],
        )
        return results

    def _find_opera_version_for_cves(
        self, cves: List[str]
    ) -> Tuple[Optional[str], Optional[str], List[str]]:
        """
        Find Opera version that fixes the given CVEs.

        First tries the security RSS feed, then falls back to version mapping.

        Args:
            cves: List of CVE identifiers

        Returns:
            Tuple(Opera version string, or None if not found, method used ("rss" or "chromium_mapping" or None), List of URLs mentioning the CVEs)
        """
        # Preferred: Direct CVE lookup against security blog posts. Not guaranteed to work though.
        rss_version, rss_urls = self._get_opera_version_from_rss(cves)
        if rss_version:
            self.logger.debug(
                "Found Opera version from RSS feed",
                cves=cves,
                version=rss_version,
                rss_urls=rss_urls,
            )
            return rss_version, "rss", rss_urls

        # If not see if we can line up the Chromium and Opera versions.
        chromium_version = self._find_chromium_version_for_cves(cves)
        if chromium_version:
            opera_version = self._map_chromium_to_opera_version(chromium_version)
            if opera_version:
                self.logger.debug(
                    "Found Opera version from Chromium mapping",
                    cves=cves,
                    chromium_version=chromium_version,
                    opera_version=opera_version,
                )
                return opera_version, "chromium_mapping", []

        return None, None, []

    def _get_opera_version_from_rss(
        self, cves: List[str]
    ) -> tuple[Optional[str], List[str]]:
        """
        Parse Opera security RSS feed to find version that fixes given CVEs.

        Uses caching to avoid fetching RSS feed more than once every 3 hours.

        Args:
            cves: List of CVE identifiers

        Returns:
            Tuple of (Opera version string or None, List of URLs mentioning the CVEs)
        """
        try:
            # Check cache first (skip caching during testing)
            cache_file = self._get_rss_cache_file_path()
            rss_content = None

            if not self._is_testing() and self._is_rss_cache_valid(cache_file):
                rss_content = self._load_rss_from_cache(cache_file)
                if rss_content:
                    self.logger.debug("Using cached RSS content")
                else:
                    self.logger.debug("Cache file exists but failed to load content")

            # Fetch fresh RSS content if cache is invalid or failed to load
            if not rss_content:
                self.logger.debug("Fetching fresh Opera security RSS feed")

                response = requests.get(self.rss_url, timeout=30)
                if response.status_code != 200:
                    self.logger.warning(
                        "Failed to fetch Opera RSS feed", status=response.status_code
                    )
                    return None, []

                rss_content = response.text

                # Save to cache (skip during testing)
                if not self._is_testing():
                    self._save_rss_to_cache(cache_file, rss_content)

            # Parse RSS XML
            root = ET.fromstring(rss_content)

            # Collect URLs of posts that mention the CVEs
            relevant_urls = []
            found_version = None

            # Look through RSS items for CVE mentions
            for item in root.findall(".//item"):
                title_elem = item.find("title")
                description_elem = item.find("description")
                content_elem = item.find(
                    "{http://purl.org/rss/1.0/modules/content/}encoded"
                )
                link_elem = item.find("link")

                if title_elem is None:
                    continue

                title = title_elem.text or ""
                description = (
                    description_elem.text if description_elem is not None else ""
                )
                content = content_elem.text if content_elem is not None else ""
                link = link_elem.text if link_elem is not None else ""

                # Check if any of our CVEs are mentioned
                combined_text = f"{title} {description} {content}"
                found_cves = self.cve_pattern.findall(combined_text)

                if any(cve in found_cves for cve in cves):
                    self.logger.debug(
                        "Found CVE mention in RSS item",
                        title=title[:100],
                        found_cves=found_cves,
                        target_cves=cves,
                    )

                    # Add URL to the list of relevant URLs
                    if link:
                        relevant_urls.append(link)

                    # Try to extract Opera version from the combined text if we haven't found one yet
                    if not found_version:
                        opera_version = self._extract_opera_version_from_text(
                            combined_text
                        )
                        if opera_version:
                            found_version = opera_version
                        elif link:
                            # If no version in RSS item, fetch the full post
                            post_version = self._get_opera_version_from_post(link)
                            if post_version:
                                found_version = post_version

            return found_version, relevant_urls

        except Exception as e:
            self.logger.error(
                "Error parsing Opera RSS feed", error=str(e), exc_info=True
            )
            return None, []

    def _get_opera_version_from_post(self, post_url: str) -> Optional[str]:
        """
        Fetch and parse individual Opera security post for version information.

        Args:
            post_url: URL of the security post

        Returns:
            Opera version string, or None if not found
        """
        try:
            self.logger.debug("Fetching Opera security post", url=post_url)

            response = requests.get(post_url, timeout=30)
            if response.status_code != 200:
                return None

            soup = BeautifulSoup(response.content, "html.parser")

            # Get main content
            content = soup.find("div", class_="content") or soup.find("article") or soup
            content_text = content.get_text() if content else ""

            return self._extract_opera_version_from_text(content_text)

        except Exception as e:
            self.logger.warning("Error fetching Opera post", url=post_url, error=str(e))
            return None

    def _extract_opera_version_from_text(self, text: str) -> Optional[str]:
        """
        Extract Opera version from text using various patterns.

        Args:
            text: Text to search for Opera version

        Returns:
            Opera version string, or None if not found
        """
        # Updated pattern to handle more Opera variant names and formats
        patterns = [
            # Format: Opera One (120.0.5543.93)
            r"Opera (?:One|GX|Air|Desktop|browser)?\s*\(([0-9]+(?:\.[0-9]+){3})\)",
            # Format: Opera v120.0.5543.93 or Opera 120.0.5543.93
            r"Opera (?:One|GX|Air|Desktop|browser)?\s*v?([0-9]+(?:\.[0-9]+){3})",
            # Format: Opera Desktop 120.0.5543.93
            r"Opera (?:One|GX|Air|Desktop|browser)\s+([0-9]+(?:\.[0-9]+){3})",
            # Format: 122.0.5643.24 – 2025-09-16 (version followed by dash and date)
            r"^([0-9]+(?:\.[0-9]+){3})\s*[–-]\s*\d{4}-\d{2}-\d{2}",
            # Format: Update to Opera v115.0.5322.68
            r"Update to Opera\s*v?([0-9]+(?:\.[0-9]+){3})",
        ]

        for pattern in patterns:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for version in matches:
                try:
                    # Validate version format
                    Version(version)
                    return version
                except Exception:
                    continue

        return None

    def _find_chromium_version_for_cves(self, cves: List[str]) -> Optional[str]:
        """
        Find Chromium version that fixes the given CVEs by querying Gentoo Bugzilla.

        This method searches for bugs with the given CVE aliases and extracts
        Chromium version information from bug titles/summaries.

        Args:
            cves: List of CVE identifiers

        Returns:
            Chromium version string, or None if not found
        """
        if not cves:
            return None

        self.logger.debug("Searching for Chromium version for CVEs", cves=cves)

        # Query Bugzilla for bugs with CVE aliases
        for cve in cves:
            try:
                # Use build_query to search for bugs with this CVE as alias
                query = self.bugzilla.bzapi.build_query(
                    product="Gentoo Security",
                    component="Vulnerabilities",
                    alias=cve,
                    include_fields=["id", "summary", "alias", "status"],
                )

                bugs = self.bugzilla.bzapi.query(query)
                if bugs:
                    bug = bugs[0]  # Take the first matching bug
                    chromium_version = self._extract_chromium_version_from_bug_summary(
                        bug.summary
                    )
                    if chromium_version:
                        self.logger.debug(
                            "Found Chromium version from bug",
                            cve=cve,
                            bug_id=bug.id,
                            summary=bug.summary,
                            chromium_version=chromium_version,
                        )
                        return chromium_version

            except Exception as e:
                self.logger.warning("Error querying bug for CVE", cve=cve, error=str(e))
                continue

        self.logger.debug("No Chromium version found for CVEs", cves=cves)
        return None

    def _load_opera_chromium_mapping(
        self,
    ) -> Dict[int, Dict[str, Optional[str]]]:
        """
        Load Opera to Chromium version mappings from YAML file.

        Returns:
            Dictionary mapping Opera major -> {Opera version -> Chromium version}
        """
        try:
            # Get the directory of this file
            mapping_file = (
                Path(__file__).resolve().parent.parent
                / "data"
                / "opera_chromium_mapping.yaml"
            )

            with open(mapping_file, "r") as f:
                data = yaml.safe_load(f)

                mapping = data.get("opera_chromium_mapping", {})
                if mapping:
                    self.logger.debug(
                        "Loaded Opera-Chromium mapping",
                        major_versions=len(mapping),
                    )

                return mapping

        except Exception as e:
            self.logger.debug("Could not load Opera-Chromium mapping", error=str(e))
            return {}

    @property
    def opera_chromium_mapping(self) -> Dict[int, Dict[str, Optional[str]]]:
        """
        Lazily load Opera-Chromium mapping. Returns empty dict if file doesn't exist.
        """
        if self._opera_chromium_mapping is None:
            self._opera_chromium_mapping = self._load_opera_chromium_mapping()
        return self._opera_chromium_mapping

    def _get_opera_major_from_chromium_major(
        self, chromium_major: int
    ) -> Optional[int]:
        """
        Find Opera major version that corresponds to a Chromium major version.

        Args:
            chromium_major: Chromium major version

        Returns:
            Opera major version, or None if not found
        """
        # Since we now have detailed mappings, we need to look through them
        for opera_major, version_mappings in self.opera_chromium_mapping.items():
            if isinstance(version_mappings, dict):
                # Look through the version mappings to find any that match the chromium major
                for opera_ver, chromium_ver in version_mappings.items():
                    if chromium_ver:
                        try:
                            chromium_version_obj = Version(chromium_ver)
                            if chromium_version_obj.major == chromium_major:
                                return opera_major
                        except Exception:
                            continue
        return None

    def _extract_chromium_version_from_bug_summary(self, summary: str) -> Optional[str]:
        """
        Extract Chromium version from a Bugzilla bug summary.

        Looks for patterns like:
        - "< www-client/chromium-129.0.6668.58"
        - "www-client/chromium-129.0.6668.58"

        Args:
            summary: Bug summary/title

        Returns:
            Chromium version string, or None if not found
        """
        import re

        # Pattern to match Chromium version constraints in bug titles
        # Look for patterns like "< www-client/chromium-X.Y.Z.W" or "www-client/chromium-X.Y.Z.W"
        chromium_pattern = re.compile(r"<?www-client/chromium-([0-9]+(?:\.[0-9]+){3})")

        match = chromium_pattern.search(summary)
        if match:
            return match.group(1)

        return None

    def _map_chromium_to_opera_version(self, chromium_version: str) -> Optional[str]:
        """
        Map Chromium version to Opera version using known YAML mappings.

        First tries global search across all major versions, then falls back to
        major version mapping with reasonable defaults.

        Args:
            chromium_version: Chromium version string

        Returns:
            Opera version string, or None if not found
        """
        try:
            chromium_ver = Version(chromium_version)
            chromium_major = chromium_ver.major

            # First try: Search globally for exact Chromium version match (handles duplicates correctly)
            global_match = self._find_global_opera_version_for_chromium_version(
                chromium_version
            )
            if global_match:
                self.logger.debug(
                    "Found Opera version from global search",
                    chromium_version=chromium_version,
                    opera_version=global_match,
                )
                return global_match

            # Second try: Use known mapping for major versions as fallback
            opera_major = self._get_opera_major_from_chromium_major(chromium_major)
            if opera_major:
                self.logger.debug(
                    "Found Opera major version from mapping",
                    chromium_version=chromium_version,
                    chromium_major=chromium_major,
                    opera_major=opera_major,
                )

                # Try to find the specific Opera version that includes this Chromium version
                opera_version = self._find_opera_version_for_chromium_version(
                    opera_major, chromium_version
                )
                if opera_version:
                    return opera_version

            # If we reach here, no mapping was found in YAML data
            self.logger.debug(
                "No Opera version mapping found for Chromium version",
                chromium_version=chromium_version,
                chromium_major=chromium_major,
                message="Consider updating the YAML mapping file if this is a newer Chromium version",
            )

        except Exception as e:
            self.logger.warning(
                "Error mapping Chromium to Opera version",
                chromium_version=chromium_version,
                error=str(e),
            )

        return None

    def _find_opera_version_for_chromium_version(
        self, opera_major: int, chromium_version: str
    ) -> Optional[str]:
        """
        Find the specific Opera version within a major release that includes the given Chromium version.

        For security purposes, this finds the FIRST Opera version that contains the security fix,
        which is the earliest Opera version with Chromium >= target version.

        Uses YAML mapping data with fallback logic:
        1. Look for exact Chromium version match in the same Opera major version
        2. If no exact match, find the earliest Opera version with Chromium >= chromium_version
        3. If no match in same major version, try adjacent major versions (±1)
        4. Warn if major version data is missing, do not fall back.

        Args:
            opera_major: Opera major version to search within
            chromium_version: Target Chromium version (contains security fixes)

        Returns:
            Opera version string (first version with the fix), or None if not found
        """
        try:
            mappings = self._load_opera_chromium_mapping()

            # Check if we have data for this major version
            if opera_major not in mappings:
                self.logger.warning(
                    "No mapping data available for Opera major version",
                    opera_major=opera_major,
                )
                return None  # Do not fall back if major version data is missing

            # Use YAML data for this major version
            mapping = mappings[opera_major]
            result = self._find_chromium_match_in_mapping(mapping, chromium_version)

            if result:
                self.logger.debug(
                    "Found Opera version from YAML mapping",
                    opera_major=opera_major,
                    chromium_version=chromium_version,
                    opera_version=result,
                )
                return result

            # No match in current major version, try adjacent major versions
            for adjacent_major in [opera_major - 1, opera_major + 1]:
                if (
                    adjacent_major in mappings and adjacent_major >= 110
                ):  # Don't go too far back
                    self.logger.debug(
                        "No match in current major version, trying adjacent major",
                        current_major=opera_major,
                        adjacent_major=adjacent_major,
                    )

                    adjacent_mapping = mappings[adjacent_major]
                    adjacent_result = self._find_chromium_match_in_mapping(
                        adjacent_mapping, chromium_version
                    )

                    if adjacent_result:
                        self.logger.debug(
                            "Using fallback from adjacent major version",
                            opera_major=opera_major,
                            chromium_version=chromium_version,
                            fallback_opera_version=adjacent_result,
                            fallback_major=adjacent_major,
                        )
                        return adjacent_result

            self.logger.debug(
                "No suitable Opera version found for Chromium version",
                opera_major=opera_major,
                chromium_version=chromium_version,
            )
            return None

        except Exception as e:
            self.logger.debug(
                "Error finding specific Opera version",
                opera_major=opera_major,
                chromium_version=chromium_version,
                error=str(e),
            )
            return None

    def _find_chromium_match_in_mapping(
        self, mapping: Dict[str, Optional[str]], target_chromium_version: str
    ) -> Optional[str]:
        """
        Find Opera version that maps to the target Chromium version, with fallback logic.

        Logic:
        1. Look for exact Chromium version matches
        2. If multiple Opera versions have the same Chromium version, return the earliest (lowest) Opera version
        3. If no exact match, find the lowest Opera version that has a Chromium mapping >= target

        Args:
            mapping: Dict of Opera version -> Chromium version (or None)
            target_chromium_version: Target Chromium version to find

        Returns:
            Opera version string or None
        """
        try:
            target_ver = Version(target_chromium_version)

            # First pass: Look for exact match - collect all matches and return the earliest
            exact_matches = []
            for opera_ver, chromium_ver in mapping.items():
                if chromium_ver and chromium_ver == target_chromium_version:
                    exact_matches.append(opera_ver)

            if exact_matches:
                # Return the earliest (lowest) Opera version that has this Chromium version
                earliest_match = min(exact_matches, key=lambda x: Version(x))
                self.logger.debug(
                    "Found exact Chromium match, returning earliest Opera version",
                    target_chromium=target_chromium_version,
                    all_matches=exact_matches,
                    earliest_match=earliest_match,
                )
                return earliest_match

            # Second pass: Find the lowest Opera version that has a Chromium mapping >= target
            # Sort Opera versions in ascending order (filter out invalid versions)
            valid_opera_versions = []
            for opera_ver in mapping.keys():
                try:
                    Version(opera_ver)  # Validate version format
                    valid_opera_versions.append(opera_ver)
                except Exception:
                    continue  # Skip invalid versions

            sorted_opera_versions = sorted(
                valid_opera_versions, key=lambda x: Version(x)
            )

            for opera_ver in sorted_opera_versions:
                chromium_ver = mapping[opera_ver]
                if chromium_ver:
                    try:
                        chromium_version_obj = Version(chromium_ver)
                        # Use this mapping if the Chromium version is >= target
                        if chromium_version_obj >= target_ver:
                            self.logger.debug(
                                "Using fallback mapping within same major version",
                                target_chromium=target_chromium_version,
                                found_opera=opera_ver,
                                found_chromium=chromium_ver,
                            )
                            return opera_ver
                    except Exception:
                        continue

            return None

        except Exception as e:
            self.logger.debug(
                "Error in chromium match finding",
                target_version=target_chromium_version,
                error=str(e),
            )
            return None

    def _get_highest_chromium_mapping_in_major(
        self, mapping: Dict[str, Optional[str]]
    ) -> Optional[Tuple[str, str]]:
        """
        Get the highest valid Chromium mapping from a major version.

        Args:
            mapping: Dict of Opera version -> Chromium version (or None)

        Returns:
            Tuple of (opera_version, chromium_version) or None
        """
        highest_chromium_ver = None
        highest_opera_ver = None

        for opera_ver, chromium_ver in mapping.items():
            if chromium_ver:
                try:
                    chromium_version_obj = Version(chromium_ver)
                    if (
                        highest_chromium_ver is None
                        or chromium_version_obj > highest_chromium_ver
                    ):
                        highest_chromium_ver = chromium_version_obj
                        highest_opera_ver = opera_ver
                except Exception:
                    continue

        if highest_opera_ver and highest_chromium_ver:
            return (highest_opera_ver, str(highest_chromium_ver))
        return None

    def _get_opera_chromium_mapping(
        self, opera_major_version: int
    ) -> Dict[str, Optional[str]]:
        """
        Get Opera to Chromium version mapping for a specific Opera major version.

        This implements the same logic as get-opera-version-mapping.py.

        Args:
            opera_major_version: Opera major version (e.g., 115)

        Returns:
            Dictionary mapping Opera version -> Chromium version
        """
        base_url = (
            f"https://blogs.opera.com/desktop/changelog-for-{opera_major_version}/"
        )
        mapping = {}

        try:
            response = requests.get(base_url, timeout=10)
            if response.status_code != 200:
                return mapping

            soup = BeautifulSoup(response.content, "html.parser")
            content = soup.find("div", class_="content")
            if not content or not isinstance(content, Tag):
                self.logger.debug(
                    "No content div found in Opera changelog",
                    opera_version=opera_major_version,
                )
                return mapping

            # Process each version section (H4 elements)
            h4_sections = content.find_all("h4")
            for section in h4_sections:
                try:
                    # Extract Opera version from section header
                    header_text = section.text.strip()
                    self.logger.debug("Processing header", header_text=header_text)

                    # Handle different header formats with various dash types
                    version_str = None
                    if " – " in header_text:
                        version_str = header_text.split(" – ")[0].strip()
                    elif " - " in header_text:
                        version_str = header_text.split(" - ")[0].strip()
                    else:
                        # Try to extract version from the beginning of the text
                        version_match = re.match(r"^(\d+(?:\.\d+){2,3})", header_text)
                        if version_match:
                            version_str = version_match.group(1)

                    if not version_str:
                        continue

                    # Validate it's a proper version
                    try:
                        Version(version_str)
                    except Exception:
                        self.logger.debug(
                            "Invalid version format", version_str=version_str
                        )
                        continue

                    # Look for "Update Chromium" in following content
                    chromium_version = None
                    next_sibling = section.find_next_sibling(
                        lambda tag: tag.name is not None
                    )

                    while next_sibling and next_sibling.name != "h4":
                        if next_sibling.name == "ul":
                            for li in next_sibling.find_all("li"):
                                li_text = li.text.strip()

                                # Look for various Chromium update patterns
                                if any(
                                    phrase in li_text
                                    for phrase in [
                                        "Update Chromium",
                                        "Updated Chromium",
                                        "Chromium update",
                                        "update Chromium",
                                        "Chromium to",
                                        "Chromium version",
                                    ]
                                ):
                                    # Extract version using regex
                                    version_patterns = [
                                        r"Chromium.*?(\d+(?:\.\d+){3})",  # General Chromium X.Y.Z.W
                                        r"to\s+(\d+(?:\.\d+){3})",  # "to X.Y.Z.W"
                                        r"version\s+(\d+(?:\.\d+){3})",  # "version X.Y.Z.W"
                                        r"(\d+(?:\.\d+){3})",  # Any X.Y.Z.W pattern
                                    ]

                                    for pattern in version_patterns:
                                        matches = re.findall(pattern, li_text)
                                        for potential_version in matches:
                                            try:
                                                Version(potential_version)
                                                chromium_version = potential_version
                                                self.logger.debug(
                                                    "Found Chromium version",
                                                    opera_version=version_str,
                                                    chromium_version=chromium_version,
                                                    source_text=li_text[:100],
                                                )
                                                break
                                            except Exception:
                                                continue
                                        if chromium_version:
                                            break

                                    if chromium_version:
                                        break

                        if chromium_version:
                            break

                        next_sibling = next_sibling.find_next_sibling(
                            lambda tag: tag.name is not None
                        )

                    # Handle case where there might be empty h4 elements between version and content
                    # Look ahead through siblings until we find a meaningful h4 or content
                    if not chromium_version:
                        # Search all siblings until the next meaningful h4
                        current = section.find_next_sibling()
                        while current:
                            if current.name == "h4":
                                # Check if this h4 has meaningful content (version number)
                                h4_text = current.get_text().strip()
                                if h4_text and re.match(
                                    r".*\d+(?:\.\d+){2,3}", h4_text
                                ):
                                    # This is a new version section, stop looking
                                    break
                                # Otherwise it's likely an empty h4, continue
                            elif current.name == "ul":
                                for li in current.find_all("li"):
                                    li_text = li.text.strip()

                                    if any(
                                        phrase in li_text
                                        for phrase in [
                                            "Update Chromium",
                                            "Updated Chromium",
                                            "Chromium update",
                                            "update Chromium",
                                            "Chromium to",
                                            "Chromium version",
                                        ]
                                    ):
                                        # Extract version using regex
                                        version_patterns = [
                                            r"Chromium.*?(\d+(?:\.\d+){3})",
                                            r"to\s+(\d+(?:\.\d+){3})",
                                            r"version\s+(\d+(?:\.\d+){3})",
                                            r"(\d+(?:\.\d+){3})",
                                        ]

                                        for pattern in version_patterns:
                                            matches = re.findall(pattern, li_text)
                                            for potential_version in matches:
                                                try:
                                                    Version(potential_version)
                                                    chromium_version = potential_version
                                                    self.logger.debug(
                                                        "Found Chromium version in extended search",
                                                        opera_version=version_str,
                                                        chromium_version=chromium_version,
                                                        source_text=li_text[:100],
                                                    )
                                                    break
                                                except Exception:
                                                    continue
                                            if chromium_version:
                                                break

                                        if chromium_version:
                                            break

                                if chromium_version:
                                    break

                            if chromium_version:
                                break

                            current = current.find_next_sibling()

                    mapping[version_str] = chromium_version

                except Exception as e:
                    self.logger.debug(
                        "Error parsing Opera version section", error=str(e)
                    )
                    continue

        except Exception as e:
            self.logger.warning(
                "Error fetching Opera changelog",
                opera_version=opera_major_version,
                error=str(e),
            )

        return mapping

    def _has_version_constraints(self, title: str) -> bool:
        """Delegate to VersionUtils and only look for Opera package constraints."""
        packages = ["www-client/opera"]
        return self.version_utils.has_version_constraints(title, packages=packages)

    def _add_opera_constraint_to_title(self, title: str, opera_version: str) -> str:
        """
        Add Opera version constraint to bug title.

        Args:
            title: Original bug title
            opera_version: Opera version to add as constraint

        Returns:
            Updated title with version constraint
        """
        # Replace "www-client/opera" with "<www-client/opera-VERSION"
        pattern = r"\bwww-client/opera\b"
        replacement = f"<www-client/opera-{opera_version}"

        new_title = re.sub(pattern, replacement, title)

        # If no replacement was made, the title might not mention opera directly
        # In that case, just return the original title
        return new_title

    def generate_version_mapping(
        self,
        version: Optional[int] = None,
        min_version: Optional[int] = None,
        max_version: Optional[int] = None,
        force: bool = False,
    ) -> Dict[int, Dict[str, Optional[str]]]:
        """
        Generate Opera to Chromium version mappings by scraping changelogs.

        Args:
            version: Specific Opera major version to generate mapping for
            min_version: Minimum Opera major version (inclusive)
            max_version: Maximum Opera major version (inclusive)
            force: Force regeneration even if mapping file exists

        Returns:
            Dictionary mapping Opera major -> {Opera version -> Chromium version}
        """
        # Determine version range
        if version:
            versions_to_process = [version]
        else:
            start = min_version or 114
            end = max_version or 124
            versions_to_process = list(range(start, end + 1))

        self.logger.info(
            "Generating Opera-Chromium mappings",
            versions=versions_to_process,
            force=force,
        )

        all_mappings = {}

        for opera_major in versions_to_process:
            self.logger.info("Processing Opera major version", version=opera_major)

            try:
                mapping = self._get_opera_chromium_mapping(opera_major)
                if mapping:
                    all_mappings[opera_major] = mapping
                    self.logger.info(
                        "Generated mapping",
                        opera_major=opera_major,
                        total_versions=len(mapping),
                        versions_with_chromium=len([v for v in mapping.values() if v]),
                    )
                else:
                    self.logger.warning(
                        "No mapping found for Opera major version", version=opera_major
                    )

            except Exception as e:
                self.logger.error(
                    "Error generating mapping for Opera major version",
                    version=opera_major,
                    error=str(e),
                    exc_info=True,
                )

        return all_mappings

    def update_mapping_file(
        self,
        mappings: Dict[int, Dict[str, Optional[str]]],
        output_file: Optional[str] = None,
    ) -> str:
        """
        Update the Opera-Chromium mapping YAML file.

        Args:
            mappings: Mapping data to save
            output_file: Optional custom output file path

        Returns:
            Path to the updated file
        """
        if output_file:
            mapping_file = Path(output_file)
        else:
            # Get the default location
            current_dir = Path(__file__).resolve().parent
            mapping_file = current_dir / ".." / "data" / "opera_chromium_mapping.yaml"

        # Load existing data if it exists
        existing_data = {}
        try:
            if mapping_file.exists():
                with open(mapping_file, "r") as f:
                    existing_data = yaml.safe_load(f) or {}
        except Exception as e:
            self.logger.warning("Could not load existing mapping file", error=str(e))

        # Update with new mappings
        detailed_mapping = existing_data.get("opera_chromium_mapping", {})

        # Convert string keys to integers for consistency
        for major_version, version_mappings in mappings.items():
            detailed_mapping[major_version] = version_mappings

        # Create the export data structure
        export_data = {
            "opera_chromium_mapping": detailed_mapping,
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "chromicler opera mapping update",
                "source": "Opera official changelog scraping",
                "last_updated_versions": list(mappings.keys()),
            },
        }

        # Write the file
        Path(mapping_file).parent.mkdir(parents=True, exist_ok=True)
        with open(mapping_file, "w") as f:
            yaml.dump(export_data, f, default_flow_style=False, sort_keys=False)

        self.logger.info(
            "Updated mapping file",
            file=str(mapping_file),
            updated_versions=list(mappings.keys()),
        )

        return str(mapping_file)

    def _find_global_opera_version_for_chromium_version(
        self, chromium_version: str
    ) -> Optional[str]:
        """
        Find the earliest Opera version across all major versions that maps to the given Chromium version.

        When a Chromium version appears in multiple Opera versions (duplicates), this function
        returns the earliest (lowest) Opera version, as that's when the Chromium version was
        first introduced in Opera.

        Args:
            chromium_version: Target Chromium version to find

        Returns:
            Earliest Opera version string that maps to the Chromium version, or None if not found
        """
        try:
            mapping = self.opera_chromium_mapping
            earliest_opera_version = None

            # Search through all major versions and their version mappings
            for opera_major in sorted(mapping.keys()):
                version_mappings = mapping[opera_major]
                if not isinstance(version_mappings, dict):
                    continue

                # Search within this major version for the Chromium version
                for opera_ver, chromium_ver in version_mappings.items():
                    if chromium_ver == chromium_version:
                        # Found a match, check if it's the earliest so far
                        if earliest_opera_version is None:
                            earliest_opera_version = opera_ver
                        else:
                            try:
                                # Compare versions to find the earliest
                                if Version(opera_ver) < Version(earliest_opera_version):
                                    earliest_opera_version = opera_ver
                            except Exception:
                                # If version comparison fails, keep the first found
                                continue

            if earliest_opera_version:
                self.logger.debug(
                    "Found earliest Opera version for Chromium version",
                    chromium_version=chromium_version,
                    earliest_opera_version=earliest_opera_version,
                )

            return earliest_opera_version

        except Exception as e:
            self.logger.debug(
                "Error in global Opera version search",
                chromium_version=chromium_version,
                error=str(e),
            )
            return None

    def _get_rss_cache_file_path(self) -> str:
        """Get cache file path for RSS feed."""
        return str(self.cache_dir / "opera_security_rss.json")

    def _is_rss_cache_valid(self, cache_file: str, max_age_hours: int = 3) -> bool:
        """Check if RSS cache file exists and is within the specified age."""
        cache_path = Path(cache_file)
        if not cache_path.exists():
            return False

        file_age = time.time() - cache_path.stat().st_mtime
        max_age_seconds = max_age_hours * 3600
        return file_age < max_age_seconds

    def _load_rss_from_cache(self, cache_file: str) -> Optional[str]:
        """Load RSS content from cache file."""
        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            self.logger.debug("Loaded RSS content from cache", cache_file=cache_file)
            return data.get("content")
        except Exception as e:
            self.logger.warning(
                "Failed to load RSS cache file", cache_file=cache_file, error=str(e)
            )
            return None

    def _save_rss_to_cache(self, cache_file: str, content: str) -> None:
        """Save RSS content to cache file."""
        try:
            cache_data = {
                "content": content,
                "cached_at": time.time(),
                "url": self.rss_url,
            }
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(cache_data, f, indent=2)
            self.logger.debug("Saved RSS content to cache", cache_file=cache_file)
        except Exception as e:
            self.logger.warning(
                "Failed to save RSS cache file", cache_file=cache_file, error=str(e)
            )

    def bump_opera(
        self,
        channels: List[str],
        repo_path: str,
        dry_run: bool = False,
    ) -> Dict[str, int]:
        """
        Bump Opera packages to latest versions.

        This implements the opera-bump logic for automated version bumping.

        Args:
            channels: List of channels to bump ("stable", "beta", "developer")
            repo_path: Path to Gentoo repository
            dry_run: If True, don't make actual changes

        Returns:
            Dict with counts of bumped, skipped, and error packages
        """
        from portage.dbapi.porttree import portdbapi
        from portage.versions import pkgsplit

        self.logger.info("Starting Opera version bump", channels=channels)

        # Package configuration
        pkg_data = {
            "stable": {
                "pkg": "opera",
                "suffix": "stable",
                "version": [],
                "dversion": [],
                "bversion": [],
                "stable": True,
                "count": 1,
            },
            "beta": {
                "pkg": "opera-beta",
                "suffix": None,
                "version": [],
                "dversion": [],
                "bversion": [],
                "stable": False,
                "count": 3,
            },
            "developer": {
                "pkg": "opera-developer",
                "suffix": None,
                "version": [],
                "dversion": [],
                "bversion": [],
                "stable": False,
                "count": 3,
            },
        }

        # Initialize portage
        db = portdbapi()

        # Look up current versions in tree
        self.logger.info("Looking up Opera version information in tree...")
        for channel in pkg_data.keys():
            pkg = pkg_data[channel]["pkg"]
            cpvs = db.cp_list(mycp=f"www-client/{pkg}", mytree=repo_path)
            for cpv in cpvs:
                cp, version, rev = pkgsplit(mypkg=cpv)
                pkg_data[channel]["version"].append((version, rev))

            if len(pkg_data[channel]["version"]) == 0:
                self.logger.warning(
                    f"Couldn't determine tree versions for www-client/{pkg}"
                )

            # Sort versions (newest first)
            pkg_data[channel]["version"].sort(
                key=functools.cmp_to_key(self._compare_version_tuples)
            )

        # Fetch upstream version information
        opera_info = {}
        for channel in pkg_data.keys():
            archive = pkg_data[channel]["pkg"]
            platform = None
            if pkg_data[channel]["suffix"] is not None:
                archive += "-" + pkg_data[channel]["suffix"]
                platform = "desktop"

            self.logger.info(
                "Fetching upstream version information",
                archive=archive,
                channel=channel,
            )
            versions = self._get_opera_versions_for_channel(
                package=pkg_data[channel]["pkg"],
                archive=archive,
                platform=platform,
                tree_versions=pkg_data[channel]["version"],
            )
            versions.sort(key=functools.cmp_to_key(self._compare_version_tuples))
            opera_info[channel] = versions

        # Compare versions
        self.logger.info("Comparing Opera version information")

        # Check which versions have been dropped upstream
        for channel in pkg_data.keys():
            versions_list = [v[0] for v in opera_info[channel]]
            for ver in pkg_data[channel]["version"]:
                if ver[0] not in versions_list:
                    self.logger.warning(
                        f"Upstream dropped version {ver[0]} from channel {channel} of www-client/{pkg_data[channel]['pkg']}"
                    )
                    pkg_data[channel]["dversion"].append(ver)

        # Determine which new versions to bump
        for channel in pkg_data.keys():
            if len(opera_info[channel]) == 0:
                self.logger.warning(f"Upstream version unknown for channel {channel}")
            else:
                for uver in opera_info[channel]:
                    bump = None
                    for tver in pkg_data[channel]["version"]:
                        ver_info = self.version_utils.compare_versions(
                            uver[0], self._get_ebuild_version(tver)
                        )
                        if ver_info is None:
                            self.logger.warning(
                                f"Cannot determine new version for channel {channel} of www-client/{pkg_data[channel]['pkg']}"
                            )
                            bump = False
                            break
                        elif ver_info > 0:
                            if bump is None:
                                bump = True
                        elif ver_info == 0:
                            bump = False
                        elif ver_info < 0:
                            bump = False

                    if bump:
                        pkg_data[channel]["bversion"].append((uver[0], "r0"))

                # Handle version count limits and cleanup
                if len(pkg_data[channel]["bversion"]) == 0 and len(
                    pkg_data[channel]["dversion"]
                ) == len(pkg_data[channel]["version"]):
                    self.logger.warning(
                        f"Update would remove all versions from tree for channel {channel} of www-client/{pkg_data[channel]['pkg']}"
                    )
                    pkg_data[channel]["dversion"] = []
                elif len(pkg_data[channel]["bversion"]) >= pkg_data[channel]["count"]:
                    # Limit new versions to max count
                    count = pkg_data[channel]["count"]
                    pkg_data[channel]["bversion"] = limit_new_versions(
                        pkg_data[channel]["bversion"], count
                    )
                    # Remove all old versions since we're adding enough new ones
                    pkg_data[channel]["dversion"] = pkg_data[channel]["version"]
                elif (
                    len(pkg_data[channel]["bversion"])
                    + len(pkg_data[channel]["version"])
                    > pkg_data[channel]["count"]
                ):
                    # Calculate which versions to remove
                    pkg_data[channel]["dversion"] = calculate_versions_to_remove(
                        pkg_data[channel]["version"],
                        pkg_data[channel]["bversion"],
                        pkg_data[channel]["count"],
                    )

        # Display version information
        for channel in pkg_data.keys():
            pkg = pkg_data[channel]["pkg"]

            # Separate versions into kept vs to-be-removed
            kept_versions = []
            removed_versions = []
            for ver in reversed(pkg_data[channel]["version"]):
                ver_str = self._get_ebuild_version(ver)
                if ver in pkg_data[channel]["dversion"]:
                    removed_versions.append(ver_str)
                else:
                    kept_versions.append(ver_str)

            # Build new versions list
            new_versions = [
                self._get_ebuild_version(ver) for ver in pkg_data[channel]["bversion"]
            ]

            # Determine action
            if len(pkg_data[channel]["bversion"]) > 0:
                action = "bump"
            elif len(pkg_data[channel]["dversion"]) > 0:
                action = "cleanup"
            else:
                action = "unchanged"

            # Build log kwargs
            log_data = {
                "channel": channel,
                "action": action,
            }

            if kept_versions:
                log_data["kept_versions"] = " ".join(kept_versions)
            if removed_versions:
                log_data["removed_versions"] = " ".join(removed_versions)
            if new_versions:
                log_data["new_versions"] = " ".join(new_versions)

            self.logger.info(
                f"www-client/{pkg} version information",
                **log_data,
            )

        # Initialize EbuildManager
        ebuild_mgr = EbuildManager(
            repo_path=repo_path, logger=self.logger, dry_run=dry_run
        )

        # Perform bumps
        result = {"bumped": 0, "skipped": 0, "errors": 0}

        for channel in channels:
            pkg = pkg_data[channel]["pkg"]
            tver = (
                pkg_data[channel]["version"][0]
                if pkg_data[channel]["version"]
                else None
            )
            tversion = self._get_ebuild_version(tver) if tver else None

            # Bump new versions
            for uver in pkg_data[channel]["bversion"]:
                uversion = self._get_ebuild_version(uver)
                major_bump = is_major_bump(
                    tver[0] if tver else "0",
                    uver[0],
                    channel,
                    self._get_prev_channel,
                )

                try:
                    self._bump_opera_package(
                        channel=channel,
                        pkg=pkg,
                        uversion=uversion,
                        tversion=tversion,
                        major_bump=major_bump,
                        pkg_data=pkg_data,
                        ebuild_mgr=ebuild_mgr,
                        repo_path=repo_path,
                        dry_run=dry_run,
                    )
                    result["bumped"] += 1
                except Exception as e:
                    self.logger.error(
                        "Failed to bump package",
                        channel=channel,
                        error=str(e),
                    )
                    result["errors"] += 1

            # Remove old versions
            if len(pkg_data[channel]["dversion"]) > 0:
                try:
                    self._remove_old_opera_versions(
                        channel=channel,
                        pkg=pkg,
                        versions_to_remove=pkg_data[channel]["dversion"],
                        ebuild_mgr=ebuild_mgr,
                        repo_path=repo_path,
                        dry_run=dry_run,
                    )
                except Exception as e:
                    self.logger.error(
                        "Failed to remove old versions",
                        channel=channel,
                        error=str(e),
                    )
                    result["errors"] += 1

        return result

    def _get_opera_versions_for_channel(
        self,
        package: str,
        archive: str,
        platform: Optional[str],
        tree_versions: List[Tuple[str, str]],
    ) -> List[Tuple[str, str]]:
        """
        Fetch Opera version data from Opera's download server.

        Args:
            package: Package name (opera, opera-beta, opera-developer)
            archive: Archive name (e.g., opera-stable)
            platform: Platform subdirectory (e.g., "desktop") or None
            tree_versions: Current versions in tree to check against

        Returns:
            List of (version, revision) tuples
        """
        base_url = "https://download1.operacdn.com/pub"
        url = f"{base_url}/{package}"
        if platform:
            url += f"/{platform}"

        req = urllib.request.urlopen(url)
        soup = BeautifulSoup(req, "html.parser")
        versions = []

        for node in soup.find_all("a"):
            v = node.get("href")
            if v.endswith("/"):
                v = v[:-1]
            if v != "..":
                # Check if this version is newer than or equal to what's in tree
                check = False
                for tver in tree_versions:
                    c = self.version_utils.compare_versions(v, tver[0])
                    if c is not None and c >= 0:
                        check = True
                        break

                if check:
                    # Check if this version has downloadable files
                    ver_info = self._get_opera_version_info(
                        base_url=url, archive=archive, arch="amd64", version=v
                    )
                    if ver_info is not None:
                        versions.append(ver_info)

        return versions

    def _get_opera_version_info(
        self, base_url: str, archive: str, arch: str, version: str
    ) -> Optional[Tuple[str, str]]:
        """
        Check if a specific Opera version has downloadable files.

        Args:
            base_url: Base URL for the package
            archive: Archive name
            arch: Architecture (amd64)
            version: Version to check

        Returns:
            (version, "0") tuple if files exist, None otherwise
        """
        if not base_url.endswith("/"):
            url = base_url + "/"
        url += f"{version}/linux"

        try:
            req = urllib.request.urlopen(url)
        except urllib.error.HTTPError:
            return None

        soup = BeautifulSoup(req, "html.parser")
        base_fn = f"{archive}_{version}_{arch}."
        rpm = False

        for node in soup.find_all("a"):
            v = node.get("href")
            if v.startswith(base_fn):
                if v.endswith("rpm"):
                    rpm = True
                elif v.endswith("deb"):
                    return (version, "0")

        if rpm:
            return (version, "0")

        return None

    def _get_prev_channel(self, channel: str) -> str:
        """Get the previous channel for cross-channel copying during major bumps."""
        return get_prev_channel_generic(channel, ["stable", "beta", "developer"])

    def _bump_opera_package(
        self,
        channel: str,
        pkg: str,
        uversion: str,
        tversion: Optional[str],
        major_bump: bool,
        pkg_data: Dict,
        ebuild_mgr: EbuildManager,
        repo_path: str,
        dry_run: bool,
    ):
        """Bump a single Opera package using shared browser bump logic."""
        atom = f"www-client/{pkg}"

        bump_browser_package(
            atom=atom,
            channel=channel,
            uversion=uversion,
            tversion=tversion,
            major_bump=major_bump,
            pkg_data=pkg_data,
            ebuild_mgr=ebuild_mgr,
            repo_path=repo_path,
            dry_run=dry_run,
            logger=self.logger,
            get_ebuild_version_func=self._get_ebuild_version,
            get_prev_channel_func=self._get_prev_channel,
            enable_stabilization=True,
        )

    def _remove_old_opera_versions(
        self,
        channel: str,
        pkg: str,
        versions_to_remove: List[Tuple[str, str]],
        ebuild_mgr: EbuildManager,
        repo_path: str,
        dry_run: bool,
    ):
        """Remove old Opera versions."""
        for dver in versions_to_remove:
            dversion = self._get_ebuild_version(dver)

            rm_ebuild = (
                Path(repo_path) / "www-client" / pkg / f"{pkg}-{dversion}.ebuild"
            )

            if dry_run:
                self.logger.info(
                    "DRY RUN - Would remove ebuild",
                    atom=f"www-client/{pkg}",
                    version=dversion,
                    file=str(rm_ebuild),
                )
            else:
                try:
                    ebuild_mgr.repo.index.remove([str(rm_ebuild)], working_tree=True)
                    self.logger.info(
                        "Removed ebuild",
                        atom=f"www-client/{pkg}",
                        version=dversion,
                        file=str(rm_ebuild),
                    )
                except Exception as e:
                    self.logger.error(
                        "Failed to remove ebuild",
                        atom=f"www-client/{pkg}",
                        version=dversion,
                        file=str(rm_ebuild),
                        error=str(e),
                    )
                    raise

        # Regenerate manifest and commit if we removed any versions
        if len(versions_to_remove) > 0 and not dry_run:
            try:
                from portage.package.ebuild import digestgen, config

                pkg_dir = Path(repo_path) / "www-client" / pkg
                cfg = config.config()
                cfg["O"] = str(pkg_dir)
                from portage.dbapi.porttree import portdbapi

                db = portdbapi()
                digestgen.digestgen(None, cfg, db)

                manifest_path = pkg_dir / "Manifest"
                ebuild_mgr.repo.index.add([str(manifest_path)])

                ebuild_mgr.repo.git.commit(
                    "-m", f"www-client/{pkg}: remove old", "-s", "-S"
                )
                self.logger.info(
                    "Committed removal of old versions",
                    atom=f"www-client/{pkg}",
                )
            except Exception as e:
                self.logger.error(
                    "Failed to commit removal",
                    atom=f"www-client/{pkg}",
                    error=str(e),
                )
                raise
