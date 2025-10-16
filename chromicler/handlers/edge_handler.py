#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Edge Handler - Manages Microsoft Edge security workflow
"""

import calendar
import functools
import json
import os
from contextlib import closing
from pathlib import Path
import time
from typing import Dict, List, Optional, Tuple
import urllib.request
import xml.etree.ElementTree as ET

from debian import deb822
import requests
import structlog
import typer

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


class EdgeHandler:
    """Handler for Microsoft Edge security updates from MSRC."""

    def __init__(
        self,
        api_key_file: str,
        logger: structlog.BoundLogger,
        version_utils: VersionUtils,
    ):
        self.api_key_file = api_key_file
        self.logger = logger
        self.version_utils = version_utils
        self._bugzilla = None  # Lazy-loaded

        # Set up cache directory
        self.cache_dir = Path.home() / ".cache" / "chromium-security-manager"
        self.cache_dir.mkdir(parents=True, exist_ok=True)

        # Create CLI app for this handler
        self.cli = typer.Typer(
            name="edge",
            help="Microsoft Edge security workflow",
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

        @self.cli.command()
        def query(
            month: Optional[int] = typer.Option(
                None, "--month", "-m", help="Month as a number (1-12)"
            ),
            year: Optional[int] = typer.Option(
                None, "--year", "-y", help="Year as a four-digit number"
            ),
            bug: Optional[List[int]] = typer.Option(
                None, "--bug", "-b", help="Bug identifiers"
            ),
            cve: Optional[List[str]] = typer.Option(
                None, "--cve", "-c", help="CVE identifiers"
            ),
            dry_run: bool = DryRunOption(),
            debug: bool = DebugOption(),
        ):
            """Query Edge CVE version mappings"""
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

                # Convert month number to month name if provided
                month_name = None
                if month:
                    month_name = calendar.month_name[month][:3]

                edge_cves = handler.query_edge_cves(
                    year=year,
                    month=month_name,
                    bugs=bug if bug else None,
                    cves=cve if cve else None,
                )

                # Display results
                if edge_cves:
                    handler.logger.bind(edge_cves=edge_cves).info(
                        "Found Edge CVE entries", count=len(edge_cves)
                    )
                else:
                    handler.logger.info(
                        "No Edge CVE data found for the specified criteria"
                    )

                result = {"action": "query", "count": len(edge_cves), "data": edge_cves}
                handler.logger.info("Workflow completed successfully", **result)

            except KeyboardInterrupt:
                typer.echo("\nOperation cancelled by user")
                raise typer.Exit(0)
            except Exception as e:
                typer.echo(f"Error: {e}")
                if debug or AppConfig.debug:
                    import traceback

                    traceback.print_exc()
                raise typer.Exit(1)

        @self.cli.command()
        def update(
            bug: Optional[List[int]] = typer.Option(
                None,
                "--bug",
                "-b",
                help="Specific bug identifiers to update (for debugging/testing)",
            ),
            dry_run: bool = DryRunOption(),
            debug: bool = DebugOption(),
        ):
            """Update existing bugs with Edge version constraints"""
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

                result = handler.update_edge_versions(
                    bugs=bug if bug else None, dry_run=dry_run or AppConfig.dry_run
                )

                handler.logger.info(
                    "Update completed",
                    updated=result["updated"],
                    skipped=result["skipped"],
                    errors=result["errors"],
                )
                handler.logger.info("Workflow completed successfully", **result)

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
                help="Specific channels to bump (stable, beta, dev). If not specified, checks all channels.",
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
            """Check for Edge updates and bump ebuilds if needed"""
            try:
                # Update AppConfig and handler state if local options were explicitly set
                if dry_run:
                    AppConfig.dry_run = dry_run
                if debug:
                    AppConfig.debug = debug

                # Show dry run banner if enabled
                if dry_run or AppConfig.dry_run:
                    handler.logger.info(
                        "Dry run mode enabled - no changes will be made"
                    )

                # Default to all channels if none specified
                if not channels:
                    channels = ["stable", "beta", "dev"]

                result = handler.bump_edge(
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
        return "Microsoft"

    def register_browsers(self, registry):
        """Register the browsers that this handler impacts."""
        registry.register_browser("edge", "www-client/microsoft-edge")

    def _is_testing(self) -> bool:
        """
        Check if code is running in a testing environment.

        Returns:
            True if running under pytest, False otherwise
        """
        return os.environ.get("PYTEST_CURRENT_TEST") is not None

    def _get_msrc_data_for_cve(self, cve_id: str) -> Optional[str]:
        """
        Get Microsoft Security Response Center (MSRC) data for a CVE.

        This method queries the MSRC API to get the CVRF document ID
        that contains information about the given CVE.

        Args:
            cve_id: CVE identifier (e.g., "CVE-2024-1234")

        Returns:
            MSRC document ID (e.g., "2024-Aug"), or None if not found
        """
        try:
            self.logger.debug("Fetching MSRC data for CVE", cve=cve_id)

            # MSRC API endpoint to get CVRF documents for a specific CVE
            msrc_url = f"https://api.msrc.microsoft.com/cvrf/v3.0/updates/{cve_id}"

            response = requests.get(msrc_url, timeout=30)
            if response.status_code != 200:
                self.logger.debug(
                    "No MSRC data found for CVE",
                    cve=cve_id,
                    status=response.status_code,
                )
                return None

            data = response.json()

            # Extract the CVRF document ID
            value = data.get("value", [])
            if not value:
                self.logger.debug("No MSRC value data found", cve=cve_id)
                return None

            # Get the first (and usually only) document ID
            msrc_id = value[0].get("ID")
            if msrc_id:
                self.logger.debug("Found MSRC data", cve=cve_id, msrc_id=msrc_id)
                return msrc_id
            else:
                self.logger.debug("No MSRC ID found in response", cve=cve_id)
                return None

        except Exception as e:
            self.logger.error(
                "Error fetching MSRC data for CVE",
                cve=cve_id,
                error=str(e),
                exc_info=True,
            )
            return None

    def fetch_vulnerability_data(self, **kwargs) -> List[Dict]:
        """Fetch Edge CVE data from Microsoft MSRC API."""
        return self.query_edge_cves(**kwargs)

    def process_vulnerabilities(self, vulnerabilities: List[Dict], **kwargs) -> Dict:
        """Process Edge vulnerabilities and return version mappings."""
        return {"vulnerabilities": vulnerabilities}

    def query_edge_cves(
        self,
        year: Optional[int] = None,
        month: Optional[str] = None,
        cves: Optional[List[str]] = None,
        bugs: Optional[List[int]] = None,
    ) -> List[Dict]:
        """Query Edge CVE data from various sources."""
        import calendar
        import datetime

        results = []

        # If no specific parameters, use current month
        if not any([year, month, cves, bugs]):
            now = datetime.datetime.now()
            year = now.year
            month = calendar.month_name[now.month][:3]

        # Handle bug numbers - get CVEs from bug aliases
        if bugs:
            all_cves = []
            for bug_id in bugs:
                bug_cves = self.bugzilla.get_cves_from_bug_alias(bug_id)
                all_cves.extend(bug_cves)

            # Get MSRC data for these CVEs
            if all_cves:
                msrcs = []
                for cve in all_cves:
                    msrc_id = self._get_msrc_data_for_cve(cve)
                    if msrc_id:
                        msrcs.append(msrc_id)

                # Get CVE data from MSRC
                for msrc_id in set(msrcs):  # Dedupe
                    msrc_year, msrc_month = msrc_id.split("-")
                    edge_cves = self.get_edge_cves_for_month(int(msrc_year), msrc_month)
                    # Filter to only requested CVEs
                    filtered_cves = [
                        cve_data
                        for cve_data in edge_cves
                        if cve_data["cve"] in all_cves
                    ]
                    results.extend(filtered_cves)

        # Handle specific CVEs
        elif cves:
            msrcs = []
            for cve in cves:
                msrc_id = self._get_msrc_data_for_cve(cve)
                if msrc_id:
                    msrcs.append(msrc_id)

            # Get CVE data from MSRC
            for msrc_id in set(msrcs):  # Dedupe
                msrc_year, msrc_month = msrc_id.split("-")
                edge_cves = self.get_edge_cves_for_month(int(msrc_year), msrc_month)
                # Filter to only requested CVEs
                filtered_cves = [
                    cve_data for cve_data in edge_cves if cve_data["cve"] in cves
                ]
                results.extend(filtered_cves)

        # Handle year/month query
        elif year and month:
            edge_cves = self.get_edge_cves_for_month(year, month)
            results.extend(edge_cves)

        return results

    def update_edge_versions(
        self, bugs: Optional[List[int]] = None, dry_run: bool = False
    ) -> Dict:
        """Update existing security bugs with Edge version constraints."""
        if bugs:
            # Update specific bugs for debugging/testing
            return self._update_specific_bugs(bugs, dry_run)
        else:
            # Automated update of all relevant bugs
            return self._update_all_bugs(dry_run)

    def _update_specific_bugs(self, bug_ids: List[int], dry_run: bool) -> Dict:
        """Update specific bugs with Edge version information."""
        results = {"updated": 0, "skipped": 0, "errors": 0}

        for bug_id in bug_ids:
            try:
                # Get bug details
                bug = self.bugzilla.bzapi.getbug(bug_id)
                self.logger.info("Processing bug", bug_id=bug_id, summary=bug.summary)

                # Check if already has Edge version constraints (package-aware)
                if self.version_utils.has_version_constraints(
                    bug.summary, packages=["www-client/microsoft-edge"]
                ):
                    self.logger.info("Bug already has Edge constraints", bug_id=bug_id)
                    results["skipped"] += 1
                    continue

                # Get CVEs from bug aliases
                cves = bug.alias if bug.alias else []
                if not cves:
                    self.logger.warning("No CVE aliases found for bug", bug_id=bug_id)
                    results["skipped"] += 1
                    continue

                # Query Edge versions for these CVEs
                edge_data = self.query_edge_cves(cves=cves)
                if not edge_data:
                    self.logger.warning(
                        "No Edge version data found", bug_id=bug_id, cves=cves
                    )
                    results["skipped"] += 1
                    continue

                # Find the highest Edge version (most recent fix)
                edge_versions = [
                    data["fixed_version"] for data in edge_data if data["fixed_version"]
                ]
                if not edge_versions:
                    self.logger.warning(
                        "No Edge fixed versions found", bug_id=bug_id, cves=cves
                    )
                    results["skipped"] += 1
                    continue

                latest_version = self._get_latest_version(edge_versions)

                # Update bug title
                new_title = self._add_edge_constraint_to_title(
                    bug.summary, latest_version
                )

                # Build comment with MSRC vulnerability URLs
                comment_lines = [
                    f"Edge version constraint added automatically: <www-client/microsoft-edge-{latest_version}",
                    "",
                    "MSRC vulnerability information:",
                ]

                # Add MSRC URLs for each CVE that exists in MSRC
                # MSRC URLs should be added to see_also; however this cannot be done until https://bugs.gentoo.org/964378 is resolved
                cves_with_msrc = [data["cve"] for data in edge_data]
                for cve in cves:
                    if cve in cves_with_msrc:
                        msrc_url = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
                        comment_lines.append(f" * {cve}: {msrc_url}")

                comment = "\n".join(comment_lines)

                if dry_run:
                    self.logger.info(
                        "Dry run - would update bug",
                        bug_id=bug_id,
                        new_title=new_title,
                        comment=comment,
                    )
                else:
                    success = self.bugzilla.update_bug(
                        bug_id, summary=new_title, comment=comment
                    )
                    if success:
                        self.logger.info(
                            "Updated bug with Edge version",
                            bug_id=bug_id,
                            version=latest_version,
                        )
                        results["updated"] += 1
                    else:
                        results["errors"] += 1

            except Exception as e:
                self.logger.error(
                    "Error processing bug", bug_id=bug_id, error=str(e), exc_info=True
                )
                results["errors"] += 1

        return results

    def _update_all_bugs(self, dry_run: bool) -> Dict:
        """Automatically find and update all relevant bugs without Edge constraints."""
        # Find security bugs and filter for those without Edge version constraints
        all_bugs = self.bugzilla.find_chromium_security_bugs()
        edge_bugs = []

        for bug in all_bugs:
            # Check if bug affects microsoft-edge and doesn't have Edge constraints
            if (
                "microsoft-edge" in bug.summary.lower()
                and not self.version_utils.has_version_constraints(
                    bug.summary, packages=["www-client/microsoft-edge"]
                )
            ):
                edge_bugs.append(bug.id)

        self.logger.info(
            "Found bugs needing Edge version updates", count=len(edge_bugs)
        )

        if edge_bugs:
            return self._update_specific_bugs(edge_bugs, dry_run)
        else:
            return {"updated": 0, "skipped": 0, "errors": 0}

    def _add_edge_constraint_to_title(self, title: str, version: str) -> str:
        """Add Edge version constraint to bug title by replacing www-client/microsoft-edge with constrained version."""
        import re

        # Look for www-client/microsoft-edge (without version constraint)
        pattern = r"www-client/microsoft-edge"

        # Replace with constrained version
        constraint = f"<www-client/microsoft-edge-{version}"
        new_title = re.sub(pattern, constraint, title)

        if new_title == title:
            # No replacement was made - this shouldn't happen in normal operation
            self.logger.warning(
                "No microsoft-edge package found to replace in title",
                title=title,
                version=version,
            )

        return new_title

    def _get_latest_version(self, versions: List[str]) -> str:
        """Get the latest version from a list of version strings."""
        # Sort versions and return the highest
        sorted_versions = sorted(versions, key=lambda v: tuple(map(int, v.split("."))))
        return sorted_versions[-1]

    def _get_cache_file_path(self, year: int, month: str) -> str:
        """Get cache file path for a specific year/month."""
        return str(self.cache_dir / f"edge_cves_{year}_{month}.json")

    def _is_cache_valid(self, cache_file: str, max_age_hours: int = 8) -> bool:
        """Check if cache file exists and is within the specified age."""
        cache_path = Path(cache_file)
        if not cache_path.exists():
            return False

        file_age = time.time() - cache_path.stat().st_mtime
        max_age_seconds = max_age_hours * 3600
        return file_age < max_age_seconds

    def _load_from_cache(self, cache_file: str) -> Optional[List[Dict]]:
        """Load Edge CVE data from cache file."""
        try:
            with open(cache_file, "r") as f:
                data = json.load(f)
            self.logger.debug(
                "Loaded Edge CVE data from cache",
                cache_file=cache_file,
                count=len(data),
            )
            return data
        except Exception as e:
            self.logger.warning(
                "Failed to load cache file", cache_file=cache_file, error=str(e)
            )
            return None

    def _save_to_cache(self, cache_file: str, data: List[Dict]) -> None:
        """Save Edge CVE data to cache file."""
        try:
            with open(cache_file, "w") as f:
                json.dump(data, f, indent=2)
            self.logger.debug(
                "Saved Edge CVE data to cache", cache_file=cache_file, count=len(data)
            )
        except Exception as e:
            self.logger.warning(
                "Failed to save cache file", cache_file=cache_file, error=str(e)
            )

    def get_edge_cves_for_month(self, year: int, month: str) -> List[Dict]:
        """
        Get Edge CVE data for a specific month from MSRC API.

        This method extracts the core logic from the original get-edge-cves.py script.
        Results are cached for 8 hours to avoid redundant API calls.

        Args:
            year: Year (e.g., 2024)
            month: Month name (e.g., "Aug")

        Returns:
            List of dictionaries with CVE data
        """
        # Check cache first (skip caching during testing)
        cache_file = self._get_cache_file_path(year, month)
        if not self._is_testing() and self._is_cache_valid(cache_file):
            cached_data = self._load_from_cache(cache_file)
            if cached_data is not None:
                self.logger.info(
                    "Using cached Edge CVE data",
                    year=year,
                    month=month,
                    count=len(cached_data),
                )
                return cached_data

        try:
            self.logger.info(
                "Fetching Edge CVE data from MSRC API", year=year, month=month
            )

            msrc_url = f"https://api.msrc.microsoft.com/cvrf/v3.0/cvrf/{year}-{month}"

            response = requests.get(msrc_url, timeout=30)
            if response.status_code != 200:
                self.logger.warning(
                    "Failed to get CVRF data",
                    year=year,
                    month=month,
                    status=response.status_code,
                )
                return []

            # Parse the XML
            root = ET.fromstring(response.text)

            # Find all vulnerabilities for Microsoft Edge (Product ID 11655)
            vulnerabilities = root.findall(
                ".//{http://www.icasi.org/CVRF/schema/vuln/1.1}Vulnerability"
            )
            edge_cves = []

            for vulnerability in vulnerabilities:
                # Check if this affects Microsoft Edge (Product ID 11655)
                product_statuses = vulnerability.findall(
                    ".//{http://www.icasi.org/CVRF/schema/vuln/1.1}ProductStatuses"
                )
                is_edge_vulnerability = False

                for product_status in product_statuses:
                    product_id = product_status.find(
                        ".//{http://www.icasi.org/CVRF/schema/vuln/1.1}ProductID"
                    )
                    if product_id is not None and product_id.text == "11655":
                        is_edge_vulnerability = True
                        break

                if not is_edge_vulnerability:
                    continue

                # Extract CVE ID and title
                cve_elem = vulnerability.find(
                    ".//{http://www.icasi.org/CVRF/schema/vuln/1.1}CVE"
                )
                title_elem = vulnerability.find(
                    ".//{http://www.icasi.org/CVRF/schema/vuln/1.1}Title"
                )

                if cve_elem is None or title_elem is None:
                    continue

                cve_id = cve_elem.text
                cve_title = title_elem.text

                # Extract fixed version
                fixed_version = None
                remediations = vulnerability.findall(
                    ".//{http://www.icasi.org/CVRF/schema/vuln/1.1}Remediations"
                )

                for remediation in remediations:
                    fixed_build = remediation.find(
                        ".//{http://www.icasi.org/CVRF/schema/vuln/1.1}FixedBuild"
                    )
                    if fixed_build is not None and fixed_build.text:
                        fixed_version = fixed_build.text
                        break

                # Fallback: parse version from notes if FixedBuild not available
                if not fixed_version:
                    fixed_version = self._parse_version_from_notes(vulnerability)

                edge_cves.append(
                    {"cve": cve_id, "title": cve_title, "fixed_version": fixed_version}
                )

            self.logger.info(
                "Parsed Edge CVEs from MSRC",
                year=year,
                month=month,
                count=len(edge_cves),
            )

            # Save to cache (skip during testing)
            if not self._is_testing():
                self._save_to_cache(cache_file, edge_cves)

            return edge_cves

        except Exception as e:
            self.logger.error(
                "Error parsing Edge CVEs from MSRC",
                year=year,
                month=month,
                error=str(e),
                exc_info=True,
            )
            return []

    def _parse_version_from_notes(self, vulnerability) -> Optional[str]:
        """Parse Edge version from vulnerability notes as fallback."""
        try:
            from bs4 import BeautifulSoup
            from portage import versions as portage_versions

            notes = vulnerability.find(
                ".//{http://www.icasi.org/CVRF/schema/vuln/1.1}Notes"
            )
            if notes is None:
                return None

            for note in notes:
                if (
                    note.attrib.get("Title") == "FAQ"
                    and note.attrib.get("Type") == "FAQ"
                    and note.text
                ):
                    # Parse HTML content from notes
                    soup = BeautifulSoup(note.text, "html.parser")
                    rows = soup.find_all("tr")

                    # Look for version in second row, second cell
                    if len(rows) > 1:
                        cells = rows[1].find_all("td")
                        if len(cells) > 1:
                            edge_version = cells[1].text.strip()
                            # Validate version format
                            if portage_versions.ververify(edge_version):
                                return edge_version

            return None

        except Exception as e:
            self.logger.debug("Failed to parse version from notes", error=str(e))
            return None

    def bump_edge(
        self,
        channels: List[str],
        repo_path: str,
        dry_run: bool = False,
    ) -> Dict[str, int]:
        """
        Bump Edge packages to latest versions.

        This implements the edge-bump logic for automated version bumping.

        Args:
            channels: List of channels to bump ("stable", "beta", "dev")
            repo_path: Path to Gentoo repository
            dry_run: If True, don't make actual changes

        Returns:
            Dict with counts of bumped, skipped, and error packages
        """
        from portage.dbapi.porttree import portdbapi
        from portage.versions import pkgsplit

        self.logger.info("Starting Edge version bump", channels=channels)

        # Fetch upstream version information
        self.logger.info("Fetching upstream version information")
        edge_info = self._get_edge_versions()

        # Package configuration
        pkg_data = {
            "stable": {
                "pkg": "microsoft-edge",
                "suffix": "stable",
                "version": [],
                "dversion": [],
                "bversion": [],
                "stable": True,
                "count": 1,
            },
            "beta": {
                "pkg": "microsoft-edge-beta",
                "suffix": None,
                "version": [],
                "dversion": [],
                "bversion": [],
                "stable": False,
                "count": 3,
            },
            "dev": {
                "pkg": "microsoft-edge-dev",
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
        self.logger.info("Looking up Edge version information in tree")
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

        # Compare versions
        self.logger.info("Comparing Edge version information")

        # Check which versions have been dropped upstream
        for channel in pkg_data.keys():
            versions_list = [v[0] for v in edge_info[channel]]
            for ver in pkg_data[channel]["version"]:
                if ver[0] not in versions_list:
                    self.logger.warning(
                        f"Upstream dropped version {ver[0]} from channel {channel} of www-client/{pkg_data[channel]['pkg']}"
                    )
                    pkg_data[channel]["dversion"].append(ver)

        # Determine which new versions to bump
        for channel in pkg_data.keys():
            if len(edge_info[channel]) == 0:
                self.logger.warning(f"Upstream version unknown for channel {channel}")
            else:
                for uver in edge_info[channel]:
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
                    self._bump_edge_package(
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
                    self._remove_old_edge_versions(
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

    def _get_edge_versions(self) -> Dict[str, List[Tuple[str, str]]]:
        """
        Fetch Edge version data from Microsoft's Debian repository.

        Returns:
            Dict mapping channel to list of (version, revision) tuples
        """
        base_url = "https://packages.microsoft.com/repos"
        url = f"{base_url}/edge/dists/stable/main/binary-amd64/Packages"

        with closing(urllib.request.urlopen(url)) as fp:
            versions_data = list(deb822.Packages.iter_paragraphs(fp, use_apt_pkg=False))

        edge_info = {
            "stable": [],
            "beta": [],
            "dev": [],
        }

        # Map package names to channels
        pkg_map = {
            "microsoft-edge-stable": "stable",
            "microsoft-edge-beta": "beta",
            "microsoft-edge-dev": "dev",
        }

        for item in versions_data:
            pkg_name = item["Package"]
            if pkg_name in pkg_map:
                channel = pkg_map[pkg_name]
                version, revision = item["Version"].split("-")
                edge_info[channel].append((version, revision))

        # Sort each channel (newest first)
        for channel in edge_info.keys():
            edge_info[channel].sort(
                key=functools.cmp_to_key(self._compare_version_tuples)
            )

        return edge_info

    def _get_prev_channel(self, channel: str) -> str:
        """Get the previous channel for cross-channel copying during major bumps."""
        return get_prev_channel_generic(channel, ["stable", "beta", "dev"])

    def _bump_edge_package(
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
        """Bump a single Edge package using shared browser bump logic."""
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

    def _remove_old_edge_versions(
        self,
        channel: str,
        pkg: str,
        versions_to_remove: List[Tuple[str, str]],
        ebuild_mgr: EbuildManager,
        repo_path: str,
        dry_run: bool,
    ):
        """Remove old Edge versions."""
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
