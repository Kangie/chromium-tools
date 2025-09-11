#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Shared Bugzilla client for Chromium security bug management.
"""

from pathlib import Path
import sys
from typing import Dict, List, Optional

import bugzilla
from bugzilla.bug import Bug
import structlog


class BugzillaClient:
    """Shared Bugzilla client with common operations."""

    def __init__(
        self, api_key_file: str, logger: structlog.BoundLogger, use_rest: bool = True
    ):
        self.logger = logger
        self.use_rest = use_rest
        self.bzapi = self._connect(api_key_file)

    def _connect(self, api_key_file: str) -> bugzilla.Bugzilla:
        """Connect to Gentoo bugzilla with API key."""
        try:
            with open(Path(api_key_file).resolve(), "r") as keyfile:
                api_key = keyfile.read().strip()
        except FileNotFoundError:
            self.logger.error("API key file not found", api_key_file=api_key_file)
            sys.exit(1)
        except PermissionError:
            self.logger.error(
                "Permission denied reading API key file", api_key_file=api_key_file
            )
            sys.exit(1)

        api_type = "REST" if self.use_rest else "XMLRPC"
        self.logger.info("Connecting to bugs.gentoo.org", api_type=api_type)

        try:
            if self.use_rest:
                bzapi = bugzilla.Bugzilla(
                    "bugs.gentoo.org", api_key=api_key, force_rest=True
                )
            else:
                bzapi = bugzilla.Bugzilla("bugs.gentoo.org", api_key=api_key)

            self.logger.debug(
                "Connected successfully",
                api_type=api_type,
                bugzilla_version=getattr(bzapi, "bz_ver_major", "unknown"),
            )
            return bzapi
        except Exception as e:
            self.logger.error(
                "Error connecting to Bugzilla", api_type=api_type, error=str(e)
            )
            sys.exit(1)

    def find_chromium_security_bugs(self) -> List:
        """Query bugzilla for open security bugs involving chromium packages."""
        self.logger.info("Querying for open chromium security bugs")

        query = self.bzapi.build_query(
            product="Gentoo Security",
            component="Vulnerabilities",
            status=["NEW", "ASSIGNED", "CONFIRMED", "IN_PROGRESS"],
            include_fields=["id", "summary", "alias", "status", "assigned_to"],
        )

        query["f1"] = "short_desc"
        query["o1"] = "anywordssubstr"
        query["v1"] = (
            "www-client/chromium www-client/google-chrome www-client/microsoft-edge"
        )

        try:
            all_bugs = self.bzapi.query(query)
            self.logger.info(
                "Found open chromium security bugs", total_bugs=len(all_bugs)
            )
            return all_bugs
        except Exception as e:
            self.logger.error("Error querying Bugzilla", error=str(e))
            return []

    def find_security_bugs_by_packages(
        self, packages: List[str], status: Optional[List[str]] = None
    ) -> List[Bug]:
        """
        Query bugzilla for security bugs involving specific packages.

        Args:
            packages: List of package names to search for (e.g., ["www-client/opera", "www-client/chromium"])
            status: List of bug statuses to include. Defaults to open statuses.

        Returns:
            List of bugs matching the criteria
        """
        if status is None:
            status = ["NEW", "ASSIGNED", "CONFIRMED", "IN_PROGRESS"]

        package_str = " ".join(packages)

        self.logger.info(
            "Querying for security bugs by packages", packages=packages, status=status
        )

        query = self.bzapi.build_query(
            product="Gentoo Security",
            component="Vulnerabilities",
            status=status,
            include_fields=["id", "summary", "alias", "status", "assigned_to"],
        )

        query["f1"] = "short_desc"
        query["o1"] = "anywordssubstr"
        query["v1"] = package_str

        try:
            all_bugs = self.bzapi.query(query)
            self.logger.info(
                "Found security bugs by packages",
                packages=packages,
                total_bugs=len(all_bugs),
            )
            return all_bugs
        except Exception as e:
            self.logger.error("Error querying Bugzilla", error=str(e))
            return []

    # _has_edge_version_constraints removed — handlers should use VersionUtils

    def get_bug_comments(self, bug_id: int) -> List[Dict]:
        """Get all comments for a bug."""
        try:
            self.logger.debug("Fetching comments for bug", bug_id=bug_id)
            comments_data = self.bzapi.get_comments([bug_id])
            bug_comments = (
                comments_data.get("bugs", {}).get(str(bug_id), {}).get("comments", [])
            )
            return bug_comments
        except Exception as e:
            self.logger.error(
                "Error getting comments for bug",
                bug_id=bug_id,
                error=str(e),
                exc_info=True,
            )
            return []

    def get_cves_from_bug_alias(self, bug_number: int) -> List[str]:
        """Get CVEs associated with a bug via aliases."""
        try:
            bug = self.bzapi.getbug(bug_number)
            cves = bug.alias if bug.alias else []
            self.logger.info(
                "Found CVEs from bug alias",
                bug_number=bug_number,
                num_cves=len(cves),
                cves=cves,
            )
            return cves
        except Exception as e:
            self.logger.error(
                "Error getting CVEs from bug alias", bug_number=bug_number, error=str(e)
            )
            return []

    def check_existing_bugs_for_cves(self, cves: List[str]) -> Dict[str, int]:
        """Check if bugs already exist for the given CVEs."""
        existing_bugs = {}

        if not cves:
            return existing_bugs

        self.logger.info("Checking for existing bugs with CVE aliases", cves=cves)

        try:
            for cve in cves:
                query = self.bzapi.build_query(
                    product="Gentoo Security",
                    component="Vulnerabilities",
                    alias=cve,
                    include_fields=["id", "summary", "alias", "status"],
                )

                bugs = self.bzapi.query(query)
                if bugs:
                    existing_bugs[cve] = bugs[0].id
                    self.logger.info(
                        "Found existing bug for CVE",
                        cve=cve,
                        bug_id=bugs[0].id,
                        summary=bugs[0].summary,
                    )
        except Exception as e:
            self.logger.error(
                "Error checking for existing CVE bugs", error=str(e), exc_info=True
            )

        return existing_bugs

    def create_security_bug(
        self,
        title: str,
        description: str,
        cves: Optional[List[str]] = None,
        url: Optional[str] = None,
        see_also: Optional[List[str]] = None,
        blocks: Optional[List[int]] = None,
    ) -> Optional[int]:
        """Create a new security bug."""
        try:
            create_info = {
                "product": "Gentoo Security",
                "component": "Vulnerabilities",
                "version": "unspecified",  # Required field for Gentoo Security bugs
                "summary": title,
                "description": description,
                "assigned_to": "security@gentoo.org",
                "cc": ["chromium@gentoo.org"],
                "severity": "normal",
                "priority": "Normal",
                "status": "CONFIRMED",
            }

            if cves:
                create_info["alias"] = cves
            if url:
                create_info["url"] = url
            if see_also:
                create_info["see_also"] = see_also
            if blocks:
                create_info["blocks"] = blocks

            new_bug = self.bzapi.createbug(**create_info)
            bug_id = new_bug.id

            self.logger.info(
                "Successfully created security bug",
                bug_id=bug_id,
                title=title,
                cves=cves,
            )
            return bug_id

        except Exception as e:
            self.logger.error(
                "Error creating security bug",
                error=str(e),
                title=title,
                cves=cves,
                exc_info=True,
            )
            return None

    def update_bug(
        self, bug_id: int, summary: Optional[str] = None, comment: Optional[str] = None
    ) -> bool:
        """Update a bug with new summary and/or comment."""
        try:
            update = self.bzapi.build_update(
                **({"summary": summary} if summary else {}),
                **({"comment": comment} if comment else {}),
            )
            self.bzapi.update_bugs([bug_id], update)
            self.logger.info("Successfully updated bug", bug_id=bug_id)
            return True
        except Exception as e:
            self.logger.error(
                "Error updating bug", bug_id=bug_id, error=str(e), exc_info=True
            )
            return False
