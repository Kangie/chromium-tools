#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Chromium Handler - Manages Chromium/Chrome security workflow

This handler implements the Chromium workflow logic extracted from
the original update-chromium-security-bugs.py script.
"""

import json
import re
import time
import urllib.request
from typing import Dict, List, Optional

import requests
import structlog
import typer
from bs4 import BeautifulSoup

from bugzilla_client import BugzillaClient
from ebuild_manager import EbuildManager
from version_utils import VersionUtils
from bump_utils import (
    is_major_bump,
    get_prev_channel_generic,
)


class ChromiumHandler:
    """Handler for Chromium/Chrome security updates from Google releases."""

    def __init__(
        self,
        api_key_file: str,
        logger: structlog.BoundLogger,
        version_utils: VersionUtils,
        dry_run: bool = False,
        browser_registry=None,
    ):
        self.api_key_file = api_key_file
        self.logger = logger
        self.version_utils = version_utils
        self.dry_run = dry_run
        self.browser_registry = browser_registry
        self._bugzilla = None  # Lazy-loaded

        # Regex patterns for parsing commit information
        self.commit_pattern = re.compile(r"commit\s+([a-f0-9]{40})")
        self.package_pattern = re.compile(
            r"(www-client/(?:chromium|google-chrome))-(\d+(?:\.\d+)*(?:\.\d+)?(?:\.\d+)?)"
        )
        self.ebuild_pattern = re.compile(
            r"(www-client/(?:chromium|google-chrome))/.*?(\d+(?:\.\d+)*(?:\.\d+)?)\.ebuild"
        )

        # Regex patterns for parsing Chrome releases
        self.cve_pattern = re.compile(r"CVE-\d{4}-\d{4,7}")
        self.version_pattern = re.compile(r"(\d+\.\d+\.\d+\.\d+)")
        self.linux_version_pattern = re.compile(r"Linux[:\s]*(\d+\.\d+\.\d+\.\d+)")

        # Pattern to capture CVE details from Chrome release posts
        # Format: [NA][445380761] High CVE-2025-10585: Type Confusion in V8. Reported by...
        self.cve_detail_pattern = re.compile(
            r"\[([^\]]*)\]\[([^\]]*)\]\s*(Critical|High|Medium|Low)\s+(CVE-\d{4}-\d{4,7}):\s*([^.]+)\.\s*Reported by\s+([^.]+(?:\s+on\s+[\d-]+)?)"
        )

        # Pattern for Chromium issue URLs
        self.chromium_issue_pattern = re.compile(
            r"https://issues\.chromium\.org/issues/\d+"
        )

        self.cli = typer.Typer(
            name="chromium",
            help="Chromium/Chrome security workflow",
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

    def _register_commands(self):
        """Register CLI commands for this handler."""
        from chromicler import DryRunOption, DebugOption, AppConfig

        handler = self

        @self.cli.command(name="create-from-releases")
        def create_from_releases(
            limit: int = typer.Option(
                10, "--limit", "-l", help="Limit number of releases to process"
            ),
            dry_run: bool = DryRunOption(),
            debug: bool = DebugOption(),
        ):
            """Create security bugs from recent Chrome releases"""
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

                # Fetch and process releases
                releases = handler.parse_chrome_releases(limit_releases=limit)
                if not releases:
                    typer.echo("No releases found")
                    return

                handler.logger.info(f"Found {len(releases)} releases")

                result = handler.process_chrome_releases(releases)

                handler.logger.info(
                    "Processing complete",
                    created=result.get("created", 0),
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

        @self.cli.command(name="update-existing")
        def update_existing(
            dry_run: bool = DryRunOption(),
            debug: bool = DebugOption(),
        ):
            """Update existing Chromium security bugs"""
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

                result = handler.update_existing_bugs()

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

        @self.cli.command(name="bump")
        def bump(
            channels: List[str] = typer.Option(
                None,
                "--channel",
                "-c",
                help="Specific channels to bump (stable, beta, dev). If not specified, checks all channels.",
            ),
            link_bugs: bool = typer.Option(
                True,
                "--link-bugs/--no-link-bugs",
                help="Search for and link CVE bugs (stable channel only)",
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
            """Check for Chrome updates and bump ebuilds if needed"""
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
                    channels = ["stable", "beta", "dev"]

                result = handler.bump_chrome(
                    channels=channels,
                    link_bugs=link_bugs,
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
        return "Google"

    def register_browsers(self, registry):
        """Register the browsers that this handler impacts."""
        # Chromium handler manages these browsers directly
        registry.register_browser("chromium", "www-client/chromium")
        registry.register_browser("chromium", "www-client/google-chrome")

    def get_affected_browsers_for_chromium(self) -> List[str]:
        """Return the list of browsers affected by Chromium security vulnerabilities."""
        # Get all registered browsers since Chromium CVEs affect all Chromium-based browsers
        return self.browser_registry.get_all_browsers()

    def fetch_vulnerability_data(self, limit_releases: int = 10) -> List[Dict]:
        """Fetch Chrome release data from Google's blog."""
        return self.parse_chrome_releases(limit_releases)

    def process_vulnerabilities(self, vulnerabilities: List[Dict], **kwargs) -> Dict:
        """Create or update security bugs for Chrome releases."""
        return self.process_chrome_releases(vulnerabilities)

    def update_existing_bugs(self) -> Dict:
        """Update existing bugs with version constraints from Larry commits."""

        # Find all relevant bugs
        bugs = self.bugzilla.find_chromium_security_bugs()
        if not bugs:
            self.logger.info("No bugs found to process")
            return {"updated": 0, "total": 0}

        # Process each bug
        updated_count = 0
        for bug in bugs:
            if self.process_bug(bug):
                updated_count += 1

        self.logger.info(
            "Processing complete", updated_count=updated_count, total_bugs=len(bugs)
        )
        return {"updated": updated_count, "total": len(bugs)}

    def parse_chrome_releases(self, limit_releases: int = 10) -> List[Dict]:
        """Parse Chrome stable release blog posts and extract release information."""
        self.logger.info(
            "Parsing Chrome stable releases blog", limit_releases=limit_releases
        )

        releases_url = (
            "https://chromereleases.googleblog.com/search/label/Desktop%20Update"
        )

        try:
            response = requests.get(releases_url, timeout=30)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, "html.parser")
            blog_posts = soup.find_all("div", class_="post")
            releases = []

            for post in blog_posts[:limit_releases]:
                try:
                    # Extract post title and URL - new structure uses h2.title
                    title_elem = post.find("h2", class_="title")
                    if not title_elem:
                        # Fallback to old structure
                        title_elem = post.find("h3", class_="post-title entry-title")

                    if not title_elem:
                        self.logger.debug("No title element found in post")
                        continue

                    post_link = title_elem.find("a")
                    if not post_link:
                        self.logger.debug("No link found in title element")
                        continue

                    title = title_elem.get_text(strip=True)

                    # Only process "Stable Channel Update for Desktop" posts
                    if "Stable Channel Update for Desktop" not in title:
                        self.logger.debug(
                            "Skipping non-stable channel post", title=title
                        )
                        continue

                    post_url = post_link.get("href")

                    # Extract date - new structure uses span.publishdate
                    date_elem = post.find("span", class_="publishdate")
                    if not date_elem:
                        # Fallback to old structure
                        date_elem = post.find("abbr", class_="published")
                        if date_elem:
                            post_date = date_elem.get("title", "").strip()
                        else:
                            post_date = None
                    else:
                        post_date = date_elem.get_text(strip=True)

                    self.logger.info(
                        "Processing Chrome release post",
                        title=title,
                        url=post_url,
                        date=post_date,
                    )

                    # Parse the individual post for detailed information
                    release_info = self._parse_individual_release_post(
                        post_url, title, post_date or "Unknown"
                    )
                    if release_info:
                        releases.append(release_info)

                except Exception as e:
                    self.logger.error(
                        "Error parsing blog post", error=str(e), exc_info=True
                    )
                    continue

            self.logger.info("Parsed Chrome releases", count=len(releases))
            return releases

        except Exception as e:
            self.logger.error("Error parsing Chrome releases blog", error=str(e))
            return []

    def _parse_individual_release_post(
        self, post_url: str, title: str, post_date: str
    ) -> Optional[Dict]:
        """Parse individual Chrome release post to extract version and CVEs."""
        try:
            self.logger.debug("Parsing individual release post", url=post_url)

            response = requests.get(post_url, timeout=30)
            response.raise_for_status()

            soup = BeautifulSoup(response.content, "html.parser")

            # Find the post content - try multiple selectors for different structures
            post_content = soup.find("div", class_="post-content")
            if not post_content:
                post_content = soup.find("div", class_="post-body entry-content")
            if not post_content:
                post_content = soup.find("div", class_="post-body")

            if not post_content:
                self.logger.warning("Could not find post content", url=post_url)
                return None

            # Get content from noscript section if available (more reliable)
            noscript_elem = post_content.find("noscript")
            if noscript_elem:
                content_text = noscript_elem.get_text(separator="\n")
            else:
                content_text = post_content.get_text(separator="\n")

            # Extract Linux version
            linux_version = None
            linux_matches = self.linux_version_pattern.findall(content_text)
            if linux_matches:
                linux_version = linux_matches[0]
            else:
                # Fallback: look for any version number in the content
                version_matches = self.version_pattern.findall(content_text)
                if version_matches:
                    linux_version = version_matches[0]

            # Extract CVEs with detailed information
            cve_details = {}
            in_the_wild_lines = []

            # Parse CVEs line by line - split on various delimiters and CVE patterns
            self._parse_cve_details_from_text(
                content_text, cve_details, post_url, in_the_wild_lines
            )

            # Extract Chromium issue URLs using BeautifulSoup to find anchor tags
            chromium_issues = self._extract_chromium_issue_urls(post_content)

            if chromium_issues:
                self.logger.info(
                    "Found Chromium issue URLs",
                    chromium_issues=chromium_issues,
                    url=post_url,
                )

            # Fallback: also collect any CVEs that might not match the detailed pattern
            all_cves = list(set(self.cve_pattern.findall(content_text)))

            # Add any CVEs that weren't captured by the detailed pattern
            for cve in all_cves:
                if cve not in cve_details:
                    cve_details[cve] = {
                        "cve": cve,
                        "severity": None,
                        "description": None,
                        "reporter": None,
                        "issue_id": None,
                        "bug_id": None,
                    }

            cves = sorted(cve_details.keys())

            if not linux_version:
                self.logger.warning(
                    "No Linux version found in release post", url=post_url, title=title
                )
                return None

            if not cves:
                self.logger.info(
                    "No CVEs found in release post",
                    url=post_url,
                    title=title,
                    version=linux_version,
                )
                # Still return the release info even without CVEs for completeness

            release_info = {
                "title": title,
                "url": post_url,
                "date": post_date,
                "linux_version": linux_version,
                "cves": cves,
                "cve_details": cve_details,
                "in_the_wild_lines": in_the_wild_lines,
                "chromium_issues": chromium_issues,
                "content_preview": content_text[:500],  # For debugging
            }

            self.logger.info(
                "Parsed Chrome release",
                version=linux_version,
                cve_count=len(cves),
                cves=cves[:5],
            )  # Show first 5 CVEs

            return release_info

        except Exception as e:
            self.logger.error(
                "Error parsing Chrome release post",
                url=post_url,
                error=str(e),
                exc_info=True,
            )
            return None

    def _parse_cve_details_from_text(
        self,
        content_text: str,
        cve_details: Dict,
        post_url: str,
        in_the_wild_lines: Optional[List[str]] = None,
    ) -> None:
        """Parse CVE details from content text by splitting on lines and parsing each CVE entry."""
        lines = content_text.split("\n")

        # Also add split by common delimiters in case some CVEs are still concatenated
        additional_lines = []
        for line in lines:
            # Split lines that might have multiple CVEs concatenated with brackets
            if line.count("[") > 2 and "CVE-" in line:
                # Try to split on bracket patterns that indicate new CVE entries
                parts = re.split(
                    r"(?=\[[^\]]*\]\[[^\]]*\]\s*(Critical|High|Medium|Low)\s+CVE-)",
                    line,
                )
                additional_lines.extend(parts)

        lines.extend(additional_lines)

        # Look for CVE patterns in each line/part
        cve_entry_pattern = re.compile(
            r"(?:\[([^\]]*)\])?"  # Optional first bracket ($Reward or N/A)
            r"(?:\[([^\]]*)\])?"  # Optional second bracket (bug ID)
            r"\s*(Critical|High|Medium|Low)\s+"  # Severity
            r"(CVE-\d{4}-\d{4,7}):\s*"  # CVE ID
            r"([^.]+?)\."  # Description until first period
            r"(?:\s*Reported by\s+([^.$]+))?"  # Optional reporter
        )

        for line in lines:
            line = line.strip()
            if not line or "CVE-" not in line:
                continue

            # Check for "in the wild" lines that contain CVE IDs
            if in_the_wild_lines is not None and "in the wild" in line.lower():
                in_the_wild_lines.append(line)
                self.logger.debug(
                    "Found 'in the wild' line with CVE",
                    line=line,
                    url=post_url,
                )

            # Try to extract CVE details from this line
            match = cve_entry_pattern.search(line)
            if match:
                issue_status, bug_id, severity, cve_id, description, reporter = (
                    match.groups()
                )

                # Clean up the extracted data
                cve_details[cve_id] = {
                    "cve": cve_id,
                    "severity": severity,
                    "description": description.strip() if description else None,
                    "reporter": reporter.strip() if reporter else None,
                    "issue_status": issue_status.strip()
                    if issue_status and issue_status.strip()
                    else None,
                    "bug_id": bug_id.strip() if bug_id and bug_id.strip() else None,
                }

                self.logger.debug(
                    "Parsed CVE details",
                    cve=cve_id,
                    severity=severity,
                    description=description.strip() if description else None,
                    reporter=reporter.strip() if reporter else None,
                    url=post_url,
                )
            else:
                # Fallback: look for any CVE in the line and try simpler extraction
                cve_matches = self.cve_pattern.findall(line)
                for cve in cve_matches:
                    if cve not in cve_details:
                        # Try to extract severity from the same line
                        severity_match = re.search(
                            r"\b(Critical|High|Medium|Low)\b", line
                        )
                        severity = severity_match.group(1) if severity_match else None

                        # Try to extract description (text after CVE ID and colon)
                        desc_match = re.search(rf"{re.escape(cve)}:\s*([^.]+)", line)
                        description = (
                            desc_match.group(1).strip() if desc_match else None
                        )

                        cve_details[cve] = {
                            "cve": cve,
                            "severity": severity,
                            "description": description,
                            "reporter": None,
                            "issue_status": None,
                            "bug_id": None,
                        }

                        self.logger.debug(
                            "Fallback CVE parsing",
                            cve=cve,
                            severity=severity,
                            description=description,
                            line_preview=line[:100],
                            url=post_url,
                        )

    def _extract_chromium_issue_urls(self, post_content) -> List[str]:
        """Extract Chromium issue URLs from BeautifulSoup element using anchor tags."""
        try:
            chromium_issues = set()

            # Find all anchor tags with href attributes within the post content
            for anchor in post_content.find_all("a", href=True):
                href = anchor.get("href", "")

                # Check if the href matches the Chromium issue pattern
                if self.chromium_issue_pattern.match(href):
                    chromium_issues.add(href)

            return sorted(list(chromium_issues))

        except Exception as e:
            self.logger.warning(
                "Failed to extract Chromium issue URLs with BeautifulSoup", error=str(e)
            )
            # Fallback to regex as backup on text content
            try:
                content_text = post_content.get_text()
                return sorted(
                    list(set(self.chromium_issue_pattern.findall(content_text)))
                )
            except Exception:
                return []

    def _generate_bug_title(self, cves: List[str], release_info: Dict) -> str:
        """Generate bug title from CVEs and release info."""
        browsers_str = ", ".join(self.get_affected_browsers_for_chromium())

        if len(cves) == 1:
            # Get CVE description from parsed data
            cve_desc = None
            if "cve_details" in release_info and cves[0] in release_info["cve_details"]:
                cve_info = release_info["cve_details"][cves[0]]
                if cve_info["description"]:
                    cve_desc = cve_info["description"]

            if cve_desc:
                return f"{browsers_str}: {cve_desc}"
            else:
                return f"{browsers_str}: {cves[0]}"
        else:
            return f"{browsers_str}: multiple vulnerabilities"

    def _generate_bug_description(
        self,
        cves: List[str],
        release_info: Dict,
        existing_bugs: Optional[Dict[str, int]] = None,
    ) -> str:
        """Generate bug description from CVEs and release info."""
        linux_version = release_info["linux_version"]

        description = f"""Security vulnerabilities in Chromium-based browsers

Release Information:
- Linux Version: {linux_version}
- Release Date: {release_info.get("date", "Unknown")}
- Release URL: {release_info["url"]}

CVEs addressed in this release:
"""

        for cve in cves:
            # Try to get detailed CVE info from parsed data
            cve_desc = None
            cve_severity = None
            cve_reporter = None

            if "cve_details" in release_info and cve in release_info["cve_details"]:
                cve_info = release_info["cve_details"][cve]
                cve_desc = cve_info["description"]
                cve_severity = cve_info["severity"]
                cve_reporter = cve_info["reporter"]

            # Format the CVE entry with available information
            cve_entry = f"- {cve}"
            if cve_severity:
                cve_entry += f" ({cve_severity})"
            if cve_desc:
                cve_entry += f": {cve_desc}"
            if cve_reporter:
                cve_entry += f" (Reported by {cve_reporter})"

            description += cve_entry + "\n"

        # Add "in the wild" information if available
        if "in_the_wild_lines" in release_info and release_info["in_the_wild_lines"]:
            description += "\n⚠️  CVEs being exploited in the wild:\n"
            for wild_line in release_info["in_the_wild_lines"]:
                description += f"- {wild_line}\n"

        if existing_bugs:
            description += (
                "\nNote: Some CVEs from this release already have existing bugs:\n"
            )
            for cve, bug_id in existing_bugs.items():
                description += f"- {cve}: bug #{bug_id}\n"

        description += f"""
Packages affected:
{chr(10).join(f"- {browser}" for browser in self.get_affected_browsers_for_chromium())}

This bug was automatically created based on Chrome stable release information.
"""
        return description

    def process_chrome_releases(self, releases: List[Dict]) -> Dict:
        """Process Chrome releases and create security bugs."""
        created_bugs = 0
        skipped_releases = 0

        for release in releases:
            try:
                bug_id = self.create_chromium_security_bug(release)
                if bug_id:
                    created_bugs += 1
                else:
                    skipped_releases += 1

                # Add delay to avoid overwhelming the server
                time.sleep(1)

            except Exception as e:
                self.logger.error(
                    "Error processing release",
                    release=release.get("title", "unknown"),
                    error=str(e),
                    exc_info=True,
                )
                skipped_releases += 1

        return {
            "created": created_bugs,
            "skipped": skipped_releases,
            "total": len(releases),
        }

    def create_chromium_security_bug(self, release_info: Dict) -> Optional[int]:
        """Create a new security bug for Chrome release with CVEs."""
        linux_version = release_info["linux_version"]
        cves = release_info["cves"]

        if not cves:
            self.logger.info(
                "No CVEs in release, skipping bug creation", version=linux_version
            )
            return None

        # Check for existing bugs
        existing_bugs = self.bugzilla.check_existing_bugs_for_cves(cves)
        new_cves = [cve for cve in cves if cve not in existing_bugs]

        if not new_cves:
            self.logger.info(
                "All CVEs already have existing bugs", existing_bugs=existing_bugs
            )
            return None

        if existing_bugs:
            self.logger.info(
                "Some CVEs already have bugs, creating for remaining",
                new_cves=new_cves,
                existing_bugs=existing_bugs,
            )

        # Generate bug title and description using shared methods
        title = self._generate_bug_title(new_cves, release_info)
        description = self._generate_bug_description(
            new_cves, release_info, existing_bugs
        )

        self.logger.info(
            "Creating new security bug",
            title=title,
            cves=new_cves,
            version=linux_version,
        )

        # Prepare see_also URLs if Chromium issues are available
        see_also = None
        if "chromium_issues" in release_info and release_info["chromium_issues"]:
            see_also = release_info["chromium_issues"]

        # Prepare blocks - new bug should block existing bugs for related CVEs
        blocks = None
        if existing_bugs:
            blocks = list(existing_bugs.values())

        try:
            # In dry run mode, just log what would be done
            if self.dry_run:
                self.logger.info(
                    "DRY RUN - Would create security bug",
                    title=title,
                    cves=new_cves,
                    version=linux_version,
                    chromium_issues=see_also,
                    blocks=blocks,
                    description_preview=description[:200] + "..."
                    if len(description) > 200
                    else description,
                )
                return 999999  # Return fake bug ID for dry run

            # Create the bug using the bugzilla client
            bug_id = self.bugzilla.create_security_bug(
                title=title,
                description=description,
                cves=new_cves,
                url=release_info["url"],
                see_also=see_also,
                blocks=blocks,
            )

            self.logger.info(
                "Successfully created security bug",
                bug_id=bug_id,
                title=title,
                cves=new_cves,
                chromium_issues=release_info.get("chromium_issues", []),
            )

            return bug_id

        except Exception as e:
            self.logger.error(
                "Error creating security bug",
                error=str(e),
                title=title,
                cves=new_cves,
                exc_info=True,
            )
            return None

    def process_bug(self, bug) -> bool:
        """Process a single bug to update with version constraints."""
        try:
            # Check if title already has version constraints - if so, skip it
            if self._has_version_constraints(bug.summary):
                self.logger.info(
                    "Bug title already has version constraints, skipping",
                    bug_id=bug.id,
                    title=bug.summary,
                )
                return False

            # Get comments for the bug
            comments = self.bugzilla.get_bug_comments(bug.id)
            if not comments:
                self.logger.info("No comments found for bug", bug_id=bug.id)
                return False

            # Parse Larry's comments to extract fixed versions
            fixed_versions = self.parse_larry_comments(comments)
            if not fixed_versions:
                self.logger.info(
                    "No version fix information found in bug", bug_id=bug.id
                )
                return False

            self.logger.info(
                "Found fixed versions", bug_id=bug.id, fixed_versions=fixed_versions
            )

            # Generate updated title
            new_title = self._generate_updated_title(bug.summary, fixed_versions)

            # Check if title actually changed
            if new_title == bug.summary:
                self.logger.info("Title already up to date for bug", bug_id=bug.id)
                return False

            self.logger.info(
                "Title update needed",
                bug_id=bug.id,
                original_title=bug.summary,
                new_title=new_title,
            )

            # Prepare automation comment
            automation_comment = (
                "Bug title automatically updated based on commit information from package updates. "
                f"Fixed versions detected: {', '.join(f'{pkg}-{ver}' for pkg, ver in fixed_versions.items())}"
            )

            # In dry run mode, just log what would be done without making actual updates
            if self.dry_run:
                self.logger.info(
                    "DRY RUN - Would update bug",
                    bug_id=bug.id,
                    original_title=bug.summary,
                    new_title=new_title,
                    automation_comment=automation_comment,
                )
                return True

            # Update the bug (only in non-dry-run mode)
            return self.bugzilla.update_bug(
                bug_id=bug.id, summary=new_title, comment=automation_comment
            )

        except Exception as e:
            self.logger.error(
                "Error updating bug", bug_id=bug.id, error=str(e), exc_info=True
            )
            return False

    def parse_larry_comments(self, comments: List[Dict]) -> Dict[str, str]:
        """Parse Larry the Git Cow's comments to extract version information."""
        fixed_versions = {}

        # Version regex for matching versions like 140.0.7339.80
        version_re = r"(\d+(?:\.\d+)*(?:\.\d+)?(?:\.\d+)?)"

        # Pattern for ebuild filename matches (e.g. "google-chrome-140.0.7339.80.ebuild")
        filename_pattern = re.compile(
            rf"((?:chromium|google-chrome)-{version_re}\.ebuild)"
        )

        # Pattern for commit-style messages
        commitmsg_pattern = re.compile(
            rf"(www-client/(?:chromium|google-chrome))[:\s][^\n\r]*?\(?({version_re})\)?"
        )

        for comment in comments:
            # Check if comment is from Larry the Git Cow
            if comment.get(
                "creator", ""
            ) == "infra-gitbot@gentoo.org" or "Larry the Git Cow" in comment.get(
                "text", ""
            ):
                comment_text = comment.get("text", "")

                # Fast skip if comment doesn't look like it contains commit info
                if (
                    "commit" not in comment_text
                    and "www-client" not in comment_text
                    and "google-chrome" not in comment_text
                    and "chromium" not in comment_text
                ):
                    continue

                # 1) Try existing ebuild path based extraction (most accurate when paths are present)
                ebuild_matches = self.ebuild_pattern.findall(comment_text)
                for package, version in ebuild_matches:
                    if (
                        package not in fixed_versions
                        or self._compare_versions(version, fixed_versions[package]) > 0
                    ):
                        fixed_versions[package] = version

                # 2) Look for standalone ebuild filenames (e.g. "google-chrome-140.0.7339.80.ebuild")
                for m in filename_pattern.finditer(comment_text):
                    full_match = m.group(0)  # e.g. "google-chrome-140.0.7339.80.ebuild"
                    ver = m.group(2)  # Extract just the version number
                    # determine package by the filename
                    if full_match.startswith("google-chrome"):
                        pkg = "www-client/google-chrome"
                    else:
                        pkg = "www-client/chromium"

                    if (
                        pkg not in fixed_versions
                        or self._compare_versions(ver, fixed_versions[pkg]) > 0
                    ):
                        fixed_versions[pkg] = ver

                # 3) Look for commit message style lines like "www-client/google-chrome: automated update (140.0.7339.80)"
                for m in commitmsg_pattern.finditer(comment_text):
                    pkg = m.group(1)
                    ver = m.group(2)
                    if (
                        pkg not in fixed_versions
                        or self._compare_versions(ver, fixed_versions[pkg]) > 0
                    ):
                        fixed_versions[pkg] = ver

        return fixed_versions

    def _compare_versions(self, v1: str, v2: str) -> int:
        """Compare two version strings using version comparison logic."""
        return self.version_utils.compare_versions(v1, v2)

    def _get_ebuild_version(self, version: tuple) -> str:
        """Convert (version, revision) tuple to ebuild version string."""
        return self.version_utils.get_ebuild_version(version)

    def _has_version_constraints(self, title: str) -> bool:
        """Delegate to VersionUtils with Chromium-related package names."""
        packages = ["www-client/chromium", "www-client/google-chrome"]
        return self.version_utils.has_version_constraints(title, packages=packages)

    def _generate_updated_title(
        self, original_title: str, fixed_versions: Dict[str, str]
    ) -> str:
        """Generate updated bug title with fixed version information."""
        if not fixed_versions:
            return original_title

        # Pattern to match existing version constraints in title
        version_constraint_pattern = re.compile(
            r"<(www-client/(?:chromium|google-chrome))-[\d.]+"
        )

        # If title already has version constraints, update them
        if version_constraint_pattern.search(original_title):
            updated_title = original_title
            for package, version in fixed_versions.items():
                # Replace existing constraints with new ones
                pattern = rf"<{re.escape(package)}-[\d.]+"
                replacement = f"<{package}-{version}"
                updated_title = re.sub(pattern, replacement, updated_title)
        else:
            # Add version constraints to packages mentioned in title
            updated_title = original_title
            for package, version in fixed_versions.items():
                # Replace package name with version-constrained package
                pattern = rf"\b{re.escape(package)}\b"
                replacement = f"<{package}-{version}"
                updated_title = re.sub(pattern, replacement, updated_title)

        return updated_title

    def bump_chrome(
        self,
        channels: List[str],
        link_bugs: bool,
        repo_path: str,
        dry_run: bool = False,
    ) -> Dict[str, int]:
        """
        Bump Chrome packages to latest versions.

        This implements the chrome-bump logic for automated version bumping.

        Args:
            channels: List of channels to bump ("stable", "beta", "dev")
            link_bugs: Whether to search for and link CVE bugs (stable only)
            repo_path: Path to Gentoo repository
            dry_run: If True, don't make actual changes

        Returns:
            Dict with counts of bumped, skipped, and error packages
        """
        from portage.dbapi.porttree import portdbapi
        from portage.versions import pkgsplit

        self.logger.info("Starting Chrome version bump", channels=channels)

        # Fetch upstream version information
        self.logger.info("Fetching upstream version information")
        chrome_info = {}
        for channel in ["stable", "beta", "dev"]:
            try:
                version = self._get_chrome_version_for_channel(channel)
                chrome_info[channel] = version
                self.logger.info(
                    f"Upstream {channel} version", channel=channel, version=version
                )
            except Exception as e:
                self.logger.error(
                    f"Failed to fetch {channel} version",
                    channel=channel,
                    error=str(e),
                )
                chrome_info[channel] = None

        # Initialize portage and git
        db = portdbapi()

        # Package configuration matching chrome-bump
        pkg_data = {
            "www-client": {
                "stable": {
                    "pkg": "google-chrome",
                    "suffix": None,
                    "version": None,
                    "bump": False,
                    "stable": True,
                },
                "beta": {
                    "pkg": "google-chrome-beta",
                    "suffix": None,
                    "version": None,
                    "bump": False,
                    "stable": False,
                },
                "dev": {
                    "pkg": "google-chrome-unstable",
                    "suffix": None,
                    "version": None,
                    "bump": False,
                    "stable": False,
                },
            },
            "www-plugins": {
                "stable": {
                    "pkg": "chrome-binary-plugins",
                    "suffix": None,
                    "version": None,
                    "bump": False,
                    "stable": True,
                },
                "beta": {
                    "pkg": "chrome-binary-plugins",
                    "suffix": "beta",
                    "version": None,
                    "bump": False,
                    "stable": False,
                },
                "dev": {
                    "pkg": "chrome-binary-plugins",
                    "suffix": "alpha",
                    "version": None,
                    "bump": False,
                    "stable": False,
                },
            },
            "www-apps": {
                "stable": {
                    "pkg": "chromedriver-bin",
                    "suffix": None,
                    "version": None,
                    "bump": False,
                    "stable": True,
                }
            },
        }

        # Look up current versions in tree
        self.logger.info("Looking up Chrome version information in tree")
        for category in pkg_data.keys():
            for channel in ["stable", "beta", "dev"]:
                # chromedriver-bin only has stable
                if category == "www-apps" and channel != "stable":
                    continue

                pkg = pkg_data[category][channel]["pkg"]
                cpvs = db.cp_list(mycp=f"{category}/{pkg}", mytree=repo_path)
                pkg_data[category][channel]["version"] = None

                for cpv in cpvs:
                    cp, version, rev = pkgsplit(mypkg=cpv)
                    suffix = pkg_data[category][channel]["suffix"]
                    if suffix is not None:
                        suffix = "_" + suffix
                        if version.endswith(suffix):
                            pkg_data[category][channel]["version"] = (
                                version[: -len(suffix)],
                                rev,
                            )
                    elif "_" not in version:
                        pkg_data[category][channel]["version"] = (version, rev)

                if pkg_data[category][channel]["version"] is None:
                    self.logger.warning(
                        f"Couldn't determine tree version for {category}/{pkg}"
                    )

        # Compare versions and determine what needs bumping
        self.logger.info("Comparing Chrome version information")
        for channel in ["stable", "beta", "dev"]:
            if chrome_info[channel] is None:
                self.logger.warning(f"Upstream version unknown for channel {channel}")
                continue

            for category in pkg_data.keys():
                # chromedriver-bin mirrors google-chrome stable
                if category == "www-apps":
                    if channel == "stable":
                        pkg_data[category][channel]["bump"] = pkg_data["www-client"][
                            channel
                        ]["bump"]
                        pkg_data[category][channel]["version"] = pkg_data["www-client"][
                            channel
                        ]["version"]
                    else:
                        continue
                else:
                    pkg_data[category][channel]["bump"] = False

                if pkg_data[category][channel]["version"] is None:
                    continue

                ver_info = self.version_utils.compare_versions(
                    chrome_info[channel], pkg_data[category][channel]["version"][0]
                )

                if ver_info is None:
                    self.logger.warning(
                        f"Cannot determine new version for {channel} of "
                        f"{category}/{pkg_data[category][channel]['pkg']}"
                    )
                elif ver_info > 0:
                    pkg_data[category][channel]["bump"] = True
                elif ver_info < 0:
                    self.logger.warning(
                        f"Upstream reverted bump for {channel} of "
                        f"{category}/{pkg_data[category][channel]['pkg']}"
                    )

        # Display version information
        for category in pkg_data.keys():
            for channel in ["stable", "beta", "dev"]:
                if category == "www-apps" and channel != "stable":
                    continue

                pkg = pkg_data[category][channel]["pkg"]
                need_bump = pkg_data[category][channel]["bump"]
                uversion = chrome_info[channel]
                tversion = (
                    self._get_ebuild_version(pkg_data[category][channel]["version"])
                    if pkg_data[category][channel]["version"]
                    else "unknown"
                )

                self.logger.info(
                    f"{category}/{pkg} version information",
                    channel=channel,
                    tree_version=tversion,
                    upstream_version=uversion,
                    action="bump" if need_bump else "no bump",
                )

        # Initialize EbuildManager
        ebuild_mgr = EbuildManager(
            repo_path=repo_path, logger=self.logger, dry_run=dry_run
        )

        # Perform bumps
        result = {"bumped": 0, "skipped": 0, "errors": 0}

        for channel in channels:
            for category in pkg_data.keys():
                if category == "www-apps" and channel != "stable":
                    continue

                if not pkg_data[category][channel]["bump"]:
                    continue

                try:
                    self._bump_chrome_package(
                        category=category,
                        channel=channel,
                        pkg_data=pkg_data,
                        chrome_info=chrome_info,
                        ebuild_mgr=ebuild_mgr,
                        link_bugs=link_bugs and channel == "stable",
                        dry_run=dry_run,
                    )
                    result["bumped"] += 1
                except Exception as e:
                    self.logger.error(
                        "Failed to bump package",
                        category=category,
                        channel=channel,
                        error=str(e),
                    )
                    result["errors"] += 1

        return result

    def _get_chrome_version_for_channel(self, channel: str) -> str:
        """
        Fetch Chrome version for a specific channel from Google's version API.

        Args:
            channel: Channel name ("stable", "beta", or "dev")

        Returns:
            Version string (e.g., "131.0.6778.33")
        """
        base_url = "https://versionhistory.googleapis.com/v1/chrome/platforms"
        url = f"{base_url}/linux/channels/{channel}/versions/all/releases?filter=endtime=1970-01-01T00:00:00Z"

        response = urllib.request.urlopen(url)
        data = json.loads(response.read())
        return data["releases"][0]["version"]

    def _get_prev_channel(self, channel: str) -> str:
        """Get the previous channel for cross-channel copying during major bumps."""
        return get_prev_channel_generic(channel, ["stable", "beta", "dev"])

    def _bump_chrome_package(
        self,
        category: str,
        channel: str,
        pkg_data: Dict,
        chrome_info: Dict,
        ebuild_mgr: EbuildManager,
        link_bugs: bool,
        dry_run: bool,
    ):
        """Bump a single Chrome package (google-chrome, chrome-binary-plugins, or chromedriver-bin)."""
        uversion = chrome_info[channel]
        tversion = self._get_ebuild_version(pkg_data[category][channel]["version"])
        pkg = pkg_data[category][channel]["pkg"]
        suffix = pkg_data[category][channel]["suffix"]
        atom = f"{category}/{pkg}"

        # Determine if this is a major bump
        major_bump = is_major_bump(
            pkg_data[category][channel]["version"][0],
            uversion,
            channel,
            self._get_prev_channel,
        )

        self.logger.info(
            f"Bumping {atom}",
            channel=channel,
            version=uversion,
            major_bump=major_bump,
        )

        # Determine source ebuild
        source_atom = None
        source_version = None
        keywords = None

        if major_bump:
            if category != "www-apps":
                # Copy from previous channel
                prev_channel = self._get_prev_channel(channel)
                prev_pkg = pkg_data[category][prev_channel]["pkg"]
                prev_version = self._get_ebuild_version(
                    pkg_data[category][prev_channel]["version"]
                )
                prev_suffix = pkg_data[category][prev_channel]["suffix"]

                # Build source atom and version
                source_atom = f"{category}/{prev_pkg}"
                if prev_suffix:
                    source_version = f"{prev_version}_{prev_suffix}"
                else:
                    source_version = prev_version
            else:
                # chromedriver-bin copies from itself (stable only)
                source_atom = atom
                source_version = tversion

            # Set keywords for stable channel major bumps
            if pkg_data[category][channel]["stable"]:
                keywords = ["amd64"]
        else:
            # For non-major bumps, copy from the current version in same package
            source_atom = atom
            if suffix:
                source_version = f"{tversion}_{suffix}"
            else:
                source_version = tversion

        # Build new version with suffix if needed
        new_version = uversion
        if suffix:
            new_version = f"{uversion}_{suffix}"

        # Search for CVEs if this is a stable channel bump with link_bugs enabled
        # Only check CVEs for the main Chrome browser package, not plugins or chromedriver
        bug_urls = []
        if link_bugs and category == "www-client":
            try:
                cves = self._get_cves_for_chrome_version(uversion)
                if cves:
                    self.logger.info(
                        f"Found CVEs for Chrome {uversion}", cves=cves, count=len(cves)
                    )
                    # Check existing bugs
                    existing_bugs = self.bugzilla.check_existing_bugs_for_cves(cves)
                    for cve, bug_id in existing_bugs.items():
                        if bug_id:
                            bug_url = f"https://bugs.gentoo.org/{bug_id}"
                            bug_urls.append(bug_url)
                            self.logger.info(f"Linking bug for {cve}", url=bug_url)
            except Exception as e:
                self.logger.warning("Failed to search for CVEs", error=str(e))

        # Perform the bump
        remove_old = not major_bump  # Only remove old if not a major bump

        try:
            ebuild_mgr.bump_ebuild(
                atom=atom,
                new_version=new_version,
                source_atom=source_atom,
                source_version=source_version,
                keywords=keywords,
                remove_old=remove_old,
                bug_urls=bug_urls if bug_urls else None,
            )
            self.logger.info(
                "Successfully bumped package", atom=atom, version=new_version
            )
        except Exception as e:
            self.logger.error("Failed to bump package", atom=atom, error=str(e))
            raise

    def _get_cves_for_chrome_version(self, version: str) -> List[str]:
        """
        Get CVEs for a specific Chrome version from the security blog.

        Args:
            version: Chrome version string (e.g., "131.0.6778.33")

        Returns:
            List of CVE IDs
        """
        releases = self.parse_chrome_releases(limit_releases=10)

        for release in releases:
            if release.get("linux_version") == version:
                return release.get("cves", [])

        return []
