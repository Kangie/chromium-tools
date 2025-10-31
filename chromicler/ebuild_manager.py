#!/usr/bin/env python3
"""
Ebuild management for Gentoo packages.

This module handles ebuild operations including version bumps, manifest generation,
and git commit operations for Gentoo package updates.
"""

import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import structlog
from git import Repo, GitCommandError

from version_utils import VersionUtils

try:
    from portage.dbapi.porttree import portdbapi
    from portage.package.ebuild import digestgen, config
    from portage.versions import catpkgsplit

    PORTAGE_AVAILABLE = True
except ImportError:
    PORTAGE_AVAILABLE = False


class EbuildManager:
    """
    Manages Gentoo ebuild operations including version bumps and git commits.

    This class provides a Python-native interface to ebuild manipulation,
    using GitPython for version control and the portage API for package
    operations.
    """

    def __init__(
        self,
        repo_path: str,
        logger: Optional[structlog.BoundLogger] = None,
        dry_run: bool = False,
    ):
        """
        Initialize the EbuildManager.

        Args:
            repo_path: Path to the Gentoo repository (e.g., /var/db/repos/gentoo)
            logger: Structured logger instance
            dry_run: If True, don't make actual changes (preview mode)
        """
        self.repo_path = Path(repo_path)
        self.logger = logger or structlog.get_logger()
        self.dry_run = dry_run
        self.version_utils = VersionUtils()

        if not PORTAGE_AVAILABLE:
            raise ImportError(
                "Portage not available. Install portage or use a Gentoo system "
                "to use ebuild management features."
            )

        if not self.repo_path.exists():
            raise ValueError(f"Repository path does not exist: {repo_path}")

        self.portdb = portdbapi(mysettings=None)

        try:
            self.repo = Repo(str(self.repo_path))
        except Exception as e:
            raise ValueError(f"Invalid git repository at {repo_path}: {e}")

        self.logger.info(
            "EbuildManager initialized",
            repo_path=str(self.repo_path),
            dry_run=self.dry_run,
        )

    def get_package_versions(self, atom: str) -> List[Tuple[str, str]]:
        """
        Get all available versions of a package in the tree.

        Args:
            atom: Package atom (e.g., "www-client/google-chrome")

        Returns:
            List of (version, ebuild_path) tuples, sorted by version
        """
        category, package = atom.split("/")
        pkg_dir = self.repo_path / category / package

        if not pkg_dir.exists():
            self.logger.warning(
                "Package directory not found", atom=atom, path=str(pkg_dir)
            )
            return []

        versions = []
        for ebuild_file in pkg_dir.glob("*.ebuild"):
            # Extract version from filename: package-version.ebuild
            filename = ebuild_file.stem  # Remove .ebuild
            if filename.startswith(package + "-"):
                version = filename[len(package) + 1 :]
                versions.append((version, str(ebuild_file)))

        # Sort by version using portage comparison
        def version_key(item):
            version, _ = item
            split = catpkgsplit(f"{atom}-{version}")
            return split if split else (category, package, version, "r0")

        versions.sort(key=version_key)

        self.logger.debug(
            "Found package versions",
            atom=atom,
            count=len(versions),
            versions=[v[0] for v in versions],
        )

        return versions

    def get_latest_version(self, atom: str) -> Optional[str]:
        """
        Get the latest version of a package in the tree.

        Args:
            atom: Package atom (e.g., "www-client/google-chrome")

        Returns:
            Latest version string, or None if package not found
        """
        versions = self.get_package_versions(atom)
        return versions[-1][0] if versions else None

    def bump_ebuild(
        self,
        atom: str,
        new_version: str,
        source_atom: Optional[str] = None,
        source_version: Optional[str] = None,
        keywords: Optional[List[str]] = None,
        remove_old: bool = True,
        commit_message: Optional[str] = None,
        bug_urls: Optional[List[str]] = None,
    ) -> Dict[str, any]:
        """
        Bump an ebuild to a new version.

        This performs the following operations:
        1. Copy the source ebuild to the new version
        2. Optionally remove the old version
        3. Update keywords if specified
        4. Generate Manifest
        5. Git add and commit

        Args:
            atom: Package atom to bump (e.g., "www-client/google-chrome")
            new_version: New version to bump to
            source_atom: Optional different package to copy from (for major bumps)
            source_version: Optional specific version to copy from
            keywords: List of keywords to set (e.g., ["~amd64", "~x86"])
            remove_old: If True, remove the previous version
            commit_message: Custom commit message (auto-generated if None)
            bug_urls: List of bug URLs to add to commit message

        Returns:
            Dict with operation results
        """
        category, package = atom.split("/")
        pkg_dir = self.repo_path / category / package

        self.logger.info(
            "Bumping ebuild",
            atom=atom,
            new_version=new_version,
            source_atom=source_atom,
            source_version=source_version,
            dry_run=self.dry_run,
        )

        # Determine source ebuild
        if source_atom and source_version:
            # Copy from specified source (may be same or different package)
            source_category, source_package = source_atom.split("/")
            source_pkg_dir = self.repo_path / source_category / source_package
            old_ebuild_path = (
                source_pkg_dir / f"{source_package}-{source_version}.ebuild"
            )
            if not old_ebuild_path.exists():
                raise ValueError(
                    f"Source ebuild not found: {source_atom}-{source_version}"
                )
            old_version = source_version

            if source_atom == atom:
                self.logger.info(
                    "Bumping ebuild using same-package source",
                    source_atom=source_atom,
                    source_version=source_version,
                )
            else:
                self.logger.info(
                    "Using cross-package source",
                    source_atom=source_atom,
                    source_version=source_version,
                )
        else:
            # Use latest version from same package
            versions = self.get_package_versions(atom)
            if not versions:
                raise ValueError(f"No existing ebuilds found for {atom}")
            old_version, old_ebuild_path = versions[-1]

        versions = self.get_package_versions(atom)
        if any(v[0] == new_version for v in versions):
            self.logger.warning("Version already exists", version=new_version)
            return {
                "success": False,
                "message": f"Version {new_version} already exists",
                "atom": atom,
                "version": new_version,
            }

        # Construct new ebuild filename
        new_ebuild_name = f"{package}-{new_version}.ebuild"
        new_ebuild_path = pkg_dir / new_ebuild_name

        result = {
            "success": True,
            "atom": atom,
            "old_version": old_version,
            "new_version": new_version,
            "old_ebuild": old_ebuild_path,
            "new_ebuild": str(new_ebuild_path),
            "operations": [],
        }

        # 1. Copy ebuild
        if self.dry_run:
            self.logger.info(
                "DRY RUN - Would copy ebuild",
                from_file=old_ebuild_path,
                to_file=str(new_ebuild_path),
            )
            result["operations"].append(f"cp {old_ebuild_path} {new_ebuild_path}")
        else:
            shutil.copyfile(old_ebuild_path, new_ebuild_path)
            self.logger.info("Copied ebuild", to=str(new_ebuild_path))
            result["operations"].append(f"copied {new_ebuild_name}")

        # 2. Remove old version if requested
        if remove_old:
            if self.dry_run:
                self.logger.info(
                    "DRY RUN - Would remove old ebuild",
                    file=old_ebuild_path,
                )
                result["operations"].append(f"git rm {old_ebuild_path}")
            else:
                try:
                    self.repo.index.remove([old_ebuild_path], working_tree=True)
                    self.logger.info("Removed old ebuild", file=old_ebuild_path)
                    result["operations"].append(f"removed {old_version}")
                except GitCommandError as e:
                    self.logger.warning(
                        "Failed to remove old ebuild from git",
                        file=old_ebuild_path,
                        error=str(e),
                    )

        # 3. Update keywords if specified
        if keywords:
            if self.dry_run:
                self.logger.info(
                    "DRY RUN - Would update keywords",
                    file=str(new_ebuild_path),
                    keywords=keywords,
                )
                result["operations"].append(
                    f"ekeyword {' '.join(keywords)} {new_ebuild_name}"
                )
            else:
                # Use ekeyword command via subprocess
                import subprocess

                try:
                    subprocess.run(
                        ["ekeyword"] + keywords + [str(new_ebuild_path)],
                        check=True,
                        capture_output=True,
                    )
                    self.logger.info("Updated keywords", keywords=keywords)
                    result["operations"].append(f"updated keywords: {keywords}")
                except subprocess.CalledProcessError as e:
                    self.logger.warning(
                        "Failed to update keywords",
                        error=e.stderr.decode() if e.stderr else str(e),
                    )

        # 4. Generate Manifest
        if self.dry_run:
            self.logger.info(
                "DRY RUN - Would generate Manifest",
                directory=str(pkg_dir),
            )
            result["operations"].append(f"ebuild {new_ebuild_name} manifest")
        else:
            try:
                cfg = config.config()
                cfg["O"] = str(pkg_dir)
                digestgen.digestgen(None, cfg, self.portdb)
                self.logger.info("Generated Manifest", directory=str(pkg_dir))
                result["operations"].append("generated Manifest")
            except Exception as e:
                self.logger.error(
                    "Failed to generate Manifest",
                    directory=str(pkg_dir),
                    error=str(e),
                )
                raise

        # 5. Git add and commit
        manifest_path = pkg_dir / "Manifest"

        if self.dry_run:
            msg = commit_message or f"{atom}: automated update ({new_version})"
            if bug_urls:
                msg += "\n\n" + "\n".join([f"Bug: {url}" for url in bug_urls])

            self.logger.info(
                "DRY RUN - Would git commit",
                message=msg,
                files=[str(new_ebuild_path), str(manifest_path)],
            )
            result["operations"].append(f"git commit -m '{msg}'")
            result["commit_message"] = msg
        else:
            files_to_add = [str(new_ebuild_path), str(manifest_path)]
            self.repo.index.add(files_to_add)

            msg = commit_message or f"{atom}: automated update ({new_version})"
            if bug_urls:
                msg += "\n\n" + "\n".join([f"Bug: {url}" for url in bug_urls])

            # Commit with signing
            try:
                self.repo.git.commit("-m", msg, "-s", "-S")
                self.logger.info(
                    "Committed changes",
                    message=msg,
                    files=files_to_add,
                )
                result["operations"].append("committed and signed")
                result["commit_message"] = msg
            except GitCommandError as e:
                self.logger.error(
                    "Failed to commit changes",
                    error=str(e),
                )
                raise

        return result

    def version_exists(self, atom: str, version: str) -> bool:
        """
        Check if a specific version of a package exists in the tree.

        Args:
            atom: Package atom (e.g., "www-client/google-chrome")
            version: Version to check

        Returns:
            True if version exists, False otherwise
        """
        versions = self.get_package_versions(atom)
        return any(v[0] == version for v in versions)

    def compare_versions(self, version1: str, version2: str) -> int:
        """
        Compare two versions using portage version comparison.

        Args:
            version1: First version
            version2: Second version

        Returns:
            -1 if version1 < version2
             0 if version1 == version2
             1 if version1 > version2
        """
        return self.version_utils.compare_versions(version1, version2)
