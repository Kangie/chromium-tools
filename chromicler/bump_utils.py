#!/usr/bin/env python3
"""
Shared utilities for ebuild bump operations.

This module contains bump-specific logic for channel management,
major bump detection, and version count limits.
"""

from typing import List, Tuple


def is_major_bump(
    current_version: str, target_version: str, channel: str, get_prev_channel_func
) -> bool:
    """
    Determine if this is a major version bump requiring cross-channel copying.

    A major bump occurs when the first version component increases (e.g., 130.x -> 131.x)
    AND we're not already at the lowest channel (since dev/developer copy from themselves).

    Args:
        current_version: Current version string (e.g., "130.0.6723.58")
        target_version: Target version string (e.g., "131.0.6778.33")
        channel: Current channel being bumped ("stable", "beta", "dev")
        get_prev_channel_func: Function to get the previous channel for this handler

    Returns:
        True if this is a major bump requiring cross-channel copy
    """
    current_parts = current_version.split(".")
    target_parts = target_version.split(".")

    # Compare first component (major version)
    try:
        current_major = int(current_parts[0])
        target_major = int(target_parts[0])

        if target_major > current_major:
            # It's a major bump if we're not copying from ourselves
            prev_channel = get_prev_channel_func(channel)
            return prev_channel != channel
    except (ValueError, IndexError):
        pass

    return False


def get_prev_channel_generic(channel: str, channels: List[str]) -> str:
    """
    Get the previous channel in the progression for cross-channel copying.

    The channel list represents the progression (e.g., ["stable", "beta", "dev"]).
    The last channel copies from itself (dev -> dev, developer -> developer).

    Args:
        channel: Current channel
        channels: List of channels in order (stable -> beta -> dev)

    Returns:
        Previous channel name (or same channel if already at end)

    Raises:
        ValueError: If channel is not in the list
    """
    # Append the last channel to itself so dev -> dev, developer -> developer
    channel_list = channels + [channels[-1]]

    for i in range(len(channel_list) - 1):
        if channel_list[i] == channel:
            return channel_list[i + 1]

    raise ValueError(f'Unknown channel "{channel}". Valid channels: {channels}')


def calculate_versions_to_remove(
    current_versions: List[Tuple[str, str]],
    versions_to_add: List[Tuple[str, str]],
    max_count: int,
) -> List[Tuple[str, str]]:
    """
    Calculate which old versions should be removed based on count limits.

    Args:
        current_versions: List of current versions in tree (sorted newest first)
        versions_to_add: List of new versions to add
        max_count: Maximum number of versions to keep for this channel

    Returns:
        List of versions to remove
    """
    if not versions_to_add:
        return []

    # Total versions after adding new ones
    total_after_bump = len(current_versions) + len(versions_to_add)

    # If we'd have more than max_count, remove oldest versions
    if total_after_bump > max_count:
        # How many to remove
        remove_count = total_after_bump - max_count
        # Remove from the end (oldest versions)
        return current_versions[-remove_count:]

    return []


def limit_new_versions(
    new_versions: List[Tuple[str, str]], max_count: int
) -> List[Tuple[str, str]]:
    """
    Limit the number of new versions to bump to.

    Args:
        new_versions: List of new versions (sorted newest first)
        max_count: Maximum number of versions to keep

    Returns:
        Limited list of new versions (newest max_count items)
    """
    if len(new_versions) > max_count:
        return new_versions[:max_count]
    return new_versions


def bump_browser_package(
    atom: str,
    channel: str,
    uversion: str,
    tversion: str,
    major_bump: bool,
    pkg_data: dict,
    ebuild_mgr,
    repo_path: str,
    dry_run: bool,
    logger,
    get_ebuild_version_func,
    get_prev_channel_func,
    enable_stabilization: bool = True,
):
    """
    Generic browser package bump implementation for Edge/Opera/NewBrowserOfTheWeek.

    This handles the common pattern:
    1. Determine source ebuild (from previous channel if major bump, or current version)
    2. Set keywords (~amd64 for stable channel major bumps)
    3. Copy metadata.xml if major bump
    4. Perform the bump
    5. Optionally stabilize (ekeyword amd64) for stable channel

    Args:
        atom: Package atom (e.g., "www-client/microsoft-edge")
        channel: Channel being bumped ("stable", "beta", "dev"/"developer")
        uversion: Upstream version to bump to
        tversion: Current tree version
        major_bump: Whether this is a major version bump
        pkg_data: Dictionary containing package data for all channels
        ebuild_mgr: EbuildManager instance
        repo_path: Path to the repository
        dry_run: Whether this is a dry run
        logger: Logger instance
        get_ebuild_version_func: Function to convert version tuple to string
        get_prev_channel_func: Function to get previous channel
        enable_stabilization: Whether to enable two-phase stabilization (default: True)

    Returns:
        None

    Raises:
        Exception: If bump or stabilization fails
    """
    import shutil
    import subprocess
    from pathlib import Path

    # Convert repo_path to Path object once and extract atom components
    repo = Path(repo_path)
    category, pkg_name = atom.split("/")

    logger.info(
        f"Bumping {atom}",
        channel=channel,
        version=uversion,
        major_bump=major_bump,
    )

    # Determine source
    source_atom = None
    source_version = None
    keywords = None

    if major_bump:
        prev_channel = get_prev_channel_func(channel)
        prev_pkg = pkg_data[prev_channel]["pkg"]
        prev_version = get_ebuild_version_func(pkg_data[prev_channel]["version"][0])

        source_atom = f"{category}/{prev_pkg}"
        source_version = prev_version

        # Set keywords for stable channel major bumps
        if pkg_data[channel]["stable"]:
            keywords = ["~amd64"]

        # Copy metadata.xml if major bump
        if not dry_run:
            try:
                from_meta = repo / category / prev_pkg / "metadata.xml"
                to_meta = repo / category / pkg_name / "metadata.xml"
                if from_meta.exists():
                    shutil.copyfile(from_meta, to_meta)
                    ebuild_mgr.repo.index.add([str(to_meta)])
                    logger.info(f"Copied metadata.xml from {prev_pkg}")
            except Exception as e:
                logger.warning("Failed to copy metadata.xml", error=str(e))
    else:
        # For non-major bumps, copy from the current version in same package
        source_atom = atom
        source_version = tversion

    # Perform the bump
    try:
        ebuild_mgr.bump_ebuild(
            atom=atom,
            new_version=uversion,
            source_atom=source_atom,
            source_version=source_version,
            keywords=keywords,
            remove_old=False,  # We handle cleanup separately
            commit_message=f"{atom}: automated bump ({uversion})",
        )
        logger.info("Successfully bumped package", atom=atom, version=uversion)
    except Exception as e:
        logger.error("Failed to bump package", atom=atom, error=str(e))
        raise

    # Stabilization phase for stable channel (two-phase workflow)
    if enable_stabilization and pkg_data[channel]["stable"] and not dry_run:
        try:
            pkg_dir = repo / category / pkg_name
            ebuild_file = pkg_dir / f"{pkg_name}-{uversion}.ebuild"

            # Run ekeyword to stabilize
            subprocess.check_call(["ekeyword", "amd64", str(ebuild_file)])
            ebuild_mgr.repo.index.add([str(ebuild_file)])

            # Regenerate Manifest
            from portage.package.ebuild import digestgen, config
            from portage.dbapi.porttree import portdbapi

            cfg = config.config()
            cfg["O"] = str(pkg_dir)
            db = portdbapi()
            digestgen.digestgen(None, cfg, db)

            manifest_path = pkg_dir / "Manifest"
            ebuild_mgr.repo.index.add([str(manifest_path)])

            # Commit stabilization
            ebuild_mgr.repo.git.commit(
                "-m",
                f"{atom}: amd64 stable ({uversion})",
                "-s",
                "-S",
            )
            logger.info(f"Stabilized {atom} {uversion} to amd64")
        except Exception as e:
            logger.error(f"Failed to stabilize {atom}", error=str(e))
            raise
