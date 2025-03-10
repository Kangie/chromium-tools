#!/usr/bin/env python3

import argparse
import logging
import os
import re
import requests
import subprocess

# Configure logging
logging.basicConfig(
    format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO,
    datefmt='%Y-%m-%d %H:%M:%S')


def get_commit(version_url):
    """Fetches the git hash from the Chromium ffmpeg submodule URL using requests.

    Args:
      version_url: The URL of the Chromium ffmpeg submodule for a specific version.

    Returns:
      The git commit hash found in the submodule URL, or None if not found.
    """
    try:
        # Use requests.get to fetch the URL content
        response = requests.get(version_url)
        response.raise_for_status()  # Raise exception for non-200 status codes

        # Search for commit hash within the 'gitlink-detail' class (adapt if needed)
        match = re.search(
            r'<div class="gitlink-detail">Submodule link to (.*?) of', response.text)
        if match:
            return match.group(1)
        else:
            return None
    except requests.exceptions.RequestException as e:
        logging.error(f"Error: Failed to fetch URL {version_url} - {e}")
        return None


def archive_ffmpeg(version, commit_hash):
    """Archives the Chromium ffmpeg repository at the specified commit hash.

    Args:
      version: The Chromium major version (e.g. 123).
      commit_hash: The git commit hash of the desired ffmpeg revision.
    """
    # Base directory for ffmpeg checkout (configurable)
    ffmpeg_dir = os.getenv("FFMPEG_TEMP_DIR", "/tmp/ffmpeg")
    # Archive filename with version substitution
    archive_name = f"/tmp/ffmpeg-chromium-{version}.tar.xz"

    repo_uri = "https://chromium.googlesource.com/chromium/third_party/ffmpeg"

    # Check if ffmpeg directory already exists
    if os.path.exists(ffmpeg_dir):
        # Verify remote URL matches expected repository
        try:
            output = subprocess.run(
                ["git", "remote", "-v"], cwd=ffmpeg_dir, capture_output=True, check=True).stdout.decode()
            if not re.search(repo_uri, output, re.MULTILINE):
                logging.error(
                    f"Existing ffmpeg directory {ffmpeg_dir} points to a different remote. Please remove and re-clone.")
                exit(1)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error verifying remote URL: {e}")
            exit(1)

        # Update existing repository
        try:
            subprocess.run(["git", "pull"], cwd=ffmpeg_dir, check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error updating ffmpeg repository: {e}")
            exit(1)
    else:
        # Clone the Chromium ffmpeg repository
        try:
            subprocess.run(
                ["git", "clone", repo_uri, ffmpeg_dir], check=True)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error cloning ffmpeg repository: {e}")
            exit(1)

    # Archive the ffmpeg directory with prefix and specific commit hash
    try:
        logging.info(
            f"Archiving ffmpeg-chromium@{commit_hash}, this may take a moment...")
        subprocess.run(["git", "archive", "--format=tar.xz", "-o", archive_name,
                       f"--prefix=ffmpeg-chromium-{version}/", commit_hash], cwd=ffmpeg_dir, check=True)
        logging.info(
            f"ffmpeg-chromium@{commit_hash} archived to {archive_name}")
    except subprocess.CalledProcessError as e:
        logging.error(f"Error archiving ffmpeg: {e}")


def copy_and_update_ebuild(version, commit_hash):
    """Copies the latest ffmpeg-chromium.ebuild and updates the COMMIT variable.

    Args:
      version: The Chromium version (e.g., 124).
      commit_hash: The git commit hash of the desired ffmpeg revision.
    """
    # Target directory for ffmpeg-chromium ebuilds (configurable)
    ebuild_dir = os.getenv("FFMPEG_EBUILD_DIR",
                           "/var/db/repos/gentoo/media-video/ffmpeg-chromium")
    # Destination ebuild filename with version substitution
    dest_ebuild = f"ffmpeg-chromium-{version}.ebuild"

    # Find the highest version ebuild file
    highest_version = None
    for filename in os.listdir(ebuild_dir):
        match = re.match(r"ffmpeg-chromium-(\d+)\.ebuild", filename)
        if match:
            current_version = int(match.group(1))
            if highest_version is None or current_version > highest_version:
                highest_version = current_version
                highest_ebuild = os.path.join(ebuild_dir, filename)
                # Check if a higher version ebuild exists
    if highest_version:
        # Copy the highest version ebuild
        try:
            subprocess.run(["cp", highest_ebuild,
                            os.path.join(ebuild_dir, dest_ebuild)],
                           check=True,)
        except subprocess.CalledProcessError as e:
            logging.error(f"Error copying ebuild file: {e}")
            exit(1)

        logging.info(
            f"Copied ffmpeg-chromium-{highest_version}.ebuild to {dest_ebuild}"
        )

        # Update the COMMIT variable in the copied ebuild
        with open(os.path.join(ebuild_dir, dest_ebuild), "r+") as f:
            lines = f.readlines()
            for i, line in enumerate(lines):
                if line.startswith("COMMIT="):
                    lines[i] = f"COMMIT={commit_hash}\n"
                    f.seek(0)
                    f.writelines(lines)
                    logging.info(
                        f"Updated COMMIT variable in {dest_ebuild} to {commit_hash}")
                    break
    else:
        logging.info(
            f"No existing ffmpeg-chromium ebuilds found in {ebuild_dir}")


def main():
    """Main function to handle user input and script execution."""
    parser = argparse.ArgumentParser(description="Package Chromium ffmpeg for a specific version.")
    parser.add_argument("version", type=str, help="Chromium version (e.g., 123.0.4567.890)")
    args = parser.parse_args()

    version_regex = r"^\d+\.\d+(?:\.\d+(?:\.\d+)?)?$"  # Validate version format
    version = args.version

    if not re.match(version_regex, version):
        print("Invalid version format. Please enter a version like X.Y.Z.W (e.g., 123.0.4567.890)")
        exit(1)

    version_url = f"https://chromium.googlesource.com/chromium/src.git/+/refs/tags/{version}/third_party/ffmpeg"
    commit_hash = get_commit(version_url)
    if commit_hash:
        logging.info(
            f"Chromium version {version} uses ffmpeg commit {commit_hash}")
        major_version = version.split(".")[0]
        archive_ffmpeg(major_version, commit_hash)
        copy_and_update_ebuild(major_version, commit_hash)
    else:
        logging.error(
            f"Failed to retrieve commit hash for Chromium version {version}")


if __name__ == "__main__":
    main()
