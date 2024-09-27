#!/usr/bin/env python

# SPDX-License-Identifier: GPL-2.0-or-later
# This script is used to extract Opera and Chromium versions from the Opera changelog (blog)
# This is incomplete data, so we need to fill in the gaps with the Chromium version from the previous known version
# The intent here is to have _some_ sort of datasource to identify a potentially-fixed version of Opera based on
# the Chromium version it includes.
# High level logic:
# We can fetch the opera blog posts that relate to a major version of Opera as long as they don't change their URIs.
# We iterate over H4 elements to get the Opera version (and date, though we throw that away)
# We then iterate over child elements until we find an "Update Chromium" entry, which we can use to get the
# Chromium version (in which case we bail early) Or we exhaust the children and give up.
# Lather, rinse, repeat.

import argparse, dataclasses

import requests
from bs4 import BeautifulSoup
from packaging.version import Version


@dataclasses.dataclass
class OperaChromiumVersion:
    opera_version: Version
    chromium_version: Version

    def __str__(self):
        chromium_version_str = 'unknown' if self.chromium_version == Version('0.0.0.0') else str(self.chromium_version)
        return f"Opera Version: {self.opera_version}, Chromium Version: {chromium_version_str}"


def get_opera_chromium_versions(base_url, start_version, end_version):
    """
    Extracts Opera and Chromium versions from the given base URL with version placeholders,
    parsing content sections for versions from start_version to end_version (inclusive).

    Args:
        base_url: The base URL for Opera changelogs with a version placeholder (e.g.,
            "https://blogs.opera.com/desktop/changelog-for-{version}/").
        start_version: The starting version to extract information for (inclusive).
        end_version: The ending version to extract information for (inclusive).

    Returns:
        A list of OperaChromiumVersion objects containing the extracted version information.
    """
    versions: list[OperaChromiumVersion] = []

    for version in range(start_version, end_version + 1):
        url = base_url.format(version)
        print(f"Processing version {version}")

        try:
            # Set a timeout to avoid hanging requests
            response = requests.get(url, timeout=5)
            response.raise_for_status()  # Raise exception for non-200 status codes

            soup = BeautifulSoup(response.content, 'html.parser')
            content = soup.find('div', class_='content')

            # Iterate through each section starting with an H4 element
            for section in content.find_all('h4'):
                chromium_version = None
                version_str, date_str = section.text.strip().split(' – ')

                # Process all content elements (including nested ones) until the next H4
                next_sibling = section.find_next_sibling(
                    lambda tag: tag.name is not None)  # Skip text nodes

                # Process content elements
                update_found = False
                while next_sibling and next_sibling.name != 'h4':
                    if next_sibling.name == 'ul':
                        for el in next_sibling.find_all('li'):
                            if 'Update Chromium' in el.text.strip():
                                update_found = True
                                break  # Stop iterating after finding update

                    # Assign Chromium version only if update is found
                    if update_found:
                        chromium_version = el.text.strip().split()[-1]

                    next_sibling = next_sibling.find_next_sibling(
                        lambda tag: tag.name is not None)  # Skip text nodes

                # Handle missing Chromium version
                if not chromium_version:
                    chromium_version = '0.0.0.0'

                versions.append(OperaChromiumVersion(
                    Version(version_str),
                    Version(chromium_version)
                ))

        except requests.exceptions.RequestException as e:
            if e.args and e.args[0] == 404:
                print(f"Version {version} not found (404)")
            else:
                print(f"Error fetching data for version {version}: {e}")
            chromium_version = None  # Reset chromium_version for next iteration

        except Exception as e:  # Catch other unexpected exceptions
            print(f"Unexpected error: {e}")
            chromium_version = None  # Reset chromium_version for next iteration

    # We're broadly sorted by major version, but within each major version we get newer entries first
    # Sort by Opera version to get the correct order
    sorted_versions = sorted(versions, key=lambda x: x.opera_version)
    return sorted_versions


def remediate_unknown_versions(versions):
    """
    Remediates entries with '0.0.0.0' values in the versions dictionary by
    assuming no change from the previous known version.

    Args:
        versions: A list of OperaChromiumVersion objects containing the extracted version information.

    Returns:
        A list of OperaChromiumVersion objects with '0.0.0.0' values replaced
        by the previous known version if available.
    """
    previous_version: Version = Version('0.0.0.0')
    fixed_versions: list[OperaChromiumVersion] = []

    for mapping in versions:
        if mapping.chromium_version == Version('0.0.0.0') and previous_version is not Version('0.0.0.0'):
            # Update with previous version
            fixed_versions.append(OperaChromiumVersion(mapping.opera_version, previous_version))
        else:
            # This should be fine, we're always parsing from oldest to newest
            if previous_version < mapping.chromium_version:
                previous_version = mapping.chromium_version
            fixed_versions.append(mapping)

    return fixed_versions


def parse_arguments():
    """
    Parses the command line arguments and returns the parsed values.

    Returns:
        The parsed command line arguments.
    """
    parser = argparse.ArgumentParser(description='Get Opera and Chromium versions.')
    parser.add_argument('start_ver', type=int, help='starting version', default=110)
    parser.add_argument('end_ver', type=int, help='ending version', default=115)
    return parser.parse_args()


def main():
    args = parse_arguments()

    # Base URL with version placeholder
    base_url = "https://blogs.opera.com/desktop/changelog-for-{}/"

    opera_chromium_versions = get_opera_chromium_versions(base_url, args.start_ver, args.end_ver)
    fixed_versions = remediate_unknown_versions(opera_chromium_versions)

    # Print the versions
    if fixed_versions:
        for mapping in fixed_versions:
            print(mapping)
    else:
        print("Failed to extract any versions.")


if __name__ == "__main__":
    main()
