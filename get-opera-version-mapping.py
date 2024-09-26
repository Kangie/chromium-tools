#!/usr/bin/env python
import requests
from bs4 import BeautifulSoup


def get_opera_chromium_versions(base_url, start_version, end_version):
    """
    Extracts Opera and Chromium versions from the given base URL with version placeholders,
    parsing content sections for versions from start_version to end_version (inclusive).

    Args:
        base_url: The base URL for Opera changelogs with a version placeholder (e.g., "https://blogs.opera.com/desktop/changelog-for-{version}/").
        start_version: The starting version to extract information for (inclusive).
        end_version: The ending version to extract information for (inclusive).

    Returns:
        A dictionary mapping Opera version to Chromium version.
        If no update is mentioned, the previous Chromium version is used.
        For missing data or errors, "unknown" is used.
    """
    versions = {}
    chromium_version = None

    for version in range(start_version, end_version + 1):
        # Fix formatting issue:
        # OR  url = base_url.format(version)
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
                version_str, date_str = section.text.strip().split(' – ')
                versions[version_str] = chromium_version

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
                    chromium_version = "unknown"

        except requests.exceptions.RequestException as e:
            if e.args and e.args[0] == 404:
                print(f"Version {version} not found (404)")
            else:
                print(f"Error fetching data for version {version}: {e}")
            chromium_version = None  # Reset chromium_version for next iteration

        except Exception as e:  # Catch other unexpected exceptions
            print(f"Unexpected error: {e}")
            chromium_version = None  # Reset chromium_version for next iteration

    return versions


def remediate_unknown_versions(versions):
    """
    Remediates entries with "unknown" values in the versions dictionary by
    assuming no change from the previous known version.

    Args:
        versions: A dictionary mapping Opera version to Chromium version.

    Returns:
        The modified versions dictionary with "unknown" values replaced based on previous entries.
    """
    previous_version = None
    for version, chromium_version in versions.items():
        if chromium_version == "unknown":
            if previous_version is not None:
                # Update with previous version
                versions[version] = previous_version
        else:
            previous_version = chromium_version  # Update known version for future references
    return versions


# Example usage
# Base URL with version placeholder
base_url = "https://blogs.opera.com/desktop/changelog-for-{}/"
opera_chromium_versions = get_opera_chromium_versions(base_url, 110, 115)

opera_chromium_versions = remediate_unknown_versions(opera_chromium_versions)

if opera_chromium_versions:
    for opera_version, chromium_version in opera_chromium_versions.items():
        print(
            f"Opera Version: {opera_version}, Chromium Version: {chromium_version}")
else:
    print("Failed to extract any versions.")
