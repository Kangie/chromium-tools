#!/usr/bin/env python3

# This script uses the processed SPDX-ish information from the
# `Chromium Licences` project (and some built-in mapping info)
# to identify the appropriate Gentoo `LICENSE` values for Chromium.

# https://github.com/TeamDev-IP/Chromium-Licenses/blob/v135.0.7049.96/chromium-licenses.spdx.json

import argparse
import logging
import os
import re
import requests
import structlog
import sys
import yaml

from typing import List, Optional # Optional needed if input can be None

logger = structlog.get_logger()

# --- Constants ---
BASE_SPDX_URL_TEMPLATE = "https://raw.githubusercontent.com/TeamDev-IP/Chromium-Licences/refs/tags/v{version}/chromium-licenses.spdx.json"
VERSION_REGEX = r"^\d+\.\d+(?:\.\d+(?:\.\d+)?)?$"
GENTOO_MAPPING_FILE_RELPATH = 'metadata/license-mapping.conf'
GENTOO_LICENSES_DIR_RELPATH = 'licenses'

logger = structlog.get_logger()

# --- Functions ---
def fetch_spdx_data(version: str) -> Optional[dict]:
    fetchuri = BASE_SPDX_URL_TEMPLATE.format(version=version)
    logger.info(f"Attempting to fetch SPDX data from: {fetchuri}")
    try:
        response = requests.get(fetchuri, timeout=10)
        response.raise_for_status() # Raise HTTPError for 4xx/5xx status codes
        logger.info(f"Successfully fetched data, status code: {response.status_code}")
        return response.json()
    except requests.exceptions.Timeout as e:
        logger.error(f"Request timed out while fetching SPDX data for version {version}: {e}")
        return None
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            logger.error(f"SPDX data not found for version {version} (404). URL: {fetchuri}")
        else:
            logger.error(f"HTTP error occurred fetching SPDX data for version {version}: {e}")
        return None
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Connection error while fetching SPDX data for version {version}: {e}")
        return None
    except requests.exceptions.RequestException as e: # Catch other requests-related errors
        logger.error(f"An unexpected error occurred during request for version {version}: {e}")
        return None
    except requests.exceptions.JSONDecodeError as e:
         logger.error(f"Failed to decode JSON response for version {version}: {e}")
         return None


def load_external_mappings(config_path="chromium_licence_mappings.yaml"):
    try:
        with open(config_path, 'r') as f:
            mappings = yaml.safe_load(f)
        return (
            mappings.get('remediation_mapping', {}),
            mappings.get('custom_licences', {}),
            set(mappings.get('ignore_list',))
         )
    except FileNotFoundError:
        logger.error(f"Mapping configuration file not found: {config_path}")
        return {}, {}, set()
    except yaml.YAMLError as e:
        logger.error(f"Error parsing mapping configuration file {config_path}: {e}")
        return {}, {}, set()
    except Exception as e:
        logger.exception(f"Unexpected error loading mapping config {config_path}: {e}")
        return {}, {}, set()


def load_gentoo_mappings(mapping_file_path: str) -> dict:
    logger.info(f"Loading Gentoo mappings from: {mapping_file_path}")
    gentoo_licence_mapping = {}
    try:
        if not os.path.exists(mapping_file_path):
             logger.error(f"Gentoo mapping file not found: {mapping_file_path}")
             return {} # Return empty dict on failure

        with open(mapping_file_path, 'r') as f:
            current_section = None
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if line.startswith('[') and line.endswith(']'):
                    current_section = line[1:-1]
                    continue
                if current_section == 'spdx-to-ebuild' and '=' in line:
                    spdx, gentoo = [x.strip() for x in line.split('=', 1)]
                    gentoo_licence_mapping[spdx] = gentoo

        logger.info(f"Successfully loaded {len(gentoo_licence_mapping)} mappings.")
        return gentoo_licence_mapping

    except FileNotFoundError:
        logger.error(f"Gentoo mapping file not found: {mapping_file_path}")
        return {}
    except PermissionError:
        logger.error(f"Permission denied reading mapping file: {mapping_file_path}")
        return {}
    except OSError as e:
        logger.error(f"OS error reading mapping file {mapping_file_path}: {e}")
        return {}
    except Exception as e:
        logger.exception(f"Unexpected error loading Gentoo mappings from {mapping_file_path}: {e}")
        return {}



def process_spdx_data(spdx_data: dict) -> tuple[list, dict, dict]:
    """
    Processes the SPDX data to extract relevant information about licenses and packages.

    This function extracts license information from both the 'hasExtractedLicensingInfos'
    section and the individual packages in the SPDX data. It handles cases where licenses
    may be combined using 'and' or separated by commas.


        A tuple containing three elements:
        - A list of all unique license names found in the SPDX data
        - A dictionary mapping license IDs to license names
        - A dictionary mapping package SPDXIDs to dictionaries containing package information
            (name, downloadLocation, externalRefs, and licence)

    Note:
        The function logs detailed information about the extraction process at debug level,
        and outputs a summary of found licenses at info level.
    """
    found_licences = set()
    licence_mapping = {}
    found_packages = {}
    # Extract relevant information from the SPDX data
    if 'hasExtractedLicensingInfos' in spdx_data:
        for licence_info in spdx_data['hasExtractedLicensingInfos']:
            if 'licenseId' in licence_info and 'name' in licence_info:
                licence_mapping[licence_info['licenseId']] = licence_info['name']
                # We can get an easy list of all licences here, and easily split them. We should still parse packages, maybe?
                if 'and' in licence_info['name'] or ',' in licence_info['name']:
                    # If the licence is a combination of licences, we need to split it
                    logger.debug(f"Splitting licence string: {licence_info['name']}")
                    licences = split_licence_string(licence_info['name'])
                    for licence in licences:
                            found_licences.add(licence)
                else:
                    # Make it an array so we can "iterate" over it below
                    logger.debug(f"Adding licence: {licence_info['name']}")
                    found_licences.add(licence_info['name'])


        logger.debug(f"Extracted {len(licence_mapping)} licence ID mappings:")
        for licence_id, name in licence_mapping.items():
            logger.debug(f"  {licence_id} -> {name}")

        # We probably don't get any new licences here, but we should still parse packages; it may be useful down the line
        for package in spdx_data['packages']:
            pkglicence = package.get('licenseConcluded', package.get('licenseInfoFromFiles', 'UNKNOWN'))
            # Handle case where pkglicence might be a single string or an array
            if isinstance(pkglicence, list):
                for licence in pkglicence:
                    found_licences.add(licence)
            elif 'and' in pkglicence or ',' in pkglicence:
                # We could have 'foo and bar and baz' or 'foo, bar, baz' which we need to split and process individually
                pkglicence = split_licence_string(pkglicence)
                for licence in pkglicence:
                    found_licences.add(licence)
            elif pkglicence:
                found_licences.add(pkglicence)
                logger.debug(f"Found licence: {pkglicence}")

            # Store package information
            found_packages[package['SPDXID']] = {
                'name': package['name'],
                'downloadLocation': package['downloadLocation'],
                'externalRefs': package.get('externalRefs', []),
                'licence': pkglicence,
            }

            logger.debug(f"Package ID: {package['SPDXID']}")
            logger.debug(f"Package Name: {package['name']}")
            logger.debug(f"URI: {package['downloadLocation']}")
            logger.debug(f"License Info: {package['externalRefs']}")
            if 'licenseConcluded' in package:
                logger.debug(f"License: {package['licenseConcluded']}")
            if 'licenseInfoFromFiles' in package:
                logger.debug(f"License Info From Files: {package['licenseInfoFromFiles']}")

        logger.info("Licences:")
        for licence in found_licences:
            logger.info(f"- {licence}")

        return found_licences, licence_mapping, found_packages


def setup_logging(args):
    """Configures logging based on structlog."""
    log_level = logging.WARNING
    if args.verbose:
        log_level = logging.INFO
    if args.debug:
        log_level = logging.DEBUG

    # Configure standard logging for libraries
    logging.basicConfig(
        format="%(message)s",
        level=log_level,
        stream=sys.stderr,
    )

    # Quiet down noisy libraries unless debugging
    if log_level > logging.DEBUG:
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)

    # Configure structlog
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(log_level))


def split_licence_string(licence_str: Optional[str]) -> List[str]:
    """
    Splits a licence string potentially containing ' and ' or ', ' delimiters.

    Args:
        license_str: The license string to split, or None.

    Returns:
        A list of individual license strings, or an empty list if
        input is None or empty after splitting.
    """
    if not licence_str:
        return

    # Basic split on ' and ' or ', '
    parts = re.split(r'\s+and\s+|\s*,\s*', licence_str)
    cleaned_parts = [part.strip() for part in parts if part and part.strip()]
    return cleaned_parts


def parse_arguments():
    parser = argparse.ArgumentParser(description="Script to fetch and display Chromium licencing information.")
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug output')
    parser.add_argument('-g', '--gentoo-repo', default='/var/db/repos/gentoo', help='Path to the Gentoo repository')
    parser.add_argument('version', help='Chromium version to fetch licences for')
    return parser.parse_args()


def main():
    args = parse_arguments()
    setup_logging(args)

    gentoo_repo = args.gentoo_repo

    version = ''
    if args.version:
        logger.info(f"Fetching licences for Chromium version: {args.version}")
        version = args.version
    else:
        print("No version specified. Please provide a Chromium version:")
        version = input("Version: ")

    if not re.match(VERSION_REGEX, version):
        logger.error("Invalid version format. Please enter a version like X.Y.Z.W (e.g., 123.0.4567.890)")
        exit(1)

    chromium_spdx_data = fetch_spdx_data(version)
    logger.debug("Available keys in the data:")
    for key in chromium_spdx_data.keys():
        logger.debug(f"- {key}")
    # Create a mapping of licence IDs to names
    found_licences, chromium_spdx_licence_mapping, found_packages = process_spdx_data(chromium_spdx_data)

    # Now to match with Gentoo licences!
    logger.info("Matching with Gentoo licences...")

    # Gentoo -> SPDX mapping
    gentoo_licence_mapping = load_gentoo_mappings(os.path.join(gentoo_repo, GENTOO_MAPPING_FILE_RELPATH))
    gentoo_licence_dir = os.path.join(gentoo_repo, GENTOO_LICENSES_DIR_RELPATH)

    if not os.path.exists(gentoo_licence_dir):
        logger.error(f"Gentoo licences directory not found at {gentoo_licence_dir}. Please check the path.")
        exit(1)

    # Read all Gentoo licences from the directory
    gentoo_licences = []
    for filename in os.listdir(gentoo_licence_dir):
        # Only consider regular files, not directories or symlinks
        if os.path.isfile(os.path.join(gentoo_licence_dir, filename)):
            gentoo_licences.append(filename)

    logger.debug(f"Found {len(gentoo_licences)} Gentoo licences")

    REMEDIATION_MAPPING, CUSTOM_LICENCES, IGNORE_LIST = load_external_mappings()

    matched_licences = set()
    unmatched_licences = set()

    # Add these to found_licences as we still need to process or discard the mapped values
    for k, v in CUSTOM_LICENCES.items():
        found_licences.add(v)
        logger.debug(f"Found custom licence: {v}")

    for l in found_licences:
        # Map the Chromium licence to its name
        chromium_licences = [l]
        if l in chromium_spdx_licence_mapping:
            logger.debug(f"Mapping {l} to {chromium_spdx_licence_mapping[l]}")
            if 'and' in chromium_spdx_licence_mapping[l] or ',' in chromium_spdx_licence_mapping[l]:
                # If the licence is a combination of licences, we need to split it
                chromium_licences = split_licence_string(chromium_spdx_licence_mapping[l])
                logger.debug(f"Splitting licence string: {chromium_licences}")
            else:
                # Make it an array so we can "iterate" over it below
                chromium_licences = [chromium_spdx_licence_mapping[l]]

        if l in IGNORE_LIST:
            continue

        for licence in chromium_licences:
            # Check if the Chromium licence exactly matches a Gentoo licence
            if licence in gentoo_licences:
                matched_licences.add(licence)
            elif licence in gentoo_licence_mapping:
                logger.debug(f"Mapping {licence} to {gentoo_licence_mapping[licence]}")
                matched_licences.add(gentoo_licence_mapping[licence])
            elif licence in REMEDIATION_MAPPING:
                logger.debug(f"Mapping {licence} to {REMEDIATION_MAPPING[licence]}")
                if REMEDIATION_MAPPING[licence] in IGNORE_LIST:
                    continue
                matched_licences.add(REMEDIATION_MAPPING[licence])
            else:
                if licence in IGNORE_LIST:
                    continue
                unmatched_licences.add(licence)

    logger.info(f"Licences for Chromium version {version}:")

    print(f'LICENSES="{' '.join(sorted(matched_licences))}"')

    if unmatched_licences:
        print(f"\nUnmatched licences ({len(unmatched_licences)}):")
        for licence in sorted(unmatched_licences):
            print(f"- {licence}")


if __name__ == "__main__":
    main()
