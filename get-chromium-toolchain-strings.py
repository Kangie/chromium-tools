#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# This script extracts the revision and sub-revision from the update.py and update_rust.py files in the Chromium source code.
# The revision and sub-revision are used to identify the version of Clang and Rust used in the Chromium toolchain.


import requests
import sys


def get_revision_info(url):
    """
    Extracts revision and sub-revision from a Chromium source file URL.

    Args:
        url (str): The URL of the source file on GitHub's raw endpoint.

    Returns:
        tuple: A tuple containing the revision (str) and sub-revision (int), 
               or (None, None) if not found.
    """
    response = requests.get(url)
    if response.status_code == 200:
        text = response.content.decode('utf-8')  # Decode to UTF-8
        lines = text.splitlines()
        revision = None
        sub_revision = None
        for line in lines:
            if line.startswith("CLANG_REVISION") and not line.startswith("PACKAGE_VERSION"):
                revision = line.split("=")[1].strip().strip("'")
            elif line.startswith("CLANG_SUB_REVISION") and not line.startswith("PACKAGE_VERSION"):
                sub_revision = int(line.split("=")[1].strip())
            elif line.startswith("RUST_REVISION") and not line.startswith("specieid") and not line.startswith("    return"):
                # I know that's spelt wrong, but apparently google cant't spell
                revision = line.split("=")[1].strip().strip("'")
            elif line.startswith("RUST_SUB_REVISION") and not line.startswith("specieid") and not line.startswith("    return"):
                sub_revision = int(line.split("=")[1].strip()[-1])
        if revision is None or sub_revision is None:
            raise ValueError("Failed to extract revision and sub-revision")
        return revision, sub_revision
    else:
        raise ValueError(f"Failed to get revision info. Status code: {response.status_code}")


def main():
    version = sys.argv[1] if len(sys.argv) > 1 else "128.0.6613.113"
    # It's a lot easier to use GH raw URLs for this
    base_url = "https://raw.githubusercontent.com/chromium/chromium/"
    clang_url = f"{base_url}{version}/tools/clang/scripts/update.py"
    rust_url = f"{base_url}{version}/tools/rust/update_rust.py"
    clang_revision, clang_sub_revision = get_revision_info(clang_url)
    rust_revision, rust_sub_revision = get_revision_info(rust_url)
    if clang_revision and clang_sub_revision:
        print(f"clang revision: {clang_revision}-{clang_sub_revision}")
    else:
        print("clang revision not found")
    if rust_revision and rust_sub_revision:
        print(f"rust revision: {rust_revision}-{rust_sub_revision}")
    else:
        print("rust revision not found")

if __name__ == "__main__":
    main()
