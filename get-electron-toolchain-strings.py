#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# This script fetches the Chromium and Node.js versions from Electron's DEPS file to enable "straightforward"
# ebuild updates (at least we don't have to do it manually!)

import ast
import requests
import sys

def get_deps_values(url) -> tuple[str, str, str]:
    """
    Reads the DEPS file (gclient) and extracts values from the vars section.

    Args:
        url (str): The URL of the DEPS file on GitHub's raw endpoint.

    Returns:
        tuple: (chromium_version, node_version)
    """

    response = requests.get(url)
    if response.status_code == 200:
        text = response.content.decode('utf-8')
        lines = text.splitlines()

        # Find the vars section
        vars_start = 0
        vars_end = 0

        for idx, line in enumerate(lines):
            if line.startswith("vars = {"):
                vars_start = idx + 1
                break

        # Find the end of vars section by counting braces
        brace_count = 1
        for idx in range(vars_start, len(lines)):
            line = lines[idx]
            brace_count += line.count('{') - line.count('}')
            if brace_count == 0:
                vars_end = idx
                break

        # Extract vars content as Python dict
        vars_lines = ['{']
        vars_lines.extend(lines[vars_start:vars_end])
        vars_lines.append('}')

        # Clean up the vars content - remove comments
        clean_vars_lines = []
        for line in vars_lines:
            # Remove inline comments
            if '#' in line:
                line = line.split('#')[0]
            clean_vars_lines.append(line.rstrip())

        try:
            # Join the lines and evaluate as Python dict
            vars_text = '\n'.join(clean_vars_lines)
            vars_dict = ast.literal_eval(vars_text)

            # Extract the values we need
            chromium_version = vars_dict.get('chromium_version', None)
            node_version = vars_dict.get('node_version', None)

            return chromium_version, node_version

        except (ValueError, SyntaxError) as e:
            print(f"Python dict parse error: {e}")
            # For debugging:
            print("Vars content:")
            for idx, line in enumerate(clean_vars_lines):
                print(f"{idx}: {line}")
            return None, None, None
    else:
        raise ValueError(f"Failed to get DEPS revision info. Status code: {response.status_code}")

def get_node_info(url) -> str:
    """
    Extracts the node revision from a Chromium source file URL.

    Args:
        url (str): The URL of the source file on GitHub's raw endpoint.

    Returns:
        str: The node revision, or None if not found.
    """
    response = requests.get(url)
    if response.status_code == 200:
        text = response.content.decode('utf-8')  # Decode to UTF-8
        lines = text.splitlines()
        revision = None
        for line in lines:
            if line.startswith("NODE_VERSION="):
                revision = line.split("=")[1].strip().strip("\"")
        if revision is None:
            raise ValueError("Failed to extract node revision")
        return revision
    else:
        raise ValueError(f"Failed to get node revision info. Status code: {response.status_code}")

def main():
    version = sys.argv[1] if len(sys.argv) > 1 else "36.4.0"
    # It's a lot easier to use GH raw URLs for this
    base_url = "https://raw.githubusercontent.com/electron/electron/"
    deps_url = f"{base_url}v{version}/DEPS"
    chromium_version, node_version = get_deps_values(deps_url)
    print(f"Toolchain strings for Electron: {version}")
    if chromium_version:
        print(f"chromium version: {chromium_version}")
    else:
        print("chromium version not found")
    if node_version:
        print(f"node version: {node_version}")
    else:
        print("node version not found")
    print(f"for Chromium bits and pieces: `get-chromium-toolchain-strings.py {chromium_version}`")

if __name__ == "__main__":
    main()
