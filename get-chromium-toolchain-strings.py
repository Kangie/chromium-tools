#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
# This script extracts the revision and sub-revision from the update.py and update_rust.py files in the Chromium source code.
# The revision and sub-revision are used to identify the version of Clang and Rust used in the Chromium toolchain.

import json
import requests
import sys

def get_testfonts(url) -> str:
    """
    Reads the DEPS file (gclient) and extracts the testfonts SHA which is used
    as the object name (SHA256 as of 2024)
    deps['src/third_party/test_fonts']['objects'][0]['object_name']

    Args:
        url (str): The URL of the DEPS file on GitHub's raw endpoint.

    Returns:
        str: The SHA256 of the testfonts, or None if not found.
        """

    # We're not properly parsing the DEPS file, but it's 'close enough' to JSON that
    # we can throw away the preamble and do some remediation to read the values in.

    testfonts = None
    response = requests.get(url)
    if response.status_code == 200:
        text = response.content.decode('utf-8')
        lines = text.splitlines()
        # throw away everything up to `deps = {`
        # We'll add our own opening brace to make it valid JSON
        start = 0
        for idx, line in enumerate(lines):
            if line.startswith("deps = {"):
                start = idx + 1
                break

        # throw away everything after the variable ends `}`
        length = 0
        for idx, line in enumerate(lines):
            if idx < start:
                continue
            if line.startswith("}"):
                length = idx
                break

        deps: list[str] = ['{', '}']
        deps[1:1] = lines[start:length]

        # remove any comments, because JSON doesn't like them
        deps = [line for line in deps if not line.strip().startswith('#')]

        # I hate to do this, but we need to remediate the JSON - single quotes to double quotes ho!
        deps = [line.replace("'", '"') for line in deps]
        # the `condition` variable is always a python comparison. Let's not even try to parse it.
        # we don't care so just drop the whole line
        deps = [line for line in deps if "condition" not in line]
        # ditto `Var()`
        deps = [line for line in deps if "Var(" not in line]
        # if a line ends in ' +' it's a python thing and we probably already stripped whatever is being
        # concatenated, so we can just remove the '+' and append a ','.
        deps = [line.replace(" +", ",") if line.endswith(" +") else line for line in deps]
        # strip ' "@",' from any lines... No idea what gclient does with this
        deps = [line.replace(' "@",', "") for line in deps]


        # If we encounter '[{' or '}]' we should expand them onto individual lines.
        # for '[{', remove the { and add it on a new line, for '}]' remove the ] and add it on a new line.
        # every instance so far has been '}],' so let's assume that holds true?
        newdeps = []
        for line in deps:
            if '[{' in line:
                # 'blah: [', '{'
                newdeps.append(line[:-1])
                newdeps.append('{')
            elif '}]' in line:
                # '},', '],'
                newdeps.append(line[:-2])
                newdeps.append('],')
            else:
                newdeps.append(line)

        deps = newdeps

        # if the last thing in an object has a trailing comma, it's invalid JSON so we need to remove it,
        # probably easiest to do if we check that the next line is '}' when stripped and remediate that
        newdeps = []
        for idx, line in enumerate(deps):
            if line.endswith(",") and deps[idx + 1].strip() == "}":
                newdeps.append(line.replace(",", ""))
            elif line.endswith(",") and deps[idx + 1].strip() == "},":
                newdeps.append(line.replace(",", ""))
            else:
                newdeps.append(line)

        deps = newdeps
        newdeps = []

        for idx, line in enumerate(deps):
            if line.endswith("},") and deps[idx + 1].strip() == "]":
                newdeps.append(line.replace(",", ""))
            elif line.endswith("},") and deps[idx + 1].strip() == "],":
                newdeps.append(line.replace(",", ""))
            else:
                newdeps.append(line)

        deps = newdeps

        # If the line does not contain a colon _and_ the previous and next lines contain '{' and '}' respectively,
        # it's very likely a naked sha and json can't parse it. We can just strip it.
        newdeps = []
        for idx, line in enumerate(deps):
            if ":" not in line and "{" in deps[idx - 1] and '}' in deps[idx + 1]:
                continue
            else:
                newdeps.append(line)

        deps = newdeps

        # final blacklist; not worth writing a rule for this
        bad_lines = [
            '+ "@" + "42e892d96e47b1f6e29844cc705e148ec4856448", # release 1.9.4',
        ]
        deps = [line for line in deps if line.strip() not in bad_lines]

        # Clean up any keys with no values. Always do this last
        newdeps = []
        for idx, line in enumerate(deps):
            if line.endswith(":") and deps[idx + 1].strip() == "":
                continue
            else:
                newdeps.append(line)

        deps = newdeps

        # debug_lines = range(1460, 1500)
        # for idx, line in enumerate(deps):
        #     if idx in debug_lines:
        #         print(f"{idx}: {line}")

        # Now we have a list of strings that should be valid JSON
        # We can join them and load them
        deps = json.loads('\n'.join(deps))
        # Now we can get the testfonts SHA
        return deps['src/third_party/test_fonts/test_fonts']['objects'][0]['object_name']
    else:
        raise ValueError(f"Failed to get revision info. Status code: {response.status_code}")

    return testfonts


def get_revision_info(url) -> str:
    """
    Extracts revision and sub-revision from a Chromium source file URL.

    Args:
        url (str): The URL of the source file on GitHub's raw endpoint.

    Returns:
        tuple: A tuple containing the revision (str) and sub-revision (int)
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
    deps_url = f"{base_url}{version}/DEPS"
    clang_revision, clang_sub_revision = get_revision_info(clang_url)
    rust_revision, rust_sub_revision = get_revision_info(rust_url)
    testfonts = get_testfonts(deps_url)
    if clang_revision and clang_sub_revision:
        print(f"clang revision: {clang_revision}-{clang_sub_revision}")
    else:
        print("clang revision not found")
    if rust_revision and rust_sub_revision:
        print(f"rust revision: {rust_revision}-{rust_sub_revision}")
    else:
        print("rust revision not found")
    if testfonts:
        print(f"test fonts: {testfonts}")
    else:
        print("test fonts not found")

if __name__ == "__main__":
    main()
