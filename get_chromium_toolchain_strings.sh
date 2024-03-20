#!/bin/bash

# This script extracts version information from Chromium sources by way of a Gentoo ebuild
# then plugs the version information into the ebuild file. This is useful for updating the
# toolchain versions in the ebuild file when a new (major) version of Chromium is released.

# Usage: get_chromium_toolchain_strings.sh <ebuild_file>
#   <ebuild_file>: The path to the Chromium ebuild file

# Extract the version string from an ebuild
get_version() {
  local filename="$1"
  [[ -z "$filename" ]] && return 1  # Check for empty filename
  local version_match="${filename##*-}";  # Extract everything after the last hyphen
  version_match="${version_match%.*}"  # Remove extension (.ebuild)
  echo "$version_match"
}

# Display script usage
usage() {
  echo "Usage: get_chromium_toolchain_strings.sh <ebuild_file>"
  echo "  <ebuild_file>: The path to the Chromium ebuild file"
}

# Get the ebuild filename as the first argument
ebuild_file="$1"

# Check for missing argument
if [[ -z "$ebuild_file" ]]; then
  echo "Error: Please provide an ebuild filename as an argument."
  usage
  exit 1
fi

# Extract version from filename
version="$(get_version "$ebuild_file")"

# Check if version extraction failed (function return code)
if [[ $? -ne 0 ]]; then
  echo "Error: Could not extract version from filename."
  exit 1
fi

# Construct S string based on version
# Bad luck if you don't use /var/tmp/portage, I guess.
S="/var/tmp/portage/www-client/chromium-${version}/work/chromium-${version}/"

# Run ebuild with clean and unpack options
ebuild "$ebuild_file" clean unpack

# No secret sauce here - it's just simpler to set the field separator to a single quote
# and then extract the final character from the sub-revision field.
# This is a bit of a hack, but it works for now - I haven't see upstream go past the
# 9th sub-revision yet!

llvm_version=$(awk -F"'" '
/CLANG_REVISION =/ { revision = $2 }
/CLANG_SUB_REVISION =/ { printf("%s-%d\n", revision, substr($1, length($1), 1)) }
' "${S}/tools/clang/scripts/update.py")

rust_version=$(awk -F"'" '
/RUST_REVISION =/ { revision = $2 }
/RUST_SUB_REVISION =/ { printf("%s-%d\n", revision, substr($1, length($1), 1)) }
' "${S}/tools/rust/update_rust.py")

# Substitute versions into ebuild (assuming specific locations)
sed -i "s/GOOGLE_CLANG_VER=.*/GOOGLE_CLANG_VER=${llvm_version}/" "$ebuild_file"
sed -i "s/GOOGLE_RUST_VER=.*/GOOGLE_RUST_VER=${rust_version}/" "$ebuild_file"

echo "Successfully substituted versions into $ebuild_file"
