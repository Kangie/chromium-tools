"""Common utilities for chromium-tools scripts."""

import re

_V8_MAJOR_VERSION_PATTERN = re.compile(r"#define\s+MAJOR_VERSION\s+(.*)")
_V8_MINOR_VERSION_PATTERN = re.compile(r"#define\s+MINOR_VERSION\s+(.*)")
_V8_BUILD_NUMBER_PATTERN = re.compile(r"#define\s+BUILD_NUMBER\s+(.*)")
_V8_PATCH_LEVEL_PATTERN = re.compile(r"#define\s+PATCH_LEVEL\s+(.*)")

_V8_PATTERNS = [
	_V8_MAJOR_VERSION_PATTERN,
	_V8_MINOR_VERSION_PATTERN,
	_V8_BUILD_NUMBER_PATTERN,
	_V8_PATCH_LEVEL_PATTERN]

def v8_extract_version(version_contents):
	"""
	Returns version number as string based on the string
	contents of version.cc file.
	"""
	version_components = []
	for pattern in _V8_PATTERNS:
	  version_components.append(pattern.search(version_contents).group(1).strip())

	if version_components[len(version_components) - 1] == '0':
	  version_components.pop()

	return '.'.join(version_components)
