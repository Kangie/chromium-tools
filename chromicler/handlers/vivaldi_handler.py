#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
Vivaldi Handler - Stub handler for Vivaldi browser

Vivaldi is based on Chromium and is affected by Chromium security vulnerabilities,
but doesn't have its own separate security update workflow. This handler exists
primarily to register Vivaldi as an affected browser.
"""

from typing import Dict, List

import structlog

from bugzilla_client import BugzillaClient
from version_utils import VersionUtils


class VivaldiHandler:
    """Stub handler for Vivaldi browser."""

    def __init__(
        self,
        api_key_file: str,
        logger: structlog.BoundLogger,
        version_utils: VersionUtils,
    ):
        self.api_key_file = api_key_file
        self.logger = logger
        self.version_utils = version_utils
        self._bugzilla = None  # Lazy-loaded (though not currently used)

    @property
    def bugzilla(self) -> BugzillaClient:
        """Lazy-load BugzillaClient only when actually needed."""
        if self._bugzilla is None:
            self._bugzilla = BugzillaClient(
                api_key_file=self.api_key_file,
                logger=self.logger,
            )
        return self._bugzilla

    def get_vendor_name(self) -> str:
        """Return the vendor name for this handler."""
        return "Vivaldi Technologies"

    def register_browsers(self, registry):
        """Register the browsers that this handler impacts."""
        registry.register_browser("vivaldi", "www-client/vivaldi")

    def fetch_vulnerability_data(self, **kwargs) -> List[Dict]:
        """Vivaldi doesn't have separate vulnerability data - uses Chromium's."""
        return []

    def process_vulnerabilities(self, vulnerabilities: List[Dict], **kwargs) -> Dict:
        """Vivaldi vulnerabilities are handled by the Chromium handler."""
        return {
            "action": "vivaldi_stub",
            "message": "Vivaldi vulnerabilities are managed through Chromium workflow",
            "processed": 0,
        }
