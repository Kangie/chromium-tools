#!/usr/bin/env python3

# SPDX-License-Identifier: GPL-2.0-or-later
"""
The Chromium Chronicler (chromicler) - Manages Gentoo bugs for Chromium-based browsers

This tool helps us manage security vulnerabilities in Chromium-based browsers
by automating the creation of (and updates to) Bugzilla bugs based on upstream
sources.
"""

import logging
from typing import Dict, List, Optional
from abc import ABC, abstractmethod

import typer
import structlog
from bugzilla_client import BugzillaClient
from version_utils import VersionUtils
from handlers.chromium_handler import ChromiumHandler
from handlers.edge_handler import EdgeHandler
from handlers.opera_handler import OperaHandler
from handlers.vivaldi_handler import VivaldiHandler


class BrowserRegistry:
    """Registry for managing browser-to-handler mappings."""

    def __init__(self):
        self._handler_browsers = {}  # Maps handler_name -> set of browsers handled by that handler

    def register_browser(self, handler_name: str, browser: str):
        """Register a browser as being handled by a specific handler."""
        if handler_name not in self._handler_browsers:
            self._handler_browsers[handler_name] = set()
        self._handler_browsers[handler_name].add(browser)

    def get_browsers_for_handler(self, handler_name: str) -> List[str]:
        """Get all browsers handled by a specific handler."""
        return sorted(list(self._handler_browsers.get(handler_name, set())))

    def get_all_browsers(self) -> List[str]:
        """Get all registered browsers in alphabetical order."""
        all_browsers = set()
        for browsers in self._handler_browsers.values():
            all_browsers.update(browsers)
        return sorted(list(all_browsers))

    def get_handlers(self) -> List[str]:
        """Get all registered handler names."""
        return list(self._handler_browsers.keys())


class BrowserSecurityHandler(ABC):
    """Abstract base class for browser-specific security handlers."""

    def __init__(
        self,
        bugzilla_client: BugzillaClient,
        logger: structlog.BoundLogger,
        version_utils: VersionUtils | None = None,
    ):
        self.bugzilla = bugzilla_client
        self.logger = logger
        self.version_utils = version_utils or VersionUtils()

    @abstractmethod
    def get_vendor_name(self) -> str:
        """Return the vendor name for this handler."""
        pass

    @abstractmethod
    def register_browsers(self, registry: BrowserRegistry):
        """Register the browsers that this handler impacts."""
        pass

    @abstractmethod
    def fetch_vulnerability_data(self, **kwargs) -> List[Dict]:
        """Fetch vulnerability data from vendor-specific sources."""
        pass

    @abstractmethod
    def process_vulnerabilities(self, vulnerabilities: List[Dict], **kwargs) -> Dict:
        """Process vulnerabilities and return results."""
        pass


class ChromiumSecurityManager:
    """Main orchestrator for Chromium security vulnerability management."""

    def __init__(
        self,
        api_key_file: str = "./bugzilla_api_key",
        dry_run: bool = False,
        debug: bool = False,
    ):
        self.dry_run = dry_run
        self.debug = debug
        self.api_key_file = api_key_file
        self.logger = self._setup_logging()

        # Initialise browser registry
        self.browser_registry = BrowserRegistry()

        # Shared VersionUtils instance (allows DI and consistent behavior)
        self.version_utils = VersionUtils()

        # Initialise handlers with API key file - they'll create BugzillaClient when needed
        self.handlers = {
            "chromium": ChromiumHandler(
                api_key_file=self.api_key_file,
                logger=self.logger,
                version_utils=self.version_utils,
                dry_run=self.dry_run,
                browser_registry=self.browser_registry,
            ),
            "edge": EdgeHandler(
                api_key_file=self.api_key_file,
                logger=self.logger,
                version_utils=self.version_utils,
            ),
            "opera": OperaHandler(
                api_key_file=self.api_key_file,
                logger=self.logger,
                version_utils=self.version_utils,
                dry_run=self.dry_run,
            ),
            "vivaldi": VivaldiHandler(
                api_key_file=self.api_key_file,
                logger=self.logger,
                version_utils=self.version_utils,
            ),
        }

        # Register browsers with the registry after handlers are created
        for handler_name, handler in self.handlers.items():
            handler.register_browsers(self.browser_registry)

    def get_affected_browsers(self, handler_name: str = None) -> List[str]:
        """Get browsers affected by a specific handler or all browsers."""
        if handler_name:
            return self.browser_registry.get_browsers_for_handler(handler_name)
        return self.browser_registry.get_all_browsers()

    def _setup_logging(self) -> structlog.BoundLogger:
        """Set up structured logging."""
        # Configure the Python logging level based on debug flag
        log_level = logging.DEBUG if self.debug else logging.INFO
        logging.basicConfig(
            level=log_level,
            format="",  # Remove the default format to eliminate INFO:__main__: prefix
            handlers=[logging.StreamHandler()],
        )

        structlog.configure(
            processors=[
                structlog.stdlib.filter_by_level,
                structlog.stdlib.add_log_level,
                structlog.stdlib.PositionalArgumentsFormatter(),
                structlog.processors.TimeStamper(fmt="[%H:%M:%S]"),
                structlog.processors.StackInfoRenderer(),
                structlog.processors.UnicodeDecoder(),
                structlog.dev.ConsoleRenderer(colors=True),
            ],
            context_class=dict,
            logger_factory=structlog.stdlib.LoggerFactory(),
            wrapper_class=structlog.stdlib.BoundLogger,
            cache_logger_on_first_use=True,
        )
        logger = structlog.get_logger()

        # Log the configuration
        if self.debug:
            logger.debug("Debug logging enabled")
        if self.dry_run:
            logger.info("Dry run mode enabled - no changes will be made")

        return logger

    def run_chromium_workflow(self, **kwargs) -> Dict:
        """Run the Chromium/Chrome security workflow."""
        return self.handlers["chromium"].process_vulnerabilities(
            self.handlers["chromium"].fetch_vulnerability_data(**kwargs)
        )

    def run_edge_workflow(self, **kwargs) -> Dict:
        """Run the Microsoft Edge security workflow."""
        return self.handlers["edge"].process_vulnerabilities(
            self.handlers["edge"].fetch_vulnerability_data(**kwargs)
        )

    def run_opera_workflow(self, **kwargs) -> Dict:
        """Run the Opera security workflow."""
        return self.handlers["opera"].update_opera_versions()

    def update_chromium_bugs(self) -> Dict:
        """Update existing Chromium bugs with version constraints."""
        return self.handlers["chromium"].update_existing_bugs()


# Reusable option definitions for handlers to use
def DryRunOption(default: bool = False):
    """Reusable --dry-run/-n option for handler commands."""
    return typer.Option(
        default,
        "--dry-run",
        "-n",
        help="Show what would be done without making changes",
    )


def DebugOption(default: bool = False):
    """Reusable --debug/-d option for handler commands."""
    return typer.Option(default, "--debug", "-d", help="Enable debug output")


# Global Typer app
app = typer.Typer(
    name="chromicler",
    help="Unified Chromium Security Bug Management System",
    no_args_is_help=True,
)


# Shared configuration that handlers can access
class AppConfig:
    """Shared application configuration accessible to all handlers."""

    api_key_file: str = "./bugzilla_api_key"
    dry_run: bool = False
    debug: bool = False
    manager: Optional["ChromiumSecurityManager"] = None


@app.callback()
def main_callback(
    api_key_file: str = typer.Option(
        "./bugzilla_api_key",
        "--api-key-file",
        "-k",
        help="Path to bugzilla API key file",
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", "-n", help="Show what would be done without making changes"
    ),
    debug: bool = typer.Option(False, "--debug", "-d", help="Enable debug output"),
):
    """Global options callback - runs before any command."""
    AppConfig.api_key_file = api_key_file
    AppConfig.dry_run = dry_run
    AppConfig.debug = debug

    if AppConfig.manager is None:
        AppConfig.manager = create_manager_with_handlers(
            api_key_file=api_key_file,
            dry_run=dry_run,
            debug=debug,
        )


def create_manager_with_handlers(
    api_key_file: str = "./bugzilla_api_key",
    dry_run: bool = False,
    debug: bool = False,
) -> ChromiumSecurityManager:
    """Create manager and register handler CLI apps with the main app."""
    manager = ChromiumSecurityManager(
        api_key_file=api_key_file,
        dry_run=dry_run,
        debug=debug,
    )

    return manager


def register_handler_clis():
    """
    Register handler CLI apps at module import time.

    Creates a minimal temporary manager just to get handler instances
    for CLI registration. Handlers won't connect to Bugzilla until they
    actually use the bugzilla property.
    """
    temp_manager = ChromiumSecurityManager(
        api_key_file="./bugzilla_api_key",  # Dummy, won't be used
        dry_run=False,
        debug=False,
    )

    # Register each handler's CLI app
    for handler_name, handler in temp_manager.handlers.items():
        if hasattr(handler, "cli") and handler.cli is not None:
            app.add_typer(handler.cli)


# Register handler CLIs at module import so --help works
register_handler_clis()


if __name__ == "__main__":
    app()
