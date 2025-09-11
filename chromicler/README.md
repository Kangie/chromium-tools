# Chromicler

**The Chromium Chronicler** - Automated Chromium security bug management for Gentoo Linux.

## Overview

Chromicler is the one-stop-shop for Gentoo's weekly Chromium workflows, consolidating standalone tooling and various CVE fetching/version matching scripts into a unified system for managing Chromium-based browser security vulnerabilities.

## What It Does

Chromicler automates the complete lifecycle of Chromium security bug management:

### Security Bug Automation

- **Chrome/Chromium**: Parse Chrome release blog posts and automatically create security bugs with proper CVE tracking
  - Automatically blocks existing CVE bugs when creating new security bugs
  - Updates bug titles when commits have `Bug:` tags and Larry infra-bot updates tickets

- **Microsoft Edge**: Query MSRC CVRF API using CVE aliases to update existing bugs with version constraints

- **Opera**: Scrape changelog blog posts to extract version info and Chromium rebases
  - Update security bug titles using Opera-to-Chromium version mapping
  - Pull CVE fixes from Opera RSS feed for additional coverage

### Package Bumping

- **Automated ebuild bumping** for Chrome, Edge, and Opera (Vivaldi support pending)
- **Automatic CVE bug fetching and linking** when bumping packages
- Integration with Portage for version management and git operations


## Architecture

### Handler System

Chromicler uses a modular handler architecture where each browser vendor has its own handler:

- **ChromiumHandler**: Google Chrome/Chromium workflow
- **EdgeHandler**: Microsoft Edge workflow
- **OperaHandler**: Opera workflow
- **VivaldiHandler**: Vivaldi (stub)

Each handler:
- Registers its affected browsers with the central `BrowserRegistry`
- Creates and manages its own CLI subcommands via Typer
- Uses dependency injection (`VersionUtils`, `BrowserRegistry`) for testability
- Lazy-loads `BugzillaClient` to avoid unnecessary API connections

### CLI Design

Built with [Typer](https://typer.tiangolo.com/), the CLI provides:
- Global options (`--dry-run`, `--debug`, `--api-key-file`) that work before or after subcommands
- Handler-specific subcommands that each handler registers independently
- Rich terminal output with structured logging
- Help text that doesn't require Bugzilla authentication

## Installation

```bash
cd chromicler
pip install -e .[dev]
```

Or with system packages:

```bash
emerge -av dev-python/requests \
    dev-python/structlog \
    dev-python/python-bugzilla \
    dev-python/beautifulsoup4 \
    dev-python/packaging \
    dev-python/typer \
    dev-python/pytest \
    dev-python/pytest-cov \
    dev-python/pytest-mock \
    dev-python/mypy \
    dev-python/types-requests \
    dev-util/ruff
```

### Requirements

- Python 3.10+
- For bumping functionality: **portage** and **git** (will fail without these), though really you should have these if you're doing Gentoo package maintenance!
- Bugzilla API key for Gentoo Bugzilla access. You will probably need to request `editbugs` permissions.

### Configuration

Create a `bugzilla_api_key` file in the working directory or specify a custom path with `--api-key-file`:

```bash
echo "YOUR_API_KEY_HERE" > bugzilla_api_key
chmod 600 bugzilla_api_key
```

## Usage

### Global Options

```bash
# Show help (no Bugzilla connection needed)
./chromicler.py --help

# Enable dry-run mode (show what would happen without making changes)
./chromicler.py --dry-run [COMMAND]

# Enable debug output
./chromicler.py --debug [COMMAND]

# Specify custom API key file
./chromicler.py --api-key-file /path/to/key [COMMAND]
```

### Chromium/Chrome Workflows

```bash
# Create security bugs from recent Chrome releases
./chromicler.py chromium create-from-releases

# Limit number of releases to process
./chromicler.py chromium create-from-releases --limit 5

# Update existing Chromium security bugs from Larry infra-bot comments
./chromicler.py chromium update-existing

# Check for Chrome updates and bump ebuilds
./chromicler.py chromium bump
```

### Microsoft Edge Workflows

```bash
# Query Edge CVE version mappings
./chromicler.py edge query

# Update existing bugs with Edge version constraints
./chromicler.py edge update

# Check for Edge updates and bump ebuilds
./chromicler.py edge bump
```

### Opera Workflows

```bash
# Update existing bugs with Opera version constraints
./chromicler.py opera update

# Update the Opera-to-Chromium version mapping file
./chromicler.py opera update-mapping

# Check for Opera updates and bump ebuilds
./chromicler.py opera bump
```

### Practical Examples

```bash
# Weekly workflow: Create new Chrome bugs (dry-run first)
./chromicler.py --dry-run chromium create-from-releases --limit 10
./chromicler.py chromium create-from-releases --limit 10

# Update all browser bugs with version constraints
./chromicler.py chromium update-existing
./chromicler.py edge update
./chromicler.py opera update

# Bump packages when new versions are available
./chromicler.py --dry-run chromium bump
./chromicler.py chromium bump
```

## Development


## Development

### Running Tests

```bash
# Install development dependencies
pip install -e .[dev]

# Run all tests
pytest

# Run with coverage report
pytest --cov=. --cov-report=html

# Run tests for a specific handler
pytest test/chromium/
pytest test/edge/
pytest test/opera/
```

### Code Quality

Just run `ruff`, I can't be bothered to argue about formatting during early development. If you have suggestions to improve, patches welcome!
### Adding a New Handler

1. Create a new handler class inheriting from base patterns
2. Implement required methods (vendor name, browser registration, data fetching)
3. Register browsers with `BrowserRegistry`
4. Create Typer CLI app and register commands
5. Inject dependencies (`VersionUtils`, `BrowserRegistry`, `api_key_file`)
6. Add tests in `test/[handler_name]/`

Example structure:
```python
class NewHandler:
    def __init__(self, api_key_file: str, logger, version_utils, browser_registry):
        # Setup with dependency injection
        self.cli = typer.Typer(name="newbrowser", help="...")
        self._register_commands()

    def register_browsers(self, registry):
        registry.register_browser("newbrowser", "www-client/newbrowser")
```

## License

GPL-2.0-or-later

## Contributing

Contributions welcome! Please:
1. Run tests and code quality checks before submitting
2. Add tests for new functionality
3. Update documentation for new features

## License

GPL-2.0-or-later
