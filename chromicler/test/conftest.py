"""
Pytest configuration and fixtures for chromicler tests.
"""

import pytest
import structlog
import tempfile
import shutil
from pathlib import Path


@pytest.fixture
def mock_logger():
    """Provide a mock structlog logger for testing."""
    return structlog.get_logger("test")


@pytest.fixture
def mock_bugzilla_client(mocker):
    """Provide a mock BugzillaClient for testing."""
    mock_client = mocker.Mock()
    mock_client.find_security_bugs_by_packages.return_value = []
    mock_client.update_bug.return_value = True
    return mock_client


@pytest.fixture
def sample_bug(mocker):
    """Provide a sample bug object for testing."""
    return mocker.Mock(
        id=12345,
        summary="www-client/opera: Multiple vulnerabilities",
        alias=["CVE-2024-1234", "CVE-2024-5678"],
    )


@pytest.fixture
def mock_version_utils(mocker):
    """Provide a mock VersionUtils for testing."""
    mv = mocker.Mock()

    def cmp_func(a, b):
        try:
            ta = tuple(map(int, str(a).split(".")))
            tb = tuple(map(int, str(b).split(".")))
            if ta > tb:
                return 1
            if ta < tb:
                return -1
            return 0
        except Exception:
            # Fallback string comparison deterministic
            return 0 if str(a) == str(b) else (1 if str(a) > str(b) else -1)

    mv.compare_versions.side_effect = cmp_func
    mv.extract_version_from_text.side_effect = lambda t: None
    # The handler will always provide a package list: implement package-aware
    # regex logic on the mock so tests that rely on detection continue to work.
    import re as _re

    def _mock_has_version_constraints(title, packages):
        if not packages:
            return False
        parts = [_re.escape(p) for p in packages]
        pattern = r"|".join(rf"<{p}-[\d.]+" for p in parts)
        return bool(_re.search(pattern, title))

    mv.has_version_constraints.side_effect = _mock_has_version_constraints
    mv.generate_constraint_string.side_effect = lambda pkg, ver: f"<{pkg}-{ver}"
    return mv


# Configure structlog for testing
structlog.configure(
    processors=[
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.UnicodeDecoder(),
        structlog.processors.JSONRenderer(),
    ],
    context_class=dict,
    logger_factory=structlog.stdlib.LoggerFactory(),
    wrapper_class=structlog.stdlib.BoundLogger,
    cache_logger_on_first_use=True,
)


@pytest.fixture
def portage_test_repo():
    """
    Factory fixture to create temporary Gentoo repository with test ebuilds.

    Returns a function that accepts:
        packages: Dict[str, Dict[str, Any]] - Package configuration
            Example: {
                "www-client/google-chrome": {
                    "versions": ["140.0.6723.58"],
                    "keywords": "~amd64",  # or ["~amd64"] for stable channel
                    "description": "Google Chrome browser"
                }
            }
        repo_name: str - Repository name (default: "test-repo")

    Returns dict with:
        - eroot: str - Root directory
        - repo_path: str - Path to repository
        - repo: git.Repo - Git repository object
    """
    pytest.importorskip("portage")  # Skip if portage not available
    git = pytest.importorskip("git")

    def _create_repo(packages, repo_name="test-repo"):
        # Create temp directory
        temp_dir = tempfile.mkdtemp(prefix="chromicler_test_")
        eroot = temp_dir
        repo_path = Path(temp_dir) / "var/db/repos" / repo_name
        repo_path.mkdir(parents=True, exist_ok=True)

        # Initialize git repo
        repo = git.Repo.init(repo_path)

        # Create repository metadata
        metadata_dir = repo_path / "metadata"
        metadata_dir.mkdir(exist_ok=True)
        (metadata_dir / "layout.conf").write_text(
            f"masters =\nrepo-name = {repo_name}\n"
        )

        # Extract all categories from packages
        categories = set()
        for pkg_name in packages.keys():
            if "/" in pkg_name:
                category = pkg_name.split("/")[0]
                categories.add(category)

        # Create profiles
        profiles_dir = repo_path / "profiles"
        profiles_dir.mkdir(exist_ok=True)
        (profiles_dir / "repo_name").write_text(f"{repo_name}\n")
        (profiles_dir / "categories").write_text("\n".join(sorted(categories)) + "\n")

        # Create profile subdirectory
        default_profile = profiles_dir / "default/linux/x86/test"
        default_profile.mkdir(parents=True, exist_ok=True)
        (default_profile / "eapi").write_text("8\n")
        (default_profile / "make.defaults").write_text("ARCH=amd64\n")

        # Create packages
        for pkg_name, pkg_config in packages.items():
            if "/" not in pkg_name:
                raise ValueError(f"Package name must include category: {pkg_name}")

            category, pkg = pkg_name.rsplit("/", 1)
            pkg_dir = repo_path / category / pkg
            pkg_dir.mkdir(parents=True, exist_ok=True)

            versions = pkg_config.get("versions", [])
            keywords = pkg_config.get("keywords", "~amd64")
            description = pkg_config.get("description", f"Test {pkg} package")

            # Normalize keywords to list
            if isinstance(keywords, str):
                keywords_list = [keywords]
            else:
                keywords_list = keywords

            for ver in versions:
                ebuild_file = pkg_dir / f"{pkg}-{ver}.ebuild"
                keywords_str = " ".join(keywords_list)
                ebuild_file.write_text(f"""# Test ebuild for {pkg}
EAPI=8
DESCRIPTION="{description}"
HOMEPAGE="https://example.com"
SLOT="0"
KEYWORDS="{keywords_str}"
""")

        # Git commit
        repo.index.add("*")
        repo.index.commit(f"Initial {repo_name} ebuilds")

        return {
            "eroot": eroot,
            "repo_path": str(repo_path),
            "repo": repo,
            "cleanup": lambda: shutil.rmtree(temp_dir),
        }

    repos_created = []

    def _factory(*args, **kwargs):
        result = _create_repo(*args, **kwargs)
        repos_created.append(result)
        return result

    yield _factory

    # Cleanup all created repos
    for repo_data in repos_created:
        try:
            repo_data["cleanup"]()
        except Exception:
            pass


@pytest.fixture
def portage_handler():
    """
    Factory fixture to create handler with real portage configuration.

    Returns a function that accepts:
        handler_class: Class to instantiate
        repo_data: Dict from portage_test_repo
        mock_logger: Logger fixture
        mocker: pytest-mock fixture
        **handler_kwargs: Additional kwargs for handler

    Returns configured handler instance.
    """

    def _create_handler(
        handler_class, repo_data, mock_logger, mocker, **handler_kwargs
    ):
        portage = pytest.importorskip("portage")
        from version_utils import VersionUtils

        # Set up PORTAGE_REPOSITORIES configuration
        repo_config_str = f"""[DEFAULT]
main-repo = test-repo

[test-repo]
location = {repo_data["repo_path"]}
"""

        # Create portage settings with test EROOT and repository config
        env = {
            "PORTAGE_CONFIGROOT": repo_data["eroot"],
            "ROOT": repo_data["eroot"],
            "EPREFIX": repo_data["eroot"],
            "PORTAGE_REPOSITORIES": repo_config_str,
        }

        # Create portage trees with our environment
        trees = portage.create_trees(env=env, eprefix=repo_data["eroot"])
        eroot_key = repo_data["eroot"]
        if not eroot_key.endswith("/"):
            eroot_key += "/"
        settings = trees[eroot_key]["vartree"].settings

        # Create handler with provided kwargs
        default_kwargs = {
            "api_key_file": "./bugzilla_api_key",
            "logger": mock_logger,
            "version_utils": VersionUtils(),
        }
        default_kwargs.update(handler_kwargs)

        handler = handler_class(**default_kwargs)

        # Patch portdbapi to use our settings
        from portage.dbapi.porttree import portdbapi as real_portdbapi

        def create_portdbapi_with_settings():
            return real_portdbapi(mysettings=settings)

        mocker.patch(
            "portage.dbapi.porttree.portdbapi",
            side_effect=create_portdbapi_with_settings,
        )

        return handler

    return _create_handler
