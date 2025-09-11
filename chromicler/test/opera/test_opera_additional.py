#!/usr/bin/env python3

"""
Additional tests for OperaHandler: RSS cache, individual post parsing,
Bugzilla-backed Chromium discovery, and mapping file loading/property.
"""

from pathlib import Path
import yaml

from handlers.opera_handler import OperaHandler
from version_utils import VersionUtils


def test_rss_cache_read_and_write(
    tmp_path, mock_bugzilla_client, mock_logger, monkeypatch
):
    handler = OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=True, version_utils=VersionUtils()
    )

    # Use a temporary cache dir
    handler.cache_dir = tmp_path

    # Ensure the handler behaves as if not running under pytest for cache testing
    monkeypatch.setattr(OperaHandler, "_is_testing", lambda self: False)

    cache_file = handler._get_rss_cache_file_path()
    assert not Path(cache_file).exists()

    # Save and then load
    handler._save_rss_to_cache(cache_file, "TEST RSS CONTENT")
    assert Path(cache_file).exists()

    loaded = handler._load_rss_from_cache(cache_file)
    assert loaded == "TEST RSS CONTENT"

    # Newly written cache should be valid
    assert handler._is_rss_cache_valid(cache_file)


def test_get_opera_version_from_post_success_and_failure(
    mocker, mock_bugzilla_client, mock_logger
):
    handler = OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=True, version_utils=VersionUtils()
    )

    html = (
        '<html><body><div class="content">Opera One (120.0.5543.93)</div></body></html>'
    )

    mock_get = mocker.patch("handlers.opera_handler.requests.get")
    resp = mocker.Mock()
    resp.status_code = 200
    resp.content = html.encode("utf-8")
    mock_get.return_value = resp

    ver = handler._get_opera_version_from_post("https://example.com/post")
    assert ver == "120.0.5543.93"

    # Non-200 response should return None
    mock_get.return_value = mocker.Mock(status_code=404)

    ver = handler._get_opera_version_from_post("https://example.com/post")
    assert ver is None


def test_find_chromium_version_for_cves_queries_bugzilla(
    mocker, mock_bugzilla_client, mock_logger
):
    handler = OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=True, version_utils=VersionUtils()
    )

    # Prepare mock bzapi that returns a bug with chromium version in the summary
    mock_bug = mocker.Mock()
    mock_bug.id = 1
    mock_bug.summary = "Security fix for <www-client/chromium-129.0.6668.58: something"

    mock_bzapi = mocker.Mock()
    mock_bzapi.build_query.return_value = {"dummy": "query"}
    mock_bzapi.query.return_value = [mock_bug]

    mock_bugzilla_client.bzapi = mock_bzapi

    result = handler._find_chromium_version_for_cves(["CVE-2025-0000"])
    assert result == "129.0.6668.58"


def test_load_opera_chromium_mapping_and_property(
    tmp_path, mock_bugzilla_client, mock_logger, monkeypatch
):
    # Write a small mapping YAML into a temporary data/ directory and make the
    # handler load from that location by monkeypatching the module __file__.
    data_dir = tmp_path / "data"
    data_dir.mkdir(parents=True, exist_ok=True)

    mapping_file = data_dir / "opera_chromium_mapping.yaml"

    # Ensure the handler constructs its mapping path under tmp_path by making
    # Path(__file__).resolve().parent.parent == tmp_path inside the module.
    # We do this by setting the module __file__ to a path whose parent.parent is tmp_path.
    import handlers.opera_handler as opera_module

    fake_module_file = tmp_path / "ignored" / "opera_handler.py"
    fake_module_file.parent.mkdir(parents=True, exist_ok=True)
    monkeypatch.setattr(opera_module, "__file__", str(fake_module_file))

    sample_mapping = {
        "opera_chromium_mapping": {
            121: {"121.0.5600.0": "137.0.7151.27", "121.0.5600.3": None}
        }
    }

    with open(mapping_file, "w", encoding="utf-8") as f:
        yaml.dump(sample_mapping, f, sort_keys=False)

    handler = OperaHandler(
        api_key_file="./bugzilla_api_key",
        logger=mock_logger,
        version_utils=VersionUtils(),
        dry_run=True,
    )
    # Mock bugzilla (though not used in this test)
    handler._bugzilla = mock_bugzilla_client

    # Force reload
    handler._opera_chromium_mapping = None
    loaded = handler._load_opera_chromium_mapping()

    assert isinstance(loaded, dict)
    assert 121 in loaded
    assert "121.0.5600.0" in loaded[121]

    # Test the property uses the cached value
    handler._opera_chromium_mapping = None
    mapping = handler.opera_chromium_mapping
    assert isinstance(mapping, dict)
    assert 121 in mapping
    assert "121.0.5600.0" in mapping[121]

    # Cleanup file (best effort)
    try:
        mapping_file.unlink()
    except Exception:
        pass
