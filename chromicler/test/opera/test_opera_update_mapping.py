#!/usr/bin/env python3

"""Tests for updating the Opera-Chromium mapping YAML file."""

from pathlib import Path
import yaml
from typing import Dict, Optional, cast

from handlers.opera_handler import OperaHandler
from version_utils import VersionUtils


def test_update_mapping_file_merges_and_writes_to_output(
    tmp_path, mock_bugzilla_client, mock_logger, monkeypatch
):
    # Prepare an existing mapping YAML in a temporary location
    output_file = tmp_path / "opera_chromium_mapping.yaml"

    existing_data = {
        "opera_chromium_mapping": {120: {"120.0.0": "136.0.7000.0"}},
        "metadata": {
            "generated_at": "2020-01-01T00:00:00",
            "tool": "old-tool",
            "source": "old-source",
            "last_updated_versions": [120],
        },
    }

    with open(output_file, "w", encoding="utf-8") as f:
        yaml.dump(existing_data, f, sort_keys=False)

    # New mappings to add
    new_mappings = cast(
        Dict[int, Dict[str, Optional[str]]], {121: {"121.0.5600.0": "137.0.7151.27"}}
    )

    handler = OperaHandler(
        mock_bugzilla_client, mock_logger, dry_run=True, version_utils=VersionUtils()
    )

    # Monkeypatch the handler module __file__ so repo default path resolution
    # points inside tmp_path and cannot affect the real repository data file.
    import handlers.opera_handler as opera_mod

    fake_mod_file = tmp_path / "fake_handlers" / "opera_handler.py"
    fake_mod_file.parent.mkdir(parents=True, exist_ok=True)
    fake_mod_file.write_text("# fake module for tests\n")
    monkeypatch.setattr(opera_mod, "__file__", str(fake_mod_file))

    repo_default = (
        Path(opera_mod.__file__).resolve().parent
        / ".."
        / "data"
        / "opera_chromium_mapping.yaml"
    )

    repo_before_mtime = repo_default.stat().st_mtime if repo_default.exists() else None

    # Call update_mapping_file with our temporary output path
    returned = handler.update_mapping_file(new_mappings, output_file=str(output_file))

    # It should return the path we provided
    assert returned == str(output_file)

    # The file at output_file should now contain both existing and new mappings
    with open(output_file, "r", encoding="utf-8") as f:
        written = yaml.safe_load(f)

    assert "opera_chromium_mapping" in written
    merged = written["opera_chromium_mapping"]

    # YAML loader will preserve integer keys; ensure both majors exist
    assert 120 in merged
    assert 121 in merged

    # Ensure the existing mapping was preserved and the new one written
    assert merged[120]["120.0.0"] == "136.0.7000.0"
    assert merged[121]["121.0.5600.0"] == "137.0.7151.27"

    # Verify metadata fields exist and include our updated versions
    assert "metadata" in written
    meta = written["metadata"]
    assert "generated_at" in meta
    assert meta.get("tool") == "chromicler opera mapping update"
    assert meta.get("source") == "Opera official changelog scraping"
    assert set(meta.get("last_updated_versions", [])) == set(new_mappings.keys())

    # Ensure repository default mapping file was not changed (mtime unchanged or still absent)
    if repo_before_mtime is None:
        assert not repo_default.exists()
    else:
        assert repo_default.stat().st_mtime == repo_before_mtime
