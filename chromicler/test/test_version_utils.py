import importlib
import sys
import types


def _reload_version_utils():
    # Ensure a clean import of version_utils for each scenario
    if "version_utils" in sys.modules:
        importlib.reload(sys.modules["version_utils"])
        return sys.modules["version_utils"]
    return importlib.import_module("version_utils")


def test_compare_delegates_to_portage(monkeypatch):
    # Create a fake portage.versions module with a vercmp that records calls
    called = {}

    def fake_vercmp(a, b):
        called["args"] = (a, b)
        return 1

    fake_pv = types.SimpleNamespace(vercmp=fake_vercmp)

    # Ensure the portage package exists and has a versions attribute
    fake_pkg = types.ModuleType("portage")
    fake_pkg.versions = fake_pv

    monkeypatch.setitem(sys.modules, "portage", fake_pkg)
    monkeypatch.setitem(sys.modules, "portage.versions", fake_pv)

    vu_mod = _reload_version_utils()
    VersionUtils = vu_mod.VersionUtils

    v = VersionUtils()
    res = v.compare_versions("2.0.0.0", "1.0.0.0")
    assert res == 1
    assert called.get("args") == ("2.0.0.0", "1.0.0.0")


def test_compare_fallback_when_portage_missing(monkeypatch):
    # Ensure any existing portage modules are removed so import fails
    saved_portage = sys.modules.pop("portage", None)
    saved_pv = sys.modules.pop("portage.versions", None)

    try:
        vu_mod = _reload_version_utils()
        VersionUtils = vu_mod.VersionUtils

        v = VersionUtils()
        # Numeric compare fallback
        assert v.compare_versions("1.2.3.5", "1.2.3.4") == 1
        assert v.compare_versions("1.2.3.4", "1.2.3.5") == -1
        assert v.compare_versions("1.2.3.4", "1.2.3.4") == 0

        # Malformed input should still return an int (not None)
        r = v.compare_versions("abc", "1.2")
        assert isinstance(r, int)
    finally:
        # Restore any removed modules
        if saved_portage is not None:
            sys.modules["portage"] = saved_portage
        if saved_pv is not None:
            sys.modules["portage.versions"] = saved_pv


def test_vercmp_returns_none_falls_back(monkeypatch):
    # Fake vercmp that returns None to force fallback behavior
    def fake_vercmp(a, b):
        return None

    fake_pv = types.SimpleNamespace(vercmp=fake_vercmp)
    fake_pkg = types.ModuleType("portage")
    fake_pkg.versions = fake_pv

    monkeypatch.setitem(sys.modules, "portage", fake_pkg)
    monkeypatch.setitem(sys.modules, "portage.versions", fake_pv)

    vu_mod = _reload_version_utils()
    VersionUtils = vu_mod.VersionUtils

    v = VersionUtils()
    # Should fall back and return a valid int
    assert isinstance(v.compare_versions("1.2.3.5", "1.2.3.4"), int)
