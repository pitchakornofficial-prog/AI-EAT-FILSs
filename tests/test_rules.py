"""Tests for the Rule Engine module."""

import pytest

from app.rules.rule_engine import RuleEngine


@pytest.fixture
def engine():
    """Create a RuleEngine instance."""
    return RuleEngine()


class TestRuleEngineClassification:
    """Tests for rule-based classification."""

    def test_safe_cache_folder(self, engine):
        """Cache folders should be classified as SAFE."""
        item = {
            "filename": "DXCache",
            "full_path": "C:\\Users\\test\\AppData\\Local\\NVIDIA\\DXCache",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local\\NVIDIA",
            "app_name": "NVIDIA",
            "file_type": "directory",
            "size_bytes": 500 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "SAFE"
        assert result["confidence"] > 0.7
        assert result["classified_by"] == "rule_engine"

    def test_safe_shader_cache(self, engine):
        """ShaderCache should be SAFE."""
        item = {
            "filename": "ShaderCache",
            "full_path": "C:\\Users\\test\\AppData\\Local\\NVIDIA\\ShaderCache",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local\\NVIDIA",
            "app_name": "NVIDIA",
            "file_type": "directory",
            "size_bytes": 1024 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "SAFE"

    def test_safe_crash_dumps(self, engine):
        """CrashDumps should be SAFE."""
        item = {
            "filename": "CrashDumps",
            "full_path": "C:\\Users\\test\\AppData\\Local\\CrashDumps",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local",
            "app_name": "",
            "file_type": "directory",
            "size_bytes": 200 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "SAFE"

    def test_safe_temp_file(self, engine):
        """Temp files should be SAFE."""
        item = {
            "filename": "tempfile.tmp",
            "full_path": "C:\\Users\\test\\AppData\\Local\\Temp\\tempfile.tmp",
            "extension": ".tmp",
            "is_directory": False,
            "parent_folder": "C:\\Users\\test\\AppData\\Local\\Temp",
            "app_name": "Temp",
            "file_type": "temporary",
            "size_bytes": 100 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "SAFE"

    def test_safe_gpu_cache(self, engine):
        """GPUCache should be SAFE."""
        item = {
            "filename": "GPUCache",
            "full_path": "C:\\Users\\test\\AppData\\Local\\Google\\Chrome\\GPUCache",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local\\Google\\Chrome",
            "app_name": "Google",
            "file_type": "directory",
            "size_bytes": 50 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "SAFE"

    def test_review_installer(self, engine):
        """Installer folders should be REVIEW."""
        item = {
            "filename": "Installer",
            "full_path": "C:\\Users\\test\\AppData\\Local\\Google\\Installer",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local\\Google",
            "app_name": "Google",
            "file_type": "directory",
            "size_bytes": 300 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "REVIEW"

    def test_review_update_folder(self, engine):
        """Update folders should be REVIEW."""
        item = {
            "filename": "Update",
            "full_path": "C:\\Users\\test\\AppData\\Local\\SomeApp\\Update",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local\\SomeApp",
            "app_name": "SomeApp",
            "file_type": "directory",
            "size_bytes": 150 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "REVIEW"

    def test_protected_saves_folder(self, engine):
        """Save folders should be PROTECTED."""
        item = {
            "filename": "saves",
            "full_path": "C:\\Users\\test\\AppData\\Local\\SomeGame\\saves",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local\\SomeGame",
            "app_name": "SomeGame",
            "file_type": "directory",
            "size_bytes": 500 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "PROTECTED"

    def test_protected_config_folder(self, engine):
        """Config folders should be PROTECTED."""
        item = {
            "filename": "config",
            "full_path": "C:\\Users\\test\\AppData\\Local\\SomeApp\\config",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local\\SomeApp",
            "app_name": "SomeApp",
            "file_type": "directory",
            "size_bytes": 50 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "PROTECTED"

    def test_unknown_unrecognized(self, engine):
        """Unrecognized items should be UNKNOWN."""
        item = {
            "filename": "SomeRandomApp",
            "full_path": "C:\\Users\\test\\AppData\\Local\\SomeRandomApp",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local",
            "app_name": "",
            "file_type": "directory",
            "size_bytes": 500 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "UNKNOWN"

    def test_known_app_nvidia_dxcache(self, engine):
        """NVIDIA DXCache should be recognized as known safe subfolder."""
        item = {
            "filename": "DXCache",
            "full_path": "C:\\Users\\test\\AppData\\Local\\NVIDIA Corporation\\DXCache",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local\\NVIDIA Corporation",
            "app_name": "NVIDIA Corporation",
            "file_type": "directory",
            "size_bytes": 2 * 1024 ** 3,
        }
        result = engine.classify(item)
        assert result["classification"] == "SAFE"
        assert "DXCache" in result["reason"] or "cache" in result["reason"].lower()

    def test_known_app_d3dscache(self, engine):
        """D3DSCache should be SAFE."""
        item = {
            "filename": "D3DSCache",
            "full_path": "C:\\Users\\test\\AppData\\Local\\D3DSCache",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\Users\\test\\AppData\\Local",
            "app_name": "",
            "file_type": "directory",
            "size_bytes": 100 * 1024 * 1024,
        }
        result = engine.classify(item)
        assert result["classification"] == "SAFE"


class TestRuleEngineOutput:
    """Tests for rule engine output format."""

    def test_result_has_required_keys(self, engine):
        """Classification result should have all required keys."""
        item = {
            "filename": "test",
            "full_path": "C:\\test",
            "extension": "",
            "is_directory": True,
            "parent_folder": "C:\\",
            "app_name": "",
            "file_type": "directory",
            "size_bytes": 0,
        }
        result = engine.classify(item)
        assert "classification" in result
        assert "confidence" in result
        assert "reason" in result
        assert "classified_by" in result

    def test_confidence_range(self, engine):
        """Confidence should be between 0 and 1."""
        items = [
            {"filename": "DXCache", "full_path": "C:\\DXCache", "extension": "",
             "is_directory": True, "parent_folder": "C:\\", "app_name": "",
             "file_type": "directory", "size_bytes": 0},
            {"filename": "RandomName", "full_path": "C:\\RandomName", "extension": "",
             "is_directory": True, "parent_folder": "C:\\", "app_name": "",
             "file_type": "directory", "size_bytes": 0},
        ]
        for item in items:
            result = engine.classify(item)
            assert 0.0 <= result["confidence"] <= 1.0

    def test_min_report_size(self, engine):
        """min_report_size_mb should return configured value."""
        assert engine.min_report_size_mb >= 0
