"""Tests for the Safety Engine module."""

import os
import pytest

from app.safety.safety_engine import SafetyEngine


@pytest.fixture
def engine():
    """Create a SafetyEngine instance."""
    return SafetyEngine()


class TestProtectedPaths:
    """Tests for protected path checking."""

    def test_windows_dir_protected(self, engine):
        """C:\\Windows should always be protected."""
        is_prot, reason = engine.is_protected("C:\\Windows")
        assert is_prot is True
        assert "protected" in reason.lower()

    def test_program_files_protected(self, engine):
        """C:\\Program Files should always be protected."""
        is_prot, reason = engine.is_protected("C:\\Program Files")
        assert is_prot is True

    def test_program_files_x86_protected(self, engine):
        """C:\\Program Files (x86) should always be protected."""
        is_prot, reason = engine.is_protected("C:\\Program Files (x86)")
        assert is_prot is True

    def test_programdata_protected(self, engine):
        """C:\\ProgramData should always be protected."""
        is_prot, reason = engine.is_protected("C:\\ProgramData")
        assert is_prot is True

    def test_user_desktop_protected(self, engine):
        """User's Desktop should be protected."""
        desktop = os.path.join(os.path.expanduser("~"), "Desktop")
        is_prot, reason = engine.is_protected(desktop)
        assert is_prot is True

    def test_user_documents_protected(self, engine):
        """User's Documents should be protected."""
        docs = os.path.join(os.path.expanduser("~"), "Documents")
        is_prot, reason = engine.is_protected(docs)
        assert is_prot is True

    def test_user_downloads_protected(self, engine):
        """User's Downloads should be protected."""
        downloads = os.path.join(os.path.expanduser("~"), "Downloads")
        is_prot, reason = engine.is_protected(downloads)
        assert is_prot is True

    def test_appdata_roaming_protected(self, engine):
        """AppData\\Roaming should be protected."""
        roaming = os.path.join(os.path.expanduser("~"), "AppData", "Roaming")
        is_prot, reason = engine.is_protected(roaming)
        assert is_prot is True

    def test_saved_games_protected(self, engine):
        """Saved Games should be protected."""
        saved = os.path.join(os.path.expanduser("~"), "Saved Games")
        is_prot, reason = engine.is_protected(saved)
        assert is_prot is True

    def test_inside_windows_protected(self, engine):
        """Files inside C:\\Windows should be protected."""
        is_prot, reason = engine.is_protected("C:\\Windows\\System32\\cmd.exe")
        assert is_prot is True
        assert "inside protected directory" in reason.lower()

    def test_inside_program_files_protected(self, engine):
        """Files inside Program Files should be protected."""
        is_prot, reason = engine.is_protected(
            "C:\\Program Files\\SomeApp\\app.exe"
        )
        assert is_prot is True

    def test_appdata_local_cache_not_protected(self, engine):
        """Cache inside AppData\\Local should NOT be protected."""
        cache = os.path.join(
            os.environ.get("LOCALAPPDATA", ""),
            "SomeApp", "Cache"
        )
        is_prot, reason = engine.is_protected(cache)
        assert is_prot is False

    def test_ollama_models_protected(self, engine):
        """Ollama model directory should be protected."""
        ollama = os.path.join(os.path.expanduser("~"), ".ollama", "models")
        is_prot, reason = engine.is_protected(ollama)
        assert is_prot is True


class TestClassificationValidation:
    """Tests for classification validation (safety override)."""

    def test_override_safe_to_protected(self, engine):
        """SAFE classification inside protected path should be overridden."""
        item = {
            "full_path": "C:\\Windows\\Temp\\cache",
            "filename": "cache",
            "classification": "SAFE",
            "confidence": 0.9,
            "reason": "Cache folder",
        }
        result = engine.validate_classification(item)
        assert result["classification"] == "PROTECTED"
        assert result["safety_override"] is True
        assert result["original_classification"] == "SAFE"

    def test_low_confidence_safe_downgraded(self, engine):
        """Low confidence SAFE should be downgraded to REVIEW."""
        item = {
            "full_path": "C:\\Users\\test\\AppData\\Local\\SomeApp\\data",
            "filename": "data",
            "classification": "SAFE",
            "confidence": 0.3,
            "reason": "Maybe cache",
        }
        result = engine.validate_classification(item)
        assert result["classification"] == "REVIEW"
        assert result["safety_override"] is True

    def test_high_confidence_safe_kept(self, engine):
        """High confidence SAFE should be kept."""
        appdata = os.environ.get("LOCALAPPDATA", "C:\\Users\\test\\AppData\\Local")
        item = {
            "full_path": os.path.join(appdata, "SomeApp", "DXCache"),
            "filename": "DXCache",
            "classification": "SAFE",
            "confidence": 0.9,
            "reason": "Shader cache",
        }
        result = engine.validate_classification(item)
        assert result["classification"] == "SAFE"
        assert result["safety_override"] is False

    def test_dangerous_folder_name_override(self, engine):
        """Folders named 'data', 'Database', etc. should not be SAFE."""
        appdata = os.environ.get("LOCALAPPDATA", "C:\\Users\\test\\AppData\\Local")
        for name in ["data", "Data", "database", "Database", "storage", "Storage"]:
            item = {
                "full_path": os.path.join(appdata, "SomeApp", name),
                "filename": name,
                "classification": "SAFE",
                "confidence": 0.9,
                "reason": "Some reason",
            }
            result = engine.validate_classification(item)
            assert result["classification"] == "REVIEW", f"'{name}' should be REVIEW, not SAFE"
            assert result["safety_override"] is True

    def test_protected_classification_preserved(self, engine):
        """PROTECTED classification should never be downgraded."""
        appdata = os.environ.get("LOCALAPPDATA", "C:\\Users\\test\\AppData\\Local")
        item = {
            "full_path": os.path.join(appdata, "SomeApp", "saves"),
            "filename": "saves",
            "classification": "PROTECTED",
            "confidence": 0.9,
            "reason": "Game saves",
        }
        result = engine.validate_classification(item)
        assert result["classification"] == "PROTECTED"


class TestCanQuarantine:
    """Tests for quarantine eligibility."""

    def test_safe_can_quarantine(self, engine):
        """SAFE items can be quarantined."""
        appdata = os.environ.get("LOCALAPPDATA", "C:\\Users\\test\\AppData\\Local")
        item = {
            "full_path": os.path.join(appdata, "SomeApp", "ShaderCache"),
            "filename": "ShaderCache",
            "classification": "SAFE",
        }
        can, reason = engine.can_quarantine(item)
        assert can is True

    def test_protected_cannot_quarantine(self, engine):
        """PROTECTED items cannot be quarantined."""
        item = {
            "full_path": "C:\\Windows\\System32",
            "filename": "System32",
            "classification": "PROTECTED",
        }
        can, reason = engine.can_quarantine(item)
        assert can is False

    def test_unknown_cannot_quarantine(self, engine):
        """UNKNOWN items cannot be quarantined."""
        item = {
            "full_path": "C:\\SomeDir",
            "filename": "SomeDir",
            "classification": "UNKNOWN",
        }
        can, reason = engine.can_quarantine(item)
        assert can is False

    def test_protected_path_override(self, engine):
        """Items in protected paths cannot be quarantined even if classified SAFE."""
        item = {
            "full_path": "C:\\Program Files\\SomeApp",
            "filename": "SomeApp",
            "classification": "SAFE",
        }
        can, reason = engine.can_quarantine(item)
        assert can is False


class TestSafetySummary:
    """Tests for safety summary."""

    def test_summary_has_required_keys(self, engine):
        """Safety summary should have required keys."""
        summary = engine.get_safety_summary()
        assert "total_protected_paths" in summary
        assert "protected_extensions" in summary
        assert "protected_filenames" in summary
        assert "user_home" in summary
        assert "appdata_local" in summary

    def test_has_protected_paths(self, engine):
        """Should have multiple protected paths configured."""
        summary = engine.get_safety_summary()
        assert summary["total_protected_paths"] > 10

    def test_get_protected_paths_returns_list(self, engine):
        """get_protected_paths should return a list of strings."""
        paths = engine.get_protected_paths()
        assert isinstance(paths, list)
        assert all(isinstance(p, str) for p in paths)
