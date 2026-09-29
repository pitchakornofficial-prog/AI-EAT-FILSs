"""Tests for the Quarantine Manager module."""

import os
import shutil
import tempfile
from pathlib import Path

import pytest

from app.quarantine.quarantine_manager import QuarantineManager
from app.safety.safety_engine import SafetyEngine


@pytest.fixture
def temp_env():
    """Create a temporary environment for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Setup paths
        source_dir = Path(tmpdir) / "source"
        quarantine_dir = Path(tmpdir) / "quarantine"
        source_dir.mkdir()
        quarantine_dir.mkdir()
        
        # Create a test file
        test_file = source_dir / "test.txt"
        test_file.write_text("Hello World")
        
        # Initialize manager
        qm = QuarantineManager(quarantine_dir=str(quarantine_dir))
        safety = SafetyEngine() # Default safety engine, it's fine for our temp dir
        
        yield {
            "source_dir": source_dir,
            "quarantine_dir": quarantine_dir,
            "test_file": test_file,
            "qm": qm,
            "safety": safety
        }


def test_quarantine_item(temp_env):
    """Test quarantining a file."""
    qm = temp_env["qm"]
    safety = temp_env["safety"]
    test_file = temp_env["test_file"]
    
    item = {
        "full_path": str(test_file),
        "filename": test_file.name,
        "classification": "SAFE",
        "size_bytes": 11
    }
    
    res = qm.quarantine_item(item, safety)
    
    assert res["status"] == "success"
    assert not test_file.exists()  # Source should be gone
    
    q_id = res["quarantine_id"]
    manifest = qm.list_quarantined()
    assert len(manifest) == 1
    assert manifest[0]["quarantine_id"] == q_id
    assert Path(manifest[0]["quarantined_path"]).exists()


def test_restore_item(temp_env):
    """Test restoring a quarantined file."""
    qm = temp_env["qm"]
    safety = temp_env["safety"]
    test_file = temp_env["test_file"]
    
    item = {
        "full_path": str(test_file),
        "filename": test_file.name,
        "classification": "SAFE",
        "size_bytes": 11
    }
    
    # Quarantine it first
    res = qm.quarantine_item(item, safety)
    q_id = res["quarantine_id"]
    
    # Now restore it
    res_restore = qm.restore_item(q_id)
    
    assert res_restore["status"] == "success"
    assert test_file.exists()  # It's back!
    assert test_file.read_text() == "Hello World"
    
    # Manifest should be empty
    assert len(qm.list_quarantined()) == 0


def test_permanent_delete(temp_env, monkeypatch):
    """Test permanently deleting a quarantined file."""
    qm = temp_env["qm"]
    safety = temp_env["safety"]
    test_file = temp_env["test_file"]
    
    item = {
        "full_path": str(test_file),
        "filename": test_file.name,
        "classification": "SAFE",
        "size_bytes": 11
    }
    
    res = qm.quarantine_item(item, safety)
    q_id = res["quarantine_id"]
    q_path = res["entry"]["quarantined_path"]
    
    # Mock send2trash to avoid actually messing with the user's recycle bin during tests
    mock_called = False
    def mock_send2trash(path):
        nonlocal mock_called
        mock_called = True
        if os.path.exists(path):
            os.remove(path)
            
    monkeypatch.setattr("app.quarantine.quarantine_manager.send2trash", mock_send2trash)
    
    # Delete it
    res_delete = qm.permanent_delete(q_id, use_recycle_bin=True)
    
    assert res_delete["status"] == "success"
    assert mock_called is True
    assert not Path(q_path).exists()
    assert len(qm.list_quarantined()) == 0


def test_quarantine_protected_fails(temp_env):
    """Test that quarantining a protected file fails."""
    qm = temp_env["qm"]
    safety = temp_env["safety"]
    
    item = {
        "full_path": "C:\\Windows\\System32\\cmd.exe",
        "filename": "cmd.exe",
        "classification": "PROTECTED",
        "size_bytes": 1024
    }
    
    res = qm.quarantine_item(item, safety)
    
    assert res["status"] == "error"
    assert "Safety check failed" in res["message"]
    assert len(qm.list_quarantined()) == 0
