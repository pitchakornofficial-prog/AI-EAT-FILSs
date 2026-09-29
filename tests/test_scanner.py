"""Tests for the File Scanner module."""

import os
import tempfile
from pathlib import Path

import pytest

from app.scanner.file_scanner import FileScanner, ScanItem


class TestScanItem:
    """Tests for the ScanItem dataclass."""

    def test_default_values(self):
        item = ScanItem()
        assert item.full_path == ""
        assert item.classification == "UNKNOWN"
        assert item.is_directory is False
        assert item.size_bytes == 0

    def test_to_dict(self):
        item = ScanItem(
            full_path="C:\\test\\file.txt",
            filename="file.txt",
            extension=".txt",
            size_bytes=1024,
        )
        d = item.to_dict()
        assert isinstance(d, dict)
        assert d["full_path"] == "C:\\test\\file.txt"
        assert d["size_bytes"] == 1024


class TestFileScanner:
    """Tests for the FileScanner class."""

    def test_init_default(self):
        scanner = FileScanner()
        assert scanner.min_size_bytes == 50 * 1024 * 1024  # 50 MB

    def test_init_custom_min_size(self):
        scanner = FileScanner(min_size_mb=10.0)
        assert scanner.min_size_bytes == 10 * 1024 * 1024

    def test_scan_nonexistent_path(self):
        scanner = FileScanner()
        with pytest.raises(FileNotFoundError):
            scanner.scan_directory("C:\\nonexistent_path_12345")

    def test_scan_file_not_directory(self):
        scanner = FileScanner()
        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
            temp_path = f.name
        try:
            with pytest.raises(NotADirectoryError):
                scanner.scan_directory(temp_path)
        finally:
            os.unlink(temp_path)

    def test_scan_empty_directory(self):
        scanner = FileScanner(min_size_mb=0)
        with tempfile.TemporaryDirectory() as tmpdir:
            items = scanner.scan_directory(tmpdir)
            assert isinstance(items, list)
            assert len(items) == 0  # Empty dir has no items

    def test_scan_directory_with_files(self):
        scanner = FileScanner(min_size_mb=0)  # No size filter for testing
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create test files
            for name in ["test1.txt", "test2.log", "test3.tmp"]:
                filepath = Path(tmpdir) / name
                filepath.write_text("test content " * 10)

            # Create a subdirectory
            subdir = Path(tmpdir) / "subdir"
            subdir.mkdir()
            (subdir / "inner.txt").write_text("inner content")

            items = scanner.scan_directory(tmpdir)
            assert len(items) > 0

            # Check that items have required fields
            for item in items:
                assert item.full_path != ""
                assert item.filename != ""

    def test_format_size(self):
        assert FileScanner.format_size(500) == "500 B"
        assert "KB" in FileScanner.format_size(2048)
        assert "MB" in FileScanner.format_size(5 * 1024 * 1024)
        assert "GB" in FileScanner.format_size(2 * 1024 ** 3)

    def test_classify_file_type(self):
        scanner = FileScanner()
        assert scanner._classify_file_type(".exe") == "executable"
        assert scanner._classify_file_type(".tmp") == "temporary"
        assert scanner._classify_file_type(".log") == "log"
        assert scanner._classify_file_type(".db") == "database"
        assert scanner._classify_file_type(".json") == "config"
        assert scanner._classify_file_type(".xyz") == "other"

    def test_errors_property(self):
        scanner = FileScanner()
        assert scanner.errors == []

    def test_progress_callback(self):
        scanner = FileScanner(min_size_mb=0)
        progress_calls = []

        def callback(current, total, name):
            progress_calls.append((current, total, name))

        with tempfile.TemporaryDirectory() as tmpdir:
            (Path(tmpdir) / "file1.txt").write_text("content")
            (Path(tmpdir) / "file2.txt").write_text("content")
            scanner.scan_directory(tmpdir, progress_callback=callback)

        assert len(progress_calls) == 2
        assert progress_calls[0][0] == 1  # First call, current=1
