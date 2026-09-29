"""
File Scanner module for AI Storage Cleaner.

Scans directories and collects metadata about files and folders.
Does NOT modify, move, or delete any files — read-only operations only.
"""

import os
import time
from datetime import datetime
from pathlib import Path
from typing import Optional
from dataclasses import dataclass, field, asdict


@dataclass
class ScanItem:
    """Represents a scanned file or folder with metadata."""

    full_path: str = ""
    filename: str = ""
    extension: str = ""
    size_bytes: int = 0
    modified_time: str = ""
    parent_folder: str = ""
    app_name: str = ""
    file_type: str = ""
    is_directory: bool = False
    classification: str = "UNKNOWN"
    confidence: float = 0.0
    reason: str = ""
    classified_by: str = ""
    ai_response: Optional[dict] = None
    children_count: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        """Convert to dictionary for database storage."""
        return asdict(self)


class FileScanner:
    """
    Scans directories and collects file/folder metadata.

    Safety: This class performs READ-ONLY filesystem operations.
    It never modifies, moves, or deletes any files.
    """

    def __init__(self, min_size_mb: float = 50.0):
        """
        Initialize the scanner.

        Args:
            min_size_mb: Minimum folder size in MB to include in results.
                         Defaults to 50 MB to filter out noise.
        """
        self.min_size_bytes = int(min_size_mb * 1024 * 1024)
        self._scan_errors: list[str] = []

    def scan_directory(
        self,
        target_path: str,
        depth: int = 1,
        progress_callback=None,
    ) -> list[ScanItem]:
        """
        Scan a directory and return metadata for top-level items.

        Args:
            target_path: Absolute path to scan.
            depth: How deep to scan (1 = immediate children only).
            progress_callback: Optional callback(current, total, name) for progress.

        Returns:
            List of ScanItem objects for items meeting the minimum size threshold.
        """
        target = Path(target_path)
        if not target.exists():
            raise FileNotFoundError(f"Path does not exist: {target_path}")
        if not target.is_dir():
            raise NotADirectoryError(f"Path is not a directory: {target_path}")

        self._scan_errors = []
        items: list[ScanItem] = []

        try:
            entries = list(target.iterdir())
        except PermissionError:
            self._scan_errors.append(f"Permission denied: {target_path}")
            return items

        total = len(entries)
        for idx, entry in enumerate(entries):
            if progress_callback:
                progress_callback(idx + 1, total, entry.name)

            try:
                item = self._scan_entry(entry, depth)
                if item and item.size_bytes >= self.min_size_bytes:
                    items.append(item)
            except Exception as e:
                self._scan_errors.append(f"Error scanning {entry}: {e}")

        # Sort by size descending
        items.sort(key=lambda x: x.size_bytes, reverse=True)
        return items

    def _scan_entry(self, entry: Path, depth: int) -> Optional[ScanItem]:
        """Scan a single file or directory entry."""
        try:
            is_dir = entry.is_dir()
        except (PermissionError, OSError):
            return None

        item = ScanItem(
            full_path=str(entry),
            filename=entry.name,
            is_directory=is_dir,
            parent_folder=str(entry.parent),
        )

        if is_dir:
            item.file_type = "directory"
            item.size_bytes = self._get_dir_size(entry)
            item.children_count = self._count_children(entry)
            item.app_name = self._guess_app_name(entry)
            # Try to get modified time of the directory itself
            try:
                stat = entry.stat()
                item.modified_time = datetime.fromtimestamp(stat.st_mtime).isoformat()
            except (PermissionError, OSError):
                item.modified_time = ""
        else:
            item.extension = entry.suffix.lower()
            item.file_type = self._classify_file_type(entry.suffix.lower())
            try:
                stat = entry.stat()
                item.size_bytes = stat.st_size
                item.modified_time = datetime.fromtimestamp(stat.st_mtime).isoformat()
            except (PermissionError, OSError):
                pass
            item.app_name = self._guess_app_name(entry)

        return item

    def _get_dir_size(self, path: Path) -> int:
        """
        Calculate total size of a directory recursively.
        Handles permission errors gracefully.
        """
        total = 0
        try:
            for dirpath, dirnames, filenames in os.walk(str(path)):
                for f in filenames:
                    fp = os.path.join(dirpath, f)
                    try:
                        total += os.path.getsize(fp)
                    except (OSError, PermissionError):
                        pass
        except (PermissionError, OSError):
            pass
        return total

    def _count_children(self, path: Path) -> int:
        """Count immediate children of a directory."""
        try:
            return sum(1 for _ in path.iterdir())
        except (PermissionError, OSError):
            return 0

    def _guess_app_name(self, path: Path) -> str:
        """
        Try to guess the application name from the path.

        For items inside AppData\\Local, the top-level folder name
        usually corresponds to the application or vendor name.
        """
        parts = path.parts
        # Look for common AppData patterns
        for i, part in enumerate(parts):
            if part.lower() == "local" and i > 0 and parts[i - 1].lower() == "appdata":
                # The folder right after "Local" is typically the app/vendor name
                if i + 1 < len(parts):
                    return parts[i + 1]
                break
        return ""

    def _classify_file_type(self, ext: str) -> str:
        """Classify file type based on extension."""
        type_map = {
            # Executables & installers
            ".exe": "executable",
            ".msi": "installer",
            ".msix": "installer",
            ".dll": "library",
            ".sys": "system",
            # Archives
            ".zip": "archive",
            ".rar": "archive",
            ".7z": "archive",
            ".tar": "archive",
            ".gz": "archive",
            # Data
            ".db": "database",
            ".sqlite": "database",
            ".json": "config",
            ".xml": "config",
            ".ini": "config",
            ".cfg": "config",
            ".yaml": "config",
            ".yml": "config",
            ".toml": "config",
            # Logs & temp
            ".log": "log",
            ".tmp": "temporary",
            ".temp": "temporary",
            ".dmp": "crash_dump",
            ".mdmp": "crash_dump",
            ".etl": "trace",
            # Cache
            ".cache": "cache",
            # Media
            ".png": "image",
            ".jpg": "image",
            ".jpeg": "image",
            ".gif": "image",
            ".bmp": "image",
            ".mp4": "video",
            ".avi": "video",
            ".mp3": "audio",
            ".wav": "audio",
        }
        return type_map.get(ext, "other")

    @property
    def errors(self) -> list[str]:
        """Return list of errors encountered during scan."""
        return self._scan_errors.copy()

    @staticmethod
    def format_size(size_bytes: int) -> str:
        """Format bytes into human-readable size string."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 ** 2:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 ** 3:
            return f"{size_bytes / (1024 ** 2):.2f} MB"
        else:
            return f"{size_bytes / (1024 ** 3):.2f} GB"
