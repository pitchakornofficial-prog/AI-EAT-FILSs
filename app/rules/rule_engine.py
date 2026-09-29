"""
Rule Engine for AI Storage Cleaner.

Performs fast, pattern-based classification of files and folders
WITHOUT calling AI. This is the first pass in the pipeline.

Classification results:
  - SAFE: Cache/temp files that can be regenerated
  - REVIEW: Might be removable but needs human check
  - PROTECTED: Must never be touched
  - UNKNOWN: Needs AI analysis
"""

import json
import fnmatch
from pathlib import Path
from typing import Optional


class RuleEngine:
    """Pattern-based pre-classifier for files and folders."""

    def __init__(self, rules_path: Optional[str] = None):
        """
        Load classification rules from JSON config.

        Args:
            rules_path: Path to rules.json. Uses default if not specified.
        """
        if rules_path is None:
            rules_path = str(
                Path(__file__).resolve().parent.parent.parent / "config" / "rules.json"
            )

        with open(rules_path, "r", encoding="utf-8") as f:
            self._rules = json.load(f)

        self._safe = self._rules.get("safe_patterns", {})
        self._review = self._rules.get("review_patterns", {})
        self._protected = self._rules.get("protected_patterns", {})
        self._known_apps = self._rules.get("known_applications", {})
        self._thresholds = self._rules.get("size_thresholds", {})

    def classify(self, item: dict) -> dict:
        """
        Classify a scan item using pattern rules.

        Args:
            item: Dictionary with keys: filename, full_path, extension,
                  is_directory, parent_folder, app_name, file_type, size_bytes.

        Returns:
            Dictionary with:
              - classification: SAFE | REVIEW | PROTECTED | UNKNOWN
              - confidence: 0.0 - 1.0
              - reason: Human-readable explanation
              - classified_by: "rule_engine"
        """
        filename = item.get("filename", "")
        full_path = item.get("full_path", "")
        extension = item.get("extension", "").lower()
        is_directory = item.get("is_directory", False)
        app_name = item.get("app_name", "")
        file_type = item.get("file_type", "")

        # 1. Check known applications first (most accurate)
        result = self._check_known_app(filename, app_name, full_path)
        if result:
            return result

        # 2. Check PROTECTED patterns (safety first)
        result = self._check_protected(filename, extension, is_directory)
        if result:
            return result

        # 3. Check SAFE patterns (cache/temp)
        result = self._check_safe(filename, extension, is_directory, full_path)
        if result:
            return result

        # 4. Check REVIEW patterns
        result = self._check_review(filename, extension, is_directory)
        if result:
            return result

        # 5. Unknown — needs AI analysis
        return {
            "classification": "UNKNOWN",
            "confidence": 0.0,
            "reason": "No matching rule found; requires AI analysis",
            "classified_by": "rule_engine",
        }

    def _check_known_app(
        self, filename: str, app_name: str, full_path: str
    ) -> Optional[dict]:
        """Check if the item belongs to a known application."""
        # Check if filename matches a known app
        app_info = self._known_apps.get(filename)
        if not app_info:
            app_info = self._known_apps.get(app_name)

        if app_info:
            app_type = app_info.get("type", "Unknown Application")
            safe_subs = app_info.get("safe_subfolders", [])

            # Check if this is a known-safe subfolder
            # Match both by filename and by any part of the path
            if filename in safe_subs:
                return {
                    "classification": "SAFE",
                    "confidence": 0.95,
                    "reason": f"{app_type}: '{filename}' is a known cache/temp subfolder of {app_name or filename}",
                    "classified_by": "rule_engine",
                }

            path_parts = Path(full_path).parts
            for sub in safe_subs:
                if sub in path_parts:
                    return {
                        "classification": "SAFE",
                        "confidence": 0.95,
                        "reason": f"{app_type}: '{sub}' is a known cache/temp subfolder of {filename or app_name}",
                        "classified_by": "rule_engine",
                    }

            # Known app, but not a safe subfolder
            # Don't block here — let the pipeline continue to check
            # safe_patterns and review_patterns, which may match the filename.
            # Only return REVIEW if filename IS the app itself (top-level folder)
            if filename == app_name or filename in self._known_apps:
                if safe_subs:
                    return {
                        "classification": "REVIEW",
                        "confidence": 0.6,
                        "reason": f"{app_type}: Contains application data for {filename or app_name}",
                        "classified_by": "rule_engine",
                    }

                # Known app with no safe subfolders defined
                if filename in ("Temp", "D3DSCache", "CrashDumps"):
                    return {
                        "classification": "SAFE",
                        "confidence": 0.9,
                        "reason": f"{app_type}: Known temporary/cache data",
                        "classified_by": "rule_engine",
                    }

        return None

    def _check_protected(
        self, filename: str, extension: str, is_directory: bool
    ) -> Optional[dict]:
        """Check PROTECTED patterns."""
        protected_folders = self._protected.get("folder_names", [])
        protected_exts = self._protected.get("file_extensions", [])

        # Protected folder names
        if is_directory and filename in protected_folders:
            return {
                "classification": "PROTECTED",
                "confidence": 0.9,
                "reason": f"Folder '{filename}' matches protected pattern (may contain user data or configs)",
                "classified_by": "rule_engine",
            }

        # Protected file extensions (only for non-directory items)
        if not is_directory and extension in protected_exts:
            # Config/data files inside directories are protected
            return {
                "classification": "PROTECTED",
                "confidence": 0.8,
                "reason": f"File extension '{extension}' is associated with important data files",
                "classified_by": "rule_engine",
            }

        return None

    def _check_safe(
        self, filename: str, extension: str, is_directory: bool, full_path: str
    ) -> Optional[dict]:
        """Check SAFE patterns (cache/temp)."""
        safe_folders = self._safe.get("folder_names", [])
        safe_contains = self._safe.get("folder_name_contains", [])
        safe_exts = self._safe.get("file_extensions", [])
        safe_file_patterns = self._safe.get("file_name_patterns", [])

        # Exact folder name match
        if is_directory and filename in safe_folders:
            return {
                "classification": "SAFE",
                "confidence": 0.9,
                "reason": f"Folder '{filename}' is a known cache/temporary folder",
                "classified_by": "rule_engine",
            }

        # Folder name contains cache/temp keywords
        if is_directory:
            for keyword in safe_contains:
                if keyword.lower() in filename.lower():
                    # Avoid false positives: folders just named "Cache" inside
                    # important apps should be reviewed
                    return {
                        "classification": "SAFE",
                        "confidence": 0.75,
                        "reason": f"Folder name contains '{keyword}', likely cache/temporary data",
                        "classified_by": "rule_engine",
                    }

        # Safe file extensions
        if not is_directory and extension in safe_exts:
            return {
                "classification": "SAFE",
                "confidence": 0.85,
                "reason": f"File extension '{extension}' is a known temporary/cache file type",
                "classified_by": "rule_engine",
            }

        # File name pattern match
        if not is_directory:
            for pattern in safe_file_patterns:
                if fnmatch.fnmatch(filename, pattern):
                    return {
                        "classification": "SAFE",
                        "confidence": 0.85,
                        "reason": f"Filename matches temporary pattern '{pattern}'",
                        "classified_by": "rule_engine",
                    }

        return None

    def _check_review(
        self, filename: str, extension: str, is_directory: bool
    ) -> Optional[dict]:
        """Check REVIEW patterns."""
        review_folders = self._review.get("folder_names", [])
        review_contains = self._review.get("folder_name_contains", [])
        review_exts = self._review.get("file_extensions", [])

        # Exact folder name match
        if is_directory and filename in review_folders:
            return {
                "classification": "REVIEW",
                "confidence": 0.7,
                "reason": f"Folder '{filename}' may contain removable data (installer/update/backup)",
                "classified_by": "rule_engine",
            }

        # Folder name contains review keywords
        if is_directory:
            for keyword in review_contains:
                if keyword.lower() in filename.lower():
                    return {
                        "classification": "REVIEW",
                        "confidence": 0.6,
                        "reason": f"Folder name contains '{keyword}', may be an old version or installer",
                        "classified_by": "rule_engine",
                    }

        # Review file extensions (installers, archives inside AppData)
        if not is_directory and extension in review_exts:
            return {
                "classification": "REVIEW",
                "confidence": 0.65,
                "reason": f"File extension '{extension}' may be an old installer or archive",
                "classified_by": "rule_engine",
            }

        return None

    @property
    def min_report_size_mb(self) -> int:
        """Get the minimum size threshold for reporting, in MB."""
        return self._thresholds.get("minimum_report_size_mb", 50)
