"""
Safety Engine for AI Storage Cleaner.

Final authority on whether a file/folder can be quarantined or deleted.
Even if AI says "SAFE", this engine can override to PROTECTED.

Key principles:
  1. Protected paths are NEVER modified
  2. AI recommendations are validated against safety rules
  3. Every action requires explicit user confirmation
  4. When in doubt, classify as REVIEW (not SAFE)
"""

import json
import os
import fnmatch
from pathlib import Path
from typing import Optional


class SafetyEngine:
    """
    Safety validation layer — the final gatekeeper before any file operation.

    This engine:
      - Resolves template variables in protected paths
      - Checks if a path is protected
      - Validates AI classifications
      - Prevents accidental deletion of important files
    """

    def __init__(self, config_path: Optional[str] = None):
        """
        Load protected paths configuration.

        Args:
            config_path: Path to protected_paths.json.
                         Uses default if not specified.
        """
        if config_path is None:
            config_path = str(
                Path(__file__).resolve().parent.parent.parent
                / "config"
                / "protected_paths.json"
            )

        with open(config_path, "r", encoding="utf-8") as f:
            self._config = json.load(f)

        # Resolve template variables
        self._user_home = str(Path.home())
        self._appdata_local = os.environ.get(
            "LOCALAPPDATA",
            str(Path.home() / "AppData" / "Local"),
        )

        # Build the full list of resolved protected paths
        self._protected_paths = self._resolve_all_paths()
        self._protected_extensions = set(
            self._config.get("protected_extensions", [])
        )
        self._protected_filenames = set(
            self._config.get("protected_filenames", [])
        )

    def _resolve_path(self, template: str) -> str:
        """Resolve template variables in a path string."""
        return (
            template.replace("{user_home}", self._user_home)
            .replace("{appdata_local}", self._appdata_local)
        )

    def _resolve_all_paths(self) -> list[str]:
        """Resolve all protected path templates to actual paths."""
        resolved = []
        path_keys = [
            "system_paths",
            "user_critical_paths",
            "appdata_protected",
            "application_data_paths",
            "gaming_paths",
            "ai_ml_paths",
            "development_paths",
        ]
        for key in path_keys:
            for template in self._config.get(key, []):
                resolved_path = self._resolve_path(template)
                resolved.append(os.path.normpath(resolved_path))
        return resolved

    def is_protected(self, path: str) -> tuple[bool, str]:
        """
        Check if a path is protected.

        Args:
            path: Absolute path to check.

        Returns:
            Tuple of (is_protected: bool, reason: str).
        """
        norm_path = os.path.normpath(path)
        path_lower = norm_path.lower()

        # 1. Check exact match or if path is inside a protected directory
        for protected in self._protected_paths:
            protected_lower = protected.lower()

            # Check for wildcard patterns
            if "*" in protected:
                # Use fnmatch for glob-style matching
                if fnmatch.fnmatch(path_lower, protected_lower):
                    return True, f"Path matches protected pattern: {protected}"
                # Also check parent dirs
                parent = os.path.dirname(norm_path)
                while parent and len(parent) > 3:  # Stop at drive root (e.g., "C:\\")
                    if fnmatch.fnmatch(parent.lower(), protected_lower):
                        return True, f"Path is inside protected directory: {protected}"
                    parent = os.path.dirname(parent)
            else:
                # Exact match
                if path_lower == protected_lower:
                    return True, f"Path is a protected location: {protected}"
                # Path is inside a protected directory
                if path_lower.startswith(protected_lower + os.sep.lower()):
                    return True, f"Path is inside protected directory: {protected}"

        # 2. Check protected filenames
        filename = os.path.basename(path)
        if filename in self._protected_filenames:
            return True, f"Filename '{filename}' is a protected system file"

        # 3. Check protected extensions (for standalone file checks)
        ext = os.path.splitext(path)[1].lower()
        # Note: We don't auto-protect by extension for directories or for the
        # top-level classification. Extension protection is an additional safety
        # layer, not a primary classifier. The rule engine handles this.

        return False, ""

    def validate_classification(self, item: dict) -> dict:
        """
        Validate and potentially override a classification.

        This is the final safety check. Even if AI or Rule Engine says SAFE,
        this engine can upgrade to PROTECTED.

        Args:
            item: Dictionary with keys: full_path, filename, extension,
                  classification, confidence, reason, classified_by.

        Returns:
            Updated classification dict with:
              - classification: final classification
              - confidence: adjusted confidence
              - reason: final reason
              - safety_override: True if classification was changed
              - original_classification: original value if overridden
        """
        path = item.get("full_path", "")
        current_class = item.get("classification", "UNKNOWN")
        current_reason = item.get("reason", "")

        result = {
            "classification": current_class,
            "confidence": item.get("confidence", 0.0),
            "reason": current_reason,
            "safety_override": False,
            "original_classification": None,
        }

        # Rule 1: Protected paths are ALWAYS protected, regardless of AI opinion
        is_prot, prot_reason = self.is_protected(path)
        if is_prot:
            if current_class != "PROTECTED":
                result["safety_override"] = True
                result["original_classification"] = current_class
            result["classification"] = "PROTECTED"
            result["confidence"] = 1.0
            result["reason"] = prot_reason
            return result

        # Rule 2: If AI said SAFE but confidence is low, downgrade to REVIEW
        if current_class == "SAFE" and item.get("confidence", 0.0) < 0.7:
            result["classification"] = "REVIEW"
            result["safety_override"] = True
            result["original_classification"] = "SAFE"
            result["reason"] = (
                f"Low confidence ({item.get('confidence', 0.0):.0%}). "
                f"Original reason: {current_reason}"
            )
            return result

        # Rule 3: Certain directories should never be auto-classified as SAFE
        #          without high confidence
        filename = item.get("filename", "")
        dangerous_names = {
            "data", "Data", "database", "Database",
            "storage", "Storage", "local", "Local",
            "state", "State", "persist", "Persist",
        }
        if filename in dangerous_names and current_class == "SAFE":
            result["classification"] = "REVIEW"
            result["safety_override"] = True
            result["original_classification"] = "SAFE"
            result["reason"] = (
                f"Folder name '{filename}' may contain important data. "
                f"Requires manual review. Original: {current_reason}"
            )
            return result

        # Rule 4: Very large items (>1GB) that are SAFE get an extra note
        size_bytes = item.get("size_bytes", 0)
        if current_class == "SAFE" and size_bytes > 1024 ** 3:
            result["reason"] = (
                f"⚠ Large item ({size_bytes / (1024**3):.2f} GB). {current_reason}"
            )

        return result

    def can_quarantine(self, item: dict) -> tuple[bool, str]:
        """
        Check if an item can be moved to quarantine.

        Args:
            item: Classified scan item dict.

        Returns:
            Tuple of (can_quarantine: bool, reason: str).
        """
        classification = item.get("classification", "UNKNOWN")

        if classification == "PROTECTED":
            return False, "Item is PROTECTED and cannot be quarantined"

        if classification == "UNKNOWN":
            return False, "Item has not been classified yet"

        is_prot, prot_reason = self.is_protected(item.get("full_path", ""))
        if is_prot:
            return False, f"Safety override: {prot_reason}"

        if classification == "SAFE":
            return True, "Item is classified as SAFE for quarantine"

        if classification == "REVIEW":
            return True, "Item is classified as REVIEW — requires user confirmation"

        return False, f"Unknown classification: {classification}"

    def get_protected_paths(self) -> list[str]:
        """Return the list of resolved protected paths (for debugging/display)."""
        return self._protected_paths.copy()

    def get_safety_summary(self) -> dict:
        """Return a summary of safety configuration."""
        return {
            "total_protected_paths": len(self._protected_paths),
            "protected_extensions": len(self._protected_extensions),
            "protected_filenames": len(self._protected_filenames),
            "user_home": self._user_home,
            "appdata_local": self._appdata_local,
        }
