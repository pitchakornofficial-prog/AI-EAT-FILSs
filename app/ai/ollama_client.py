"""
Ollama AI Client for AI Storage Cleaner.

Communicates with local Ollama server to classify unknown files/folders.
The AI ONLY performs classification and explanation — it has ZERO access
to the filesystem and cannot execute any commands.

Model: qwen3:8b (local)
Endpoint: http://localhost:11434
"""

import json
import httpx
from typing import Optional


# Default Ollama configuration
DEFAULT_OLLAMA_URL = "http://localhost:11434"
DEFAULT_MODEL = "qwen3:8b"
DEFAULT_TIMEOUT = 120.0  # seconds per request


SYSTEM_PROMPT = """You are a Windows filesystem analysis assistant. Your ONLY job is to classify files and folders.

You will receive information about a file or folder found in a Windows user's AppData\\Local directory.
You must classify it into one of these categories:

- SAFE: Cache, temporary files, shader caches, crash dumps, browser cache, package manager cache.
  These can be safely deleted because the application will regenerate them.

- REVIEW: Old installers, updaters, download caches, application-specific data that MIGHT be removable.
  The user should review these before deciding.

- PROTECTED: Application core files, user data, game saves, configuration files, databases, models.
  These should NEVER be deleted.

IMPORTANT RULES:
1. When in doubt, choose REVIEW or PROTECTED — never guess SAFE.
2. Game save files are ALWAYS PROTECTED.
3. Configuration files (.json, .ini, .cfg, .yaml) are ALWAYS PROTECTED.
4. Database files (.db, .sqlite) are ALWAYS PROTECTED.
5. Application executables and DLLs are PROTECTED.
6. Shader caches (DXCache, GLCache, ShaderCache) are SAFE.
7. Crash dumps (.dmp, .mdmp) are SAFE.
8. Browser caches are SAFE.
9. npm/pip/yarn caches are SAFE.

You MUST respond with valid JSON only. No markdown, no code blocks, no extra text.
Response format:
{
  "classification": "SAFE" | "REVIEW" | "PROTECTED",
  "confidence": 0.0 to 1.0,
  "reason": "Brief explanation of why this classification was chosen",
  "file_type": "cache | temp | installer | app_data | game | config | system | unknown",
  "can_regenerate": true | false,
  "risk_if_deleted": "none | low | medium | high | critical"
}"""


class OllamaClient:
    """
    Client for Ollama AI classification.

    Safety: This client ONLY sends text descriptions to the AI and receives
    JSON classification responses. It has NO filesystem access and cannot
    execute any commands.
    """

    def __init__(
        self,
        base_url: str = DEFAULT_OLLAMA_URL,
        model: str = DEFAULT_MODEL,
        timeout: float = DEFAULT_TIMEOUT,
    ):
        self.base_url = base_url.rstrip("/")
        self.model = model
        self.timeout = timeout
        self._client = httpx.Client(timeout=timeout)

    def is_available(self) -> bool:
        """Check if Ollama server is running and the model is available."""
        try:
            response = self._client.get(f"{self.base_url}/api/tags")
            if response.status_code == 200:
                data = response.json()
                models = [m.get("name", "") for m in data.get("models", [])]
                return any(self.model in m for m in models)
            return False
        except (httpx.ConnectError, httpx.TimeoutException):
            return False

    def classify_item(self, item: dict) -> Optional[dict]:
        """
        Ask AI to classify a single item.

        Args:
            item: Dictionary with file/folder metadata.

        Returns:
            Classification dict from AI, or None on error.
        """
        prompt = self._build_prompt(item)

        try:
            response = self._client.post(
                f"{self.base_url}/api/generate",
                json={
                    "model": self.model,
                    "prompt": prompt,
                    "system": SYSTEM_PROMPT,
                    "stream": False,
                    "options": {
                        "temperature": 0.1,  # Low temp for consistent classification
                        "num_predict": 300,   # Limit output length
                    },
                },
                timeout=self.timeout,
            )

            if response.status_code != 200:
                return None

            data = response.json()
            raw_response = data.get("response", "")

            # Parse JSON from AI response
            return self._parse_response(raw_response)

        except (httpx.ConnectError, httpx.TimeoutException, httpx.ReadTimeout) as e:
            return {
                "classification": "REVIEW",
                "confidence": 0.0,
                "reason": f"AI unavailable: {e}. Defaulting to REVIEW for safety.",
                "file_type": "unknown",
                "can_regenerate": False,
                "risk_if_deleted": "medium",
                "error": str(e),
            }

    def classify_batch(self, items: list[dict], progress_callback=None) -> list[dict]:
        """
        Classify multiple items. Sends them one at a time to avoid
        overwhelming the model.

        Args:
            items: List of item dicts.
            progress_callback: Optional callback(current, total, name).

        Returns:
            List of classification dicts.
        """
        results = []
        total = len(items)

        for idx, item in enumerate(items):
            if progress_callback:
                progress_callback(idx + 1, total, item.get("filename", ""))

            result = self.classify_item(item)
            if result:
                results.append(result)
            else:
                # Default to REVIEW on error (safe fallback)
                results.append({
                    "classification": "REVIEW",
                    "confidence": 0.0,
                    "reason": "AI classification failed. Defaulting to REVIEW.",
                    "file_type": "unknown",
                    "can_regenerate": False,
                    "risk_if_deleted": "medium",
                })

        return results

    def _build_prompt(self, item: dict) -> str:
        """Build a classification prompt from item metadata."""
        size_str = self._format_size(item.get("size_bytes", 0))

        prompt = f"""Classify this Windows file/folder found in AppData\\Local:

Path: {item.get('full_path', 'unknown')}
Name: {item.get('filename', 'unknown')}
Type: {'Directory' if item.get('is_directory') else 'File'}
Extension: {item.get('extension', 'N/A')}
Size: {size_str}
Last Modified: {item.get('modified_time', 'unknown')}
Parent Folder: {item.get('parent_folder', 'unknown')}
Application: {item.get('app_name', 'unknown')}
File Type: {item.get('file_type', 'unknown')}

Respond with JSON classification only."""

        return prompt

    def _parse_response(self, raw: str) -> Optional[dict]:
        """Parse AI response, extracting JSON from possible markdown wrapping."""
        text = raw.strip()

        # Remove thinking tags if present (qwen3 sometimes includes these)
        if "<think>" in text:
            # Find the closing tag and take content after it
            think_end = text.find("</think>")
            if think_end != -1:
                text = text[think_end + len("</think>"):].strip()

        # Try direct JSON parse first
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass

        # Try extracting JSON from markdown code blocks
        for marker in ["```json", "```"]:
            if marker in text:
                start = text.find(marker) + len(marker)
                end = text.find("```", start)
                if end != -1:
                    try:
                        return json.loads(text[start:end].strip())
                    except json.JSONDecodeError:
                        pass

        # Try finding JSON object in the text
        brace_start = text.find("{")
        brace_end = text.rfind("}")
        if brace_start != -1 and brace_end != -1:
            try:
                return json.loads(text[brace_start : brace_end + 1])
            except json.JSONDecodeError:
                pass

        # Failed to parse — return safe default
        return {
            "classification": "REVIEW",
            "confidence": 0.0,
            "reason": "Could not parse AI response. Defaulting to REVIEW.",
            "file_type": "unknown",
            "can_regenerate": False,
            "risk_if_deleted": "medium",
            "raw_response": raw[:500],
        }

    @staticmethod
    def _format_size(size_bytes: int) -> str:
        """Format bytes to human-readable."""
        if size_bytes < 1024:
            return f"{size_bytes} B"
        elif size_bytes < 1024 ** 2:
            return f"{size_bytes / 1024:.1f} KB"
        elif size_bytes < 1024 ** 3:
            return f"{size_bytes / (1024 ** 2):.2f} MB"
        else:
            return f"{size_bytes / (1024 ** 3):.2f} GB"

    def close(self):
        """Close the HTTP client."""
        self._client.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
