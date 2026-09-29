# AI Storage Cleaner 🧹

Intelligent disk space analyzer for Windows that uses local AI (Ollama) to safely identify removable cache and temporary files.

## 🎯 Phase 2 Features (Active)

This release implements a **Safe Quarantine System** with Recycle Bin integration.

- **File Scanner**: Rapidly scans Windows AppData folders and calculates sizes.
- **Rule Engine**: Pattern-based pre-classification to identify known SAFE files instantly.
- **AI Classification**: Uses `qwen3:8b` via Ollama to analyze unknown folders.
- **Safety Engine**: A robust gatekeeper that enforces protected paths and validates AI decisions.
- **Quarantine Manager**: Safely moves files to quarantine, allowing restoration or permanent deletion (via Recycle Bin).
- **Local SQLite DB**: Tracks scan sessions and items.
- **Rich CLI**: Beautiful terminal outputs and progress bars.

## ⚠️ Safety First

- **Explicit Confirmation**: The tool will NEVER move or delete files without explicit user confirmation.
- **Protected Paths**: `C:\Windows`, `Program Files`, User Desktop/Docs, Game Saves, and AI Models are strictly protected and can never be quarantined.
- **AI Sandboxed**: The AI only returns JSON classifications and has **zero access** to your filesystem.
- **Recycle Bin Integration**: Permanent deletion defaults to sending files to the Windows Recycle Bin for ultimate safety.

## 🛠️ Requirements

- Windows 11
- Python 3.10+
- Node.js (for future web UI integration)
- Ollama with `qwen3:8b` model installed

## 🚀 Quick Start

1. **Install dependencies**:
   ```cmd
   pip install -r requirements.txt
   ```

2. **Run a scan**:
   ```cmd
   python -m app.main scan
   ```
   *(Defaults to `C:\Users\<username>\AppData\Local`)*

3. **Check status**:
   ```cmd
   python -m app.main status
   ```

4. **Review items**:
   ```cmd
   python -m app.main review --classification SAFE
   ```

## 🏗️ Architecture

```
File Scanner → Rule Engine → Safety Check → AI Analysis → Safety Validation → Database
```

## 🧪 Testing

Run the test suite using pytest:
```cmd
python -m pytest tests/ -v
```
