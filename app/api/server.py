"""
FastAPI Server for AI Storage Cleaner Web UI.
"""

import os
import uuid
import time
from typing import List, Optional, Dict, Any
from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.database.db import Database
from app.scanner.file_scanner import FileScanner
from app.rules.rule_engine import RuleEngine
from app.safety.safety_engine import SafetyEngine
from app.ai.ollama_client import OllamaClient
from app.quarantine.quarantine_manager import QuarantineManager

app = FastAPI(
    title="AI Storage Cleaner API",
    description="Backend API for the AI Storage Cleaner Web UI",
    version="0.1.0"
)

# Enable CORS for the Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact frontend URL
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ── Models ─────────────────────────────────────────────────────────────

class ScanRequest(BaseModel):
    target_path: Optional[str] = None
    min_size_mb: int = 50
    use_ai: bool = True

class QuarantineRequest(BaseModel):
    scan_id: str
    item_ids: Optional[List[int]] = None  # If None, quarantine all SAFE

class RestoreRequest(BaseModel):
    quarantine_ids: List[str]

class DeleteRequest(BaseModel):
    quarantine_ids: List[str]
    permanent: bool = False

# ── State ──────────────────────────────────────────────────────────────

# Simple in-memory tracker for long-running scans
# For a real app, you might use a task queue like Celery or RQ
scan_tasks = {}

# ── Endpoints ──────────────────────────────────────────────────────────

@app.get("/api/system/status")
def get_system_status():
    """Get overall system health and status."""
    ollama = OllamaClient()
    ollama_ok = ollama.is_available()
    ollama_model = ollama.model if ollama_ok else None
    ollama.close()
    
    safety = SafetyEngine()
    safety_stats = safety.get_safety_summary()
    
    qm = QuarantineManager()
    q_stats = qm.get_quarantine_stats()
    
    return {
        "ollama": {
            "available": ollama_ok,
            "model": ollama_model
        },
        "safety_engine": safety_stats,
        "quarantine": q_stats
    }

def run_scan_task(scan_id: str, target_path: str, min_size_mb: int, use_ai: bool):
    """Background task to run the full scan pipeline."""
    scan_tasks[scan_id] = {"status": "scanning", "progress": 0, "message": "Scanning filesystem..."}
    
    try:
        db = Database()
        scanner = FileScanner(min_size_mb=min_size_mb)
        rule_engine = RuleEngine()
        safety_engine = SafetyEngine()
        
        # 1. Scan filesystem
        items = scanner.scan_directory(target_path)
        scan_tasks[scan_id]["message"] = f"Found {len(items)} items. Classifying with rules..."
        scan_tasks[scan_id]["progress"] = 30
        
        # 2. Rule Engine & Safety
        classified_items = []
        unknown_items = []
        
        for item in items:
            item_dict = item.to_dict()
            rule_result = rule_engine.classify(item_dict)
            item_dict.update(rule_result)
            
            safety_result = safety_engine.validate_classification(item_dict)
            item_dict.update({
                "classification": safety_result["classification"],
                "confidence": safety_result["confidence"],
                "reason": safety_result["reason"]
            })
            
            if safety_result.get("safety_override"):
                item_dict["classified_by"] = "safety_engine"
            
            if item_dict["classification"] == "UNKNOWN":
                unknown_items.append(item_dict)
            else:
                classified_items.append(item_dict)
                
        scan_tasks[scan_id]["progress"] = 60
        
        # 3. AI Analysis
        if use_ai and unknown_items:
            ollama = OllamaClient()
            if ollama.is_available():
                scan_tasks[scan_id]["message"] = f"Analyzing {len(unknown_items)} items with AI..."
                for idx, item_dict in enumerate(unknown_items):
                    ai_result = ollama.classify_item(item_dict)
                    if ai_result:
                        item_dict["classification"] = ai_result.get("classification", "REVIEW")
                        item_dict["confidence"] = ai_result.get("confidence", 0.0)
                        item_dict["reason"] = ai_result.get("reason", "")
                        item_dict["classified_by"] = "ollama_ai"
                        item_dict["ai_response"] = ai_result
                        
                        safety_result = safety_engine.validate_classification(item_dict)
                        item_dict["classification"] = safety_result["classification"]
                        item_dict["confidence"] = safety_result["confidence"]
                        item_dict["reason"] = safety_result["reason"]
                        
                        if safety_result.get("safety_override"):
                            item_dict["classified_by"] = "safety_engine"
                            
                    classified_items.append(item_dict)
                    scan_tasks[scan_id]["progress"] = 60 + int(40 * (idx / len(unknown_items)))
                ollama.close()
            else:
                # Fallback
                for item_dict in unknown_items:
                    item_dict["classification"] = "REVIEW"
                    item_dict["reason"] = "AI unavailable"
                    classified_items.append(item_dict)
        elif unknown_items:
            for item_dict in unknown_items:
                item_dict["classification"] = "REVIEW"
                item_dict["reason"] = "AI disabled"
                classified_items.append(item_dict)
                
        # 4. Save to DB
        classified_items.sort(key=lambda x: x.get("size_bytes", 0), reverse=True)
        db.add_scan_items_batch(scan_id, classified_items)
        total_size = sum(item.get("size_bytes", 0) for item in classified_items)
        db.complete_scan(scan_id, len(classified_items), total_size)
        db.close()
        
        scan_tasks[scan_id]["status"] = "completed"
        scan_tasks[scan_id]["progress"] = 100
        scan_tasks[scan_id]["message"] = "Scan complete!"
        
    except Exception as e:
        scan_tasks[scan_id]["status"] = "error"
        scan_tasks[scan_id]["message"] = str(e)


@app.post("/api/scans")
def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new directory scan."""
    target_path = request.target_path or os.path.join(os.environ.get("LOCALAPPDATA", ""), "")
    
    if not os.path.exists(target_path):
        raise HTTPException(status_code=400, detail="Target path does not exist")
        
    db = Database()
    scan_id = str(uuid.uuid4())[:8]
    db.create_scan(scan_id, target_path)
    db.close()
    
    background_tasks.add_task(run_scan_task, scan_id, target_path, request.min_size_mb, request.use_ai)
    
    return {"scan_id": scan_id, "target_path": target_path}

@app.get("/api/scans/{scan_id}/status")
def get_scan_status(scan_id: str):
    """Get the progress of a running scan."""
    if scan_id in scan_tasks:
        return scan_tasks[scan_id]
        
    # Check DB if not in memory
    db = Database()
    scan = db.get_scan(scan_id)
    db.close()
    
    if scan:
        if scan["status"] == "completed":
            return {"status": "completed", "progress": 100, "message": "Scan complete"}
        return {"status": scan["status"], "progress": 0, "message": "Unknown state"}
        
    raise HTTPException(status_code=404, detail="Scan not found")

@app.get("/api/scans")
def list_scans():
    """List recent scans."""
    db = Database()
    scans = db.list_scans()
    db.close()
    return scans

@app.get("/api/scans/{scan_id}/summary")
def get_scan_summary(scan_id: str):
    """Get summary of a completed scan."""
    db = Database()
    summary = db.get_scan_summary(scan_id)
    scan = db.get_scan(scan_id)
    db.close()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return {"scan": scan, "summary": summary}

@app.get("/api/scans/{scan_id}/items")
def get_scan_items(scan_id: str, classification: Optional[str] = None):
    """Get items from a scan."""
    db = Database()
    items = db.get_scan_items(scan_id, classification=classification)
    db.close()
    return items

@app.post("/api/quarantine/move")
def quarantine_items(request: QuarantineRequest):
    """Move items to quarantine."""
    db = Database()
    items = db.get_scan_items(request.scan_id)
    
    if request.item_ids is not None:
        items = [i for i in items if i["item_id"] in request.item_ids]
    else:
        items = [i for i in items if i["classification"] == "SAFE"]
        
    if not items:
        db.close()
        return {"status": "success", "quarantined_count": 0, "errors": []}
        
    safety_engine = SafetyEngine()
    qm = QuarantineManager()
    
    success = 0
    errors = []
    
    for item in items:
        res = qm.quarantine_item(item, safety_engine)
        if res["status"] == "success":
            success += 1
            db.log_action("quarantine", item["full_path"], res["entry"]["quarantined_path"],
                          size_bytes=item.get("size_bytes", 0),
                          classification=item.get("classification", ""),
                          reason="Moved via Web UI", user_confirmed=True)
        else:
            errors.append({"item_id": item["item_id"], "error": res["message"]})
            
    db.close()
    return {"status": "success", "quarantined_count": success, "errors": errors}

@app.get("/api/quarantine/items")
def list_quarantined_items():
    """List items currently in quarantine."""
    qm = QuarantineManager()
    return qm.list_quarantined()

@app.post("/api/quarantine/restore")
def restore_items(request: RestoreRequest):
    """Restore quarantined items."""
    qm = QuarantineManager()
    success = 0
    errors = []
    
    for q_id in request.quarantine_ids:
        res = qm.restore_item(q_id)
        if res["status"] == "success":
            success += 1
        else:
            errors.append({"quarantine_id": q_id, "error": res["message"]})
            
    return {"status": "success", "restored_count": success, "errors": errors}

@app.post("/api/quarantine/delete")
def delete_items(request: DeleteRequest):
    """Delete quarantined items permanently or to recycle bin."""
    qm = QuarantineManager()
    success = 0
    errors = []
    
    for q_id in request.quarantine_ids:
        res = qm.permanent_delete(q_id, use_recycle_bin=not request.permanent)
        if res["status"] == "success":
            success += 1
        else:
            errors.append({"quarantine_id": q_id, "error": res["message"]})
            
    return {"status": "success", "deleted_count": success, "errors": errors}
