"""
AI Storage Cleaner — CLI Entry Point

Usage:
    python -m app.main scan [PATH]
    python -m app.main analyze [--scan-id ID]
    python -m app.main review [--scan-id ID] [--classification TYPE]
    python -m app.main status
    python -m app.main quarantine
    python -m app.main restore
    python -m app.main clean
    python -m app.main serve        (Launch API server for Web UI)
"""

import os
import sys
import time
import uuid
from pathlib import Path

import click

from app.scanner.file_scanner import FileScanner
from app.rules.rule_engine import RuleEngine
from app.safety.safety_engine import SafetyEngine
from app.ai.ollama_client import OllamaClient
from app.quarantine.quarantine_manager import QuarantineManager
from app.database.db import Database
from app.utils.formatting import (
    console,
    print_banner,
    print_scan_header,
    print_scan_results,
    print_scan_summary,
    print_item_detail,
    print_error,
    print_warning,
    print_success,
    print_info,
    format_size,
    get_progress_bar,
    confirm_action,
)


# Default scan target
DEFAULT_TARGET = os.path.join(os.environ.get("LOCALAPPDATA", ""), "")


@click.group()
@click.version_option(version="0.1.0", prog_name="AI Storage Cleaner")
def cli():
    """AI Storage Cleaner — Intelligent disk space analyzer for Windows."""
    pass


# ═══════════════════════════════════════════════════════════════════════
# SCAN COMMAND
# ═══════════════════════════════════════════════════════════════════════

@cli.command()
@click.argument("path", default=None, required=False, type=str)
@click.option("--min-size", default=50, help="Minimum folder size in MB to report (default: 50)")
@click.option("--no-ai", is_flag=True, help="Skip AI analysis, use rule engine only")
@click.option("--depth", default=1, help="Scan depth (default: 1, immediate children)")
def scan(path: str, min_size: int, no_ai: bool, depth: int):
    """
    Scan a directory and classify files/folders.

    If no path is provided, you will be prompted to select a drive.
    """
    print_banner()

    if not path:
        import string
        from rich.prompt import Prompt
        drives = [f"{d}:\\" for d in string.ascii_uppercase if os.path.exists(f"{d}:\\")]
        console.print("[bold]Available Drives and Paths:[/bold]")
        for i, d in enumerate(drives, 1):
            console.print(f"  [cyan]{i}.[/cyan] Drive {d}")
        console.print(f"  [cyan]{len(drives)+1}.[/cyan] Default Target ({DEFAULT_TARGET})")
        
        choice = Prompt.ask("Select a drive to scan", choices=[str(i) for i in range(1, len(drives)+2)], default=str(len(drives)+1))
        choice_idx = int(choice) - 1
        if choice_idx < len(drives):
            path = drives[choice_idx]
        else:
            path = DEFAULT_TARGET
    elif not os.path.exists(path):
        print_error(f"Path does not exist: {path}")
        return

    # Resolve path
    target_path = os.path.abspath(path)
    print_scan_header(target_path)

    # Initialize components
    db = Database()
    scanner = FileScanner(min_size_mb=min_size)
    rule_engine = RuleEngine()
    safety_engine = SafetyEngine()
    quarantine_mgr = QuarantineManager()

    # Check Ollama availability (unless --no-ai)
    ollama = None
    if not no_ai:
        ollama = OllamaClient()
        if ollama.is_available():
            print_success(f"Ollama connected (model: {ollama.model})")
        else:
            print_warning("Ollama not available. Using rule engine only.")
            ollama = None

    # Create scan record
    scan_id = str(uuid.uuid4())[:8]
    db.create_scan(scan_id, target_path)
    print_info(f"Scan ID: {scan_id}")
    console.print()

    # ── Phase 1: File scanning ───────────────────────────────────────
    start_time = time.time()

    with get_progress_bar() as progress:
        task = progress.add_task("Scanning filesystem...", total=None)

        def scan_progress(current, total, name):
            progress.update(task, total=total, completed=current,
                          description=f"Scanning: {name[:40]}")

        items = scanner.scan_directory(target_path, depth=depth,
                                       progress_callback=scan_progress)

    if scanner.errors:
        print_warning(f"{len(scanner.errors)} access errors (permission denied)")

    print_info(f"Found {len(items)} items above {min_size} MB threshold")
    console.print()

    # ── Phase 2: Rule Engine classification ──────────────────────────
    console.print("[bold]🔍 Classifying with Rule Engine...[/bold]")
    classified_items = []
    unknown_items = []

    for item in items:
        item_dict = item.to_dict()

        # Rule engine classification
        rule_result = rule_engine.classify(item_dict)
        item_dict.update(rule_result)

        # Safety engine validation (can override rule engine)
        safety_result = safety_engine.validate_classification(item_dict)
        item_dict.update({
            "classification": safety_result["classification"],
            "confidence": safety_result["confidence"],
            "reason": safety_result["reason"],
        })

        if safety_result.get("safety_override"):
            item_dict["classified_by"] = "safety_engine"
            item_dict["reason"] = (
                f"[Safety Override] {safety_result['reason']}"
            )

        if item_dict["classification"] == "UNKNOWN":
            unknown_items.append(item_dict)
        else:
            classified_items.append(item_dict)

    print_success(
        f"Rule Engine classified {len(classified_items)}/{len(items)} items"
    )

    # ── Phase 3: AI classification for unknowns ──────────────────────
    if unknown_items and ollama:
        console.print()
        console.print(
            f"[bold]🤖 Analyzing {len(unknown_items)} unknown items with AI...[/bold]"
        )
        console.print("[dim]   (This may take a moment)[/dim]")

        with get_progress_bar() as progress:
            task = progress.add_task("AI Analysis...", total=len(unknown_items))

            for idx, item_dict in enumerate(unknown_items):
                progress.update(
                    task, completed=idx + 1,
                    description=f"AI: {item_dict['filename'][:35]}",
                )

                ai_result = ollama.classify_item(item_dict)
                if ai_result:
                    item_dict["classification"] = ai_result.get(
                        "classification", "REVIEW"
                    )
                    item_dict["confidence"] = ai_result.get("confidence", 0.0)
                    item_dict["reason"] = ai_result.get("reason", "")
                    item_dict["classified_by"] = "ollama_ai"
                    item_dict["ai_response"] = ai_result

                    # Final safety validation on AI results
                    safety_result = safety_engine.validate_classification(item_dict)
                    item_dict["classification"] = safety_result["classification"]
                    item_dict["confidence"] = safety_result["confidence"]
                    item_dict["reason"] = safety_result["reason"]

                    if safety_result.get("safety_override"):
                        item_dict["classified_by"] = "safety_engine"

                classified_items.append(item_dict)

        print_success(f"AI classified {len(unknown_items)} items")
    elif unknown_items:
        # No AI available — mark all as REVIEW
        for item_dict in unknown_items:
            item_dict["classification"] = "REVIEW"
            item_dict["confidence"] = 0.0
            item_dict["reason"] = "No AI available; requires manual review"
            item_dict["classified_by"] = "fallback"
            classified_items.append(item_dict)
        print_warning(
            f"{len(unknown_items)} items marked as REVIEW (no AI available)"
        )

    # ── Phase 4: Store results and display ───────────────────────────
    # Sort by size descending
    classified_items.sort(key=lambda x: x.get("size_bytes", 0), reverse=True)

    # Store in database
    db.add_scan_items_batch(scan_id, classified_items)

    total_size = sum(item.get("size_bytes", 0) for item in classified_items)
    scan_time = time.time() - start_time

    db.complete_scan(scan_id, len(classified_items), total_size)

    # Display results
    console.print()
    print_scan_results(classified_items, title="📋 Classification Results")

    # Summary
    summary = db.get_scan_summary(scan_id)
    print_scan_summary(summary, len(classified_items), total_size, scan_time)

    # Show recoverable space
    safe_size = summary.get("SAFE", {}).get("total_size", 0)
    review_size = summary.get("REVIEW", {}).get("total_size", 0)
    if safe_size > 0:
        print_success(
            f"Potentially recoverable (SAFE): {format_size(safe_size)}"
        )
    if review_size > 0:
        print_info(
            f"Needs review (REVIEW): {format_size(review_size)}"
        )

    console.print()
    print_info(f"Results saved. Use 'review --scan-id {scan_id}' to inspect items.")

    # Cleanup
    if ollama:
        ollama.close()
    db.close()


# ═══════════════════════════════════════════════════════════════════════
# ANALYZE COMMAND
# ═══════════════════════════════════════════════════════════════════════

@cli.command()
@click.option("--scan-id", default=None, help="Scan ID to analyze (default: latest)")
def analyze(scan_id: str):
    """Re-analyze unclassified items from a previous scan using AI."""
    print_banner()

    db = Database()

    if scan_id is None:
        scan = db.get_latest_scan()
        if not scan:
            print_error("No scans found. Run 'scan' first.")
            db.close()
            return
        scan_id = scan["scan_id"]

    print_info(f"Analyzing scan: {scan_id}")

    # Get unclassified items
    unknown = db.get_unclassified_items(scan_id)
    if not unknown:
        print_success("All items are already classified!")
        # Show summary
        summary = db.get_scan_summary(scan_id)
        print_scan_summary(summary, 0, 0, 0)
        db.close()
        return

    print_info(f"Found {len(unknown)} unclassified items")

    # Check Ollama
    ollama = OllamaClient()
    if not ollama.is_available():
        print_error("Ollama is not available. Please start Ollama and try again.")
        db.close()
        return

    safety_engine = SafetyEngine()

    # Classify with AI
    with get_progress_bar() as progress:
        task = progress.add_task("AI Analysis...", total=len(unknown))

        for idx, item in enumerate(unknown):
            progress.update(
                task, completed=idx + 1,
                description=f"AI: {item['filename'][:35]}",
            )

            ai_result = ollama.classify_item(item)
            if ai_result:
                item["classification"] = ai_result.get("classification", "REVIEW")
                item["confidence"] = ai_result.get("confidence", 0.0)
                item["reason"] = ai_result.get("reason", "")

                # Safety check
                safety_result = safety_engine.validate_classification(item)

                db.update_item_classification(
                    item_id=item["item_id"],
                    classification=safety_result["classification"],
                    confidence=safety_result["confidence"],
                    reason=safety_result["reason"],
                    classified_by="ollama_ai",
                    ai_response=ai_result,
                )

    print_success(f"Classified {len(unknown)} items")

    # Show updated summary
    summary = db.get_scan_summary(scan_id)
    items = db.get_scan_items(scan_id)
    total_size = sum(i.get("size_bytes", 0) for i in items)
    print_scan_summary(summary, len(items), total_size, 0)

    ollama.close()
    db.close()


# ═══════════════════════════════════════════════════════════════════════
# REVIEW COMMAND
# ═══════════════════════════════════════════════════════════════════════

@cli.command()
@click.option("--scan-id", default=None, help="Scan ID to review (default: latest)")
@click.option(
    "--classification", "-c",
    type=click.Choice(["SAFE", "REVIEW", "PROTECTED", "UNKNOWN", "ALL"], case_sensitive=False),
    default="ALL",
    help="Filter by classification",
)
@click.option("--detail", "-d", is_flag=True, help="Show detailed view for each item")
@click.option("--min-size", default=0, help="Minimum size in MB to show")
def review(scan_id: str, classification: str, detail: bool, min_size: int):
    """Review classified items from a previous scan."""
    print_banner()

    db = Database()

    if scan_id is None:
        scan = db.get_latest_scan()
        if not scan:
            print_error("No scans found. Run 'scan' first.")
            db.close()
            return
        scan_id = scan["scan_id"]

    scan_info = db.get_scan(scan_id)
    if not scan_info:
        print_error(f"Scan '{scan_id}' not found.")
        db.close()
        return

    print_info(f"Reviewing scan: {scan_id}")
    print_info(f"Target: {scan_info['target_path']}")
    print_info(f"Scanned at: {scan_info['started_at']}")
    console.print()

    # Get items
    cls_filter = None if classification.upper() == "ALL" else classification.upper()
    items = db.get_scan_items(
        scan_id,
        classification=cls_filter,
        min_size=min_size * 1024 * 1024,
    )

    if not items:
        print_info("No items match the filter criteria.")
        db.close()
        return

    if detail:
        for item in items:
            print_item_detail(item)
            console.print()
    else:
        title = f"📋 Items — {classification.upper()}"
        print_scan_results(items, title=title)

    # Summary
    summary = db.get_scan_summary(scan_id)
    total_size = sum(i.get("size_bytes", 0) for i in items)
    print_scan_summary(summary, len(items), total_size, 0)

    db.close()


# ═══════════════════════════════════════════════════════════════════════
# STATUS COMMAND
# ═══════════════════════════════════════════════════════════════════════

@cli.command()
def status():
    """Show system status and recent scans."""
    print_banner()

    # Check components
    console.print("[bold]System Status:[/bold]")
    console.print()

    # Ollama
    ollama = OllamaClient()
    if ollama.is_available():
        print_success(f"Ollama: Connected (model: {ollama.model})")
    else:
        print_warning("Ollama: Not available")
    ollama.close()

    # Safety engine
    safety = SafetyEngine()
    safety_info = safety.get_safety_summary()
    print_success(
        f"Safety Engine: {safety_info['total_protected_paths']} protected paths, "
        f"{safety_info['protected_extensions']} protected extensions"
    )

    # Database
    db = Database()
    scans = db.list_scans(limit=5)

    console.print()
    if scans:
        console.print("[bold]Recent Scans:[/bold]")
        from rich.table import Table
        from rich import box

        table = Table(box=box.SIMPLE)
        table.add_column("Scan ID", style="cyan")
        table.add_column("Target")
        table.add_column("Items", justify="right")
        table.add_column("Size", justify="right")
        table.add_column("Status")
        table.add_column("Date")

        for s in scans:
            table.add_row(
                s["scan_id"],
                s["target_path"][:40],
                str(s.get("total_items", 0)),
                format_size(s.get("total_size", 0)),
                s.get("status", "unknown"),
                s.get("started_at", "")[:19],
            )
        console.print(table)
    else:
        print_info("No scans found. Run 'scan' to get started.")

    # Quarantine
    qm = QuarantineManager()
    q_stats = qm.get_quarantine_stats()
    print_info(f"Quarantine: {q_stats['total_items']} items, {format_size(q_stats['total_size'])} total")

    db.close()


# ═══════════════════════════════════════════════════════════════════════
# PHASE 2: QUARANTINE COMMANDS
# ═══════════════════════════════════════════════════════════════════════

@cli.command()
@click.option("--scan-id", default=None, help="Scan ID to process (default: latest)")
@click.option("--all-safe", is_flag=True, help="Quarantine all SAFE items (requires confirmation)")
def quarantine(scan_id: str, all_safe: bool):
    """Move SAFE items to quarantine."""
    print_banner()
    db = Database()

    if scan_id is None:
        scan = db.get_latest_scan()
        if not scan:
            print_error("No scans found. Run 'scan' first.")
            db.close()
            return
        scan_id = scan["scan_id"]

    items = db.get_scan_items(scan_id, classification="SAFE")
    if not items:
        print_info("No SAFE items found in this scan.")
        db.close()
        return

    print_info(f"Found {len(items)} SAFE items to review for quarantine.")
    if not confirm_action(f"Do you want to proceed with quarantining up to {len(items)} items?"):
        db.close()
        return

    safety_engine = SafetyEngine()
    qm = QuarantineManager()
    
    success_count = 0
    with get_progress_bar() as progress:
        task = progress.add_task("Quarantining...", total=len(items))
        
        for item in items:
            progress.update(task, description=f"Processing: {item['filename'][:30]}")
            
            if not all_safe:
                # Interactive mode inside progress bar is tricky, so we just process if all_safe
                # Actually, rich prompt might break progress bar. We will just auto-quarantine SAFE ones 
                # if they agreed to the prompt above.
                pass
                
            res = qm.quarantine_item(item, safety_engine)
            
            if res["status"] == "success":
                success_count += 1
                db.log_action("quarantine", item["full_path"], res["entry"]["quarantined_path"],
                              size_bytes=item.get("size_bytes", 0),
                              classification=item.get("classification", ""),
                              reason=res["message"], user_confirmed=True)
            
            progress.advance(task)

    print_success(f"Successfully quarantined {success_count}/{len(items)} items.")
    db.close()


@cli.command()
@click.option("--id", "q_id", required=False, help="Specific quarantine ID to restore")
@click.option("--all", "restore_all", is_flag=True, help="Restore all quarantined items")
def restore(q_id: str, restore_all: bool):
    """Restore quarantined items back to their original locations."""
    print_banner()
    qm = QuarantineManager()
    items = qm.list_quarantined()
    
    if not items:
        print_info("Quarantine is empty.")
        return
        
    if not q_id and not restore_all:
        console.print("[bold]Currently Quarantined Items:[/bold]")
        for item in items:
            console.print(f"  - [cyan]{item['quarantine_id']}[/cyan]: {item['original_path']} ({format_size(item.get('size_bytes', 0))})")
        print_info("Use --id <ID> to restore a specific item, or --all to restore all.")
        return

    targets = items if restore_all else [i for i in items if i['quarantine_id'] == q_id]
    
    if not targets:
        print_error("Item not found.")
        return

    if not confirm_action(f"Restore {len(targets)} item(s) to their original locations?"):
        return

    success = 0
    for item in targets:
        res = qm.restore_item(item["quarantine_id"])
        if res["status"] == "success":
            print_success(f"Restored: {item['original_path']}")
            success += 1
        else:
            print_error(f"Failed to restore {item['original_path']}: {res['message']}")
            
    print_info(f"Restored {success}/{len(targets)} items.")


@cli.command()
@click.option("--id", "q_id", required=False, help="Specific quarantine ID to delete")
@click.option("--all", "delete_all", is_flag=True, help="Delete all quarantined items")
@click.option("--permanent", is_flag=True, help="Permanently delete instead of sending to Recycle Bin")
def clean(q_id: str, delete_all: bool, permanent: bool):
    """Delete quarantined items (sends to Recycle Bin by default)."""
    print_banner()
    qm = QuarantineManager()
    items = qm.list_quarantined()
    
    if not items:
        print_info("Quarantine is empty.")
        return
        
    if not q_id and not delete_all:
        console.print("[bold]Currently Quarantined Items:[/bold]")
        for item in items:
            console.print(f"  - [cyan]{item['quarantine_id']}[/cyan]: {item['original_path']} ({format_size(item.get('size_bytes', 0))})")
        print_info("Use --id <ID> to delete a specific item, or --all to delete all.")
        return

    targets = items if delete_all else [i for i in items if i['quarantine_id'] == q_id]
    
    if not targets:
        print_error("Item not found.")
        return

    action_text = "PERMANENTLY DELETE" if permanent else "send to Recycle Bin"
    if not confirm_action(f"Are you sure you want to {action_text} {len(targets)} item(s)?"):
        return

    success = 0
    for item in targets:
        res = qm.permanent_delete(item["quarantine_id"], use_recycle_bin=not permanent)
        if res["status"] == "success":
            print_success(f"Deleted: {item['filename']}")
            success += 1
        else:
            print_error(f"Failed to delete {item['filename']}: {res['message']}")
            
    print_info(f"Processed {success}/{len(targets)} items.")


# ═══════════════════════════════════════════════════════════════════════
# INTERACTIVE DELETE COMMAND
# ═══════════════════════════════════════════════════════════════════════

@cli.command(name="interactive-delete")
@click.option("--scan-id", default=None, help="Scan ID to process (default: latest)")
@click.option(
    "--classification", "-c", 
    type=click.Choice(["SAFE", "REVIEW", "ALL"], case_sensitive=False), 
    default="SAFE", 
    help="Filter by classification"
)
def interactive_delete(scan_id: str, classification: str):
    """Interactively review and delete files/folders."""
    print_banner()
    db = Database()

    if scan_id is None:
        scan = db.get_latest_scan()
        if not scan:
            print_error("No scans found. Run 'scan' first.")
            db.close()
            return
        scan_id = scan["scan_id"]

    cls_filter = None if classification.upper() == "ALL" else classification.upper()
    items = db.get_scan_items(scan_id, classification=cls_filter)
    
    if not items:
        print_info(f"No {classification} items found in this scan.")
        db.close()
        return

    from rich.prompt import Confirm
    import send2trash

    print_info(f"Found {len(items)} items for review.")
    deleted_count = 0
    reclaimed_space = 0

    for item in items:
        console.print("\n" + "━"*60)
        console.print(f"[bold cyan]Target:[/bold cyan] {item['full_path']}")
        console.print(f"[bold cyan]Size:[/bold cyan] {format_size(item.get('size_bytes', 0))}")
        console.print(f"[bold cyan]Classification:[/bold cyan] {item.get('classification', 'UNKNOWN')} (Confidence: {item.get('confidence', 0):.2f})")
        
        reason = item.get('reason', 'No description available.')
        console.print(f"\n[bold yellow]Importance / Function:[/bold yellow]\n{reason}")
        console.print("━"*60)
        
        if Confirm.ask(f"Do you want to delete this item? (will be sent to Recycle Bin)"):
            try:
                full_path = item["full_path"]
                if os.path.exists(full_path):
                    send2trash.send2trash(full_path)
                    print_success(f"Deleted: {full_path}")
                    deleted_count += 1
                    reclaimed_space += item.get('size_bytes', 0)
                else:
                    print_warning(f"File/Folder not found: {full_path}")
            except Exception as e:
                print_error(f"Failed to delete {item['full_path']}: {e}")
        else:
            print_info("Skipped.")

    console.print("\n" + "━"*60)
    print_success("Interactive deletion complete.")
    print_success(f"Items deleted: {deleted_count}")
    print_success(f"Space reclaimed: {format_size(reclaimed_space)}")
    
    db.close()


@cli.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8000, help="Port to bind to")
def serve(host: str, port: int):
    """Launch the API server for the Web UI."""
    import uvicorn
    print_banner()
    print_info(f"Starting API server on http://{host}:{port}")
    uvicorn.run("app.api.server:app", host=host, port=port, reload=True)


# ═══════════════════════════════════════════════════════════════════════
# Entry point
# ═══════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    cli()
