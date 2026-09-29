"""
CLI Formatting utilities for AI Storage Cleaner.

Provides rich terminal output for scan results, summaries, and status.
"""

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn
from rich import box


console = Console()


# ── Color scheme ─────────────────────────────────────────────────────

COLORS = {
    "SAFE": "green",
    "REVIEW": "yellow",
    "PROTECTED": "red",
    "UNKNOWN": "dim white",
}

STATUS_ICONS = {
    "SAFE": "[SAFE]",
    "REVIEW": "[REVIEW]",
    "PROTECTED": "[PROTECTED]",
    "UNKNOWN": "[UNKNOWN]",
}


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


def print_banner():
    """Print the application banner."""
    banner = Text()
    banner.append("AI Storage Cleaner", style="bold cyan")
    banner.append(" v0.1.0", style="dim")
    banner.append("\n   Intelligent disk space analyzer for Windows", style="italic dim")
    console.print(Panel(banner, box=box.ROUNDED, border_style="cyan"))


def print_scan_header(target_path: str):
    """Print scan start header."""
    console.print()
    console.print(f"Scanning: [bold]{target_path}[/bold]")
    console.print("─" * 60)


def print_scan_results(items: list[dict], title: str = "Scan Results"):
    """Print scan results in a formatted table."""
    if not items:
        console.print("\n[dim]No items found matching criteria.[/dim]")
        return

    table = Table(
        title=title,
        box=box.ROUNDED,
        show_lines=True,
        title_style="bold cyan",
        header_style="bold white",
    )

    table.add_column("Name", style="bold", min_width=25, max_width=40)
    table.add_column("Size", justify="right", min_width=10)
    table.add_column("Type", min_width=15)
    table.add_column("Status", justify="center", min_width=12)
    table.add_column("Reason", min_width=30, max_width=50)

    for item in items:
        classification = item.get("classification", "UNKNOWN")
        color = COLORS.get(classification, "white")
        icon = STATUS_ICONS.get(classification, "")

        name = item.get("filename", "unknown")
        if item.get("app_name") and item["app_name"] != name:
            name = f"{item['app_name']}/{name}"

        table.add_row(
            name,
            format_size(item.get("size_bytes", 0)),
            item.get("file_type", "unknown"),
            f"[{color}]{icon} {classification}[/{color}]",
            item.get("reason", "")[:80],
        )

    console.print(table)


def print_scan_summary(summary: dict, total_items: int, total_size: int, scan_time: float):
    """Print a summary of the scan."""
    console.print()

    summary_table = Table(
        title="📊 Scan Summary",
        box=box.ROUNDED,
        title_style="bold cyan",
        header_style="bold white",
    )
    summary_table.add_column("Classification", style="bold", min_width=15)
    summary_table.add_column("Count", justify="right", min_width=8)
    summary_table.add_column("Total Size", justify="right", min_width=12)

    for classification, data in summary.items():
        color = COLORS.get(classification, "white")
        icon = STATUS_ICONS.get(classification, "")
        summary_table.add_row(
            f"[{color}]{icon} {classification}[/{color}]",
            str(data.get("count", 0)),
            format_size(data.get("total_size", 0)),
        )

    console.print(summary_table)

    console.print()
    console.print(f"  Total items scanned: [bold]{total_items}[/bold]")
    console.print(f"  Total size analyzed: [bold]{format_size(total_size)}[/bold]")
    console.print(f"  Scan time: [bold]{scan_time:.1f}s[/bold]")
    console.print()


def print_item_detail(item: dict):
    """Print detailed information about a single item."""
    classification = item.get("classification", "UNKNOWN")
    color = COLORS.get(classification, "white")
    icon = STATUS_ICONS.get(classification, "")

    panel_content = Text()
    panel_content.append(f"Path: {item.get('full_path', 'unknown')}\n")
    panel_content.append(f"Size: {format_size(item.get('size_bytes', 0))}\n")
    panel_content.append(f"Type: {item.get('file_type', 'unknown')}\n")
    panel_content.append(f"Modified: {item.get('modified_time', 'unknown')}\n")
    panel_content.append(f"App: {item.get('app_name', 'unknown')}\n")
    panel_content.append(f"Classified by: {item.get('classified_by', 'unknown')}\n")
    panel_content.append(f"Confidence: {item.get('confidence', 0):.0%}\n")
    panel_content.append(f"\nReason: {item.get('reason', 'N/A')}")

    console.print(Panel(
        panel_content,
        title=f"{icon} {item.get('filename', 'unknown')} — [{color}]{classification}[/{color}]",
        box=box.ROUNDED,
        border_style=color,
    ))


def print_error(message: str):
    """Print an error message."""
    console.print(f"[red]Error:[/red] {message}")


def print_warning(message: str):
    """Print a warning message."""
    console.print(f"[yellow]Warning:[/yellow] {message}")


def print_success(message: str):
    """Print a success message."""
    console.print(f"[green]Success: {message}[/green]")


def print_info(message: str):
    """Print an info message."""
    console.print(f"[cyan]Info: {message}[/cyan]")


def get_progress_bar():
    """Create a progress bar for long operations."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=30),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )


def confirm_action(message: str) -> bool:
    """Ask user for confirmation."""
    response = console.input(f"\n[yellow]{message} (y/N): [/yellow]")
    return response.strip().lower() in ("y", "yes")
