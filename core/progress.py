"""
progress.py - Rich-based progress bar and live statistics helpers.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)


def build_progress() -> Progress:
    """Construct a standardized Rich Progress instance for scan phases.

    Returns:
        Configured rich.progress.Progress instance.
    """
    return Progress(
        SpinnerColumn(),
        TextColumn("[bold blue]{task.description}"),
        BarColumn(bar_width=40),
        MofNCompleteColumn(),
        TextColumn("•"),
        TimeElapsedColumn(),
        TextColumn("•"),
        TimeRemainingColumn(),
        transient=False,
    )


@contextmanager
def progress_task(progress: Progress, description: str, total: int) -> Iterator[int]:
    """Context manager yielding a task ID for manual progress updates.

    Args:
        progress: An active rich Progress instance.
        description: Task description text.
        total: Total number of steps for this task.

    Yields:
        The task_id to pass to progress.update()/progress.advance().
    """
    task_id = progress.add_task(description, total=total)
    try:
        yield task_id
    finally:
        progress.update(task_id, completed=total)
