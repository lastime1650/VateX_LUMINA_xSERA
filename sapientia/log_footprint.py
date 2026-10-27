"""Bounded, node-local data-directory footprint telemetry.

This is sampled file metadata, not an admission or free-space authority. An
incomplete walk never presents its measured prefix as a complete disk total.
"""

import os
import threading
import time
from pathlib import Path

_cache = {}
_guard = threading.Lock()
_CATEGORIES = ("root_files", "parquet_segments", "search_indexes_and_snapshots",
               "spool", "temporary", "other")


def _category(relative):
    if len(relative.parts) == 1:
        return "root_files"
    first = relative.parts[0].lower()
    if first == "log-segments":
        return "parquet_segments"
    if first == "log-search":
        return "search_indexes_and_snapshots"
    if "spool" in first:
        return "spool"
    if "tmp" in first or "temp" in first:
        return "temporary"
    return "other"


def _collect(root, budget, max_entries):
    started = time.monotonic()
    deadline = started + budget
    totals = dict.fromkeys(_CATEGORIES, 0)
    seen = files = skipped = errors = 0
    complete = True
    if root.is_symlink() or (os.name == "nt" and os.path.isjunction(root)):
        pending, skipped, complete = [], 1, False
    else:
        pending = [root]
    while pending and complete:
        directory = pending.pop()
        try:
            with os.scandir(directory) as entries:
                for entry in entries:
                    if seen >= max_entries or time.monotonic() >= deadline:
                        complete = False
                        break
                    seen += 1
                    try:
                        # Windows junctions also cross a managed directory
                        # boundary; never follow one for capacity telemetry.
                        if entry.is_symlink() or (os.name == "nt" and os.path.isjunction(entry.path)):
                            skipped += 1
                            complete = False
                            continue
                        if entry.is_dir(follow_symlinks=False):
                            pending.append(Path(entry.path))
                        elif entry.is_file(follow_symlinks=False):
                            relative = Path(entry.path).relative_to(root)
                            totals[_category(relative)] += entry.stat(follow_symlinks=False).st_size
                            files += 1
                    except OSError:
                        errors += 1
                        complete = False
        except OSError:
            errors += 1
            complete = False
    return {"scope": "node_local_data_directory_only_excludes_sibling_backups",
            "method": "sampled_logical_file_sizes_not_allocated_blocks_or_free_space",
            "measured_at_epoch": time.time(), "collection_seconds": time.monotonic() - started,
            "complete": complete and not pending, "measured_bytes": sum(totals.values()),
            "components": totals, "files_observed": files, "entries_observed": seen,
            "skipped_links": skipped, "metadata_errors": errors}


def status(directory, *, cache_seconds=30., budget=.25, max_entries=20000):
    """Return a cached bounded sample; no raw file names or tenant counts leak."""
    root = Path(directory).absolute()
    key = str(root)
    with _guard:
        cached = _cache.get(key)
        if cached and time.monotonic() - cached[0] < cache_seconds:
            value = cached[1]
        else:
            value = _collect(root, max(.001, min(1., budget)), max(1, max_entries))
            _cache[key] = (time.monotonic(), value)
        # Callers may decorate their response, but cannot mutate the cache.
        return {**value, "components": dict(value["components"]),
                "age_seconds": max(0, time.time() - value["measured_at_epoch"]),
                "cache_seconds": cache_seconds}
