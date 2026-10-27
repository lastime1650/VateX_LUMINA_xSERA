"""Read-only console endpoints; SQL and permissions remain server controlled."""

import threading
import time
from functools import partial

import anyio
from fastapi import Request

from . import console_data
from .storage import CapacityError


def register(app, store, runtime, who, body):
    @app.get("/api/console/summary", name="console_summary")
    async def console_summary(request: Request):
        deadline = time.monotonic() + console_data.SECONDS
        actor = who(request, ("admin", "analyst", "viewer"))
        if set(request.query_params) - {"start", "end"}:
            raise ValueError("Console query accepts only start and end")
        values = {}
        for key in ("start", "end"):
            if len(request.query_params.getlist(key)) > 1:
                raise ValueError("Duplicate console time parameter")
            if key in request.query_params:
                try:
                    values[key] = float(request.query_params[key])
                except ValueError:
                    raise ValueError(
                        "Console time parameters must be epoch timestamps"
                    ) from None
        abort = threading.Event()
        try:
            # The queue wait consumes the same deadline as SQL. Abandoned work
            # observes abort through both DuckDB's watcher and SQLite progress.
            with anyio.fail_after(max(0.001, deadline - time.monotonic())):
                return await anyio.to_thread.run_sync(
                    partial(
                        console_data.summary,
                        store,
                        actor,
                        cancel=lambda: abort.is_set() or runtime.stop.is_set(),
                        _deadline=deadline,
                        **values,
                    ),
                    abandon_on_cancel=True,
                )
        except TimeoutError:
            raise CapacityError(
                "Console summary 5 second request deadline expired"
            ) from None
        finally:
            abort.set()
