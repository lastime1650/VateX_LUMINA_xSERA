"""Commit notifications with generation tokens; durable journals remain authoritative.

Notifications are hints only. Periodic polling repairs a missed process-local hint
and a generation captured before work prevents the clear/wait lost-wakeup race.
"""
import threading
import time


class Dispatch:
    def __init__(self):
        self.condition = threading.Condition()
        self.generations = {}
        self.notifications = {}
        self.closed = False

    def token(self, stage):
        with self.condition:
            return self.generations.get(stage, 0)

    def notify(self, *stages):
        with self.condition:
            for stage in stages:
                self.generations[stage] = self.generations.get(stage, 0) + 1
                self.notifications[stage] = time.time()
            self.condition.notify_all()

    def wait(self, stage, token, timeout):
        with self.condition:
            return self.condition.wait_for(
                lambda: self.closed or self.generations.get(stage, 0) != token,
                timeout=timeout,
            )

    def close(self):
        with self.condition:
            self.closed = True
            self.condition.notify_all()

    def snapshot(self):
        with self.condition:
            return {"generation": dict(self.generations), "last_commit_hint": dict(self.notifications),
                    "durable_poll_fallback": True, "gpu_enabled": False}


def notify(store, *stages):
    dispatch = getattr(store, "pipeline_dispatch", None)
    if dispatch is not None:
        dispatch.notify(*stages)
