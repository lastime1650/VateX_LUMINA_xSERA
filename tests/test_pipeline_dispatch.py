"""Commit hints cannot lose a generation or publish rolled-back input."""
# ruff: noqa: F811 - imported disposable Store fixture.
import threading
import time

import pytest

from sapientia.pipeline_dispatch import Dispatch
from sapientia.runtime import Runtime
from tests.test_backend_upgrade import actor, lab  # noqa: F401


def test_hint_between_work_and_wait_returns_immediately():
    dispatch=Dispatch();token=dispatch.token('index')
    dispatch.notify('index')
    began=time.monotonic()
    assert dispatch.wait('index',token,1)
    assert time.monotonic()-began<.25
    assert not dispatch.wait('index',dispatch.token('index'),.01)


def test_ingest_and_flush_hint_only_follow_commits(lab):
    runtime=Runtime(lab)
    before=runtime.dispatch.token('index')
    def deny(db):
        raise PermissionError('authorization denied')
    event={'event_id':'dispatch-1','event_time':time.time(),'host':'virtual','index':'public','message':'safe'}
    with pytest.raises(PermissionError):
        lab.ingest('a',[event],'owner',['public'],deny)
    assert runtime.dispatch.token('index')==before
    lab.ingest('a',[event],'owner',['public'])
    assert runtime.dispatch.token('index')==before+1
    assert runtime.dispatch.token('research')==0
    lab.flush()
    assert runtime.dispatch.token('research')==1
    with lab.control() as db:
        assert db.execute('SELECT count(*) FROM queue').fetchone()[0]==0


def test_close_wakes_all_stages():
    dispatch=Dispatch();done=threading.Event()
    thread=threading.Thread(target=lambda:(dispatch.wait('research',0,10),done.set()))
    thread.start();dispatch.close();thread.join(1)
    assert done.is_set()
