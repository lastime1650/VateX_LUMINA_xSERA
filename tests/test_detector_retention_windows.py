"""Unfinished analysis/recovery protects indexed originals without a Case."""
import time

import pytest

from sapientia import detections, detector_ops, detection_automation as da, lookups, runtime
from tests.test_detection_automation import store, actor


@pytest.mark.parametrize("consumer",["correlation","schedule","saved_search","partial_schedule"])
def test_pending_recovery_outlives_wall_clock_horizon_and_releases_on_ack(store,consumer):
    now=time.time(); end=now-3600
    store.ingest("a",[{"event_id":"pending","event_time":end-10,"host":"h","index":"public"}]); store.flush()
    if consumer=="correlation":
        identifier=detections.save(store,actor(),{"name":"Recovery","window":30,"interval":30,"steps":[{"filters":[]}],"enabled":True})
        with store.control() as db:
            db.execute("INSERT INTO log_correlation_late_ranges(policy_id,version,tenant,first_end,last_end,cursor) VALUES(?,1,'a',?,?,?)",(identifier,end,end,end))
        pending_table="log_correlation_late_ranges"
    elif consumer in {"schedule","partial_schedule"}:
        lookups.save(store,actor(),"feed",lookups.threat_intel("domain",["example.test"],"synthetic",now+600))
        item=da.save_schedule(store,actor(),{"name":"Recovery","kind":"intel","indexes":["public"],"lookups":["feed"],"interval":30,"lookback":30,"enabled":True})
        identifier=item["id"]
        with store.control() as db:
            row=db.execute("SELECT * FROM analysis_schedules WHERE id=?",(identifier,)).fetchone()
            digest=da.late_definition_digest("schedule",row)
            if consumer=="schedule":
                db.execute("INSERT INTO analysis_late_ranges(kind,source_id,definition_digest,tenant,first_end,last_end,cursor) VALUES('schedule',?,?,'a',?,?,?)",(identifier,digest,end,end,end))
            else:
                db.execute("INSERT INTO analysis_window_inputs(kind,source_id,definition_digest,tenant,window_start,window_end,scope) VALUES('schedule',?,?,'a',?,?,'[\"public\"]')",(identifier,digest,end-30,end))
        pending_table="analysis_late_ranges" if consumer=="schedule" else "analysis_window_inputs"
    else:
        identifier=runtime.save_rule(store,actor(),{"name":"Recovery","query":{"query":"search index=public"},"interval":30,"lookback":30,"enabled":True})
        with store.control() as db:
            row=db.execute("SELECT * FROM rules WHERE id=?",(identifier,)).fetchone()
            digest=da.late_definition_digest("saved_search",row)
            db.execute("INSERT INTO analysis_late_ranges(kind,source_id,definition_digest,tenant,first_end,last_end,cursor) VALUES('saved_search',?,?,'a',?,?,?)",(identifier,digest,end,end,end))
        pending_table="analysis_late_ranges"
    with store.control() as db:
        assert db.execute("SELECT count(*) FROM incidents").fetchone()[0]==0
        assert detector_ops.protected_ids(db,"a",["pending"],now,store)=={"pending"}
        assert detector_ops.protected_ids(db,"b",["pending"],now,store)==set()
        # Simulate the scheduler's durable completion acknowledgement.
        db.execute("DELETE FROM "+pending_table)
        assert detector_ops.protected_ids(db,"a",["pending"],now,store)==set()
