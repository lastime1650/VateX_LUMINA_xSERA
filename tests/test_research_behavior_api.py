"""Real authenticated HTTP contracts for reviewed CPU research and lifecycle."""

import pytest
from fastapi.testclient import TestClient

from sapientia import auth
from sapientia.api import create_app
from sapientia.storage import Settings
from test_research_behavior import definition,seed

PASSWORD="Research-HTTP-fixture-password-2026"


def login(client,name):
    value=client.post("/api/login",json={"name":name,"password":PASSWORD})
    assert value.status_code==200,value.text
    client.headers["X-CSRF-Token"]=value.json()["csrf"]


@pytest.fixture
def client(tmp_path):
    app=create_app(Settings(tmp_path,min_free_bytes=0),background=False)
    for name,role,tenant in (("trainer","analyst","a"),("reviewer","analyst","a"),("admin","admin","a"),("viewer","viewer","a"),("foreign","analyst","b")):
        auth.create_user(app.state.store,name,PASSWORD,role,tenant)
    seed(app.state.store)
    with TestClient(app) as value:yield value


def test_research_routes_require_authentication_and_respect_read_only_viewer(client):
    assert client.get("/api/research/status").status_code==401
    login(client,"viewer")
    status=client.get("/api/research/status")
    assert status.status_code==200,status.text
    assert "research_fusion" in {item["id"] for item in status.json()["capabilities"]}
    assert status.json()["legacy_gate_preserved"]
    assert status.json()["new_training_gate"]=="cpu_relation_temporal_multihorizon_fusion_v2"
    assert status.json()["recommended_gate_version"]=="v2"
    assert status.json()["default_compatible_training_gate"]=="cpu_relation_temporal_sketch_fusion_v1"
    assert status.json()["shadow_default"] and not status.json()["device_authority"]
    assert client.get("/api/research/catalog").status_code==200
    assert client.post("/api/research/train",json=definition()).status_code==403
    assert client.post("/api/research/analyze",json={"event_ids":["research-101"]}).status_code==403
    quality=client.post("/api/research/quality",json={"training_ids":[f"research-{i}" for i in range(16)],"validation_ids":[f"research-{i}" for i in range(32,40)]})
    assert quality.status_code==200,quality.text
    assert quality.json()["temporal_overlap"][0]["chronological"]
    assert quality.json()["real_world_detection_rate_measured"] is False


def test_http_training_peer_live_review_analysis_scoped_history_and_lifecycle(client):
    login(client,"trainer")
    bad=client.post("/api/research/train",json={**definition(),"features":[1,2,3]})
    assert bad.status_code==400
    saved=client.post("/api/research/train",json=definition(seeds=[17]))
    assert saved.status_code==201,saved.text
    model=saved.json()
    assert model["detection_gate"]["method"]=="cpu_relation_temporal_sketch_fusion_v1"
    assert model["detection_gate"]["version"]=="xsera.research-fusion.v1"
    assert model["detection_gate"]["feature_width"]==24
    assert model["detection_gate"]["horizons_seconds"]==[]
    assert model["state"]=="pending" and model["metrics"]["seeds"][0]["validation_relation_accuracy"]>.9
    assert client.post(f"/api/research/models/{model['id']}/review",json={"approve":True,"mode":"live","reason":"self approval denied"}).status_code==403
    login(client,"reviewer")
    approved=client.post(f"/api/research/models/{model['id']}/review",json={"approve":True,"mode":"live","reason":"independent review of cohort and withheld originals"})
    assert approved.status_code==200,approved.text
    login(client,"trainer")
    result=client.post("/api/research/analyze",json={"event_ids":["research-100"],"model_id":model["id"]})
    assert result.status_code==201,result.text
    run=result.json()
    assert run["mode"]=="live" and run["decision"]["publishable"]
    assert client.get("/api/research/runs").json()["items"][0]["id"]==run["id"]
    protected=client.post("/api/research/runs/archive",json={"run_ids":[run["id"]],"reason":"preserve live anomaly"})
    assert protected.status_code==200 and protected.json()["items"][0]["state"]=="protected"
    login(client,"foreign")
    assert client.get(f"/api/research/runs/{run['id']}").status_code==404
    assert client.get("/api/research/models").json()["items"]==[]
    login(client,"trainer")
    normal=client.post("/api/research/analyze",json={"event_ids":["research-101"],"model_id":model["id"]}).json()
    archived=client.post("/api/research/runs/archive",json={"run_ids":[normal["id"]],"reason":"normal payload lifecycle"})
    assert archived.status_code==200 and archived.json()["items"][0]["state"]=="archived"
    assert client.get(f"/api/research/runs/{normal['id']}").json()["archive"]["permanent_hash_metadata_retained"]
    stopped=client.post(f"/api/research/models/{model['id']}/disable",json={"reason":"retire reviewed candidate"})
    assert stopped.status_code==200 and stopped.json()["state"]=="disabled"
    login(client,"reviewer")
    retired=client.post(f"/api/research/models/{model['id']}/retire",json={"reason":"independent reviewed retirement"})
    assert retired.status_code==200,retired.text
    assert retired.json()["retired"] and retired.json()["model_weights_and_provenance_retained"]
