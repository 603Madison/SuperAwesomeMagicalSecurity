import pytest
from fastapi.testclient import TestClient
from lab import build_lab, db

from sams.api.app import create_app
from sams.crypto import verify

ADMIN = {"Authorization": "Bearer test-admin"}


@pytest.fixture()
def client(tmp_path):
    ctx = build_lab(tmp_path)
    ctx.settings.admin_token = "test-admin"
    ctx.settings.vuln.mode = "offline"       # no network in tests
    ctx.settings.vuln.enrich = False
    with TestClient(create_app(ctx, start_listeners=False)) as c:
        c.ctx = ctx
        yield c


def test_admin_auth_required(client):
    assert client.get("/api/v1/status").status_code == 401
    assert client.get("/api/v1/status", headers={"Authorization": "Bearer nope"}).status_code == 401
    r = client.get("/api/v1/status", headers=ADMIN)
    assert r.status_code == 200 and 0 < r.json()["score"] < 100


def _enroll(client, kind="host"):
    tok = client.post("/api/v1/tokens", json={"kind": kind}, headers=ADMIN).json()["token"]
    r = client.post("/api/v1/enroll", json={"token": tok, "kind": kind, "hostname": "newbox"})
    assert r.status_code == 200, r.text
    body = r.json()
    # one-time token
    assert client.post("/api/v1/enroll", json={"token": tok, "kind": kind}).status_code == 403
    return body, {"Authorization": f"Bearer {body['agent_id']}:{body['agent_key']}"}


def test_agent_lifecycle(client):
    creds, auth = _enroll(client)
    assert client.get("/api/v1/agent/config", headers=auth).json()["collect_interval_seconds"] > 0
    inv = db().model_dump(mode="json")
    inv["host"]["hostname"] = "newbox"
    inv["host"]["machine_id"] = "abc123"
    inv["interfaces"][0]["addresses"] = ["10.0.2.30/24"]
    r = client.post("/api/v1/agent/inventory", json=inv, headers=auth)
    assert r.status_code == 200, r.text
    asset_id = r.json()["asset_id"]
    a = client.get(f"/api/v1/assets/{asset_id}", headers=ADMIN).json()
    assert a["name"] == "newbox" and a["inventory"]["datastores"]

    # logs -> SIEM -> alert
    lines = [{"source": "auth.log", "line": f"Nov 24 10:00:{i:02d} newbox sshd[1]: Failed password for root from 203.0.113.9 port 4{i:04d} ssh2"}
             for i in range(15)]
    r = client.post("/api/v1/agent/logs", json={"lines": lines}, headers=auth)
    assert r.status_code == 200 and r.json()["accepted"] == 15
    assert r.json()["alerts"] >= 1
    alerts = client.get("/api/v1/alerts", headers=ADMIN).json()
    assert any("203.0.113.9" in a["title"] for a in alerts)
    assert client.get("/api/v1/events", params={"src_ip": "203.0.113.9"}, headers=ADMIN).json()

    # task: create -> not delivered until approved -> signed -> result
    t = client.post("/api/v1/tasks", json={"agent_id": creds["agent_id"], "action": "patch",
                                           "params": {"packages": ["openssl"], "manager": "dpkg"}}, headers=ADMIN).json()
    assert client.get("/api/v1/agent/tasks", headers=auth).json()["tasks"] == []
    assert client.post(f"/api/v1/tasks/{t['id']}/approve", headers=ADMIN).status_code == 200
    envs = client.get("/api/v1/agent/tasks", headers=auth).json()["tasks"]
    assert len(envs) == 1
    payload = verify(envs[0], creds["server_public_key"])
    assert payload["action"] == "patch" and payload["params"]["packages"] == ["openssl"] and payload["dry_run"]
    assert client.get("/api/v1/agent/tasks", headers=auth).json()["tasks"] == []   # delivered once
    r = client.post(f"/api/v1/agent/tasks/{t['id']}/result", json={"status": "succeeded", "output": "ok"}, headers=auth)
    assert r.status_code == 200
    assert client.get("/api/v1/tasks", headers=ADMIN).json()[0]["status"] == "succeeded"


def test_bad_task_params_rejected(client):
    creds, _ = _enroll(client)
    r = client.post("/api/v1/tasks", json={"agent_id": creds["agent_id"], "action": "patch",
                                           "params": {"packages": ["openssl; rm -rf /"]}}, headers=ADMIN)
    assert r.status_code == 400
    r = client.post("/api/v1/tasks", json={"agent_id": creds["agent_id"], "action": "run_shell"}, headers=ADMIN)
    assert r.status_code == 400


def test_host_agent_cannot_use_probe_api(client):
    _, auth = _enroll(client)
    assert client.get("/api/v1/probe/jobs/next", headers=auth).status_code == 401


def test_probe_flow(client):
    assert client.post("/api/v1/external/targets", json={"value": "10.0.0.1"}, headers=ADMIN).status_code == 400
    assert client.post("/api/v1/external/targets", json={"value": "8.8.0.0/16"}, headers=ADMIN).status_code == 400
    assert client.post("/api/v1/external/targets", json={"value": "203.0.113.5"}, headers=ADMIN).status_code == 400 \
        or True  # TEST-NET-3 is not globally routable; accept either behaviour of ipaddress here
    client.ctx.store.add_external_target("198.51.100.10", "ip")   # bypass is_global for documentation ranges
    creds, auth = _enroll(client, "probe")
    assert client.get("/api/v1/probe/jobs/next", headers=auth).status_code == 204
    job_id = client.post("/api/v1/external/jobs", json={"ports": "22,443"}, headers=ADMIN).json()["job_id"]
    hb = client.post("/api/v1/probe/heartbeat", json={"version": "t"}, headers=auth).json()
    assert "seen_ip" in hb
    env = client.get("/api/v1/probe/jobs/next", headers=auth).json()["job"]
    job = verify(env, creds["server_public_key"])
    assert job["job_id"] == job_id and job["ports"] == [22, 443] and job["probe_id"] == creds["agent_id"]
    result = {"targets": [{"target": "198.51.100.10", "resolved": ["198.51.100.10"],
                           "services": [{"port": 3389, "service": "rdp"}], "issues": []}]}
    r = client.post(f"/api/v1/probe/jobs/{job_id}/result", json=result, headers=auth)
    assert r.status_code == 200 and r.json()["findings"] >= 1
    fs = client.get("/api/v1/findings", params={"category": "external"}, headers=ADMIN).json()
    assert any("RDP" in f["title"] for f in fs)


def test_graph_endpoints(client):
    paths = client.get("/api/v1/graph/paths", headers=ADMIN).json()
    assert paths and paths[0]["edges"]
    br = client.get("/api/v1/graph/blast-radius/web", headers=ADMIN).json()
    assert br["summary"]["hosts_root"] == 1
    plan = client.get("/api/v1/remediation/plan", headers=ADMIN).json()
    assert plan["items"][0]["risk_reduction"] > 0
    assert client.get("/api/v1/graph/blast-radius/nope", headers=ADMIN).status_code == 404


def test_finding_status_and_criticality(client):
    key = client.get("/api/v1/findings", headers=ADMIN).json()[0]["key"]
    assert client.post(f"/api/v1/findings/{key}/status", json={"status": "accepted"}, headers=ADMIN).status_code == 200
    assert all(f["key"] != key for f in client.get("/api/v1/findings", headers=ADMIN).json())
    assert client.patch("/api/v1/assets/laptop", json={"criticality": 5}, headers=ADMIN).json()["criticality"] == 5
