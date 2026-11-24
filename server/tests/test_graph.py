from lab import FP_DEPLOY, build_lab

from sams.graph.engine import INTERNET
from sams.posture import compute
from sams.remediation.planner import build_plan


def test_internet_path_to_crown_jewel(tmp_path):
    ctx = build_lab(tmp_path)
    g = ctx.graph()
    paths = g.attack_paths(INTERNET, k=5)
    assert paths, g.to_dict()["notes"]
    top = paths[0]
    assert top["target"].startswith("data:db:postgresql")
    names = [e["name"] for e in top["edges"]]
    assert names == ["exploit_public", "suid", "steal_key", "ssh_key", "sudo", "local_data"], names
    assert 0.3 < top["likelihood"] < 1


def test_blast_radius_of_web(tmp_path):
    g = build_lab(tmp_path).graph()
    br = g.blast_radius("web")
    reached = {r["node"] for r in br["reachable"]}
    assert "host:db#root" in reached
    assert f"cred:ssh:{FP_DEPLOY}" in reached
    assert br["summary"]["hosts_root"] == 1
    # the laptop is in LAN; SERVERS -> LAN is blocked by the firewall
    assert not any(n.startswith("host:laptop") for n in reached)
    assert br["containment"], "should suggest containment fixes"


def test_laptop_blast_radius_reaches_cloud(tmp_path):
    g = build_lab(tmp_path).graph()
    br = g.blast_radius("host:laptop#user:alice")
    kinds = {r["kind"] for r in br["reachable"]}
    assert "cloud" in kinds
    assert any(r["node"] == "host:laptop#root" and r["path"][0]["name"] == "docker_group" for r in br["reachable"])


def test_k_shortest_paths(tmp_path):
    g = build_lab(tmp_path).graph()
    paths = g.attack_paths(INTERNET, target="data:db:postgresql:customers", k=3)
    assert len(paths) >= 1
    likes = [p["likelihood"] for p in paths]
    assert likes == sorted(likes, reverse=True)


def test_plan_ranks_attack_path_fixes_first(tmp_path):
    ctx = build_lab(tmp_path)
    plan = build_plan(ctx)
    assert plan[0]["reason"] == "attack_path"
    top_ids = [p["id"] for p in plan[:4]]
    # breaking the chain at the internet edge or the key/ssh/sudo links must rank highest
    assert any(k.startswith(("vuln:web", "fw:internet->web", "hard:web:ssh_key_unencrypted", "access:db",
                             "hard:db:sudo", "hard:web:suid")) for k in top_ids), top_ids
    assert any(p["reason"] == "hygiene" for p in plan)
    assert plan[0]["risk_reduction"] > 0


def test_posture(tmp_path):
    ctx = build_lab(tmp_path)
    p = compute(ctx)
    assert 0 < p["score"] < 100
    assert p["internet_attack_paths"] >= 1
    assert {h["asset_id"] for h in p["hosts"]} == {"web", "db", "laptop"}
