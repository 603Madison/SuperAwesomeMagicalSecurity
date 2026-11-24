from datetime import datetime, timedelta, timezone

import pytest

from sams.db import Store
from sams.models import Event, Severity
from sams.siem.engine import DetectionEngine
from sams.siem.rules import Rule, RuleError, eval_condition, get_field, load_rules, parse_rules

T0 = datetime(2025, 11, 24, 10, 0, tzinfo=timezone.utc)


def ev(sec=0, **kw):
    kw.setdefault("host", "web01")
    return Event(timestamp=T0 + timedelta(seconds=sec), **kw)


def rule(yaml_text):
    rs = parse_rules(yaml_text)
    assert len(rs) == 1
    return rs[0]


# --------------------------------------------------------------------------- #
# rule validation + operators
# --------------------------------------------------------------------------- #
def test_rule_validation_errors():
    with pytest.raises(RuleError, match="unknown operator"):
        parse_rules("id: x\ntitle: t\nmatch: {user: {bogus: 1}}")
    with pytest.raises(RuleError, match="requires a 'threshold'"):
        parse_rules("id: x\ntitle: t\ntype: threshold\nmatch: {user: a}")
    with pytest.raises(RuleError, match="bad regex"):
        parse_rules("id: x\ntitle: t\nmatch: {user: {regex: '('}}")
    with pytest.raises(RuleError, match="bad cidr"):
        parse_rules("id: x\ntitle: t\nmatch: {src_ip: {cidr: 999.1.1.1/8}}")
    with pytest.raises(RuleError, match="MITRE"):
        parse_rules("id: x\ntitle: t\nmitre: [X123]\nmatch: {user: a}")
    with pytest.raises(RuleError, match="needs 'match'"):
        parse_rules("id: x\ntitle: t")
    with pytest.raises(RuleError, match="extra|Extra"):
        parse_rules("id: x\ntitle: t\nmatch: {user: a}\nunknown_key: 1")
    with pytest.raises(RuleError, match="rule id"):
        parse_rules("id: Bad Id\ntitle: t\nmatch: {user: a}")
    with pytest.raises(RuleError, match="invalid YAML"):
        parse_rules("id: [unclosed")


def test_operators():
    e = ev(user="Alice", src_ip="10.1.2.3", dst_port=4444, fields={"group": "sudo", "n": 5, "nested": {"k": "v"}})
    assert eval_condition(get_field(e, "user"), "alice")
    assert eval_condition(get_field(e, "user"), ["bob", "ALICE"])
    assert eval_condition(get_field(e, "user"), {"in": ["x", "alice"]})
    assert eval_condition(get_field(e, "user"), {"contains": "lic"})
    assert eval_condition(get_field(e, "user"), {"startswith": ["z", "al"]})
    assert eval_condition(get_field(e, "user"), {"endswith": "ICE"})
    assert eval_condition(get_field(e, "user"), {"regex": "^A.+e$"})
    assert not eval_condition(get_field(e, "user"), {"regex": "^a"})
    assert eval_condition(get_field(e, "src_ip"), {"cidr": ["192.168.0.0/16", "10.0.0.0/8"]})
    assert eval_condition(get_field(e, "src_ip"), {"not": {"cidr": "172.16.0.0/12"}})
    assert eval_condition(get_field(e, "dst_port"), {"gte": 4000, "lte": 5000})
    assert not eval_condition(get_field(e, "dst_port"), {"gt": 4444})
    assert eval_condition(get_field(e, "fields.group"), "sudo")
    assert eval_condition(get_field(e, "group"), "sudo")           # bare name falls back to fields
    assert eval_condition(get_field(e, "fields.nested.k"), "v")
    assert eval_condition(get_field(e, "fields.n"), {"lt": 6})
    assert eval_condition(get_field(e, "fields.missing"), {"exists": False})
    assert eval_condition(get_field(e, "user"), {"exists": True})
    assert not eval_condition(get_field(e, "fields.missing"), "x")
    assert eval_condition(get_field(e, "severity"), "info")        # enum values
    e2 = ev(fields={"flag": True, "uid": 0})
    assert eval_condition(get_field(e2, "fields.flag"), True)
    assert eval_condition(get_field(e2, "fields.uid"), 0)
    assert not eval_condition(get_field(e2, "fields.uid"), 1)


# --------------------------------------------------------------------------- #
# rule types
# --------------------------------------------------------------------------- #
def test_match_rule_and_any_of():
    r = rule("""
id: m
title: "{user} on {host} did {action}"
severity: high
mitre: [T1078]
match: {category: iam}
any_of:
  - {action: sudo, fields.root_shell: true}
  - {action: sudo_denied}
""")
    eng = DetectionEngine([r])
    out = eng.process([
        ev(0, category="iam", action="sudo", user="a", fields={"root_shell": False}),
        ev(1, category="iam", action="sudo", user="a", fields={"root_shell": True}),
        ev(2, category="iam", action="sudo_denied", user="b"),
        ev(3, category="network", action="sudo_denied", user="c"),
    ])
    assert [a.title for a in out] == ["a on web01 did sudo", "b on web01 did sudo_denied"]
    assert out[0].severity == Severity.high and out[0].mitre == ["T1078"]


def test_threshold_rule_sliding_window():
    r = rule("""
id: th
title: "brute {src_ip} {count}"
type: threshold
match: {action: ssh_failed}
threshold: {count: 3, window_seconds: 60, group_by: [src_ip]}
""")
    eng = DetectionEngine([r])
    # two in window, then a gap that expires them, then three in window
    evs = [ev(0, action="ssh_failed", src_ip="1.1.1.1", id=1), ev(10, action="ssh_failed", src_ip="1.1.1.1", id=2),
           ev(100, action="ssh_failed", src_ip="1.1.1.1", id=3), ev(110, action="ssh_failed", src_ip="2.2.2.2", id=4),
           ev(120, action="ssh_failed", src_ip="1.1.1.1", id=5), ev(130, action="ssh_failed", src_ip="1.1.1.1", id=6)]
    out = eng.process(evs)
    assert len(out) == 1
    a = out[0]
    assert a.title == "brute 1.1.1.1 3" and a.group_key == "src_ip=1.1.1.1"
    assert a.event_ids == [3, 5, 6] and a.context["count"] == 3


def test_threshold_ignores_events_missing_group_field():
    r = rule("""
id: th
title: t
type: threshold
match: {action: ssh_failed}
threshold: {count: 2, window_seconds: 60, group_by: [src_ip]}
""")
    assert DetectionEngine([r]).process([ev(i, action="ssh_failed") for i in range(5)]) == []


def test_threshold_distinct():
    r = rule("""
id: scan
title: "scan from {src_ip}: {count} ports"
type: threshold
match: {category: firewall, action: blocked}
threshold: {count: 5, window_seconds: 60, group_by: [src_ip], distinct: dst_port}
""")
    eng = DetectionEngine([r])
    same_port = [ev(i, category="firewall", action="blocked", src_ip="9.9.9.9", dst_port=22) for i in range(20)]
    assert eng.process(same_port) == []
    ports = [ev(30 + i, category="firewall", action="blocked", src_ip="9.9.9.9", dst_port=p) for i, p in enumerate([80, 443, 8080, 3389])]
    out = eng.process(ports)
    assert len(out) == 1 and out[0].title == "scan from 9.9.9.9: 5 ports"
    assert out[0].context["distinct_values"] == ["22", "3389", "443", "80", "8080"]


def test_sequence_rule():
    r = rule("""
id: seq
title: "success after brute from {src_ip} as {user}"
severity: critical
type: sequence
sequence:
  group_by: [src_ip]
  within_seconds: 300
  steps:
    - {match: {action: ssh_failed}, count: 3}
    - {match: {action: ssh_login, outcome: success}}
""")
    eng = DetectionEngine([r])
    # success without enough failures -> nothing
    assert eng.process([ev(0, action="ssh_failed", src_ip="5.5.5.5", id=1),
                        ev(1, action="ssh_login", outcome="success", src_ip="5.5.5.5", user="x", id=2)]) == []
    out = eng.process([ev(2, action="ssh_failed", src_ip="5.5.5.5", id=3), ev(3, action="ssh_failed", src_ip="5.5.5.5", id=4),
                       ev(4, action="ssh_failed", src_ip="5.5.5.5", id=5),
                       ev(5, action="ssh_login", outcome="success", src_ip="6.6.6.6", user="y", id=6),
                       ev(6, action="ssh_login", outcome="success", src_ip="5.5.5.5", user="bob", id=7)])
    assert len(out) == 1
    assert out[0].title == "success after brute from 5.5.5.5 as bob"
    assert set(out[0].event_ids) >= {1, 3, 4, 7} or set(out[0].event_ids) >= {3, 4, 5, 7}


def test_sequence_expires():
    r = rule("""
id: seq
title: t
type: sequence
sequence:
  group_by: [src_ip]
  within_seconds: 60
  steps:
    - {match: {action: a}, count: 2}
    - {match: {action: b}}
""")
    eng = DetectionEngine([r])
    assert eng.process([ev(0, action="a", src_ip="1.1.1.1"), ev(1, action="a", src_ip="1.1.1.1"),
                        ev(500, action="b", src_ip="1.1.1.1")]) == []
    # failures spread out beyond the window don't count
    assert eng.process([ev(1000, action="a", src_ip="1.1.1.1"), ev(1100, action="a", src_ip="1.1.1.1"),
                        ev(1101, action="b", src_ip="1.1.1.1")]) == []
    assert len(eng.process([ev(1102, action="a", src_ip="1.1.1.1"), ev(1103, action="b", src_ip="1.1.1.1")])) == 1


def test_new_value_rule():
    r = rule("""
id: nv
title: "{user} from new ip {src_ip}"
type: new_value
match: {action: ssh_login}
new_value: {field: src_ip, group_by: [user], learning_seconds: 100}
""")
    eng = DetectionEngine([r])
    learn = [ev(0, action="ssh_login", user="alice", src_ip="10.0.0.1"),
             ev(50, action="ssh_login", user="alice", src_ip="10.0.0.2")]
    assert eng.process(learn) == []
    out = eng.process([ev(200, action="ssh_login", user="alice", src_ip="10.0.0.1"),
                       ev(201, action="ssh_login", user="alice", src_ip="203.0.113.1"),
                       ev(202, action="ssh_login", user="bob", src_ip="10.0.0.1"),
                       ev(203, action="ssh_login", user="alice", src_ip="203.0.113.1")])
    titles = [a.title for a in out]
    assert titles == ["alice from new ip 203.0.113.1", "bob from new ip 10.0.0.1"]
    assert out[0].context["new_value"] == "203.0.113.1"


def test_in_memory_suppression():
    r = rule("""
id: th
title: t
type: threshold
match: {action: x}
threshold: {count: 2, window_seconds: 60, group_by: [src_ip]}
""")
    eng = DetectionEngine([r], suppress_seconds=600)
    evs = [ev(i, action="x", src_ip="1.1.1.1") for i in range(10)]
    assert len(eng.process(evs)) == 1
    later = [ev(1000 + i, action="x", src_ip="1.1.1.1") for i in range(2)]
    assert len(eng.process(later)) == 1


def test_store_backed_suppression():
    store = Store(":memory:")
    r = rule("""
id: th
title: t
type: threshold
match: {action: x}
threshold: {count: 2, window_seconds: 60, group_by: [src_ip]}
""")
    eng1 = DetectionEngine([r], store=store)
    a = eng1.process([ev(0, action="x", src_ip="1.1.1.1"), ev(1, action="x", src_ip="1.1.1.1")])
    assert len(a) == 1
    store.insert_alert(a[0])
    # a fresh engine (e.g. after restart) consults the store
    eng2 = DetectionEngine([r], store=store)
    assert eng2.process([ev(5000, action="x", src_ip="1.1.1.1"), ev(5001, action="x", src_ip="1.1.1.1")]) == []
    assert len(eng2.process([ev(5002, action="x", src_ip="2.2.2.2"), ev(5003, action="x", src_ip="2.2.2.2")])) == 1


def test_events_processed_in_time_order():
    r = rule("""
id: seq
title: t
type: sequence
sequence:
  group_by: [src_ip]
  within_seconds: 60
  steps:
    - {match: {action: a}}
    - {match: {action: b}}
""")
    out = DetectionEngine([r]).process([ev(5, action="b", src_ip="1.1.1.1"), ev(1, action="a", src_ip="1.1.1.1")])
    assert len(out) == 1


def test_broken_rule_does_not_break_engine(monkeypatch):
    r = rule("id: m\ntitle: t\nmatch: {action: a}")
    good = rule("id: g\ntitle: g\nmatch: {action: a}")
    monkeypatch.setattr(type(r), "selects", lambda self, e: (_ for _ in ()).throw(RuntimeError("boom")) if self.id == "m" else True)
    out = DetectionEngine([r, good]).process([ev(0, action="a")])
    assert [a.rule_id for a in out] == ["g"]


def test_prune_keeps_memory_bounded():
    r = rule("""
id: th
title: t
type: threshold
match: {action: x}
threshold: {count: 1000, window_seconds: 10, group_by: [src_ip]}
""")
    eng = DetectionEngine([r])
    eng.process([ev(i, action="x", src_ip=f"10.0.{i // 250}.{i % 250}") for i in range(3000)])
    assert len(eng._windows) < 100


# --------------------------------------------------------------------------- #
# builtin rules
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def builtin():
    return load_rules()


def test_builtin_rules_load(builtin):
    ids = {r.id for r in builtin}
    assert len(builtin) >= 20
    for required in ("ssh_bruteforce", "ssh_password_spraying", "ssh_bruteforce_success", "ssh_root_login",
                     "ssh_login_new_source", "sudo_denied", "sudo_root_shell", "linux_user_created",
                     "admin_group_membership_added", "root_password_changed", "fw_port_scan", "fw_horizontal_scan",
                     "fw_suspicious_egress", "win_failed_logon_burst", "win_account_lockout", "win_audit_log_cleared",
                     "win_service_installed", "win_admin_group_change", "win_suspicious_powershell",
                     "win_office_spawned_shell"):
        assert required in ids, required
    assert all(r.mitre for r in builtin)


def test_override_and_disable_builtin(tmp_path):
    (tmp_path / "local.yml").write_text("""
- id: ssh_root_login
  title: overridden
  enabled: false
  match: {action: ssh_login}
- id: local_rule
  title: mine
  match: {action: zzz}
""")
    ids = {r.id for r in load_rules([tmp_path])}
    assert "ssh_root_login" not in ids and "local_rule" in ids


def _fired(builtin, events):
    return [a.rule_id for a in DetectionEngine(builtin).process(events)]


def test_builtin_bruteforce_then_success(builtin):
    evs = [ev(i, category="authentication", action="ssh_failed", outcome="failure", user="root", src_ip="203.0.113.7")
           for i in range(12)]
    evs.append(ev(20, category="authentication", action="ssh_login", outcome="success", user="root", src_ip="203.0.113.7",
                  fields={"method": "password"}))
    fired = _fired(builtin, evs)
    assert "ssh_bruteforce" in fired
    assert "ssh_bruteforce_success" in fired
    assert "ssh_root_login" in fired
    assert "ssh_public_login_password" in fired


def test_builtin_password_spray(builtin):
    evs = [ev(i, action="ssh_invalid_user", user=f"user{i}", src_ip="198.51.100.9") for i in range(6)]
    fired = _fired(builtin, evs)
    assert "ssh_password_spraying" in fired and "ssh_invalid_user_probing" in fired


def test_builtin_port_scan(builtin):
    evs = [ev(i * 0.5, category="firewall", action="blocked", src_ip="198.51.100.200", dst_ip="192.0.2.10",
              dst_port=1000 + i) for i in range(25)]
    assert "fw_port_scan" in _fired(builtin, evs)
    hz = [ev(i * 0.5, category="firewall", action="blocked", src_ip="198.51.100.201", dst_ip=f"192.0.2.{i}",
             dst_port=445) for i in range(25)]
    assert "fw_horizontal_scan" in _fired(builtin, hz)


def test_builtin_suspicious_egress(builtin):
    evs = [ev(i, category="firewall", action="blocked", src_ip="192.168.1.44", dst_ip="203.0.113.200", dst_port=4444)
           for i in range(3)]
    assert "fw_suspicious_egress" in _fired(builtin, evs)


def test_builtin_admin_group_and_uid0(builtin):
    fired = _fired(builtin, [
        ev(0, source="auth.log", category="iam", action="group_member_added", user="bob", fields={"group": "sudo"}),
        ev(1, source="auth.log", category="iam", action="user_created", user="backdoor", fields={"uid": 0}),
        ev(2, source="auth.log", category="iam", action="group_member_added", user="eve", fields={"group": "marketing"}),
    ])
    assert fired.count("admin_group_membership_added") == 1
    assert "uid0_account_created" in fired and "linux_user_created" in fired


def test_builtin_windows_fixture_stream(builtin):
    from pathlib import Path

    from sams.siem.parsers import parse_line
    lines = (Path(__file__).parent / "fixtures" / "siem" / "windows.jsonl").read_text().splitlines()
    evs = [parse_line("windows", l) for l in lines if l.strip()]
    fired = set(_fired(builtin, evs))
    for rid in ("win_audit_log_cleared", "win_service_installed", "win_service_suspicious_path", "win_admin_group_change",
                "win_user_created", "win_suspicious_powershell", "win_office_spawned_shell", "win_account_lockout",
                "win_rdp_logon_public"):
        assert rid in fired, rid
    lockouts = [ev(i, source="windows", action="win_logon_failed", user="admin", host="DC01") for i in range(10)]
    assert "win_failed_logon_burst" in _fired(builtin, lockouts)
