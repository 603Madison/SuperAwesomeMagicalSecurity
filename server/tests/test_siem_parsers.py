from datetime import datetime, timezone
from pathlib import Path

import pytest

from sams.models import Severity
from sams.siem.parsers import parse_header, parse_line, parse_syslog

FIX = Path(__file__).parent / "fixtures" / "siem"


def _lines(name):
    return [l for l in (FIX / name).read_text().splitlines() if l.strip()]


# --------------------------------------------------------------------------- #
# headers
# --------------------------------------------------------------------------- #
def test_rfc3164_header_with_pri():
    h = parse_header("<38>Nov 24 10:00:01 web01 sshd[1201]: hello world",
                     now=datetime(2025, 11, 24, 12, tzinfo=timezone.utc))
    assert h.ts == datetime(2025, 11, 24, 10, 0, 1, tzinfo=timezone.utc)
    assert (h.host, h.ident, h.pid, h.msg) == ("web01", "sshd", 1201, "hello world")
    assert h.facility == 4 and h.severity == Severity.info


def test_rfc3164_space_padded_day_and_no_pid():
    h = parse_header("Feb  3 01:02:03 host1 CRON: job", now=datetime(2026, 3, 1, tzinfo=timezone.utc))
    assert h.ts.day == 3 and h.ts.month == 2 and h.ts.year == 2026
    assert h.ident == "CRON" and h.pid == 0 and h.msg == "job"


def test_rfc3164_year_rollover():
    # December line seen on Jan 2nd belongs to the previous year
    h = parse_header("Dec 31 23:59:59 h sshd[1]: x", now=datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert h.ts.year == 2025
    h2 = parse_header("Jan  1 00:00:01 h sshd[1]: x", now=datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert h2.ts.year == 2026


def test_rfc5424_header_with_structured_data():
    line = ('<165>1 2025-11-24T10:00:01.123456+01:00 fw01 filterlog 4242 - '
            '[meta sequenceId="1" note="a\\]b"][x@1 y="z"] ﻿hello msg')
    h = parse_header(line)
    assert h.ts == datetime(2025, 11, 24, 9, 0, 1, 123456, tzinfo=timezone.utc)
    assert (h.host, h.ident, h.pid, h.msg) == ("fw01", "filterlog", 4242, "hello msg")


def test_rfc5424_nil_values():
    h = parse_header("<14>1 - - - - - - just text")
    assert h.ts is None and h.host == "" and h.ident == "" and h.msg == "just text"


def test_journald_agent_format():
    h = parse_header("2025-11-24T10:00:01.500000Z web01 sshd[99]: Failed password for bob from 1.2.3.4 port 1 ssh2")
    assert h.ts == datetime(2025, 11, 24, 10, 0, 1, 500000, tzinfo=timezone.utc)
    assert (h.host, h.ident, h.pid) == ("web01", "sshd", 99)
    ev = parse_line("journald", "2025-11-24T10:00:01+00:00 web01 sshd[99]: Failed password for bob from 1.2.3.4 port 1 ssh2")
    assert ev.action == "ssh_failed" and ev.user == "bob" and ev.src_ip == "1.2.3.4"
    assert ev.timestamp == datetime(2025, 11, 24, 10, 0, 1, tzinfo=timezone.utc)


def test_iso_without_host():
    h = parse_header("2025-11-24T10:00:01Z sudo: alice : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/ls")
    assert h.host == "" and h.ident == "sudo"


def test_plain_line_without_header():
    ev = parse_line("app.log", "something happened")
    assert ev is not None and ev.action == "log" and ev.message == "something happened"


def test_blank_lines_return_none():
    assert parse_line("auth.log", "   \n") is None
    assert parse_syslog(b"\n\x00", "1.1.1.1") is None


def test_explicit_ts_and_host_override():
    ts = datetime(2020, 1, 1, tzinfo=timezone.utc)
    ev = parse_line("auth.log", "Nov 24 10:00:01 web01 sshd[1]: x", host="agent-host", ts=ts, asset_id="a1")
    assert ev.timestamp == ts and ev.host == "agent-host" and ev.asset_id == "a1"


# --------------------------------------------------------------------------- #
# auth.log
# --------------------------------------------------------------------------- #
@pytest.fixture(scope="module")
def auth_events():
    return [parse_line("auth.log", l) for l in _lines("auth.log")]


def test_auth_log_never_drops(auth_events):
    assert all(e is not None for e in auth_events)
    assert len(auth_events) == len(_lines("auth.log"))


def test_sshd_events(auth_events):
    e = auth_events
    assert (e[0].action, e[0].outcome, e[0].user, e[0].src_ip, e[0].src_port) == ("ssh_login", "success", "alice", "192.168.1.50", 52144)
    assert e[0].fields["method"] == "publickey" and e[0].fields["key_fingerprint"].startswith("SHA256:")
    assert e[1].user == "root" and e[1].fields["root_login"] and e[1].severity == Severity.medium
    assert e[2].action == "ssh_failed" and e[2].user == "bob"
    assert e[3].action == "ssh_invalid_user" and e[3].user == "admin"
    assert e[4].action == "ssh_invalid_user" and e[4].user == "oracle" and e[4].src_port == 51517
    assert e[5].action == "ssh_failed" and e[5].fields["preauth_disconnect"]
    assert e[6].action == "ssh_failed" and e[6].fields["max_attempts_exceeded"]
    assert e[7].action == "ssh_auth_failure" and e[7].src_ip == "203.0.113.7" and e[7].user == "bob"
    assert e[8].action == "ssh_probe" and e[8].src_ip == "198.51.100.4"
    assert e[9].action == "ssh_failed" and e[9].fields["method"] == "publickey"
    assert all(x.category == "authentication" for x in e[:8] if x.action != "ssh_probe")


def test_sudo_su_events(auth_events):
    e = auth_events
    assert e[10].action == "sudo" and e[10].fields["root_shell"] is True and e[10].fields["target_user"] == "root"
    assert e[11].action == "sudo" and e[11].fields["root_shell"] is False and e[11].fields["command"] == "/usr/bin/apt update"
    assert e[12].action == "sudo_denied" and e[12].user == "mallory" and e[12].severity == Severity.medium
    assert e[13].action == "sudo_failed" and e[13].fields["attempts"] == 3
    assert e[14].action == "sudo_failed" and e[14].user == "mallory"
    assert e[15].action == "su" and e[15].user == "alice" and e[15].fields["target_user"] == "root"
    assert e[16].action == "su_failed" and e[16].user == "bob"


def test_account_management_events(auth_events):
    e = auth_events
    assert e[17].action == "user_created" and e[17].user == "backdoor" and e[17].fields["uid"] == 0
    assert e[18].action == "group_created" and e[18].fields["group"] == "deploy"
    assert e[19].action == "group_member_added" and e[19].user == "bob" and e[19].fields["group"] == "sudo"
    assert e[19].severity == Severity.high and e[19].fields["admin_group"]
    assert e[20].fields.get("shadow") is True
    assert e[21].action == "group_member_added" and e[21].user == "carol" and e[21].fields["group"] == "docker"
    assert e[22].action == "password_changed" and e[22].user == "root"
    assert e[23].action == "session_opened" and e[23].user == "alice"
    assert e[24].action == "cron_exec" and e[24].user == "root" and "backup.sh" in e[24].fields["command"]
    assert e[27].action == "user_deleted" and e[27].user == "olduser"
    assert e[28].action == "docker_started"
    assert e[29].action == "auth_failure" and e[29].fields["service"] == "login"


def test_kernel_firewall_lines(auth_events):
    ufw, ipt = auth_events[25], auth_events[26]
    assert (ufw.category, ufw.action, ufw.src_ip, ufw.dst_ip, ufw.dst_port) == ("firewall", "blocked", "198.51.100.23", "192.168.1.10", 3389)
    assert ufw.fields["vendor"] == "ufw" and ufw.fields["protocol"] == "tcp"
    assert ipt.action == "blocked" and ipt.fields["protocol"] == "udp" and ipt.dst_port == 161


# --------------------------------------------------------------------------- #
# network devices
# --------------------------------------------------------------------------- #
def test_filterlog():
    evs = [parse_syslog(l.encode(), "10.0.0.1") for l in _lines("filterlog.log")]
    assert all(e.source == "filterlog" for e in evs)
    a, b, c, d, icmp = evs
    assert (a.action, a.src_ip, a.dst_ip, a.src_port, a.dst_port) == ("blocked", "203.0.113.50", "192.0.2.10", 51234, 22)
    assert a.fields["interface"] == "igb0" and a.fields["rule_tracker"] == "1000000103" and a.fields["tcp_flags"] == "S"
    assert a.host == "fw.home"
    assert (b.action, b.dst_port, b.fields["protocol"]) == ("allowed", 53, "udp")
    assert c.fields["ip_version"] == 6 and c.src_ip == "fe80::1" and c.dst_port == 0
    assert (d.src_ip, d.dst_ip, d.dst_port, d.fields["protocol"]) == ("2001:db8::5", "2001:db8:1::10", 443, "tcp")
    assert icmp.fields["protocol"] == "icmp" and icmp.action == "blocked"


def test_filterlog_via_parse_line_source():
    line = "5,,,1000000103,em0,match,block,in,4,0x0,,64,1,0,DF,6,tcp,60,203.0.113.5,192.0.2.1,1111,23,0,S,1,,1,,"
    ev = parse_line("filterlog", line)
    assert ev.action == "blocked" and ev.dst_port == 23


def test_unifi():
    evs = [parse_syslog(l.encode(), "192.168.1.1") for l in _lines("unifi.log")]
    assert all(e.source == "unifi" for e in evs)
    assert evs[0].action == "blocked" and evs[0].fields["ruleset"] == "WAN_IN" and evs[0].dst_port == 8443
    assert evs[1].action == "allowed" and evs[1].fields["rule"] == "2000"
    assert evs[2].action == "blocked" and evs[2].fields["ruleset"] == "Internal_External" and evs[2].dst_port == 4444
    assert evs[0].host == "UDM-Pro"


def test_syslog_unknown_message_keeps_severity():
    ev = parse_syslog(b"<10>Nov 24 10:00:00 sw1 foo: link down", "10.0.0.2")
    assert ev.action == "log" and ev.severity == Severity.critical and ev.fields["peer_ip"] == "10.0.0.2"
    ev2 = parse_syslog(b"<14>Nov 24 10:00:00 sw1 foo: chatter", "10.0.0.2")
    assert ev2.severity == Severity.info


def test_syslog_without_hostname_uses_peer():
    ev = parse_syslog(b"<13>bare message", "10.9.9.9")
    assert ev.host == "10.9.9.9"


def test_syslog_latin1_does_not_crash():
    assert parse_syslog(b"<13>Nov 24 10:00:00 h app: caf\xe9", "1.1.1.1") is not None


# --------------------------------------------------------------------------- #
# windows
# --------------------------------------------------------------------------- #
def test_windows_events():
    evs = [parse_line("windows", l, host="") for l in _lines("windows.jsonl")]
    by = {e.fields["event_id"]: e for e in evs}
    lo = by[4624]
    assert lo.action == "win_logon" and lo.fields["logon_type"] == 10 and lo.src_ip == "198.51.100.88" and lo.src_port == 50123
    assert lo.host == "DC01" and lo.timestamp == datetime(2025, 11, 24, 10, 10, tzinfo=timezone.utc)
    assert by[4625].action == "win_logon_failed" and by[4625].outcome == "failure" and by[4625].user == "administrator"
    assert by[4672].action == "win_special_privileges"
    assert by[4720].action == "user_created" and by[4720].user == "svc_new"
    g = by[4732]
    assert g.action == "group_member_added" and g.user == "svc_new" and g.fields["group"] == "Administrators"
    assert g.fields["admin_group"] and g.severity == Severity.high
    assert by[4728].fields["admin_group"] is False and by[4728].severity == Severity.low
    assert by[4740].action == "account_locked"
    assert by[1102].action == "audit_log_cleared" and by[1102].severity == Severity.critical
    svc = by[7045]
    assert svc.action == "service_installed" and svc.fields["image_path"].endswith("upd.exe")
    p = by[4688]
    assert p.action == "process_created" and p.fields["office_spawned_shell"] and p.fields["suspicious_command"]
    assert p.severity == Severity.high
    ps = by[4104]
    assert ps.action == "powershell_script" and ps.fields["suspicious_command"] and ps.severity == Severity.high
    assert by[4697].timestamp == datetime.fromtimestamp(1764000000, tz=timezone.utc)
    assert by[4697].fields["image_path"].endswith("svc.exe")


def test_windows_bad_json_falls_back():
    ev = parse_line("windows", "{not json")
    assert ev is not None and ev.action == "log"
