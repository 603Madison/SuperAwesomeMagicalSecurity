# SIEM detection rules

Every `*.yml` / `*.yaml` file in this directory is loaded at startup. Extra
directories can be added with `siem.extra_rules_dir` in `sams.yaml`. A rule
there with the same `id` as a builtin **overrides** it, and `enabled: false`
disables it.

A file holds one rule (mapping) or a list of rules.

```yaml
id: ssh_bruteforce                 # unique, lowercase [a-z0-9_.-]
title: "SSH brute force from {src_ip} ({count} failures)"   # {placeholders}, see below
description: "..."
severity: high                     # info | low | medium | high | critical
mitre: [T1110.001]                 # ATT&CK technique / tactic ids
tags: [ssh, linux]
type: threshold                    # match | threshold | sequence | new_value (default match)
enabled: true

match:                             # AND of field conditions
  action: ssh_failed               # scalar = equals, list = in
  src_ip: {not: {cidr: 127.0.0.0/8}}
any_of:                            # optional OR-blocks (each block is an AND)
  - {user: root}
  - {fields.invalid_user: true}
```

## Rule types

| type | extra section | fires when |
|---|---|---|
| `match` | none | a single event matches |
| `threshold` | `threshold: {count, window_seconds, group_by: [..], distinct: field?}` | ≥ `count` matching events (or ≥ `count` *distinct values* of `distinct`) per group within the sliding window |
| `sequence` | `sequence: {steps: [{match, any_of, count}], within_seconds, group_by}` | the steps occur in order (each `count` times) for the same group within the time limit. Top-level `match` filters every step |
| `new_value` | `new_value: {field, group_by, learning_seconds}` | `field` takes a value never seen before for the group, after the learning period |

## Fields

Any `Event` attribute: `timestamp, host, asset_id, source, category, action,
outcome, severity, user, src_ip, src_port, dst_ip, dst_port, process, message`.
Parser-specific data lives in `fields.*`, for example `fields.method`,
`fields.group`, `fields.command`, `fields.logon_type`. A bare unknown name
falls back to `fields.<name>`.

## Operators

`equals, in, contains, startswith, endswith, regex, cidr, not, gte, lte, gt, lt, exists`.
Several operators in one mapping are ANDed. String comparisons are
case-insensitive, except `regex` (use `(?i)`). `contains`, `startswith`,
`endswith` and `cidr` take a value or a list.

## Title placeholders

`{field}` is replaced from the group values, the triggering event (including
`fields.*` paths), and for thresholds also `{count}` and `{window_seconds}`.
Unknown placeholders render as `?`.

## Normalized actions produced by the parsers

`ssh_login, ssh_failed, ssh_invalid_user, ssh_auth_failure, ssh_probe,
ssh_disconnect, ssh_session_opened/closed, sudo, sudo_failed, sudo_denied,
su, su_failed, user_created, user_deleted, user_modified, group_created,
group_member_added, password_changed, session_opened/closed, cron_exec,
blocked, allowed, logged (firewall), docker_started, container_*,
win_logon, win_logon_failed, win_special_privileges, account_locked,
audit_log_cleared, service_installed, process_created, powershell_script, log`
(generic fallback).
