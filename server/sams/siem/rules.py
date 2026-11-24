"""Detection rule format (YAML) and field matching.

A rule file contains one rule (mapping) or a list of rules. Format::

    id: ssh_bruteforce                 # unique, [a-z0-9_.-]
    title: "SSH brute force from {src_ip}"   # {field} placeholders filled from the group/event
    description: "..."
    severity: high                     # info | low | medium | high | critical
    mitre: [T1110.001]
    tags: [ssh, linux]
    type: threshold                    # match | threshold | sequence | new_value  (default: match)
    enabled: true

    # event selection -- used by match / threshold / new_value
    match:                             # every key must match (AND)
      action: ssh_failed               # bare value == equals (lists == in)
      src_ip: {not: {cidr: 127.0.0.0/8}}
      fields.method: {in: [password, keyboard-interactive]}
    any_of:                            # optional: at least one block must ALSO match (OR)
      - {user: root}
      - {fields.invalid_user: true}

    threshold:                         # type: threshold
      count: 10                        # fire when >= count events ...
      window_seconds: 300              # ... within this sliding window
      group_by: [src_ip]               # ... per distinct combination of these fields
      distinct: dst_port               # optional: count distinct values of this field instead

    sequence:                          # type: sequence
      group_by: [src_ip]
      within_seconds: 600
      steps:                           # each step: {match, any_of, count (default 1)}
        - {match: {action: ssh_failed}, count: 5}
        - {match: {action: ssh_login, outcome: success}}

    new_value:                         # type: new_value
      field: src_ip                    # alert when this value is first seen ...
      group_by: [user]                 # ... for this group
      learning_seconds: 86400          # nothing alerts during the initial learning period

Operators (inside a dict value): ``equals, in, contains, startswith, endswith,
regex, cidr, not, gte, lte, gt, lt, exists``. Several operators in one dict are
ANDed. String comparisons are case-insensitive except ``regex`` (use ``(?i)``).
``contains/startswith/endswith/cidr`` accept a list (any). Field names may be
top-level ``Event`` attributes or dotted paths into ``fields``
(``fields.group``); a bare unknown name falls back to ``fields.<name>``.
"""
from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path
from typing import Any, Literal, Optional

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator, model_validator

from ..models import Event, Severity

BUILTIN_RULES_DIR = Path(__file__).parent / "rules"

OPERATORS = {"equals", "in", "contains", "startswith", "endswith", "regex", "cidr", "not", "gte", "lte", "gt",
             "lt", "exists"}


class RuleError(ValueError):
    pass


# --------------------------------------------------------------------------- #
# field access + predicate evaluation
# --------------------------------------------------------------------------- #
_MISSING = object()


def get_field(ev: Event, path: str) -> Any:
    if path.startswith("fields."):
        cur: Any = ev.fields
        for part in path[len("fields."):].split("."):
            if isinstance(cur, dict) and part in cur:
                cur = cur[part]
            else:
                return _MISSING
        return cur
    if "." not in path and path in Event.model_fields:
        v = getattr(ev, path)
        if hasattr(v, "value"):  # enums
            return v.value
        return v
    cur = ev.fields
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _norm(v: Any) -> Any:
    if isinstance(v, str):
        return v.lower()
    if isinstance(v, bool):
        return v
    return v


def _eq(a: Any, b: Any) -> bool:
    if a is _MISSING:
        return b is None
    if isinstance(b, bool) or isinstance(a, bool):
        if isinstance(a, str):
            return a.lower() == str(b).lower()
        return bool(a) == bool(b) if isinstance(b, bool) and isinstance(a, (bool, int)) else a == b
    if isinstance(b, (int, float)) and not isinstance(b, bool):
        try:
            return float(a) == float(b)
        except (TypeError, ValueError):
            return False
    return _norm(str(a)) == _norm(str(b))


def _as_list(v: Any) -> list:
    return v if isinstance(v, list) else [v]


@lru_cache(maxsize=4096)
def _net(spec: str):
    return ipaddress.ip_network(spec, strict=False)


@lru_cache(maxsize=1024)
def _rx(p: str) -> re.Pattern:
    return re.compile(p)


def _in_cidr(value: Any, specs: Any) -> bool:
    try:
        addr = ipaddress.ip_address(str(value))
    except ValueError:
        return False
    for s in _as_list(specs):
        n = _net(str(s))
        if addr.version == n.version and addr in n:
            return True
    return False


def _num(v: Any) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def eval_condition(value: Any, cond: Any) -> bool:
    """Evaluate a single field condition (bare value, list, or operator dict)."""
    if isinstance(cond, dict):
        for op, arg in cond.items():
            if not _eval_op(value, op, arg):
                return False
        return True
    if isinstance(cond, list):
        return any(_eq(value, c) for c in cond)
    return _eq(value, cond)


def _eval_op(value: Any, op: str, arg: Any) -> bool:
    if op == "exists":
        present = value is not _MISSING and value not in ("", None)
        return present == bool(arg)
    if op == "not":
        return not eval_condition(value, arg)
    if value is _MISSING or value is None:
        return False
    s = str(value).lower()
    if op == "equals":
        return _eq(value, arg)
    if op == "in":
        return any(_eq(value, a) for a in _as_list(arg))
    if op == "contains":
        return any(str(a).lower() in s for a in _as_list(arg))
    if op == "startswith":
        return any(s.startswith(str(a).lower()) for a in _as_list(arg))
    if op == "endswith":
        return any(s.endswith(str(a).lower()) for a in _as_list(arg))
    if op == "regex":
        return any(_rx(str(a)).search(str(value)) is not None for a in _as_list(arg))
    if op == "cidr":
        return _in_cidr(value, arg)
    if op in ("gte", "lte", "gt", "lt"):
        a, b = _num(value), _num(arg)
        if a is None or b is None:
            return False
        return {"gte": a >= b, "lte": a <= b, "gt": a > b, "lt": a < b}[op]
    raise RuleError(f"unknown operator {op!r}")


def _validate_condition(field: str, cond: Any) -> None:
    if isinstance(cond, dict):
        for op, arg in cond.items():
            if op not in OPERATORS:
                raise RuleError(f"field {field!r}: unknown operator {op!r} (valid: {', '.join(sorted(OPERATORS))})")
            if op == "regex":
                for a in _as_list(arg):
                    try:
                        re.compile(str(a))
                    except re.error as exc:
                        raise RuleError(f"field {field!r}: bad regex {a!r}: {exc}") from exc
            if op == "cidr":
                for a in _as_list(arg):
                    try:
                        ipaddress.ip_network(str(a), strict=False)
                    except ValueError as exc:
                        raise RuleError(f"field {field!r}: bad cidr {a!r}") from exc
            if op == "not":
                _validate_condition(field, arg)


# --------------------------------------------------------------------------- #
# rule models
# --------------------------------------------------------------------------- #
class Selector(BaseModel):
    model_config = ConfigDict(extra="forbid")
    match: dict[str, Any] = Field(default_factory=dict)
    any_of: list[dict[str, Any]] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> "Selector":
        for f, c in self.match.items():
            _validate_condition(f, c)
        for block in self.any_of:
            if not isinstance(block, dict):
                raise RuleError("any_of entries must be mappings of field -> condition")
            for f, c in block.items():
                _validate_condition(f, c)
        return self

    def matches(self, ev: Event) -> bool:
        for f, c in self.match.items():
            if not eval_condition(get_field(ev, f), c):
                return False
        if self.any_of:
            return any(all(eval_condition(get_field(ev, f), c) for f, c in block.items()) for block in self.any_of)
        return True


class Threshold(BaseModel):
    model_config = ConfigDict(extra="forbid")
    count: int = Field(ge=1)
    window_seconds: int = Field(ge=1)
    group_by: list[str] = Field(default_factory=list)
    distinct: Optional[str] = None


class SequenceStep(Selector):
    count: int = Field(default=1, ge=1)


class Sequence(BaseModel):
    model_config = ConfigDict(extra="forbid")
    steps: list[SequenceStep] = Field(min_length=2)
    within_seconds: int = Field(ge=1)
    group_by: list[str] = Field(default_factory=list)


class NewValue(BaseModel):
    model_config = ConfigDict(extra="forbid")
    field: str
    group_by: list[str] = Field(default_factory=list)
    learning_seconds: int = Field(default=86400, ge=0)


class Rule(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    title: str
    description: str = ""
    severity: Severity = Severity.medium
    mitre: list[str] = Field(default_factory=list)
    tags: list[str] = Field(default_factory=list)
    type: Literal["match", "threshold", "sequence", "new_value"] = "match"
    enabled: bool = True
    match: dict[str, Any] = Field(default_factory=dict)
    any_of: list[dict[str, Any]] = Field(default_factory=list)
    threshold: Optional[Threshold] = None
    sequence: Optional[Sequence] = None
    new_value: Optional[NewValue] = None
    source_file: str = ""
    _selector: Optional[Selector] = PrivateAttr(default=None)

    @field_validator("id")
    @classmethod
    def _id(cls, v: str) -> str:
        if not re.fullmatch(r"[a-z0-9][a-z0-9_.\-]*", v):
            raise ValueError("rule id must match [a-z0-9][a-z0-9_.-]*")
        return v

    @field_validator("mitre")
    @classmethod
    def _mitre(cls, v: list[str]) -> list[str]:
        for t in v:
            if not re.fullmatch(r"T\d{4}(\.\d{3})?|TA\d{4}", t):
                raise ValueError(f"bad MITRE ATT&CK id {t!r}")
        return v

    @model_validator(mode="after")
    def _check(self) -> "Rule":
        need = {"threshold": self.threshold, "sequence": self.sequence, "new_value": self.new_value}
        if self.type in need and need[self.type] is None:
            raise ValueError(f"type {self.type!r} requires a '{self.type}' section")
        for k, v in need.items():
            if v is not None and k != self.type:
                raise ValueError(f"section '{k}' given but rule type is {self.type!r}")
        if self.type != "sequence" and not self.match and not self.any_of:
            raise ValueError("rule needs 'match' and/or 'any_of'")
        if self.type == "sequence" and (self.match or self.any_of):
            # allowed: acts as a pre-filter applied to every step
            pass
        Selector(match=self.match, any_of=self.any_of)  # validates conditions
        return self

    @property
    def selector(self) -> Selector:
        if self._selector is None:
            self._selector = Selector(match=self.match, any_of=self.any_of)
        return self._selector

    def selects(self, ev: Event) -> bool:
        return self.selector.matches(ev)



# --------------------------------------------------------------------------- #
# loading
# --------------------------------------------------------------------------- #
def parse_rules(text: str, origin: str = "<string>") -> list[Rule]:
    try:
        data = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise RuleError(f"{origin}: invalid YAML: {exc}") from exc
    if data is None:
        return []
    items = data if isinstance(data, list) else [data]
    out = []
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise RuleError(f"{origin}[{i}]: rule must be a mapping")
        try:
            r = Rule.model_validate({**item, "source_file": origin})
        except (ValidationError, RuleError) as exc:
            rid = item.get("id", f"#{i}")
            raise RuleError(f"{origin}: rule {rid}: {exc}") from exc
        out.append(r)
    return out


def load_rules(paths: Optional[list[Path]] = None, include_builtin: bool = True) -> list[Rule]:
    """Load builtin rules plus any rule files / directories in ``paths``.
    Later definitions with the same id override earlier ones (so a site can
    override or disable a builtin by re-declaring its id)."""
    dirs: list[Path] = []
    if include_builtin:
        dirs.append(BUILTIN_RULES_DIR)
    dirs += [Path(p) for p in (paths or [])]
    by_id: dict[str, Rule] = {}
    for d in dirs:
        files = sorted(d.glob("*.y*ml")) if d.is_dir() else [d]
        for f in files:
            if f.suffix not in (".yml", ".yaml"):
                continue
            for r in parse_rules(f.read_text(), str(f)):
                by_id[r.id] = r
    return [r for r in by_id.values() if r.enabled]
