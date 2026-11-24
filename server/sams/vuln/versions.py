"""Ecosystem-aware version comparison.

``compare(ecosystem, a, b)`` returns <0, 0, >0 like ``cmp``. The ecosystem is
an OSV ecosystem string (``"Debian:12"``, ``"Ubuntu:22.04:LTS"``, ``"PyPI"``...);
only the prefix before the first ``:`` is used for dispatch.

Implementations:

* dpkg   -- the canonical ``verrevcmp`` algorithm from dpkg (epoch, upstream, revision, ``~``)
* rpm    -- ``rpmvercmp`` from rpm >= 4.15 (``~`` and ``^``), epoch:version-release
* apk    -- Alpine version semantics (numbers, letter, suffixes, ``-rN``), good-enough subset
* pep440 -- epochs, release, pre/post/dev; local versions ignored
* semver -- SemVer 2.0 precedence (npm, Go, crates.io); leading ``v`` allowed
* gem    -- RubyGems segment semantics (string segments are prereleases)
* maven  -- simplified ComparableVersion (qualifier ordering)
* generic -- tokenized fallback (numbers numerically, words lexically)
"""
from __future__ import annotations

import re
from functools import cmp_to_key
from typing import Callable, Optional


def _sign(x: int) -> int:
    return (x > 0) - (x < 0)


# --------------------------------------------------------------------------- #
# dpkg
# --------------------------------------------------------------------------- #
def _dpkg_order(c: str) -> int:
    if not c:
        return 0
    if c.isdigit():
        return 0
    if c.isascii() and c.isalpha():
        return ord(c)
    if c == "~":
        return -1
    return ord(c) + 256


def _dpkg_verrevcmp(a: str, b: str) -> int:
    i, j = 0, 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        first_diff = 0
        while (i < la and not a[i].isdigit()) or (j < lb and not b[j].isdigit()):
            ac = _dpkg_order(a[i] if i < la else "")
            bc = _dpkg_order(b[j] if j < lb else "")
            if ac != bc:
                return _sign(ac - bc)
            i += 1
            j += 1
        while i < la and a[i] == "0":
            i += 1
        while j < lb and b[j] == "0":
            j += 1
        while i < la and j < lb and a[i].isdigit() and b[j].isdigit():
            if not first_diff:
                first_diff = ord(a[i]) - ord(b[j])
            i += 1
            j += 1
        if i < la and a[i].isdigit():
            return 1
        if j < lb and b[j].isdigit():
            return -1
        if first_diff:
            return _sign(first_diff)
    return 0


def _dpkg_parse(v: str) -> tuple[int, str, str]:
    v = v.strip()
    epoch = 0
    if ":" in v:
        e, v = v.split(":", 1)
        try:
            epoch = int(e)
        except ValueError:
            epoch = 0
    if "-" in v:
        upstream, revision = v.rsplit("-", 1)
    else:
        upstream, revision = v, ""
    return epoch, upstream, revision


def compare_dpkg(a: str, b: str) -> int:
    ea, ua, ra = _dpkg_parse(a)
    eb, ub, rb = _dpkg_parse(b)
    if ea != eb:
        return _sign(ea - eb)
    c = _dpkg_verrevcmp(ua, ub)
    if c:
        return c
    return _dpkg_verrevcmp(ra, rb)


# --------------------------------------------------------------------------- #
# rpm
# --------------------------------------------------------------------------- #
def _rpm_isalnum(c: str) -> bool:
    return c.isascii() and c.isalnum()


def rpmvercmp(a: str, b: str) -> int:
    if a == b:
        return 0
    i, j = 0, 0
    la, lb = len(a), len(b)
    while i < la or j < lb:
        while i < la and not _rpm_isalnum(a[i]) and a[i] not in "~^":
            i += 1
        while j < lb and not _rpm_isalnum(b[j]) and b[j] not in "~^":
            j += 1
        ca = a[i] if i < la else ""
        cb = b[j] if j < lb else ""
        # tilde sorts before everything, even end of string
        if ca == "~" or cb == "~":
            if ca != "~":
                return 1
            if cb != "~":
                return -1
            i += 1
            j += 1
            continue
        # caret sorts after end of string but before anything else
        if ca == "^" or cb == "^":
            if not ca:
                return -1
            if not cb:
                return 1
            if ca != "^":
                return 1
            if cb != "^":
                return -1
            i += 1
            j += 1
            continue
        if not (ca and cb):
            break
        si, sj = i, j
        if ca.isdigit():
            while i < la and a[i].isdigit():
                i += 1
            while j < lb and b[j].isdigit():
                j += 1
            isnum = True
        else:
            while i < la and a[i].isascii() and a[i].isalpha():
                i += 1
            while j < lb and b[j].isascii() and b[j].isalpha():
                j += 1
            isnum = False
        seg_a, seg_b = a[si:i], b[sj:j]
        if not seg_b:
            # segments of different types: numeric is newer than alpha
            return 1 if isnum else -1
        if isnum:
            seg_a = seg_a.lstrip("0")
            seg_b = seg_b.lstrip("0")
            if len(seg_a) != len(seg_b):
                return 1 if len(seg_a) > len(seg_b) else -1
        if seg_a != seg_b:
            return 1 if seg_a > seg_b else -1
    if i >= la and j >= lb:
        return 0
    return -1 if i >= la else 1


def _rpm_parse(v: str) -> tuple[Optional[int], str, Optional[str]]:
    v = v.strip()
    epoch: Optional[int] = None
    m = re.match(r"^(\d+):(.*)$", v)
    if m:
        epoch, v = int(m.group(1)), m.group(2)
    if "-" in v:
        ver, rel = v.rsplit("-", 1)
        return epoch, ver, rel
    return epoch, v, None


def compare_rpm(a: str, b: str, lenient_epoch: bool = False) -> int:
    """EVR comparison. With ``lenient_epoch`` a missing epoch on either side
    is assumed to equal the other side's epoch (agents/tools frequently omit
    it while advisories always include it)."""
    ea, va, ra = _rpm_parse(a)
    eb, vb, rb = _rpm_parse(b)
    if lenient_epoch and (ea is None or eb is None):
        ea = eb = 0
    c = _sign((ea or 0) - (eb or 0))
    if c:
        return c
    c = rpmvercmp(va, vb)
    if c:
        return c
    if ra is None or rb is None:
        return 0
    return rpmvercmp(ra, rb)


# --------------------------------------------------------------------------- #
# apk (Alpine)
# --------------------------------------------------------------------------- #
_APK_SUFFIX = {"alpha": -4, "beta": -3, "pre": -2, "rc": -1, "cvs": 1, "svn": 2, "git": 3, "hg": 4, "p": 5}
_APK_RE = re.compile(r"^(\d+(?:\.\d+)*)([a-z]?)((?:_[a-z]+\d*)*)(?:-r(\d+))?$")


def _apk_key(v: str) -> Optional[tuple]:
    m = _APK_RE.match(v.strip())
    if not m:
        return None
    nums = tuple(int(x) for x in m.group(1).split("."))
    letter = m.group(2) or ""
    suffixes = []
    for s in filter(None, m.group(3).split("_")):
        sm = re.match(r"^([a-z]+)(\d*)$", s)
        if not sm or sm.group(1) not in _APK_SUFFIX:
            return None
        suffixes.append((_APK_SUFFIX[sm.group(1)], int(sm.group(2) or 0)))
    rel = int(m.group(4) or 0)
    return nums, letter, suffixes, rel


def compare_apk(a: str, b: str) -> int:
    ka, kb = _apk_key(a), _apk_key(b)
    if ka is None or kb is None:
        return compare_generic(a, b)
    na, nb = ka[0], kb[0]
    for x, y in zip(na, nb):
        if x != y:
            return _sign(x - y)
    if len(na) != len(nb):
        return 1 if len(na) > len(nb) else -1
    if ka[1] != kb[1]:
        return 1 if ka[1] > kb[1] else -1
    sa, sb = ka[2], kb[2]
    for idx in range(max(len(sa), len(sb))):
        x = sa[idx] if idx < len(sa) else (0, 0)
        y = sb[idx] if idx < len(sb) else (0, 0)
        if x != y:
            return 1 if x > y else -1
    return _sign(ka[3] - kb[3])


# --------------------------------------------------------------------------- #
# PEP 440
# --------------------------------------------------------------------------- #
_PEP440_RE = re.compile(
    r"""^\s*v?
    (?:(?P<epoch>\d+)!)?
    (?P<release>\d+(?:\.\d+)*)
    (?P<pre>[-_.]?(?P<pre_l>a|b|c|rc|alpha|beta|pre|preview)[-_.]?(?P<pre_n>\d+)?)?
    (?P<post>(?:-(?P<post_n1>\d+))|(?:[-_.]?(?P<post_l>post|rev|r)[-_.]?(?P<post_n2>\d+)?))?
    (?P<dev>[-_.]?(?P<dev_l>dev)[-_.]?(?P<dev_n>\d+)?)?
    (?:\+(?P<local>[a-z0-9]+(?:[-_.][a-z0-9]+)*))?
    \s*$""",
    re.VERBOSE | re.IGNORECASE,
)
_PRE_RANK = {"a": 0, "alpha": 0, "b": 1, "beta": 1, "c": 2, "rc": 2, "pre": 2, "preview": 2}


def _pep440_key(v: str) -> Optional[tuple]:
    m = _PEP440_RE.match(v)
    if not m:
        return None
    epoch = int(m.group("epoch") or 0)
    release = [int(x) for x in m.group("release").split(".")]
    while len(release) > 1 and release[-1] == 0:
        release.pop()
    has_pre = m.group("pre") is not None
    has_post = m.group("post") is not None
    has_dev = m.group("dev") is not None
    if has_pre:
        pre = (0, _PRE_RANK[m.group("pre_l").lower()], int(m.group("pre_n") or 0))
    elif not has_post and has_dev:
        pre = (-1, 0, 0)          # 1.0.dev1 < 1.0a1
    else:
        pre = (1, 0, 0)
    if has_post:
        post = (0, int(m.group("post_n1") or m.group("post_n2") or 0))
    else:
        post = (-1, 0)
    dev = (0, int(m.group("dev_n") or 0)) if has_dev else (1, 0)
    return epoch, tuple(release), pre, post, dev


def compare_pep440(a: str, b: str) -> int:
    ka, kb = _pep440_key(a), _pep440_key(b)
    if ka is None or kb is None:
        return compare_generic(a, b)
    ea, ra, *rest_a = ka
    eb, rb, *rest_b = kb
    if ea != eb:
        return _sign(ea - eb)
    n = max(len(ra), len(rb))
    ra2 = ra + (0,) * (n - len(ra))
    rb2 = rb + (0,) * (n - len(rb))
    if ra2 != rb2:
        return 1 if ra2 > rb2 else -1
    ta, tb = tuple(rest_a), tuple(rest_b)
    return 0 if ta == tb else (1 if ta > tb else -1)


# --------------------------------------------------------------------------- #
# SemVer
# --------------------------------------------------------------------------- #
def _semver_split(v: str) -> Optional[tuple[list[int], list[str]]]:
    s = v.strip()
    if s[:1] in ("v", "V"):
        s = s[1:]
    s = s.split("+", 1)[0]
    main, _, pre = s.partition("-")
    parts = main.split(".")
    if not parts or not all(p.isdigit() for p in parts):
        return None
    nums = [int(p) for p in parts]
    while len(nums) < 3:
        nums.append(0)
    return nums, (pre.split(".") if pre else [])


def compare_semver(a: str, b: str) -> int:
    sa, sb = _semver_split(a), _semver_split(b)
    if sa is None or sb is None:
        return compare_generic(a, b)
    if sa[0] != sb[0]:
        return 1 if sa[0] > sb[0] else -1
    pa, pb = sa[1], sb[1]
    if not pa and not pb:
        return 0
    if not pa:
        return 1        # release > prerelease
    if not pb:
        return -1
    for x, y in zip(pa, pb):
        if x == y:
            continue
        xn, yn = x.isdigit(), y.isdigit()
        if xn and yn:
            return _sign(int(x) - int(y))
        if xn:
            return -1   # numeric identifiers have lower precedence
        if yn:
            return 1
        return 1 if x > y else -1
    return _sign(len(pa) - len(pb))


# --------------------------------------------------------------------------- #
# RubyGems
# --------------------------------------------------------------------------- #
def _gem_segments(v: str) -> list:
    segs: list = []
    for part in re.findall(r"[0-9]+|[a-zA-Z]+", v.strip()):
        segs.append(int(part) if part.isdigit() else part)
    # trailing zeros are insignificant ("1.0" == "1")
    while segs and segs[-1] == 0:
        segs.pop()
    return segs


def compare_gem(a: str, b: str) -> int:
    sa, sb = _gem_segments(a), _gem_segments(b)
    for idx in range(max(len(sa), len(sb))):
        x = sa[idx] if idx < len(sa) else 0
        y = sb[idx] if idx < len(sb) else 0
        if x == y:
            continue
        if isinstance(x, str) and isinstance(y, str):
            return 1 if x > y else -1
        if isinstance(x, str):
            return -1   # string segment == prerelease, sorts before numbers
        if isinstance(y, str):
            return 1
        return _sign(x - y)
    return 0


# --------------------------------------------------------------------------- #
# Maven (simplified ComparableVersion)
# --------------------------------------------------------------------------- #
_MAVEN_QUAL = {"alpha": 0, "a": 0, "beta": 1, "b": 1, "milestone": 2, "m": 2, "rc": 3, "cr": 3,
               "snapshot": 4, "": 5, "ga": 5, "final": 5, "release": 5, "sp": 6}


def _maven_items(v: str) -> list:
    items: list = []
    for tok in re.findall(r"[0-9]+|[a-zA-Z]+", v.strip().lower()):
        items.append(int(tok) if tok.isdigit() else tok)
    while items and (items[-1] == 0 or items[-1] in ("", "ga", "final", "release")):
        items.pop()
    return items


def _maven_item_cmp(x, y) -> int:
    if x is None:
        x = 0 if isinstance(y, int) else ""
    if y is None:
        y = 0 if isinstance(x, int) else ""
    if isinstance(x, int) and isinstance(y, int):
        return _sign(x - y)
    if isinstance(x, int):
        return 1
    if isinstance(y, int):
        return -1
    rx, ry = _MAVEN_QUAL.get(x), _MAVEN_QUAL.get(y)
    if rx is not None and ry is not None:
        return _sign(rx - ry)
    if rx is not None:
        return -1 if rx < 5 else 1
    if ry is not None:
        return 1 if ry < 5 else -1
    return 0 if x == y else (1 if x > y else -1)


def compare_maven(a: str, b: str) -> int:
    ia, ib = _maven_items(a), _maven_items(b)
    for idx in range(max(len(ia), len(ib))):
        c = _maven_item_cmp(ia[idx] if idx < len(ia) else None, ib[idx] if idx < len(ib) else None)
        if c:
            return c
    return 0


# --------------------------------------------------------------------------- #
# generic
# --------------------------------------------------------------------------- #
def compare_generic(a: str, b: str) -> int:
    ta = re.findall(r"[0-9]+|[a-zA-Z]+", a)
    tb = re.findall(r"[0-9]+|[a-zA-Z]+", b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        xd, yd = x.isdigit(), y.isdigit()
        if xd and yd:
            return _sign(int(x) - int(y))
        if xd:
            return 1
        if yd:
            return -1
        return 1 if x > y else -1
    return _sign(len(ta) - len(tb))


# --------------------------------------------------------------------------- #
# dispatch
# --------------------------------------------------------------------------- #
_RPM_ECOSYSTEMS = ("Red Hat", "Rocky Linux", "AlmaLinux", "openSUSE", "SUSE", "Mageia", "openEuler",
                   "Azure Linux")
_DPKG_ECOSYSTEMS = ("Debian", "Ubuntu")
_APK_ECOSYSTEMS = ("Alpine", "Wolfi", "Chainguard")
_SEMVER_ECOSYSTEMS = ("npm", "Go", "crates.io", "Hex", "Pub", "SwiftURL", "Packagist", "NuGet")

# Ecosystems for which our comparator is exact enough to overrule the OSV API
PRECISE_ECOSYSTEMS = _RPM_ECOSYSTEMS + _DPKG_ECOSYSTEMS + _APK_ECOSYSTEMS + ("PyPI", "npm", "Go", "crates.io")


def base_ecosystem(ecosystem: str) -> str:
    return (ecosystem or "").split(":", 1)[0]


def comparator(ecosystem: str) -> Callable[[str, str], int]:
    base = base_ecosystem(ecosystem)
    if base in _DPKG_ECOSYSTEMS:
        return compare_dpkg
    if base in _RPM_ECOSYSTEMS:
        return lambda a, b: compare_rpm(a, b, lenient_epoch=True)
    if base in _APK_ECOSYSTEMS:
        return compare_apk
    if base == "PyPI":
        return compare_pep440
    if base in _SEMVER_ECOSYSTEMS:
        return compare_semver
    if base == "RubyGems":
        return compare_gem
    if base == "Maven":
        return compare_maven
    return compare_generic


def compare(ecosystem: str, a: str, b: str) -> int:
    return comparator(ecosystem)(a, b)


def sort_key(ecosystem: str):
    return cmp_to_key(comparator(ecosystem))


def max_version(ecosystem: str, versions: list[str]) -> Optional[str]:
    vs = [v for v in versions if v]
    if not vs:
        return None
    return max(vs, key=sort_key(ecosystem))
