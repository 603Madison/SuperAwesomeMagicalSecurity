import json
import zipfile
from pathlib import Path

import httpx
import pytest

from sams.config import Settings
from sams.models import FindingCategory, HostInfo, Inventory, OSInfo, Package, RemediationKind, Severity
from sams.vuln import cvss
from sams.vuln.ecosystems import normalize_pypi, resolve
from sams.vuln.enrich import ThreatIntel
from sams.vuln.osv import LocalOSVDB, OSVClient, evaluate, fixed_for, range_affects
from sams.vuln.scanner import VulnScanner, sync_ecosystems

FIX = Path(__file__).parent / "fixtures" / "vuln"


def load(name: str) -> dict:
    return json.loads((FIX / f"{name}.json").read_text())


UBUNTU_2204 = OSInfo(family="linux", id="ubuntu", id_like=["debian"], version_id="22.04", codename="jammy")


# --------------------------------------------------------------------------- #
# CVSS
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize("vector,score", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H", 7.8),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", 7.5),
    ("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:H", 7.4),
    ("CVSS:3.1/AV:P/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0),
    ("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 8.8),
    ("CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 8.8),
])
def test_cvss3_scores(vector, score):
    assert cvss.cvss3_base_score(vector) == score


def test_cvss_misc():
    assert cvss.roundup(4.02) == 4.1
    assert cvss.roundup(4.0) == 4.0
    assert cvss.attack_vector("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H") == "local"
    assert cvss.cvss3_base_score("garbage") is None
    v4 = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"
    info = cvss.from_osv({"severity": [{"type": "CVSS_V4", "score": v4}]})
    assert info.attack_vector == "network" and info.version == "4.0" and info.score >= 9.0
    # label fallbacks
    assert cvss.from_osv({"database_specific": {"severity": "HIGH"}}).score == 7.5
    assert cvss.from_osv({"severity": [{"type": "Ubuntu", "score": "negligible"}]}).score == 1.0
    assert cvss.from_osv({}, {"ecosystem_specific": {"urgency": "low"}}).score == 3.0
    assert cvss.from_osv({}).score is None
    # highest of several vectors wins
    info = cvss.from_osv(load("UBUNTU-CVE-2022-1292"))
    assert info.score == 9.8 and info.attack_vector == "network" and info.label == "medium"


# --------------------------------------------------------------------------- #
# Ecosystem mapping
# --------------------------------------------------------------------------- #
def test_ecosystem_mapping():
    q = resolve(Package(name="libssl3", version="3.0.2-0ubuntu1.10", manager="dpkg", source_name="openssl",
                        source_version="3.0.2-0ubuntu1.10"), UBUNTU_2204)
    assert q and q[0].ecosystem == "Ubuntu:22.04:LTS" and q[0].name == "openssl" and q[0].binary_name == "libssl3"

    nonlts = OSInfo(id="ubuntu", version_id="24.10")
    assert resolve(Package(name="x", version="1", manager="dpkg"), nonlts)[0].ecosystem == "Ubuntu:24.10"
    mint = OSInfo(id="linuxmint", id_like=["ubuntu", "debian"], version_id="21.3", codename="jammy")
    assert resolve(Package(name="x", version="1", manager="dpkg"), mint)[0].ecosystem == "Ubuntu:22.04:LTS"

    deb = OSInfo(id="debian", version_id="12", codename="bookworm")
    q = resolve(Package(name="zlib1g", version="1:1.2.13.dfsg-1+b1", manager="dpkg", source_name="zlib"), deb)[0]
    assert q.ecosystem == "Debian:12" and q.name == "zlib" and q.version == "1:1.2.13.dfsg-1"   # binNMU stripped
    sid = OSInfo(id="debian", version_id="", codename="trixie")
    assert resolve(Package(name="x", version="1", manager="dpkg"), sid)[0].ecosystem == "Debian:13"
    kali = OSInfo(id="kali", id_like=["debian"], version_id="2024.1", codename="kali-rolling")
    assert resolve(Package(name="x", version="1", manager="dpkg"), kali) is None

    alp = OSInfo(id="alpine", version_id="3.19.1")
    q = resolve(Package(name="libcrypto3", version="3.1.4-r5", manager="apk", source_name="openssl"), alp)[0]
    assert q.ecosystem == "Alpine:v3.19" and q.name == "openssl"

    rhel = OSInfo(id="rhel", id_like=["fedora"], version_id="9.3")
    qs = resolve(Package(name="openssl-libs", version="1:3.0.7-24.el9", manager="rpm"), rhel)
    assert [x.ecosystem for x in qs] == ["Red Hat:enterprise_linux:9::baseos", "Red Hat:enterprise_linux:9::appstream"]
    assert resolve(Package(name="x", version="1", manager="rpm"), OSInfo(id="rocky", version_id="9.3"))[0].ecosystem == "Rocky Linux:9"
    assert resolve(Package(name="x", version="1", manager="rpm"), OSInfo(id="almalinux", version_id="8.9"))[0].ecosystem == "AlmaLinux:8"
    assert resolve(Package(name="x", version="1", manager="rpm"), OSInfo(id="opensuse-leap", version_id="15.5"))[0].ecosystem == "openSUSE:Leap 15.5"
    assert resolve(Package(name="x", version="1", manager="rpm"), OSInfo(id="fedora", version_id="39")) is None

    q = resolve(Package(name="Jinja2", version="2.10", manager="pypi"), UBUNTU_2204)[0]
    assert q.ecosystem == "PyPI" and q.name == "jinja2"
    assert normalize_pypi("Zope.Interface_x") == "zope-interface-x"
    assert resolve(Package(name="lodash", version="4.17.0", manager="npm"), UBUNTU_2204)[0].ecosystem == "npm"
    assert resolve(Package(name="git", version="2.4", manager="brew"), OSInfo(family="darwin", id="macos")) is None
    assert resolve(Package(name="7-Zip", version="23", manager="windows"), OSInfo(family="windows", id="windows")) is None


# --------------------------------------------------------------------------- #
# OSV range evaluation
# --------------------------------------------------------------------------- #
def test_range_semantics():
    eco = "Debian:12"
    rng = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1.5-1"}, {"introduced": "2.0-1"},
                                            {"fixed": "2.5-1"}]}
    assert range_affects(eco, rng, "1.0-1")
    assert not range_affects(eco, rng, "1.5-1")
    assert not range_affects(eco, rng, "1.7-1")
    assert range_affects(eco, rng, "2.0-1")
    assert range_affects(eco, rng, "2.4-1")
    assert not range_affects(eco, rng, "3.0-1")
    # events out of order must be sorted
    shuffled = {"type": "ECOSYSTEM", "events": list(reversed(rng["events"]))}
    assert range_affects(eco, shuffled, "2.4-1") and not range_affects(eco, shuffled, "1.7-1")
    # last_affected is inclusive
    la = {"type": "SEMVER", "events": [{"introduced": "1.0.0"}, {"last_affected": "1.2.0"}]}
    assert range_affects("npm", la, "1.2.0") and not range_affects("npm", la, "1.2.1")
    assert not range_affects("npm", la, "0.9.0")
    # limit
    lim = {"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"limit": "2.0.0"}]}
    assert range_affects("PyPI", lim, "1.0") and not range_affects("PyPI", lim, "2.1")
    # GIT ranges are ignored
    assert not range_affects("PyPI", {"type": "GIT", "events": [{"introduced": "0"}]}, "1.0")
    # fixed_for picks the next fix above the installed version
    aff = {"ranges": [rng]}
    assert fixed_for(eco, aff, "2.1-1") == "2.5-1"
    assert fixed_for(eco, aff, "1.0-1") == "1.5-1"


def test_evaluate_versions_list_and_ecosystem():
    v = load("UBUNTU-CVE-2022-1292")
    assert evaluate(v, "Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1") == (True, "3.0.2-0ubuntu1.1", v["affected"][0])
    assert evaluate(v, "Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.1")[0] is False
    assert evaluate(v, "Ubuntu:22.04:LTS", "nginx", "1.0")[0] is None       # no entry for package
    assert evaluate(v, "Debian:12", "openssl", "1.0")[0] is None             # other ecosystem
    # explicit versions list alone also counts
    only_list = {"id": "X", "affected": [{"package": {"name": "p", "ecosystem": "PyPI"}, "versions": ["1.0"]}]}
    assert evaluate(only_list, "PyPI", "P", "1.0")[0] is True
    assert evaluate(only_list, "PyPI", "p", "1.1")[0] is False
    # RHEL baseos query matches appstream records of the same major
    rh = {"id": "RHSA-1", "affected": [{"package": {"name": "openssl", "ecosystem": "Red Hat:enterprise_linux:9::appstream"},
                                        "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "1:3.0.7-25.el9"}]}]}]}
    assert evaluate(rh, "Red Hat:enterprise_linux:9::baseos", "openssl", "3.0.7-24.el9")[0] is True
    assert evaluate(rh, "Red Hat:enterprise_linux:9::baseos", "openssl", "1:3.0.7-27.el9")[0] is False


# --------------------------------------------------------------------------- #
# Local mirror
# --------------------------------------------------------------------------- #
def _make_zip(path: Path, names: list[str]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for n in names:
            zf.writestr(f"{n}.json", (FIX / f"{n}.json").read_text())
        zf.writestr("README.txt", "not json")
    return path


def test_local_db_import_and_match(tmp_path):
    db = LocalOSVDB(tmp_path / "osv.db")
    n = db.import_zip("Ubuntu", _make_zip(tmp_path / "u.zip", ["UBUNTU-CVE-2022-1292", "UBUNTU-CVE-2023-0286",
                                                               "UBUNTU-CVE-2023-22809"]))
    assert n == 3
    assert db.ecosystems() == ["Ubuntu"] and db.covers("Ubuntu:22.04:LTS") and not db.covers("PyPI")
    ids = sorted(v["id"] for v in db.match("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1"))
    assert ids == ["UBUNTU-CVE-2022-1292", "UBUNTU-CVE-2023-0286"]
    ids = [v["id"] for v in db.match("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.5")]
    assert ids == ["UBUNTU-CVE-2023-0286"]
    assert db.match("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1.20") == []
    assert db.get("UBUNTU-CVE-2023-22809")["id"] == "UBUNTU-CVE-2023-22809"
    # re-import replaces affected rows rather than duplicating
    db.import_zip("Ubuntu", _make_zip(tmp_path / "u2.zip", ["UBUNTU-CVE-2023-0286"]))
    assert [v["id"] for v in db.match("Ubuntu:22.04:LTS", "openssl", "3.0.2-0ubuntu1")] == ["UBUNTU-CVE-2023-0286"]
    # PyPI names are normalized
    db.import_zip("PyPI", _make_zip(tmp_path / "p.zip", ["GHSA-462w-v97r-4m45"]))
    assert [v["id"] for v in db.match("PyPI", "Jinja2", "2.10")] == ["GHSA-462w-v97r-4m45"]


def test_sync_downloads_bulk_zip(tmp_path):
    zip_bytes = _make_zip(tmp_path / "src.zip", ["GHSA-462w-v97r-4m45"]).read_bytes()
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append(str(req.url))
        return httpx.Response(200, content=zip_bytes)

    s = Settings(data_dir=tmp_path / "data")
    out = sync_ecosystems(s, ["PyPI"], transport=httpx.MockTransport(handler))
    assert out == {"PyPI": 1}
    assert seen == ["https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"]


# --------------------------------------------------------------------------- #
# Online client
# --------------------------------------------------------------------------- #
def test_query_batch_pagination_and_cache(tmp_path):
    calls = {"batch": 0, "vuln": 0}

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.path == "/v1/querybatch":
            calls["batch"] += 1
            body = json.loads(req.content)
            res = []
            for q in body["queries"]:
                if q.get("page_token") == "p2":
                    res.append({"vulns": [{"id": "B"}]})
                elif q["package"]["name"] == "multi":
                    res.append({"vulns": [{"id": "A"}], "next_page_token": "p2"})
                else:
                    res.append({})
            return httpx.Response(200, json={"results": res})
        calls["vuln"] += 1
        return httpx.Response(200, json={"id": req.url.path.rsplit("/", 1)[-1]})

    s = Settings(data_dir=tmp_path)
    c = OSVClient(s.vuln, s.cache_dir, transport=httpx.MockTransport(handler))
    assert c.query_batch([("PyPI", "multi", "1.0"), ("PyPI", "none", "1.0")]) == [["A", "B"], []]
    assert calls["batch"] == 2
    assert c.query_batch([("PyPI", "multi", "1.0")]) == [["A", "B"]]      # cached
    assert calls["batch"] == 2
    assert set(c.get_vulns(["A", "B", "A"])) == {"A", "B"}
    c.get_vuln("A")
    assert calls["vuln"] == 2


def test_threat_intel_degrades_gracefully(tmp_path):
    def boom(req):
        raise httpx.ConnectError("offline")

    s = Settings(data_dir=tmp_path)
    ti = ThreatIntel(s.vuln, s.cache_dir, transport=httpx.MockTransport(boom))
    assert ti.kev() == {} and ti.epss(["CVE-2023-0001"]) == {}


# --------------------------------------------------------------------------- #
# Scanner end-to-end (mocked OSV + KEV + EPSS)
# --------------------------------------------------------------------------- #
def _mock_world():
    vulns = {n: load(n) for n in ["UBUNTU-CVE-2022-1292", "UBUNTU-CVE-2023-0286", "UBUNTU-CVE-2023-22809",
                                  "GHSA-462w-v97r-4m45"]}
    index = {("Ubuntu:22.04:LTS", "openssl"): ["UBUNTU-CVE-2022-1292", "UBUNTU-CVE-2023-0286"],
             ("Ubuntu:22.04:LTS", "sudo"): ["UBUNTU-CVE-2023-22809"],
             ("PyPI", "jinja2"): ["GHSA-462w-v97r-4m45"],
             # API claims a match that our precise comparator rejects (should be dropped)
             ("Ubuntu:22.04:LTS", "bash"): ["UBUNTU-CVE-BASH"]}
    vulns["UBUNTU-CVE-BASH"] = {"id": "UBUNTU-CVE-BASH", "affected": [
        {"package": {"name": "bash", "ecosystem": "Ubuntu:22.04:LTS"},
         "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "5.0-1"}]}]}]}
    epss_calls = []

    def handler(req: httpx.Request) -> httpx.Response:
        if req.url.host == "api.osv.dev" and req.url.path == "/v1/querybatch":
            out = []
            for q in json.loads(req.content)["queries"]:
                ids = index.get((q["package"]["ecosystem"], q["package"]["name"]), [])
                out.append({"vulns": [{"id": i} for i in ids]} if ids else {})
            return httpx.Response(200, json={"results": out})
        if req.url.host == "api.osv.dev" and req.url.path.startswith("/v1/vulns/"):
            vid = req.url.path.rsplit("/", 1)[-1]
            return httpx.Response(200, json=vulns[vid]) if vid in vulns else httpx.Response(404)
        if "known_exploited" in req.url.path:
            return httpx.Response(200, content=(FIX / "kev.json").read_bytes())
        if req.url.host == "api.first.org":
            cves = req.url.params["cve"].split(",")
            epss_calls.append(cves)
            data = [{"cve": c, "epss": "0.9" if c == "CVE-2022-1292" else "0.01", "percentile": "0.5"} for c in cves]
            return httpx.Response(200, json={"data": data})
        return httpx.Response(404)

    return httpx.MockTransport(handler), epss_calls


def _inventory() -> Inventory:
    return Inventory(
        host=HostInfo(hostname="web1", os=UBUNTU_2204),
        packages=[
            Package(name="openssl", version="3.0.2-0ubuntu1", manager="dpkg", source_name="openssl"),
            Package(name="libssl3", version="3.0.2-0ubuntu1", manager="dpkg", source_name="openssl"),
            Package(name="sudo", version="1.9.9-1ubuntu2", manager="dpkg"),
            Package(name="bash", version="5.1-6ubuntu1", manager="dpkg"),
            Package(name="Jinja2", version="2.10", manager="pypi"),
            Package(name="htop", version="3.0", manager="brew"),
        ],
    )


def test_scanner_end_to_end(tmp_path):
    transport, epss_calls = _mock_world()
    s = Settings(data_dir=tmp_path)
    s.vuln.mode = "online"
    sc = VulnScanner(s, transport=transport)
    findings = {f.evidence["package"]: f for f in sc.scan(_inventory(), "asset_web1")}
    assert set(findings) == {"openssl", "sudo", "jinja2"}

    ossl = findings["openssl"]
    assert ossl.key == "vuln:asset_web1:dpkg:openssl"
    assert ossl.category == FindingCategory.vulnerability
    assert ossl.severity == Severity.critical                    # CVSS 9.8
    assert ossl.title == "openssl 3.0.2-0ubuntu1: 2 vulnerabilities (fixed in 3.0.2-0ubuntu1.8)"
    ev = ossl.evidence
    assert ev["binary_packages"] == ["openssl", "libssl3"]
    assert ev["fixed_version"] == "3.0.2-0ubuntu1.8"
    assert ev["remote_exploitable"] is True and ev["privesc"] is False and ev["kev"] is False
    assert ev["max_cvss"] == 9.8 and ev["max_epss"] == 0.9
    first = ev["vulns"][0]
    assert first["id"] == "UBUNTU-CVE-2022-1292" and "CVE-2022-1292" in first["aliases"]
    assert first["attack_vector"] == "network" and first["fixed"] == "3.0.2-0ubuntu1.1"
    assert ossl.remediation.kind == RemediationKind.patch and ossl.remediation.automatable
    assert ossl.remediation.task == {"action": "patch", "manager": "dpkg", "packages": ["openssl", "libssl3"]}
    assert "apt-get" in ossl.remediation.commands[0]
    assert "remote" in ossl.tags

    sudo = findings["sudo"]
    assert sudo.evidence["kev"] is True and sudo.severity == Severity.critical   # KEV bump from high
    assert sudo.evidence["privesc"] is True and sudo.evidence["vulns"][0]["kev_info"]["product"] == "Sudo"
    assert set(sudo.tags) == {"kev", "privesc"}

    j = findings["jinja2"]
    assert j.severity == Severity.high and j.evidence["fixed_version"] == "2.10.1"
    assert j.remediation.automatable is False and "pip install" in j.remediation.commands[0]

    st = sc.last_stats
    assert st["packages_total"] == 6 and st["packages_unsupported"] == 1 and st["packages_vulnerable"] == 3
    assert st["unsupported_managers"] == {"brew": 1}
    assert len(epss_calls) == 1


def test_scanner_offline_mode_uses_local_mirror(tmp_path):
    def no_network(req):
        raise AssertionError(f"network used in offline mode: {req.url}")

    s = Settings(data_dir=tmp_path)
    s.vuln.mode = "offline"
    s.vuln.enrich = False
    db = LocalOSVDB(tmp_path / "osv.db")
    db.import_zip("Ubuntu", _make_zip(tmp_path / "u.zip", ["UBUNTU-CVE-2022-1292", "UBUNTU-CVE-2023-22809"]))
    db.close()
    sc = VulnScanner(s, transport=httpx.MockTransport(no_network))
    findings = sc.scan(_inventory(), "a1")
    assert sorted(f.evidence["package"] for f in findings) == ["openssl", "sudo"]   # PyPI not mirrored
    assert sc.last_stats["mode"] == "offline"


def test_scanner_hybrid_routes_by_mirror(tmp_path):
    transport, _ = _mock_world()
    s = Settings(data_dir=tmp_path)
    s.vuln.mode = "hybrid"
    s.vuln.enrich = False
    db = LocalOSVDB(tmp_path / "osv.db")
    db.import_zip("PyPI", _make_zip(tmp_path / "p.zip", ["GHSA-462w-v97r-4m45"]))
    db.close()
    findings = VulnScanner(s, transport=transport).scan(_inventory(), "a1")
    assert sorted(f.evidence["package"] for f in findings) == ["jinja2", "openssl", "sudo"]


def test_dedupe_aggregate_and_twin_records():
    from sams.vuln.scanner import dedupe

    def v(vid, aliases, score=None, fixed=None):
        return {"id": vid, "aliases": aliases, "cvss_score": score, "fixed": fixed}

    out = dedupe([
        v("USN-1-1", ["CVE-2024-10001", "CVE-2024-10002"], fixed="1.2"),
        v("UBUNTU-CVE-2024-10001", ["CVE-2024-10001"], 9.8),
        v("UBUNTU-CVE-2024-10002", ["CVE-2024-10002"], 5.0),
        v("USN-2-1", ["CVE-2024-10003"]),                   # its CVE has no per-CVE record -> kept
        v("PYSEC-2019-217", ["CVE-2019-10906", "GHSA-462w"]),
        v("GHSA-462w", ["CVE-2019-10906", "PYSEC-2019-217"], 8.6),
    ])
    assert sorted(x["id"] for x in out) == ["GHSA-462w", "UBUNTU-CVE-2024-10001", "UBUNTU-CVE-2024-10002", "USN-2-1"]
    ghsa = next(x for x in out if x["id"] == "GHSA-462w")
    assert ghsa["related_ids"] == ["PYSEC-2019-217"]
    first = next(x for x in out if x["id"] == "UBUNTU-CVE-2024-10001")
    assert first["related_ids"] == ["USN-1-1"] and first["fixed"] == "1.2"
