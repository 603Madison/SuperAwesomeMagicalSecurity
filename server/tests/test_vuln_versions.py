import pytest

from sams.vuln import versions as V


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0),
    ("1.0-1", "1.0-2", -1),
    ("1:1.0", "2.0", 1),                       # epoch wins
    ("1.0~rc1", "1.0", -1),                    # tilde sorts before release
    ("1.0~rc1", "1.0~rc2", -1),
    ("1.0~~", "1.0~", -1),
    ("1.0", "1.0+deb12u1", -1),
    ("1.0a", "1.0+", -1),                      # letters before non-letters
    ("3.0.2-0ubuntu1.10", "3.0.2-0ubuntu1.9", 1),
    ("3.0.2-0ubuntu1", "3.0.2-0ubuntu1.1", -1),
    ("3.0.11-1~deb12u1", "3.0.11-1~deb12u2", -1),
    ("3.0.11-1~deb12u2", "3.0.11-1", -1),
    ("1.2.3-1", "1.2.3", 1),
    ("1.0-0", "1.0", 0),
    ("2:8.2.3995-1ubuntu2", "1:9.0", 1),
    ("1.01", "1.1", 0),                        # leading zeros
    ("12.22.9~dfsg-1ubuntu3", "12.22.9~dfsg-1ubuntu3.1", -1),
])
def test_dpkg(a, b, expected):
    assert V.compare_dpkg(a, b) == expected
    assert V.compare_dpkg(b, a) == -expected


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0", 0),
    ("1.0", "1.0.1", -1),
    ("1.0a", "1.0", 1),
    ("1.0~rc1", "1.0", -1),
    ("1.0^", "1.0", 1),                        # caret: post-release snapshot
    ("1.0^git1", "1.0.1", -1),
    ("1.0~rc1^git1", "1.0~rc1", 1),
    ("1.0~rc1^git1", "1.0", -1),
    ("2.0", "10", -1),
    ("1.010", "1.10", 0),
    ("a", "1", -1),                            # numeric newer than alpha
    ("1.0.1", "1.0a", 1),
    ("5.3p1", "5.3", 1),
])
def test_rpmvercmp(a, b, expected):
    assert V.rpmvercmp(a, b) == expected
    assert V.rpmvercmp(b, a) == -expected


def test_rpm_evr():
    assert V.compare_rpm("1:3.0.1-41.el9_0", "1:3.0.1-43.el9_0") == -1
    assert V.compare_rpm("3.0.1-41.el9_0", "1:3.0.1-43.el9_0") == -1          # strict epoch: 0 < 1
    assert V.compare_rpm("3.0.7-1.el9", "1:3.0.1-43.el9_0") == -1             # strict
    assert V.compare_rpm("3.0.7-1.el9", "1:3.0.1-43.el9_0", lenient_epoch=True) == 1
    assert V.compare_rpm("1.0", "1.0-5") == 0                                 # missing release ignored
    assert V.compare("Rocky Linux:9", "3.0.7-1.el9", "1:3.0.1-43.el9_0") == 1  # dispatch is lenient


@pytest.mark.parametrize("a,b,expected", [
    ("1.2.3-r0", "1.2.3-r1", -1),
    ("1.2.3", "1.2.3-r0", 0),
    ("1.2.3_rc1", "1.2.3", -1),
    ("1.2.3_alpha1", "1.2.3_beta1", -1),
    ("1.2.3_p1", "1.2.3", 1),
    ("1.2.3a", "1.2.3", 1),
    ("1.2.3a", "1.2.4", -1),
    ("1.1.1t-r1", "1.1.1t-r2", -1),
    ("1.1.1t", "1.1.1", 1),
    ("3.1.0-r0", "3.1.0-r4", -1),
    ("1.10", "1.9", 1),
])
def test_apk(a, b, expected):
    assert V.compare_apk(a, b) == expected
    assert V.compare_apk(b, a) == -expected


@pytest.mark.parametrize("a,b,expected", [
    ("1.0", "1.0.0", 0),
    ("1.0.dev1", "1.0a1", -1),
    ("1.0a1", "1.0b1", -1),
    ("1.0b2", "1.0rc1", -1),
    ("1.0rc1", "1.0", -1),
    ("1.0", "1.0.post1", -1),
    ("1.0.post1.dev1", "1.0.post1", -1),
    ("1.0a1.dev1", "1.0a1", -1),
    ("1!0.1", "2.0", 1),
    ("2.10", "2.9", 1),
    ("1.0+local", "1.0", 0),
    ("1.0-1", "1.0.post1", 0),
    ("1.0alpha1", "1.0a1", 0),
    ("2.11.3", "2.10", 1),
])
def test_pep440(a, b, expected):
    assert V.compare_pep440(a, b) == expected
    assert V.compare_pep440(b, a) == -expected


@pytest.mark.parametrize("a,b,expected", [
    ("1.0.0", "v1.0.0", 0),
    ("1.0.0-alpha", "1.0.0", -1),
    ("1.0.0-alpha", "1.0.0-alpha.1", -1),
    ("1.0.0-alpha.1", "1.0.0-alpha.beta", -1),
    ("1.0.0-alpha.beta", "1.0.0-beta", -1),
    ("1.0.0-beta.2", "1.0.0-beta.11", -1),
    ("1.0.0-rc.1", "1.0.0", -1),
    ("1.0.0+build1", "1.0.0+build2", 0),
    ("1.2", "1.2.0", 0),
    ("0.0.0-20210101000000-abcdef", "0.0.1", -1),   # Go pseudo-version
    ("1.10.0", "1.9.0", 1),
])
def test_semver(a, b, expected):
    assert V.compare_semver(a, b) == expected
    assert V.compare_semver(b, a) == -expected


def test_gem_and_maven():
    assert V.compare_gem("1.0.0.pre", "1.0.0") == -1
    assert V.compare_gem("1.0", "1") == 0
    assert V.compare_gem("6.1.7.3", "6.1.7.10") == -1
    assert V.compare_maven("1.0-SNAPSHOT", "1.0") == -1
    assert V.compare_maven("1.0-alpha", "1.0-beta") == -1
    assert V.compare_maven("1.0-rc1", "1.0") == -1
    assert V.compare_maven("1.0", "1.0-sp1") == -1
    assert V.compare_maven("2.17.1", "2.15.0") == 1


def test_dispatch_and_max():
    assert V.comparator("Ubuntu:22.04:LTS") is V.compare_dpkg
    assert V.comparator("Debian:12") is V.compare_dpkg
    assert V.comparator("Alpine:v3.19") is V.compare_apk
    assert V.comparator("PyPI") is V.compare_pep440
    assert V.comparator("npm") is V.compare_semver
    assert V.comparator("Go") is V.compare_semver
    assert V.max_version("Debian:12", ["1.0-1", "1.0-10", "1.0-2"]) == "1.0-10"
    assert V.max_version("PyPI", []) is None
    assert V.compare_generic("1.2.10", "1.2.9") == 1
