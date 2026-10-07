"""Testes de normalizacao/fingerprint."""
from app.core.normalizer import compute_fingerprint, normalize_snippet
from app.schemas.common import RawFinding


def _make(**over):
    base = dict(
        source_tool="semgrep",
        category="sast",
        title="SQL injection",
        rule_id="python.lang.security.sqli",
        file_path="app/db.py",
        line_start=10, line_end=12,
        snippet="cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
    )
    base.update(over)
    return RawFinding(**base)


def test_normalize_collapses_whitespace_and_identifiers():
    a = normalize_snippet("  cursor.execute(f'SELECT * FROM t WHERE id={user_id}')  ")
    b = normalize_snippet("cursor.execute(f'SELECT * FROM t WHERE id={USER_ID}')")
    c = normalize_snippet("cursor.execute(f'SELECT * FROM t WHERE id={id2}')")
    # a e b diferem so no case → devem colapsar em snippets iguais
    assert a == b
    # identificadores locais viram placeholder → c bate com a/b
    assert a == c


def test_fingerprint_stable_for_same_rule_same_location():
    rf1 = _make()
    rf2 = _make()
    assert compute_fingerprint(rf1) == compute_fingerprint(rf2)


def test_fingerprint_survives_cosmetic_rename():
    rf1 = _make(snippet="query = f'SELECT * FROM users WHERE id={user_id}'")
    rf2 = _make(snippet="query = f'SELECT * FROM users WHERE id={uid}'")
    assert compute_fingerprint(rf1) == compute_fingerprint(rf2)


def test_fingerprint_changes_on_different_file():
    rf1 = _make(file_path="app/a.py")
    rf2 = _make(file_path="app/b.py")
    assert compute_fingerprint(rf1) != compute_fingerprint(rf2)


def test_fingerprint_changes_on_different_rule():
    rf1 = _make(rule_id="rule.a")
    rf2 = _make(rule_id="rule.b")
    assert compute_fingerprint(rf1) != compute_fingerprint(rf2)


def test_fingerprint_uses_cve_for_sca():
    rf1 = RawFinding(
        source_tool="trivy", category="sca",
        title="requests vuln", rule_id="CVE-2024-0001", cve="CVE-2024-0001",
        package_name="requests", package_version="2.20.0",
    )
    rf2 = RawFinding(
        source_tool="trivy", category="sca",
        title="requests vuln", rule_id="CVE-2024-0001", cve="CVE-2024-0001",
        package_name="requests", package_version="2.20.0",
    )
    assert compute_fingerprint(rf1) == compute_fingerprint(rf2)
