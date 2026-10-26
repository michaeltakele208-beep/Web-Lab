"""Automated tests for Phase 3 vulnerability scenarios: SQLi, XSS, IDOR, and Security Headers.

Proves that vulnerable and secure editions behave differently as intended under identical inputs.
"""

from app.models.lab import LabProduct


def test_sqli_vulnerable_and_secure(client, lab_seed):
    """Scenario A (VADL-SQLI-001): Verify SQL injection query alteration in vulnerable edition vs parameterization defense."""
    # 1. Normal benign lookup in vulnerable edition
    resp_vuln_benign = client.get("/lab/vulnerable/sqli?category=hardware")
    assert resp_vuln_benign.status_code == 200
    html_vuln_benign = resp_vuln_benign.get_data(as_text=True)
    assert "Firewall Appliance" in html_vuln_benign
    assert "CONFIDENTIAL_LAB_FLAG" not in html_vuln_benign

    # 2. Crafted SQL injection payload in vulnerable edition (' OR '1'='1)
    # Alters query semantics to retrieve all catalog items including confidential test flags
    payload = "' OR '1'='1"
    resp_vuln_attack = client.get(f"/lab/vulnerable/sqli?category={payload}")
    assert resp_vuln_attack.status_code == 200
    html_vuln_attack = resp_vuln_attack.get_data(as_text=True)
    assert "CONFIDENTIAL_LAB_FLAG{vadl_sqli_success}" in html_vuln_attack
    assert (
        "Security Scanner Suite" in html_vuln_attack
    )  # Software item exposed under hardware search

    # 3. Same crafted input against the secure edition
    # Parameterized query treats input strictly as literal category data
    resp_secure_attack = client.get(f"/lab/secure/sqli?category={payload}")
    assert resp_secure_attack.status_code == 200
    html_secure_attack = resp_secure_attack.get_data(as_text=True)
    assert "CONFIDENTIAL_LAB_FLAG" not in html_secure_attack
    assert "No products found matching category" in html_secure_attack

    # 4. Benign lookup against the secure edition
    resp_secure_benign = client.get("/lab/secure/sqli?category=hardware")
    assert resp_secure_benign.status_code == 200
    html_secure_benign = resp_secure_benign.get_data(as_text=True)
    assert "Firewall Appliance" in html_secure_benign
    assert "CONFIDENTIAL_LAB_FLAG" not in html_secure_benign

    # 5. Verify database integrity remained uncorrupted
    total_products = LabProduct.query.count()
    assert total_products == 4


def test_xss_vulnerable_and_secure(client, auth):
    """Scenario B (VADL-XSS-001): Verify unencoded markup execution in vulnerable edition vs contextual auto-escaping."""
    payload = '<span id="synthetic-xss-proof">harmless_poc</span>'

    # 1. Post payload to vulnerable endpoint
    token_vuln = auth.get_csrf_token("/lab/vulnerable/xss")
    client.post(
        "/lab/vulnerable/xss",
        data={
            "author": "Attacker",
            "content": payload,
            "csrf_token": token_vuln,
        },
    )

    # In vulnerable edition, payload is marked safe and rendered unescaped in HTML response
    resp_vuln = client.get("/lab/vulnerable/xss")
    assert resp_vuln.status_code == 200
    html_vuln = resp_vuln.get_data(as_text=True)
    assert '<span id="synthetic-xss-proof">harmless_poc</span>' in html_vuln

    # 2. Post payload to secure endpoint
    token_sec = auth.get_csrf_token("/lab/secure/xss")
    client.post(
        "/lab/secure/xss",
        data={
            "author": "Defender",
            "content": payload,
            "csrf_token": token_sec,
        },
    )

    # In secure edition, Jinja context-aware auto-escaping encodes all HTML brackets
    resp_secure = client.get("/lab/secure/xss")
    assert resp_secure.status_code == 200
    html_secure = resp_secure.get_data(as_text=True)
    assert '<span id="synthetic-xss-proof">harmless_poc</span>' not in html_secure
    assert "&lt;span id=&#34;synthetic-xss-proof&#34;&gt;harmless_poc&lt;/span&gt;" in html_secure


def test_idor_vulnerable_and_secure(client, lab_seed):
    """Scenario C (VADL-AC-001): Verify missing ownership check allows IDOR in vulnerable edition vs 403 rejection in secure edition."""
    # Record #1 belongs to 'synthetic-user-1@vadl.local'
    # Record #2 belongs to 'synthetic-user-2@vadl.local'

    # 1. In vulnerable edition: synthetic-user-1 accesses record #2 (Belonging to synthetic-user-2)
    # The vulnerable endpoint ignores ownership and exposes synthetic user 2's private note
    resp_vuln = client.get(
        "/lab/vulnerable/records/2",
        headers={"X-Lab-User": "synthetic-user-1@vadl.local"},
    )
    assert resp_vuln.status_code == 200
    html_vuln = resp_vuln.get_data(as_text=True)
    assert "Bravo Project Brief" in html_vuln
    assert "synthetic participant 2" in html_vuln

    # 2. In secure edition: synthetic-user-1 accesses own record #1 (Authorized)
    resp_sec_own = client.get(
        "/lab/secure/records/1",
        headers={"X-Lab-User": "synthetic-user-1@vadl.local"},
    )
    assert resp_sec_own.status_code == 200
    assert "Alpha Project Brief" in resp_sec_own.get_data(as_text=True)

    # 3. In secure edition: synthetic-user-1 attempts horizontal access to record #2 (Unauthorized)
    # Server enforces ownership check and aborts with HTTP 403 Forbidden
    resp_sec_tampered = client.get(
        "/lab/secure/records/2",
        headers={"X-Lab-User": "synthetic-user-1@vadl.local"},
    )
    assert resp_sec_tampered.status_code == 403
    assert "Access Denied" in resp_sec_tampered.get_data(as_text=True)


def test_security_headers_vulnerable_and_secure(client):
    """Scenario D (VADL-HEADERS-001): Inspect actual HTTP responses for missing vs enforced defensive headers."""
    # 1. Vulnerable edition endpoint deliberately omits defense headers
    resp_vuln = client.get("/lab/vulnerable/headers")
    assert resp_vuln.status_code == 200
    headers_vuln = resp_vuln.headers

    assert "Content-Security-Policy" not in headers_vuln
    assert "X-Content-Type-Options" not in headers_vuln
    assert "X-Frame-Options" not in headers_vuln

    # 2. Secure edition endpoint explicitly enforces full defensive headers
    resp_secure = client.get("/lab/secure/headers")
    assert resp_secure.status_code == 200
    headers_secure = resp_secure.headers

    assert "Content-Security-Policy" in headers_secure
    assert "frame-ancestors 'none'" in headers_secure["Content-Security-Policy"]
    assert headers_secure.get("X-Content-Type-Options") == "nosniff"
    assert headers_secure.get("X-Frame-Options") == "DENY"
    assert headers_secure.get("Referrer-Policy") == "strict-origin-when-cross-origin"
