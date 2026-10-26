"""Automated tests for authentication, sessions, rate limiting, and CSRF protection."""

from app.models.user import UserStatus


def test_successful_login(client, auth):
    """Verify valid credentials establish an authenticated session and redirect to dashboard."""
    auth.create_user(email="alice@vadl.local", password="Password123!@")

    response = auth.login(email="ALICE@VADL.LOCAL", password="Password123!@", follow_redirects=True)
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "Welcome back" in html
    assert "alice@vadl.local" in html

    # Verify session is populated
    with client.session_transaction() as sess:
        assert sess.get("user_email") == "alice@vadl.local"


def test_login_incorrect_password_rejection(client, auth):
    """Verify incorrect password returns generic failure without leaking user existence."""
    auth.create_user(email="bob@vadl.local", password="Password123!@")

    response = auth.login(
        email="bob@vadl.local", password="WrongPassword999!@", follow_redirects=True
    )
    assert response.status_code == 401
    html = response.get_data(as_text=True)
    assert "Invalid email or password" in html


def test_login_unknown_account_rejection_has_generic_message(client, auth):
    """Verify unknown accounts receive the exact same generic error message as wrong passwords."""
    response = auth.login(
        email="nonexistent@vadl.local", password="AnyPassword123!@", follow_redirects=True
    )
    assert response.status_code == 401
    html = response.get_data(as_text=True)
    assert "Invalid email or password" in html


def test_disabled_account_cannot_authenticate(client, auth):
    """Verify disabled accounts cannot log in even with valid passwords."""
    auth.create_user(
        email="disabled@vadl.local",
        password="Password123!@",
        status=UserStatus.DISABLED,
    )

    response = auth.login(
        email="disabled@vadl.local", password="Password123!@", follow_redirects=True
    )
    assert response.status_code == 401
    html = response.get_data(as_text=True)
    assert "Invalid email or password" in html

    # Verify no session was created
    with client.session_transaction() as sess:
        assert "user_id" not in sess


def test_logout_invalidates_session(client, auth):
    """Verify logout purges session credentials and prevents further protected access."""
    auth.create_user(email="user@vadl.local", password="Password123!@")
    auth.login(email="user@vadl.local", password="Password123!@")

    # Verify authenticated
    resp = client.get("/profile")
    assert resp.status_code == 200

    # Submit logout request with CSRF token
    token = auth.get_csrf_token("/profile")
    logout_resp = client.post("/logout", data={"csrf_token": token}, follow_redirects=True)
    assert logout_resp.status_code == 200
    assert "You have been logged out" in logout_resp.get_data(as_text=True)

    # Subsequent access to protected route must redirect to login
    re_check = client.get("/profile")
    assert re_check.status_code == 302
    assert "/login" in re_check.headers["Location"]


def test_anonymous_access_to_protected_routes_denied(client):
    """Verify unauthenticated requests to protected endpoints are redirected to login."""
    # HTML endpoints
    endpoints = ["/profile", "/admin", "/admin/users", "/assessments"]
    for ep in endpoints:
        resp = client.get(ep)
        assert resp.status_code == 302
        assert f"/login?next={ep}" in resp.headers["Location"]

    # API / JSON endpoint
    json_resp = client.get("/profile", headers={"Accept": "application/json"})
    assert json_resp.status_code == 401
    assert json_resp.get_json() == {"error": "Authentication required"}


def test_login_rate_limiting(client, auth):
    """Verify repeated failed login attempts trigger HTTP 429 Too Many Requests."""
    token = auth.get_csrf_token("/login")

    # Max attempts in test config is 5
    for _ in range(5):
        resp = client.post(
            "/login",
            data={
                "email": "victim@vadl.local",
                "password": "WrongPassword1!",
                "csrf_token": token,
            },
        )
        assert resp.status_code == 401

    # 6th attempt must be rate-limited
    rate_limited_resp = client.post(
        "/login",
        data={
            "email": "victim@vadl.local",
            "password": "WrongPassword1!",
            "csrf_token": token,
        },
    )
    assert rate_limited_resp.status_code == 429
    assert "Too many failed login attempts" in rate_limited_resp.get_data(as_text=True)


def test_csrf_protection_rejects_missing_and_invalid_tokens(client, auth):
    """Verify state-changing POST requests require a valid cryptographic CSRF token."""
    # 1. Missing CSRF token
    resp_missing = client.post(
        "/login",
        data={
            "email": "test@vadl.local",
            "password": "Password123!@",
        },
    )
    assert resp_missing.status_code == 400
    assert "CSRF verification failed" in resp_missing.get_data(as_text=True)

    # 2. Invalid CSRF token
    _ = client.get("/login")  # Initialize session
    resp_invalid = client.post(
        "/login",
        data={
            "email": "test@vadl.local",
            "password": "Password123!@",
            "csrf_token": "tampered-forged-csrf-token",
        },
    )
    assert resp_invalid.status_code == 400
    assert "CSRF verification failed" in resp_invalid.get_data(as_text=True)


def test_login_rejects_external_url_redirect(client, auth):
    """Verify login redirection rejects absolute external domains."""
    auth.create_user(email="redirect1@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/login")
    response = client.post(
        "/login?next=https://malicious-attacker.com",
        data={
            "email": "redirect1@vadl.local",
            "password": "Password123!@",
            "csrf_token": token,
        },
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_login_rejects_protocol_relative_redirect(client, auth):
    """Verify login redirection rejects protocol-relative redirect URLs."""
    auth.create_user(email="redirect2@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/login")
    response = client.post(
        "/login?next=//malicious-attacker.com/evil",
        data={
            "email": "redirect2@vadl.local",
            "password": "Password123!@",
            "csrf_token": token,
        },
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def test_login_accepts_valid_internal_redirect(client, auth):
    """Verify login redirection permits safe local destination paths."""
    auth.create_user(email="redirect3@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/login")
    response = client.post(
        "/login?next=/profile",
        data={
            "email": "redirect3@vadl.local",
            "password": "Password123!@",
            "csrf_token": token,
        },
    )
    assert response.status_code == 302
    assert response.headers["Location"] == "/profile"
