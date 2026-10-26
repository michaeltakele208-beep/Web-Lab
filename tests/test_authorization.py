"""Automated tests for role-based authorization boundaries and horizontal privilege escalation prevention."""

from app.extensions import db
from app.models.user import Role, User, UserStatus


def test_ordinary_user_cannot_access_admin_pages(client, auth):
    """Verify ordinary users receive HTTP 403 when attempting to access administrative interfaces."""
    auth.create_user(email="regular@vadl.local", password="Password123!@", role=Role.USER)
    auth.login(email="regular@vadl.local", password="Password123!@")

    # Accessing admin dashboard
    resp = client.get("/admin")
    assert resp.status_code == 403
    assert "Forbidden" in resp.get_data(as_text=True)

    # Accessing user management
    resp = client.get("/admin/users")
    assert resp.status_code == 403


def test_security_analyst_cannot_access_admin_operations(client, auth):
    """Verify security analysts are prevented from accessing administrative user management."""
    auth.create_user(
        email="analyst@vadl.local", password="Password123!@", role=Role.SECURITY_ANALYST
    )
    auth.login(email="analyst@vadl.local", password="Password123!@")

    # Analyst accessing admin console
    resp = client.get("/admin")
    assert resp.status_code == 403

    # Analyst accessing assessment console (Authorized)
    resp_assess = client.get("/assessments")
    assert resp_assess.status_code == 200
    assert "Security Assessment Console" in resp_assess.get_data(as_text=True)


def test_admin_can_access_authorized_management_pages(client, auth):
    """Verify administrator account can access admin dashboard and user management console."""
    auth.create_user(email="admin@vadl.local", password="Password123!@", role=Role.ADMIN)
    auth.login(email="admin@vadl.local", password="Password123!@")

    # Admin dashboard
    resp_dashboard = client.get("/admin")
    assert resp_dashboard.status_code == 200
    assert "Laboratory Administration" in resp_dashboard.get_data(as_text=True)

    # User management list
    resp_users = client.get("/admin/users")
    assert resp_users.status_code == 200
    assert "Participant Identity Management" in resp_users.get_data(as_text=True)

    # Admin assessment access (Authorized)
    resp_assess = client.get("/assessments")
    assert resp_assess.status_code == 200


def test_ordinary_user_cannot_access_assessment_console(client, auth):
    """Verify ordinary users receive HTTP 403 when attempting to access the security assessment console."""
    auth.create_user(email="user@vadl.local", password="Password123!@", role=Role.USER)
    auth.login(email="user@vadl.local", password="Password123!@")

    resp = client.get("/assessments")
    assert resp.status_code == 403
    assert "Forbidden" in resp.get_data(as_text=True)


def test_users_cannot_access_other_user_profiles_via_url_id(client, auth):
    """Verify horizontal access control: users cannot access other users' profile data by tampering with user IDs."""
    user1 = auth.create_user(
        email="user1@vadl.local", password="Password123!@", display_name="User One"
    )
    user2 = auth.create_user(
        email="user2@vadl.local", password="Password123!@", display_name="User Two"
    )

    # Log in as user1
    auth.login(email="user1@vadl.local", password="Password123!@")

    # Access own profile via ID
    own_resp = client.get(f"/users/{user1.id}")
    assert own_resp.status_code == 200
    assert "User One" in own_resp.get_data(as_text=True)

    # Attempt to access user2's profile via ID tampering
    tampered_resp = client.get(f"/users/{user2.id}")
    assert tampered_resp.status_code == 403
    assert "Forbidden" in tampered_resp.get_data(as_text=True)


def test_admin_can_view_user_profiles_via_url_id(client, auth):
    """Verify administrators can inspect participant profiles for audit purposes."""
    auth.create_user(email="admin@vadl.local", password="Password123!@", role=Role.ADMIN)
    target = auth.create_user(
        email="target@vadl.local", password="Password123!@", display_name="Target User"
    )

    auth.login(email="admin@vadl.local", password="Password123!@")
    resp = client.get(f"/users/{target.id}")
    assert resp.status_code == 200
    assert "Target User" in resp.get_data(as_text=True)


def test_role_changes_cannot_be_performed_by_unauthorized_users(client, auth):
    """Verify ordinary users cannot invoke role management endpoints."""
    attacker = auth.create_user(
        email="attacker@vadl.local", password="Password123!@", role=Role.USER
    )
    victim = auth.create_user(email="victim@vadl.local", password="Password123!@", role=Role.USER)

    auth.login(email="attacker@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/profile")

    # Attempt to post to role update endpoint
    resp = client.post(
        f"/admin/users/{victim.id}/role",
        data={"role": Role.ADMIN, "csrf_token": token},
    )
    assert resp.status_code == 403

    # Attempt to elevate self via profile update
    resp_profile = client.post(
        "/profile",
        data={
            "display_name": "Attacker Updated",
            "role": Role.ADMIN,
            "status": "admin",
            "csrf_token": token,
        },
        follow_redirects=True,
    )
    assert resp_profile.status_code == 200
    # Verify role was unchanged in database
    refreshed_attacker = db.session.get(User, attacker.id)
    assert refreshed_attacker.role == Role.USER


def test_admin_can_update_user_role_and_status(client, auth):
    """Verify administrator can promote users and toggle account statuses."""
    auth.create_user(email="admin@vadl.local", password="Password123!@", role=Role.ADMIN)
    target = auth.create_user(email="target@vadl.local", password="Password123!@", role=Role.USER)

    auth.login(email="admin@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/admin/users")

    # Promote to Security Analyst
    resp_role = client.post(
        f"/admin/users/{target.id}/role",
        data={"role": Role.SECURITY_ANALYST, "csrf_token": token},
        follow_redirects=True,
    )
    assert resp_role.status_code == 200
    html_role = resp_role.get_data(as_text=True)
    assert "updated to" in html_role and "security_analyst" in html_role

    refreshed = db.session.get(User, target.id)
    assert refreshed.role == Role.SECURITY_ANALYST

    # Disable user account
    token = auth.get_csrf_token("/admin/users")
    resp_status = client.post(
        f"/admin/users/{target.id}/status",
        data={"status": UserStatus.DISABLED, "csrf_token": token},
        follow_redirects=True,
    )
    assert resp_status.status_code == 200
    html_status = resp_status.get_data(as_text=True)
    assert "updated to" in html_status and "disabled" in html_status

    refreshed = db.session.get(User, target.id)
    assert refreshed.status == UserStatus.DISABLED


def test_admin_cannot_demote_or_disable_themselves(client, auth):
    """Verify built-in safeguard preventing administrators from locking themselves out."""
    admin = auth.create_user(email="admin@vadl.local", password="Password123!@", role=Role.ADMIN)
    auth.login(email="admin@vadl.local", password="Password123!@")
    token = auth.get_csrf_token("/admin/users")

    # Attempt to demote self
    resp_demote = client.post(
        f"/admin/users/{admin.id}/role",
        data={"role": Role.USER, "csrf_token": token},
        follow_redirects=True,
    )
    assert resp_demote.status_code == 200
    assert "cannot remove the administrator role from your own account" in resp_demote.get_data(
        as_text=True
    )

    refreshed = db.session.get(User, admin.id)
    assert refreshed.role == Role.ADMIN

    # Attempt to disable self
    token = auth.get_csrf_token("/admin/users")
    resp_disable = client.post(
        f"/admin/users/{admin.id}/status",
        data={"status": UserStatus.DISABLED, "csrf_token": token},
        follow_redirects=True,
    )
    assert resp_disable.status_code == 200
    assert "cannot disable your own administrator account" in resp_disable.get_data(as_text=True)

    refreshed = db.session.get(User, admin.id)
    assert refreshed.status == UserStatus.ACTIVE


def test_cli_create_admin_and_promote(runner):
    """Verify administrative CLI commands create and promote users correctly."""
    # Test create-admin
    res = runner.invoke(
        args=[
            "user",
            "create-admin",
            "--email",
            "cliadmin@vadl.local",
            "--name",
            "CLI Admin",
            "--password",
            "AdminSecret123!@",
        ]
    )
    assert res.exit_code == 0
    assert "Successfully created administrator account" in res.output

    admin = User.query.filter_by(email="cliadmin@vadl.local").first()
    assert admin is not None
    assert admin.role == Role.ADMIN
    assert admin.check_password("AdminSecret123!@") is True

    # Test promote
    res_promote = runner.invoke(
        args=[
            "user",
            "promote",
            "--email",
            "cliadmin@vadl.local",
            "--role",
            Role.SECURITY_ANALYST,
        ]
    )
    assert res_promote.exit_code == 0
    assert "updated role" in res_promote.output

    refreshed = User.query.filter_by(email="cliadmin@vadl.local").first()
    assert refreshed.role == Role.SECURITY_ANALYST


def test_cli_lab_seed_and_targets(runner):
    """Verify CLI commands for seeding and listing laboratory targets."""
    # Seed lab
    res_seed = runner.invoke(args=["lab", "seed"])
    assert res_seed.exit_code == 0
    assert (
        "Created authorized lab target" in res_seed.output
        or "Lab seeding completed" in res_seed.output
    )

    # List targets
    res_list = runner.invoke(args=["lab", "targets"])
    assert res_list.exit_code == 0
    assert "VADL Local Laboratory Target" in res_list.output
    assert "http://127.0.0.1:5000" in res_list.output
