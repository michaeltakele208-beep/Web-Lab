"""Pytest configuration and reusable fixtures for VADL test suites."""

import re

import pytest

from app import create_app
from app.extensions import db
from app.models.user import Role, User, UserStatus
from app.security import clear_all_rate_limits


@pytest.fixture(autouse=True)
def reset_security_state():
    """Automatically reset authentication rate-limiting counters between tests."""
    clear_all_rate_limits()
    yield
    clear_all_rate_limits()


@pytest.fixture
def app():
    """Create and configure a clean Flask application context for testing."""
    application = create_app("testing")

    with application.app_context():
        db.create_all()
        yield application
        db.session.remove()
        db.drop_all()


@pytest.fixture
def client(app):
    """A test client for dispatching HTTP requests to the application."""
    return app.test_client()


@pytest.fixture
def runner(app):
    """A test CLI runner for executing application CLI commands."""
    return app.test_cli_runner()


class AuthHelper:
    """Helper methods for authentication, session handling, and CSRF tokens."""

    def __init__(self, client):
        self.client = client

    def get_csrf_token(self, url: str = "/login") -> str:
        """Fetch a page to initialize a session and extract the active CSRF token."""
        response = self.client.get(url)
        html = response.get_data(as_text=True)
        match = re.search(r'name=["\']csrf_token["\']\s+value=["\']([^"\']+)["\']', html)
        if match:
            return match.group(1)
        # Fallback to session inspection
        with self.client.session_transaction() as sess:
            return sess.get("_csrf_token", "")

    def create_user(
        self,
        email: str = "testuser@vadl.local",
        password: str = "Password123!@",
        display_name: str = "Test User",
        role: str = Role.USER,
        status: str = UserStatus.ACTIVE,
    ) -> User:
        """Create and persist a user directly in the test database."""
        user = User(
            email=email.strip().lower(),
            display_name=display_name.strip(),
            role=role,
            status=status,
        )
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        return user

    def login(
        self,
        email: str = "testuser@vadl.local",
        password: str = "Password123!@",
        follow_redirects: bool = True,
    ):
        """Submit a login request with a valid CSRF token."""
        token = self.get_csrf_token("/login")
        return self.client.post(
            "/login",
            data={
                "email": email,
                "password": password,
                "csrf_token": token,
            },
            follow_redirects=follow_redirects,
        )


@pytest.fixture
def auth(client):
    """Fixture providing AuthHelper methods."""
    return AuthHelper(client)


@pytest.fixture
def lab_seed(app):
    """Seed synthetic toy datasets for Phase 3 vulnerability scenarios."""
    from app.models.lab import LabProduct, LabRecord

    with app.app_context():
        # Toy products for SQL injection demonstration
        p1 = LabProduct(
            name="Firewall Appliance",
            category="hardware",
            description="Perimeter network defense box",
            price=299.99,
            is_secret_test_flag=False,
        )
        p2 = LabProduct(
            name="Network Gateway",
            category="hardware",
            description="Routing and access control bridge",
            price=499.00,
            is_secret_test_flag=False,
        )
        p3 = LabProduct(
            name="Security Scanner Suite",
            category="software",
            description="Static and dynamic analysis toolkit",
            price=89.50,
            is_secret_test_flag=False,
        )
        p4 = LabProduct(
            name="CONFIDENTIAL_LAB_FLAG{vadl_sqli_success}",
            category="secret_flags",
            description="Restricted test artifact",
            price=0.0,
            is_secret_test_flag=True,
        )
        db.session.add_all([p1, p2, p3, p4])

        # Synthetic records for Broken Access Control (IDOR) demonstration
        r1 = LabRecord(
            owner_username="synthetic-user-1@vadl.local",
            title="Alpha Project Brief",
            confidential_note="Confidential research payload for synthetic participant 1.",
        )
        r2 = LabRecord(
            owner_username="synthetic-user-2@vadl.local",
            title="Bravo Project Brief",
            confidential_note="Confidential research payload for synthetic participant 2.",
        )
        db.session.add_all([r1, r2])

        db.session.commit()
