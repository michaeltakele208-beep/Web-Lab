"""Automated tests for user registration and password policy enforcement."""

from app.models.user import Role, User


def test_successful_registration(client, auth):
    """Verify valid registration persists a new user with normalized email and ordinary role."""
    token = auth.get_csrf_token("/register")
    response = client.post(
        "/register",
        data={
            "display_name": "Alice Cyber",
            "email": " Alice@University.EDU ",
            "password": "SecurePassword123!@",
            "confirm_password": "SecurePassword123!@",
            "csrf_token": token,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert "Registration successful" in response.get_data(as_text=True)

    # Verify database persistence and normalization
    user = User.query.filter_by(email="alice@university.edu").first()
    assert user is not None
    assert user.display_name == "Alice Cyber"
    assert user.role == Role.USER
    assert user.is_active_account is True


def test_duplicate_email_rejection(client, auth):
    """Verify that registering an existing normalized email is rejected."""
    # Pre-register user
    auth.create_user(email="bob@vadl.local", password="Password123!@")

    token = auth.get_csrf_token("/register")
    response = client.post(
        "/register",
        data={
            "display_name": "Bob Clone",
            "email": "BOB@VADL.LOCAL",
            "password": "Password123!@",
            "confirm_password": "Password123!@",
            "csrf_token": token,
        },
    )
    assert response.status_code == 400
    assert "already exists" in response.get_data(as_text=True)


def test_registration_password_mismatch_rejection(client, auth):
    """Verify mismatched password confirmation fails safely."""
    token = auth.get_csrf_token("/register")
    response = client.post(
        "/register",
        data={
            "display_name": "Carol",
            "email": "carol@vadl.local",
            "password": "Password123!@",
            "confirm_password": "DifferentPassword123!@",
            "csrf_token": token,
        },
    )
    assert response.status_code == 400
    assert "Passwords do not match" in response.get_data(as_text=True)


def test_registration_invalid_inputs_rejection(client, auth):
    """Verify server-side validation rejects invalid names, email formats, and weak passwords."""
    token = auth.get_csrf_token("/register")

    # 1. Invalid display name (empty or single char)
    res = client.post(
        "/register",
        data={
            "display_name": "A",
            "email": "valid@vadl.local",
            "password": "Password123!@",
            "confirm_password": "Password123!@",
            "csrf_token": token,
        },
    )
    assert res.status_code == 400
    assert "Display name must be between" in res.get_data(as_text=True)

    # 2. Invalid email format
    token = auth.get_csrf_token("/register")
    res = client.post(
        "/register",
        data={
            "display_name": "Valid Name",
            "email": "not-an-email",
            "password": "Password123!@",
            "confirm_password": "Password123!@",
            "csrf_token": token,
        },
    )
    assert res.status_code == 400
    assert "valid email address format" in res.get_data(as_text=True)

    # 3. Password policy: Too short (< 10 chars)
    token = auth.get_csrf_token("/register")
    res = client.post(
        "/register",
        data={
            "display_name": "Valid Name",
            "email": "valid@vadl.local",
            "password": "Short1!a",
            "confirm_password": "Short1!a",
            "csrf_token": token,
        },
    )
    assert res.status_code == 400
    assert "at least 10 characters" in res.get_data(as_text=True)

    # 4. Password policy: Missing uppercase
    token = auth.get_csrf_token("/register")
    res = client.post(
        "/register",
        data={
            "display_name": "Valid Name",
            "email": "valid@vadl.local",
            "password": "lowercase123!@",
            "confirm_password": "lowercase123!@",
            "csrf_token": token,
        },
    )
    assert res.status_code == 400
    assert "uppercase" in res.get_data(as_text=True)

    # 5. Password policy: Missing number
    token = auth.get_csrf_token("/register")
    res = client.post(
        "/register",
        data={
            "display_name": "Valid Name",
            "email": "valid@vadl.local",
            "password": "NoDigitsPassword!@",
            "confirm_password": "NoDigitsPassword!@",
            "csrf_token": token,
        },
    )
    assert res.status_code == 400
    assert "number" in res.get_data(as_text=True)

    # 6. Password policy: Missing special character
    token = auth.get_csrf_token("/register")
    res = client.post(
        "/register",
        data={
            "display_name": "Valid Name",
            "email": "valid@vadl.local",
            "password": "NoSpecialCharacter123",
            "confirm_password": "NoSpecialCharacter123",
            "csrf_token": token,
        },
    )
    assert res.status_code == 400
    assert "special character" in res.get_data(as_text=True)


def test_password_hashing_verification(client, auth):
    """Verify passwords are cryptographic hashes and plaintext is never stored."""
    raw_pwd = "SuperSecretPassword123!@"
    token = auth.get_csrf_token("/register")
    client.post(
        "/register",
        data={
            "display_name": "Dave",
            "email": "dave@vadl.local",
            "password": raw_pwd,
            "confirm_password": raw_pwd,
            "csrf_token": token,
        },
    )

    user = User.query.filter_by(email="dave@vadl.local").first()
    assert user is not None
    # Password hash must not equal plaintext
    assert user.password_hash != raw_pwd
    # Werkzeug scrypt hashing prefix
    assert user.password_hash.startswith("scrypt:")
    # Check verification method works
    assert user.check_password(raw_pwd) is True
    assert user.check_password("WrongPassword123!@") is False


def test_crafted_request_cannot_assign_privileged_role(client, auth):
    """Verify mass assignment attempts (submitting role=admin) are ignored and user role is assigned."""
    token = auth.get_csrf_token("/register")
    response = client.post(
        "/register",
        data={
            "display_name": "Attacker",
            "email": "attacker@vadl.local",
            "password": "Password123!@",
            "confirm_password": "Password123!@",
            "role": Role.ADMIN,
            "is_admin": "true",
            "status": "superadmin",
            "csrf_token": token,
        },
        follow_redirects=True,
    )
    assert response.status_code == 200

    attacker = User.query.filter_by(email="attacker@vadl.local").first()
    assert attacker is not None
    assert attacker.role == Role.USER
    assert attacker.is_admin is False
