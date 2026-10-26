"""Administrative CLI management commands for VADL."""

import click
from flask import Flask

from app.extensions import db
from app.models.user import Role, User, UserStatus
from app.security import normalize_email, validate_password


def register_cli_commands(app: Flask) -> None:
    """Register administrative CLI command groups."""

    @app.cli.group("user")
    def user_group():
        """User identity and authorization management commands."""
        pass

    @user_group.command("create-admin")
    @click.option("--email", prompt=True, help="Administrator email address")
    @click.option("--name", prompt=True, help="Administrator display name")
    @click.option(
        "--password",
        prompt=True,
        hide_input=True,
        confirmation_prompt=True,
        help="Administrator password",
    )
    def create_admin(email: str, name: str, password: str):
        """Create an active administrator account securely via server console."""
        normalized = normalize_email(email)
        valid_pwd, pwd_error = validate_password(password)
        if not valid_pwd:
            click.echo(f"Password policy violation: {pwd_error}", err=True)
            return

        existing = User.query.filter_by(email=normalized).first()
        if existing:
            click.echo(f"Error: User with email '{normalized}' already exists.", err=True)
            return

        admin_user = User(
            email=normalized,
            display_name=name.strip(),
            role=Role.ADMIN,
            status=UserStatus.ACTIVE,
        )
        admin_user.set_password(password)
        db.session.add(admin_user)
        db.session.commit()
        click.echo(
            f"Successfully created administrator account '{normalized}' (ID: {admin_user.id})."
        )

    @user_group.command("promote")
    @click.option("--email", prompt=True, help="User email address")
    @click.option(
        "--role",
        type=click.Choice(list(Role.ALL_ROLES)),
        default=Role.ADMIN,
        prompt=True,
        help="New authorization role",
    )
    def promote_user(email: str, role: str):
        """Promote or modify user role via server console."""
        normalized = normalize_email(email)
        target = User.query.filter_by(email=normalized).first()
        if not target:
            click.echo(f"Error: User '{normalized}' not found.", err=True)
            return

        target.role = role
        db.session.commit()
        click.echo(f"Successfully updated role for user '{normalized}' to '{role}'.")

    @user_group.command("list")
    def list_users():
        """List registered users with authorization roles."""
        users = User.query.order_by(User.id.asc()).all()
        if not users:
            click.echo("No users registered.")
            return

        click.echo(f"{'ID':<6} {'Email':<30} {'Role':<18} {'Status':<10} {'Name'}")
        click.echo("-" * 75)
        for u in users:
            click.echo(f"{u.id:<6} {u.email:<30} {u.role:<18} {u.status:<10} {u.display_name}")

    @app.cli.group("lab")
    def lab_group():
        """Laboratory target and scenario management commands."""
        pass

    @lab_group.command("seed")
    def seed_lab():
        """Seed default authorized local lab targets and scenario synthetic data."""
        from app.models.lab import LabProduct, LabRecord, LabTarget

        # 1. Target
        target = LabTarget.query.filter_by(base_url="http://127.0.0.1:5000").first()
        if not target:
            target = LabTarget(
                name="VADL Local Laboratory Target",
                target_type="internal_lab_edition",
                environment_id="development",
                base_url="http://127.0.0.1:5000",
                is_authorized=True,
            )
            db.session.add(target)
            click.echo(
                "Created authorized lab target 'VADL Local Laboratory Target' (http://127.0.0.1:5000)."
            )
        else:
            click.echo("Authorized lab target already exists.")

        # 2. Products
        if LabProduct.query.count() == 0:
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
            click.echo("Seeded 4 synthetic catalog products for SQL injection testing.")

        # 3. Records
        if LabRecord.query.count() == 0:
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
            click.echo("Seeded 2 synthetic user records for IDOR testing.")

        # 4. Demo Users
        from werkzeug.security import generate_password_hash

        from app.models.user import Role, User

        analyst = User.query.filter_by(email="analyst@vadl.local").first()
        if not analyst:
            analyst = User(
                email="analyst@vadl.local",
                password_hash=generate_password_hash("AnalystPassword123!@"),
                display_name="Security Analyst",
                role=Role.SECURITY_ANALYST,
            )
            db.session.add(analyst)
            click.echo("Seeded default analyst user (analyst@vadl.local).")

        admin = User.query.filter_by(email="admin@vadl.local").first()
        if not admin:
            admin = User(
                email="admin@vadl.local",
                password_hash=generate_password_hash("AdminSecurePass123!@"),
                display_name="System Administrator",
                role=Role.ADMIN,
            )
            db.session.add(admin)
            click.echo("Seeded default admin user (admin@vadl.local).")

        db.session.commit()
        click.echo("Lab seeding completed successfully.")

    @lab_group.command("targets")
    def list_targets():
        """List registered laboratory targets and authorization status."""
        from app.models.lab import LabTarget

        targets = LabTarget.query.order_by(LabTarget.id.asc()).all()
        if not targets:
            click.echo(
                "No lab targets registered. Run 'flask lab seed' to create the default target."
            )
            return

        click.echo(f"{'ID':<6} {'Name':<35} {'Base URL':<30} {'Authorized'}")
        click.echo("-" * 82)
        for t in targets:
            click.echo(f"{t.id:<6} {t.name:<35} {t.base_url:<30} {str(t.is_authorized)}")
