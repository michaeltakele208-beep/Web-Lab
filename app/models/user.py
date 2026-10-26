"""User domain model and role definitions for VADL identity management."""

from datetime import UTC, datetime

from werkzeug.security import check_password_hash, generate_password_hash

from app.extensions import db


class Role:
    """Supported user authorization roles within VADL."""

    USER = "user"
    SECURITY_ANALYST = "security_analyst"
    ADMIN = "admin"

    ALL_ROLES = (USER, SECURITY_ANALYST, ADMIN)


class UserStatus:
    """Account status constants."""

    ACTIVE = "active"
    DISABLED = "disabled"

    ALL_STATUSES = (ACTIVE, DISABLED)


class User(db.Model):
    """User account entity representing authenticated lab participants and administrators."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False, index=True)
    display_name = db.Column(db.String(100), nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(30), nullable=False, default=Role.USER)
    status = db.Column(db.String(20), nullable=False, default=UserStatus.ACTIVE)
    created_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    updated_at = db.Column(
        db.DateTime,
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    def set_password(self, password: str) -> None:
        """Hash and store the password using Werkzeug's maintained scrypt algorithm."""
        if not password or not isinstance(password, str):
            raise ValueError("Password must be a non-empty string.")
        # scrypt provides state-of-the-art resistance against hardware-assisted brute forcing
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password: str) -> bool:
        """Verify candidate plaintext password against stored cryptographic hash."""
        if not password or not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password)

    @property
    def is_active_account(self) -> bool:
        """Check whether the account is currently active and permitted to authenticate."""
        return self.status == UserStatus.ACTIVE

    @property
    def is_admin(self) -> bool:
        """Convenience property checking for administrator role."""
        return self.role == Role.ADMIN

    @property
    def is_analyst(self) -> bool:
        """Convenience property checking for security analyst or administrator role."""
        return self.role in (Role.SECURITY_ANALYST, Role.ADMIN)

    def has_role(self, *roles: str) -> bool:
        """Verify whether user holds one of the specified roles."""
        return self.role in roles

    def to_dict(self) -> dict:
        """Safe dictionary representation strictly excluding sensitive password hashes."""
        return {
            "id": self.id,
            "email": self.email,
            "display_name": self.display_name,
            "role": self.role,
            "status": self.status,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }

    def __repr__(self) -> str:
        return f"<User id={self.id} email='{self.email}' role='{self.role}' status='{self.status}'>"
