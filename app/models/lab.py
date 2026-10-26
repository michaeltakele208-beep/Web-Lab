"""Domain models for Phase 3: Vulnerability Lab toy datasets and target authorization registry."""

from datetime import UTC, datetime

from app.extensions import db


class LabProduct(db.Model):
    """Toy catalog items used strictly for SQL injection demonstration."""

    __tablename__ = "lab_products"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=False, index=True)
    description = db.Column(db.Text, nullable=False)
    price = db.Column(db.Float, nullable=False, default=0.0)
    # Synthetic test flag used exclusively to verify query alteration in tests
    is_secret_test_flag = db.Column(db.Boolean, nullable=False, default=False)

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "description": self.description,
            "price": self.price,
            "is_secret_test_flag": self.is_secret_test_flag,
        }


class LabComment(db.Model):
    """Toy feedback messages used strictly for XSS demonstration."""

    __tablename__ = "lab_comments"

    id = db.Column(db.Integer, primary_key=True)
    author_name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_vulnerable_demo = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "author_name": self.author_name,
            "content": self.content,
            "is_vulnerable_demo": self.is_vulnerable_demo,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class LabRecord(db.Model):
    """Synthetic confidential records used strictly for Broken Access Control / IDOR demonstration."""

    __tablename__ = "lab_records"

    id = db.Column(db.Integer, primary_key=True)
    owner_username = db.Column(db.String(100), nullable=False, index=True)
    title = db.Column(db.String(150), nullable=False)
    confidential_note = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "owner_username": self.owner_username,
            "title": self.title,
            "confidential_note": self.confidential_note,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class LabTarget(db.Model):
    """Database-backed registry of explicitly authorized lab targets."""

    __tablename__ = "lab_targets"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    target_type = db.Column(db.String(50), nullable=False, default="internal_lab_edition")
    environment_id = db.Column(db.String(50), nullable=False, default="development")
    base_url = db.Column(db.String(255), nullable=False, unique=True)
    is_authorized = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(UTC))
    registered_by_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True)

    # Relationship to user who registered the target
    registered_by = db.relationship("User", backref=db.backref("registered_targets", lazy=True))

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "target_type": self.target_type,
            "environment_id": self.environment_id,
            "base_url": self.base_url,
            "is_authorized": self.is_authorized,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "registered_by_id": self.registered_by_id,
        }
