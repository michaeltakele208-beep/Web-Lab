"""Hardened and defended laboratory endpoints (Phase 3).

Demonstrates remediation patterns for the documented lab scenarios.
"""

from flask import (
    Blueprint,
    abort,
    make_response,
    render_template,
    request,
)
from sqlalchemy import text

from app.extensions import db
from app.models.lab import LabComment, LabRecord
from app.security import get_current_user

lab_secure_bp = Blueprint("lab_secure", __name__, url_prefix="/lab/secure")


@lab_secure_bp.route("", methods=["GET"])
def index():
    """Secure edition overview and remediation catalog."""
    return render_template("lab/secure/index.html")


@lab_secure_bp.route("/sqli", methods=["GET", "POST"])
def sqli_demo():
    """Secure SQL lookup demonstration using parameterized queries.

    DEFENSE (VADL-SQLI-001): Parameter binding ensures untrusted input cannot alter query semantics.
    """
    category = request.args.get("category") or request.form.get("category") or "hardware"
    products = []
    executed_query = (
        "SELECT id, name, category, description, price, is_secret_test_flag "
        "FROM lab_products WHERE category = :cat"
    )

    if category:
        # Secure implementation: input bound via parameterized query placeholder (:cat)
        cursor = db.session.execute(
            text(executed_query),
            {"cat": category},
        )
        products = cursor.mappings().all()

    return render_template(
        "lab/secure/sqli.html",
        products=products,
        executed_query=executed_query,
        category=category,
    )


@lab_secure_bp.route("/xss", methods=["GET", "POST"])
def xss_demo():
    """Secure Cross-Site Scripting (XSS) demonstration using context-aware auto-escaping.

    DEFENSE (VADL-XSS-001): Dynamic input is auto-escaped by Jinja, rendering raw markup as literal text.
    """
    if request.method == "POST":
        author = (request.form.get("author") or "Anonymous").strip()
        content = request.form.get("content") or ""

        # Store comment marked for secure demonstration
        comment = LabComment(
            author_name=author,
            content=content,
            is_vulnerable_demo=False,
        )
        db.session.add(comment)
        db.session.commit()

    comments = (
        LabComment.query.filter_by(is_vulnerable_demo=False)
        .order_by(LabComment.id.desc())
        .limit(10)
        .all()
    )

    # Secure implementation: comments passed directly to Jinja without Markup bypass
    return render_template("lab/secure/xss.html", comments=comments)


@lab_secure_bp.route("/records/<int:record_id>", methods=["GET"])
def record_demo(record_id: int):
    """Secure Broken Access Control (IDOR) demonstration with server-side ownership verification.

    DEFENSE (VADL-AC-001): The server strictly validates that the requester owns the target record.
    """
    record = db.session.get(LabRecord, record_id)
    if not record:
        abort(404, description="Lab record not found.")

    # Determine requesting identity: current session user or synthetic test header
    current_user = get_current_user()
    requester_identity = (
        current_user.email if current_user else request.headers.get("X-Lab-User", "")
    )

    # Enforce object-level ownership check on the server
    if record.owner_username != requester_identity:
        abort(
            403,
            description="Access Denied: You do not possess authorization to view this private laboratory record.",
        )

    return render_template("lab/secure/record.html", record=record)


@lab_secure_bp.route("/headers", methods=["GET"])
def headers_demo():
    """Secure security headers demonstration.

    DEFENSE (VADL-HEADERS-001): Hardened HTTP response headers enforce CSP, nosniff, frame controls, and referrer policy.
    """
    response = make_response(render_template("lab/secure/headers.html"))

    # Explicitly enforce defensive HTTP headers
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; "
        "frame-ancestors 'none'; object-src 'none';"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
