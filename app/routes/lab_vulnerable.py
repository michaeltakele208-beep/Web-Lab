"""Deliberately vulnerable laboratory endpoints (Phase 3).

ISOLATION WARNING:
These endpoints are designed exclusively for controlled security training.
They are disabled in production and strictly bound to synthetic toy datasets.
"""

from flask import (
    Blueprint,
    abort,
    current_app,
    make_response,
    render_template,
    request,
)
from markupsafe import Markup
from sqlalchemy import text

from app.extensions import db
from app.models.lab import LabComment, LabRecord

lab_vulnerable_bp = Blueprint("lab_vulnerable", __name__, url_prefix="/lab/vulnerable")


@lab_vulnerable_bp.before_request
def check_lab_enabled():
    """Ensure vulnerable edition is completely disabled outside explicitly approved lab configurations."""
    if not current_app.config.get("ENABLE_VULNERABLE_LAB", False):
        abort(
            404,
            description="Vulnerable training edition is disabled in this environment profile.",
        )


@lab_vulnerable_bp.route("", methods=["GET"])
def index():
    """Vulnerable edition overview and scenario index."""
    return render_template("lab/vulnerable/index.html")


@lab_vulnerable_bp.route("/sqli", methods=["GET", "POST"])
def sqli_demo():
    """Vulnerable SQL injection demonstration using toy catalog data.

    VULNERABILITY: Raw string interpolation concatenates untrusted input directly into SQL statement.
    """
    category = request.args.get("category") or request.form.get("category") or "hardware"
    products = []
    executed_query = ""

    if category:
        # INTENTIONAL FLAW (VADL-SQLI-001): Direct string concatenation permits query alteration
        raw_sql = (
            "SELECT id, name, category, description, price, is_secret_test_flag "
            f"FROM lab_products WHERE category = '{category}'"  # nosec B608
        )
        executed_query = raw_sql
        try:
            cursor = db.session.execute(text(raw_sql))
            products = cursor.mappings().all()
        except Exception as exc:
            # In vulnerable mode, verbose database errors are exposed to demonstrate exploitation feedback
            return (
                render_template(
                    "lab/vulnerable/sqli.html",
                    error=str(exc),
                    executed_query=executed_query,
                    category=category,
                ),
                500,
            )

    return render_template(
        "lab/vulnerable/sqli.html",
        products=products,
        executed_query=executed_query,
        category=category,
    )


@lab_vulnerable_bp.route("/xss", methods=["GET", "POST"])
def xss_demo():
    """Vulnerable Cross-Site Scripting (XSS) demonstration using toy comments.

    VULNERABILITY: User input is explicitly marked as safe HTML, bypassing output encoding.
    """
    if request.method == "POST":
        author = (request.form.get("author") or "Anonymous").strip()
        content = request.form.get("content") or ""

        # Store comment marked for vulnerable demonstration
        comment = LabComment(
            author_name=author,
            content=content,
            is_vulnerable_demo=True,
        )
        db.session.add(comment)
        db.session.commit()

    comments = (
        LabComment.query.filter_by(is_vulnerable_demo=True)
        .order_by(LabComment.id.desc())
        .limit(10)
        .all()
    )

    # INTENTIONAL FLAW (VADL-XSS-001): Mark unencoded user content as safe HTML markup
    prepared_comments = [
        {
            "id": c.id,
            "author": c.author_name,
            "content": Markup(c.content),  # nosec B704
            "created_at": c.created_at,
        }
        for c in comments
    ]

    return render_template("lab/vulnerable/xss.html", comments=prepared_comments)


@lab_vulnerable_bp.route("/records/<int:record_id>", methods=["GET"])
def record_demo(record_id: int):
    """Vulnerable Insecure Direct Object Reference (IDOR) demonstration.

    VULNERABILITY: Missing server-side ownership verification exposes arbitrary synthetic records.
    """
    # INTENTIONAL FLAW (VADL-AC-001): Retrieves and renders record without verifying request ownership
    record = db.session.get(LabRecord, record_id)
    if not record:
        abort(404, description="Lab record not found.")

    return render_template("lab/vulnerable/record.html", record=record)


@lab_vulnerable_bp.route("/headers", methods=["GET"])
def headers_demo():
    """Vulnerable security headers demonstration.

    VULNERABILITY: Insecure response deliberately omitting modern defense headers.
    """
    response = make_response(render_template("lab/vulnerable/headers.html"))

    # INTENTIONAL FLAW (VADL-HEADERS-001): Explicitly strip security headers
    response.headers.pop("Content-Security-Policy", None)
    response.headers.pop("X-Content-Type-Options", None)
    response.headers.pop("X-Frame-Options", None)
    response.headers.pop("Referrer-Policy", None)
    return response
