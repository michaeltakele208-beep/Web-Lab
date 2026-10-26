"""Vulnerability Assessment and Defense Lab (VADL) - Application Entry Point."""

import os

from app import create_app

# Load configuration profile from environment or default to development
config_name = os.environ.get("FLASK_CONFIG", "development")
app = create_app(config_name)

if __name__ == "__main__":
    host = app.config.get("HOST", "127.0.0.1")
    port = app.config.get("PORT", 5000)
    debug = app.config.get("DEBUG", False)

    # In development mode, run Flask's built-in WSGI server bound strictly to loopback
    app.run(host=host, port=port, debug=debug)
