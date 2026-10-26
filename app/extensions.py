"""Extensions module for VADL.

Initializes SQLAlchemy and Flask-Migrate instances decoupled from the app context.
"""

from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()
migrate = Migrate()
