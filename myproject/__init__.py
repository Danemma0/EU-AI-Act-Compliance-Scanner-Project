# __init__.py
# ─────────────────────────────────────────────────────────────────────────────
# Application factory for the EU AI Act Compliance Scanner.
#
# Flask recommends the "application factory" pattern: instead of creating the
# app object at module level (which makes testing and configuration hard), we
# wrap it inside a create_app() function that can be called with different
# settings at will.
#
# Why a factory?
#   - Each call to create_app() produces a fresh Flask instance, which makes
#     writing automated tests straightforward.
#   - All initialisation (database, routes, models) happens inside the
#     function, so there are no circular-import issues at module load time.
# ─────────────────────────────────────────────────────────────────────────────

from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from config import Config

# Create the SQLAlchemy database object at module level but *without* attaching
# it to an app yet.  Attaching happens inside create_app() via db.init_app().
# This pattern (sometimes called "late binding") lets models import `db` from
# this file without needing to know which Flask app they belong to.
db = SQLAlchemy()


def create_app():
    """
    Build, configure, and return the Flask application instance.

    Called once by run.py (or by the test harness) to bootstrap the scanner.
    The returned app object has the database initialised, all routes registered,
    and all SQLite tables created if they do not already exist.
    """

    # __name__ tells Flask where to find templates and static files relative to
    # this package directory.
    myproject = Flask(__name__)

    # Pull in all settings (database URI, API keys, demo mode flag) from the
    # Config class defined in config.py.
    myproject.config.from_object(Config)

    # Attach the SQLAlchemy instance to this specific Flask app so it knows
    # which database URI to connect to.
    db.init_app(myproject)

    # Models and routes must be imported *inside* the app context because:
    #   1. Models reference `db` which now has a real app backing it.
    #   2. Routes use `current_app`, which only resolves inside an app context.
    # Importing them at the top of this file would cause circular imports
    # (models.py imports db from here, and here imports models).
    with myproject.app_context():
        from . import models   # registers the ORM table definitions with SQLAlchemy
        from . import routes   # registers all URL routes with Flask

        # Create any database tables that do not yet exist.
        # If myproject.db already has the tables this is a no-op, so it is
        # safe to call on every startup.
        db.create_all()

    return myproject
