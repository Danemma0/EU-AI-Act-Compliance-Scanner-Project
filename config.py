# config.py
# ─────────────────────────────────────────────────────────────────────────────
# Central configuration file for the EU AI Act Compliance Scanner.
# All environment-sensitive values (API keys, passwords, feature flags) are
# loaded from a .env file so they never have to be hard-coded in source code.
# Any module that needs a setting imports the Config class from here.
# ─────────────────────────────────────────────────────────────────────────────

import os
from dotenv import load_dotenv

# Read the .env file into the process environment so os.environ.get() works
# below.  The .env file must sit in the same directory as this file.
load_dotenv()

# Build an absolute filesystem path to the project root.
# os.path.dirname(__file__) gives the folder containing config.py, and
# os.path.abspath makes it absolute so SQLite can locate the database
# regardless of the working directory the app is launched from.
basedir = os.path.abspath(os.path.dirname(__file__))

# ─── Target registry ──────────────────────────────────────────────────────────
# A catalogue of the scan targets the scanner knows about by name.
# This is used for documentation and feature flags; the actual adapter
# selection logic lives in routes.py and engine.py.
# Adding a new entry here is a good first step when onboarding a new target.
TARGET_REGISTRY = {
    "dvla": {
        # The Damn Vulnerable LLM Agent — an intentionally insecure banking
        # chatbot running inside Docker on localhost:8501.
        "label":           "Damn Vulnerable LLM Agent",
        "adapter":         "DVLASeleniumTarget",
        "url":             "http://localhost:8501",
        "requires_docker": True
    },
    "deepseek_demo": {
        # The DeepSeek API chatbot used as the primary API-based scan target.
        # When DEMO_MODE is ON the adapter returns fabricated responses without
        # consuming API credits.
        "label":           "DeepSeek Demo (API)",
        "adapter":         "DeepSeekDemoTarget",
        "url":             None,
        "requires_docker": False
    }
}


class Config:
    """
    A single class that bundles every application-wide setting.
    Flask, SQLAlchemy, and the scanner modules all read from this class.
    Values are drawn from environment variables so they can differ between
    development and production without touching source code.
    """

    # ── Database ──────────────────────────────────────────────────────────────
    # SQLite database stored inside the myproject/instance/ folder.
    # Keeping it in instance/ is the Flask convention — it separates generated
    # runtime data (the database) from committed source code, and makes it
    # easy to find and back up.
    #
    # The URI format is:  sqlite:///<absolute-path>
    # Three slashes = relative path; four slashes = absolute path.
    # We always build an absolute path using basedir so the database is found
    # correctly no matter which directory the app is launched from.
    #
    # basedir points to the project root (where config.py lives), so the full
    # path resolves to:  <project-root>/myproject/instance/myproject.db
    #
    # SQLAlchemy creates the file automatically on first run if it does not
    # already exist — no manual setup needed.
    SQLALCHEMY_DATABASE_URI = 'sqlite:///' + os.path.join(basedir, 'myproject', 'instance', 'myproject.db')

    # The modification-tracking feature fires a signal every time a model object
    # changes, which adds memory overhead we do not need.  Disabling it keeps
    # things lean.
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # ── External API keys ─────────────────────────────────────────────────────
    # These are loaded exclusively from environment variables; they must never
    # appear as string literals in committed code.
    OPENAI_API_KEY   = os.environ.get('OPENAI_API_KEY')    # used by the LLM Judge + dynamic payload generator
    DEEPSEEK_API_KEY = os.environ.get('DEEPSEEK_API_KEY')  # used by the DeepSeek demo target

    # ── Demo mode flag ────────────────────────────────────────────────────────
    # When True:  scans against DeepSeek return randomly fabricated (placeholder)
    #             results — no real API calls are made to DeepSeek or OpenAI.
    #             Safe for live demonstrations without consuming credits.
    # When False: the scanner calls the real DeepSeek API and the real OpenAI
    #             LLM Judge, producing genuine vulnerability findings.
    # Toggled at runtime via the dashboard toggle; this is the startup default.
    DEMO_MODE = os.environ.get('DEMO_MODE', 'True').strip().lower() == 'true'

    # ── Basic-auth password ───────────────────────────────────────────────────
    # The dashboard is protected by HTTP Basic Authentication.
    # The username is always 'examiner'; the password comes from the environment.
    SCANNER_PASSWORD = os.environ.get('SCANNER_PASSWORD', 'default_password')
