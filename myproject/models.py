# models.py
# ─────────────────────────────────────────────────────────────────────────────
# SQLAlchemy ORM models — the database schema for the EU AI Act Compliance
# Scanner.  Every class here maps to one SQLite table.  SQLAlchemy translates
# Python attribute access into SQL so the rest of the application never has to
# write raw SQL queries.
#
# Table hierarchy (parent → child, via foreign keys):
#   Scan ──┬── Vulnerability ── ProbeResult
#          └── ProbeResult   (direct child for error/pending rows with no vuln)
#
# Cascade rule: deleting a Scan automatically deletes all its Vulnerability and
# ProbeResult rows.  This keeps the database tidy when a scan is removed from
# the dashboard.
# ─────────────────────────────────────────────────────────────────────────────

from . import db
from datetime import datetime
import uuid


# ─── Scan ─────────────────────────────────────────────────────────────────────
class Scan(db.Model):
    """
    Top-level record for one complete scan session.

    Every time the user presses "Run Scan" a new Scan row is inserted.
    The overall_risk_score (0–100) is calculated at the end of the scan and
    summarises how many high/medium/low vulnerabilities were detected across
    all categories.  A score of 0 means either the target defended perfectly
    or all probes errored out without a useful response.
    """
    __tablename__ = 'scans'

    id                 = db.Column(db.Integer, primary_key=True)
    target_url         = db.Column(db.String(255), nullable=False)  # e.g. "deepseek_demo (API)"
    scan_date          = db.Column(db.DateTime, default=datetime.utcnow)
    overall_risk_score = db.Column(db.Integer)  # 0 = fully safe, 100 = highly vulnerable

    # One Scan → many Vulnerability summaries.
    # cascade='all, delete-orphan' means: if a Scan row is deleted, SQLAlchemy
    # will automatically delete all its child Vulnerability rows too.
    vulnerabilities = db.relationship(
        'Vulnerability', backref='scan', lazy=True,
        cascade='all, delete-orphan'
    )

    # One Scan → many granular ProbeResult rows (also cascade-deleted).
    probe_results = db.relationship(
        'ProbeResult', backref='scan', lazy=True,
        cascade='all, delete-orphan'
    )


# ─── Vulnerability ────────────────────────────────────────────────────────────
class Vulnerability(db.Model):
    """
    A summary record for one vulnerability category within a scan.

    There is at most one Vulnerability row per (scan_id, vuln_category) pair
    per individual payload test.  If the chatbot passes (defends successfully)
    the row has test_passed=True and severity='Safe'.  If it fails, severity is
    'High', 'Medium', or 'Low' depending on the LLM Judge's confidence.

    Vulnerability rows are NOT created for probes that returned a
    [SCANNER_ERROR] response — those are recorded only in ProbeResult with
    result_label='error'.  This keeps the audit card counts accurate.
    """
    __tablename__ = 'vulnerabilities'

    id          = db.Column(db.Integer, primary_key=True)
    scan_id     = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)
    vuln_type   = db.Column(db.String(100), nullable=False)  # e.g. 'prompt_injection'
    test_passed = db.Column(db.Boolean, default=False, nullable=False)
    severity    = db.Column(db.String(50))   # 'High' | 'Medium' | 'Low' | 'Safe'
    description = db.Column(db.Text)         # Evidence sentence produced by the LLM Judge

    # One Vulnerability → many ProbeResult rows (the individual turns / payloads
    # that contributed to this finding).
    probe_results = db.relationship(
        'ProbeResult', backref='vulnerability', lazy=True,
        cascade='all, delete-orphan'
    )


# ─── ProbeResult ──────────────────────────────────────────────────────────────
class ProbeResult(db.Model):
    """
    The most granular unit of scan data: one payload fired, one response
    received, one LLM Judge verdict.

    Every probe — static hardcoded payload, AI-generated dynamic payload,
    each turn of a multi-turn sequence — gets its own ProbeResult row.
    This is what populates the "All Probe Results" table on the dashboard and
    the detailed Probe Detail modal.

    Key fields explained:
      payload_text   – the exact text sent to the target chatbot
      response_text  – the exact text the chatbot replied with (or a
                       [SCANNER_ERROR] sentinel if the interaction failed)
      result_label   – 'high' | 'medium' | 'low' | 'pass' | 'error' | 'pending'
      confidence     – LLM Judge confidence as a float 0.0–1.0
      payload_source – 'static' (hardcoded), 'dynamic' (GPT-4o-mini generated),
                       or 'custom' (user-entered via the dashboard)
      turn_number    – 1 for single-turn probes; 1–4 for multi-turn sequences
      session_id     – UUID shared across all turns of the same multi-turn
                       sequence so they can be grouped in the UI
      eu_article     – the EU AI Act article name the verdict relates to
    """
    __tablename__ = 'probe_results'

    id               = db.Column(db.Integer, primary_key=True)
    scan_id          = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False)

    # vulnerability_id is nullable because error/pending probes do not have a
    # parent Vulnerability summary row.
    vulnerability_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.id'), nullable=True)

    target_name      = db.Column(db.String(100), nullable=False)
    vuln_category    = db.Column(db.String(50),  nullable=False)
    payload_text     = db.Column(db.Text, nullable=False)
    response_text    = db.Column(db.Text, nullable=False)
    result_label     = db.Column(db.String(20),  nullable=False)
    confidence       = db.Column(db.Float, nullable=False, default=0.0)
    payload_source   = db.Column(db.String(20),  nullable=False, default='static')
    turn_number      = db.Column(db.Integer, default=1)

    # Each ProbeResult gets its own UUID by default; multi-turn rows belonging
    # to the same attack sequence share the same session_id (set explicitly by
    # the engine when it starts a multi-turn block).
    session_id       = db.Column(db.String(36), default=lambda: str(uuid.uuid4()))

    eu_article       = db.Column(db.String(50),  nullable=True)
    generated_at     = db.Column(db.DateTime, default=datetime.utcnow)


# ─── ComplianceRule ───────────────────────────────────────────────────────────
class ComplianceRule(db.Model):
    """
    Stores EU AI Act regulatory text for reference.
    Currently seeded manually; could be populated from a JSON file on first run
    to give the scanner a queryable regulatory database.
    Not actively used by the scanning pipeline — compliance lookups are handled
    by the in-memory EU_AI_ACT_MAPPING dict in compliance_rules.py for speed.
    """
    __tablename__ = 'compliance_rules'

    id             = db.Column(db.Integer, primary_key=True)
    article_number = db.Column(db.String(50), nullable=False)  # e.g. 'Article 15'
    requirement    = db.Column(db.Text, nullable=False)
