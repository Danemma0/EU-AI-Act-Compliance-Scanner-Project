# routes.py
# ─────────────────────────────────────────────────────────────────────────────
# All Flask URL routes and API endpoints for the EU AI Act Compliance Scanner.
#
# This file sits between the browser (dashboard.html) and the scanning engine.
# It is responsible for:
#   - Rendering the main dashboard page with historical scan data
#   - Accepting and validating scan-launch requests from the browser
#   - Streaming real-time scan log output to the browser via Server-Sent Events
#   - Returning probe-result data as JSON for the dashboard charts and tables
#   - Protecting every endpoint with HTTP Basic Authentication
#
# Threading model:
#   Scans are heavy — they involve Selenium, OpenAI API calls, and LangChain
#   tool invocations.  To keep Flask's request thread responsive, the scan runs
#   in a dedicated daemon thread (_run).  The request thread blocks on
#   thread.join() until the scan completes, then returns the result to the
#   browser.  The real-time log stream is delivered separately via SSE.
# ─────────────────────────────────────────────────────────────────────────────

from flask import request, Response, current_app
from functools import wraps
from config import Config
from collections import Counter
from flask import current_app as app, jsonify, render_template
from .scanner.engine import ScanningEngine
from .models import ProbeResult, Scan, Vulnerability
from .scanner.compliance_rules import EU_AI_ACT_MAPPING
from . import db

import queue
import threading
import sys
import io
import logging

logger = logging.getLogger(__name__)


# ─── Basic Authentication ─────────────────────────────────────────────────────
# The dashboard handles real attack payloads and sensitive scan results, so it
# must not be publicly accessible.  HTTP Basic Auth provides a lightweight gate
# that requires a username/password before any page or API can be reached.

def check_auth(username, password):
    """
    Validate a username/password pair against the configured credentials.
    The username is fixed as 'examiner'; the password comes from the .env file.
    """
    expected_password = getattr(Config, 'SCANNER_PASSWORD', 'examiner123')
    return username == 'examiner' and password == expected_password


def authenticate():
    """
    Return a 401 Unauthorized response that tells the browser to prompt for
    HTTP Basic Auth credentials.  The WWW-Authenticate header is what triggers
    the browser's built-in login dialog.
    """
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials (see README.md)',
        401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )


def requires_auth(f):
    """
    Decorator that wraps any route function with an authentication check.
    Apply it to every route so unauthenticated users can never reach the
    dashboard, API endpoints, or scan triggers.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


# ─── Target name formatter ────────────────────────────────────────────────────
# Internal target identifiers (e.g. 'deepseek_demo', 'http://localhost:8501')
# are technical strings used by the engine.  The formatter converts them into
# clean display names that appear on the dashboard and in audit reports.

def format_target_name(raw: str) -> str:
    """
    Map an internal target key or URL to a human-readable display name.

    Falls back to returning the raw string unchanged if no mapping exists,
    so custom-URL targets display their actual URL on the dashboard.
    """
    mapping = {
        "deepseek_demo":              "DeepSeek Demo",
        "deepseek_demo (api)":        "DeepSeek API",
        "dvla":                       "DVLA",
        "http://localhost:8501":      "DVLA",
        "http://localhost:5001/chat": "Vulnerable Flask Chatbot"
    }
    return mapping.get(raw.lower(), raw)


# Register the formatter as a Jinja2 context processor so every template can
# call {{ format_target(scan.target_url) }} without needing an explicit import.
@app.context_processor
def inject_helpers():
    return {"format_target": format_target_name}

# ─── Real-time scan log (Server-Sent Events) ─────────────────────────────────
# The scan runs in a background thread and produces progress output via
# print() calls.  To stream those messages to the browser in real time, a
# custom _QueueWriter replaces sys.stdout during the scan: every print() call
# is intercepted, written into a thread-safe queue, and then the original
# stdout so the terminal also gets the output.
#
# The browser opens a persistent connection to /api/scan_log which reads from
# the queue via Server-Sent Events (SSE) and forwards each line as a DOM event.
# When the scan finishes the sentinel value "__DONE__" is put into the queue,
# causing the SSE stream to send a "done" event and close.
_log_queue: queue.Queue = queue.Queue()
_scan_running: bool = False           # True while a scan thread is active
_scan_stop_requested: bool = False    # Set to True by the Stop button or page reload

@app.route('/api/stop_scan', methods=['POST'])
@requires_auth
def stop_scan():
    global _scan_stop_requested
    _scan_stop_requested = True
    return jsonify({"status": "success", "message": "Stop signal sent."})

@app.route('/api/clear_stop', methods=['POST'])
@requires_auth
def clear_stop():
    global _scan_stop_requested
    _scan_stop_requested = False
    return jsonify({'status': 'success'})

class _QueueWriter(io.TextIOBase):
    """
    A custom stdout replacement that intercepts every print() call produced by
    the scanner during a scan and forwards the text into the log queue.
    The original stdout is also written to so the server terminal still shows
    the output — the queue is additive, not a replacement.
    """

    def __init__(self, real_stdout, q: queue.Queue):
        self._real  = real_stdout   # the original sys.stdout before substitution
        self._queue = q             # the queue that the SSE endpoint reads from

    def write(self, text: str) -> int:
        # Only queue non-empty lines to avoid cluttering the terminal stream
        # with blank lines produced by Python's print() newline.
        if text.strip():
            self._queue.put(text.rstrip())
        self._real.write(text)
        return len(text)

    def flush(self):
        self._real.flush()


# ── /api/scan_log — Server-Sent Events stream ─────────────────────────────────
# The browser opens this as a persistent HTTP connection.  Flask's Response
# generator yields one SSE message per queue item.  Each message is a line
# prefixed with "data: " followed by two newlines (the SSE wire format).
# The browser-side EventSource object fires an "onmessage" event for each one.
@app.route('/api/scan_log')
@requires_auth
def scan_log():
    """
    Stream scan log lines to the browser as Server-Sent Events.
    The connection stays open until the "__DONE__" sentinel is dequeued,
    at which point a "done" custom event is sent and the generator exits.
    """
    def generate():
        while True:
            try:
                # Block for up to 60 seconds waiting for the next log line.
                # If nothing arrives, yield a keepalive comment so the browser
                # does not interpret the silence as a connection drop.
                line = _log_queue.get(timeout=60)
                if line == "__DONE__":
                    # Signal the browser that the scan has finished
                    yield "event: done\ndata: SCAN_COMPLETE\n\n"
                    break
                # Collapse any internal newlines so the SSE message stays
                # on a single data: line (SSE spec requires one line per message).
                safe = line.replace('\n', ' ').replace('\r', '')
                yield f"data: {safe}\n\n"
            except queue.Empty:
                yield ": keepalive\n\n"   # SSE comments start with ":" and are ignored by the browser

    return Response(
        generate(),
        mimetype='text/event-stream',
        headers={
            'Cache-Control':     'no-cache',
            'X-Accel-Buffering': 'no'   # disables Nginx response buffering so messages arrive immediately
        }
    )


# ── /api/abort_on_reload ──────────────────────────────────────────────────────
# If the user refreshes the browser while a scan is running, the scan thread
# keeps running and writing to the queue — creating a "ghost scan" that cannot
# be seen or stopped from the dashboard.  This endpoint is called automatically
# on every page load (via DOMContentLoaded in dashboard.html) to detect and
# clean up that scenario by setting the stop flag so the thread exits cleanly
# on its next per-payload check.
@app.route('/api/abort_on_reload', methods=['POST'])
@requires_auth
def abort_on_reload():
    """
    Detect and terminate a scan that was left running by a page reload or
    tab close.  Returns was_running=True if an active scan was found so the
    browser can show a "previous scan interrupted" warning toast.
    """
    global _scan_running, _scan_stop_requested
    was_running = _scan_running
    if _scan_running:
        _scan_stop_requested = True
        logger.info("Page reload detected during active scan — stop signal sent.")
    return jsonify({'status': 'success', 'was_running': was_running})

# ─── Main Dashboard ───────────────────────────────────────────────────────────
# The root route renders dashboard.html with every historical scan pre-loaded.
# Python-side data preparation is minimal: we build the chart datasets and
# the latest-scan breakdown here so the template does not need to make
# additional API calls on page load.
@app.route('/')
@requires_auth
def dashboard():
    """
    Render the main dashboard page.

    Passes to the template:
      scans          – all Scan rows, newest first, for the scan selector
      chart_labels   – x-axis labels for the historical risk-trend chart
      chart_scores   – y-axis values for the same chart
      breakdown_data – counts of each result label for the latest-scan doughnut
    """
    # Newest-first order for the scan selector and audit card list
    all_scans = Scan.query.order_by(Scan.scan_date.desc()).all()
    
    chronological_scans = list(reversed(all_scans))

    chart_labels = [
        f"Scan {s.id} ({format_target_name(s.target_url)})"
        for s in chronological_scans
    ]
    
    chart_scores = [s.overall_risk_score for s in chronological_scans]
    
    latest_scan = all_scans[0] if all_scans else None
    breakdown_data = [0, 0, 0, 0, 0, 0, 0]  # Passed, Low, Medium, High, Fail, Pending, Error

    if latest_scan:
        from .models import ProbeResult
        probe_results = ProbeResult.query.filter_by(scan_id=latest_scan.id).all()
        label_index = {'pass': 0,
                        'low': 1,
                        'medium': 2,
                        'high': 3,
                        'fail': 4,
                        'pending': 5,
                        'error': 6}
        
        for probe in probe_results:
            idx = label_index.get(probe.result_label)
            if idx is not None:
                breakdown_data[idx] += 1

    # Pass everything to the HTML template
    return render_template(
        'dashboard.html', 
        scans=all_scans,
        chart_labels=chart_labels,
        chart_scores=chart_scores,
        breakdown_data=breakdown_data
    )

# ─── Scan Detail API ─────────────────────────────────────────────────────────
# Returns all ProbeResult rows for a specific scan as JSON.
# The dashboard JavaScript calls this whenever the user picks a scan from the
# dropdown, then uses the response to render the three charts and the table.

@app.route('/api/scan_detail/<int:scan_id>')
@requires_auth
def scan_detail(scan_id):
    """
    Return all ProbeResult rows for a given scan as JSON.

    The response contains:
      severity_breakdown – result_label counts used by the doughnut chart
      category_breakdown – probe count per vuln_category for the bar chart
      source_breakdown   – static vs dynamic vs custom payload counts
      rows               – the full table data (one dict per ProbeResult)
    """
    # Chronological order so the table rows appear in the order payloads were fired
    results = ProbeResult.query.filter_by(scan_id=scan_id).order_by(ProbeResult.generated_at.asc()).all()

    if not results:
        # Return an empty-but-valid structure rather than a 404 so the frontend
        # can render a "no results" state without additional error handling.
        return jsonify({
            "scan_id": scan_id, "target": "—",
            "severity_breakdown": {}, "category_breakdown": {},
            "source_breakdown":   {}, "rows": []
        })

    # Aggregate counts for the three chart datasets
    severity_counts = dict(Counter(r.result_label    for r in results))
    category_counts = dict(Counter(r.vuln_category   for r in results))
    source_counts   = dict(Counter(r.payload_source  for r in results))

    # Build the row list for the probe table.
    # Long payloads and responses are truncated in the table view to prevent
    # cell overflow; the full versions are kept so the modal can display them.
    rows = []
    for r in results:
        rows.append({
            "id":            r.id,
            "category":      r.vuln_category,
            "payload":       r.payload_text[:100] + "…" if len(r.payload_text) > 100 else r.payload_text,
            "payload_full":  r.payload_text,
            "response":      r.response_text[:120] + "…" if len(r.response_text) > 120 else r.response_text,
            "response_full": r.response_text,
            "result":        r.result_label,
            "confidence":    round(r.confidence * 100),  # stored as 0.0–1.0; displayed as 0–100
            "source":        r.payload_source,
            "article":       r.eu_article or "—",
            "turn":          r.turn_number,
            # session_id is a UUID shared by all turns of the same multi-turn
            # attack sequence (set once in _run_multi_turn_block in engine.py).
            # Single-turn probes each get their own unique session_id by default,
            # so they never accidentally group with each other.
            # The dashboard JavaScript uses this field to visually group
            # multi-turn rows together into a single conversation card.
            "session_id":    r.session_id,
            "timestamp":     r.generated_at.strftime('%H:%M:%S')
        })

    return jsonify({
        "scan_id":            scan_id,
        "target":             results[0].target_name,
        "severity_breakdown": severity_counts,
        "category_breakdown": category_counts,
        "source_breakdown":   source_counts,
        "rows":               rows
    })


# ─── List All Scans  ─────────────────────────────────────────────────────────

@app.route('/api/scans')
@requires_auth
def list_scans():
    """
    Returns a lightweight list of all scans for populating a scan selector
    dropdown on the dashboard — id, target, date, and risk score only.
    """
    scans = Scan.query.order_by(Scan.scan_date.desc()).all()
    return jsonify([{
        "id":         s.id,
        "target":     s.target_url,
        "date":       s.scan_date.strftime('%Y-%m-%d %H:%M'),
        "risk_score": s.overall_risk_score
    } for s in scans])


# ─── Delete Scan ──────────────────────────────────────────────────

@app.route('/api/delete_scan/<int:scan_id>', methods=['DELETE'])
@requires_auth
def delete_scan(scan_id):
    """
    Deletes a scan and ALL its child records (Vulnerability + ProbeResult rows)
    via the cascade='all, delete-orphan' relationship defined in models.py.
    """
    scan = Scan.query.get(scan_id)
    if not scan:
        return jsonify({"status": "error", "message": f"Scan {scan_id} not found."}), 404

    try:
        db.session.delete(scan)
        db.session.commit()
        return jsonify({"status": "success", "message": f"Scan {scan_id} deleted."})
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to delete scan {scan_id}: {e}")
        return jsonify({"status": "error", "message": "Deletion failed. Check server logs."}), 500

# ─── Database Reset ───────────────────────────────────────────────

@app.route('/api/reset_database', methods=['POST'])
@requires_auth
def reset_database():
    """
    Wipes and recreates all tables. Requires two-click confirmation from the
    frontend (the dashboard button must be clicked twice within 5 seconds).
    """
    try:
        db.drop_all()
        db.create_all()
        return jsonify({"status": "success", "message": "Database reset. All scan data cleared."})
    except Exception as e:
        logger.error(f"Database reset failed: {e}")
        return jsonify({"status": "error", "message": "Reset failed. Check server logs."}), 500

# ─── Trigger Scan ─────────────────────────────────────────────────────────────
# The dashboard "Run Scan" button POSTs a JSON body here.  This route validates
# the request, selects the right engine method for the chosen target, and kicks
# off the scan in a background thread.  The thread writes to _log_queue so the
# /api/scan_log SSE stream can show progress in real time.

@app.route('/trigger_api_scan', methods=['POST'])
@requires_auth
def trigger_api_scan():
    """
    Validate a scan request from the dashboard and run the scan.

    Expected JSON body keys:
      target          – 'deepseek_demo' | 'dvla' | 'vulnerable_flask' | 'custom'
      vuln_categories – list of category keys to test
      custom_url      – full endpoint URL (required when target == 'custom')
      custom_api_key  – optional Bearer token for custom targets
      demo_mode_off   – bool; True means real API calls, False means demo
      custom_payload  – optional free-text payload to include in the scan
    """
    global _scan_running, _scan_stop_requested

    # Reject concurrent scan attempts — the engine is not designed to run
    # multiple scans in parallel (Selenium uses one browser window at a time).
    if _scan_running:
        return jsonify({
            "status":  "error",
            "message": "A scan is already running. Please wait for it to finish."
        }), 429

    # Always clear any leftover stop signal from the previous scan so the new
    # one does not immediately exit on its first payload check.
    _scan_stop_requested = False

    body            = request.get_json(silent=True) or {}
    target          = body.get('target', 'deepseek_demo')
    vuln_categories = body.get('vuln_categories', list(EU_AI_ACT_MAPPING.keys()))
    custom_url      = body.get('custom_url', '').strip()
    custom_api_key  = body.get('custom_api_key', '').strip()
    demo_mode_off   = body.get('demo_mode_off', False)
    custom_payload  = body.get('custom_payload', None)

    # If the user entered only a custom payload with no category checkboxes
    # ticked, treat it as a 'custom_probe' scan so the engine still runs.
    if not vuln_categories and custom_payload:
        vuln_categories = ['custom_probe']
    elif not vuln_categories:
        return jsonify({
            "status":  "error",
            "message": "Select at least one vulnerability category or enter a custom payload."
        }), 400

    if target == 'custom' and not custom_url:
        return jsonify({"status": "error", "message": "Custom URL is required."}), 400

    # Server-side sanitisation of the custom payload.
    # The front end also sanitises, but never trust client-side validation alone
    # — someone could send a raw POST request with malicious HTML in the field.
    if custom_payload:
        import re
        custom_payload = re.sub(r'<[^>]+>', '', custom_payload)   # strip HTML tags
        custom_payload = custom_payload[:1000].strip()            # enforce max length

    # current_app is a thread-local proxy that only works on the request thread.
    # _get_current_object() extracts the real underlying Flask app instance so it
    # can be passed safely into the daemon thread below.
    flask_app = current_app._get_current_object()  # type: ignore

    # Flush any log lines left in the queue from the previous scan so the
    # terminal panel starts clean when the new scan begins.
    while not _log_queue.empty():
        try:
            _log_queue.get_nowait()
        except queue.Empty:
            break

    # Shared state between the request thread and the scan thread.
    # Using a dict rather than a bare variable avoids closure-capture issues
    # with Python's scoping rules.
    result_holder: dict = {"scan_id": None, "error": None}

    def _run():
        """
        The actual scan logic, executed on a daemon thread.

        sys.stdout is replaced with _QueueWriter so every print() call in
        engine.py and orchestrator.py is captured and streamed to the browser.
        The original stdout is restored in the finally block regardless of
        whether the scan succeeds or raises an exception.
        """
        global _scan_running
        _scan_running = True
        real_stdout   = sys.stdout
        sys.stdout    = _QueueWriter(real_stdout, _log_queue)

        with flask_app.app_context():
            try:
                from .scanner.engine import ScanningEngine
                engine = ScanningEngine()

                if target == 'dvla':
                    # DVLA is a Selenium-based UI scan against the Streamlit
                    # chatbot running in Docker on port 8501.
                    scan_id = engine.run_full_ui_scan(
                        target_url      = "http://localhost:8501",
                        input_sel       = '[data-testid="stChatInput"] textarea',
                        response_sel    = '[data-testid="stChatMessage"]',
                        vuln_categories = vuln_categories,
                        custom_payload  = custom_payload,
                        stop_flag       = lambda: _scan_stop_requested
                    )
                elif target == 'custom' and custom_url:
                    # Generic HTTP POST scan — works with any REST chatbot API.
                    scan_id = engine.run_generic_api_scan(
                        endpoint_url    = custom_url,
                        api_key         = custom_api_key or None,
                        vuln_categories = vuln_categories,
                        custom_payload  = custom_payload,
                        stop_flag       = lambda: _scan_stop_requested
                    )
                elif target == 'vulnerable_flask':
                    # The Vulnerable Flask Chatbot runs locally on port 5001.
                    scan_id = engine.run_generic_api_scan(
                        endpoint_url    = "http://localhost:5001/chat",
                        api_key         = None,
                        vuln_categories = vuln_categories,
                        custom_payload  = custom_payload,
                        stop_flag       = lambda: _scan_stop_requested
                    )
                else:
                    # DeepSeek demo — uses direct API calls.
                    # demo_mode_off is forwarded here so the engine correctly
                    # switches between fabricated (demo ON) and real (demo OFF)
                    # results based on the dashboard toggle.
                    scan_id = engine.run_demo_api_scan(
                        target          = target,
                        vuln_categories = vuln_categories,
                        demo_mode_off   = demo_mode_off,
                        stop_flag       = lambda: _scan_stop_requested,
                        custom_payload  = custom_payload,
                    )

                result_holder["scan_id"] = scan_id

            except Exception as e:
                logger.error(f"Scan thread failed: {e}")
                result_holder["error"] = str(e)

            finally:
                # Always restore stdout and signal the SSE stream to close,
                # even if the scan raised an exception.
                sys.stdout    = real_stdout
                _scan_running = False
                _log_queue.put("__DONE__")

    thread = threading.Thread(target=_run, daemon=True)
    thread.start()
    thread.join()   # block the HTTP response until the scan finishes

    if result_holder["error"]:
        return jsonify({
            "status":  "error",
            "message": result_holder["error"]
        }), 500

    return jsonify({
        "status":  "success",
        "scan_id": result_holder["scan_id"],
        "message": f"Scan {result_holder['scan_id']} completed. Refresh the dashboard!"
    })