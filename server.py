"""
cvss_server/server.py
=====================

This module provides a minimal web server for evaluating CVSS v3.1
scores, persisting the results in a SQLite database and presenting
a simple dashboard.  It relies only on the Python standard library
and works without any external dependencies or internet access.

Key features:

* **Evaluation form**: A web form at ``/`` accepts CVSS base
  metrics along with optional metadata (title, CVE ID, source).
  When submitted via POST, the server calculates the CVSS base
  score using the logic from ``cvss.py``, stores the result and
  returns a results page summarising the evaluation.

* **Dashboard**: A page at ``/dashboard`` shows a summary of
  recorded evaluations.  It displays key metrics (number of
  evaluations per severity level) and a simple bar chart using
  plain HTML and CSS.  The dashboard queries the underlying
  database directly; no external JavaScript libraries are used.

* **API endpoints**: Several JSON endpoints provide programmatic
  access to the stored evaluations:
    - ``/api/dashboard/summary``: Returns counts by severity and
      the top vulnerabilities by score.
    - ``/api/vulns``: Lists all evaluations with their metadata.
    - ``/api/vulns/<id>``: Returns the details of a single
      evaluation (id is the record's primary key).
    - ``/api/export/csv``: Streams all evaluations as a CSV file.

The server stores evaluations in a SQLite database located in
the same directory.  On startup, it creates the database if it
does not exist.

To run the server locally:

```
python cvss_server/server.py
```

Then open ``http://localhost:8000/`` in your browser.  For
demonstration purposes the server binds to all interfaces on
port 8000.  Adjust ``HOST`` and ``PORT`` below to change that.
"""

import http.server
import json
import os
import sqlite3
import urllib.parse
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    # When running as part of the cvss_server package (e.g., `python -m cvss_server.server`)
    from .cvss import calculate_base_score  # type: ignore
except ImportError:
    # Fallback to absolute import when executed as a script (`python cvss_server/server.py`)
    import sys
    from pathlib import Path
    # Add the parent directory of this file to sys.path
    current_path = Path(__file__).resolve()
    parent_dir = current_path.parent
    sys.path.append(str(parent_dir.parent))
    try:
        from cvss_server.cvss import calculate_base_score  # type: ignore
    except ImportError:
        # As a last resort, import from relative path by adjusting sys.path again
        sys.path.append(str(parent_dir))
        from cvss import calculate_base_score  # type: ignore


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Host and port the server listens on.  Bind to all interfaces by default.
HOST = "0.0.0.0"
PORT = 8000

# Path to the SQLite database file.  Stored relative to this script's
# directory to avoid writing outside the repo.  If you change this
# filename or location, existing data will not be migrated automatically.
DB_PATH = Path(__file__).resolve().parent / "database.db"

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------


def init_db(db_path: Path) -> None:
    """Initialise the SQLite database if it does not already exist.

    Creates a table ``evaluations`` with columns for storing
    vulnerability metadata, the metrics provided, the computed
    base score and severity, and a timestamp.  This function is
    idempotent: running it repeatedly does not modify an existing
    database unless the schema is missing.

    Args:
        db_path: Path to the SQLite database file.
    """
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS evaluations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT,
                cve_id TEXT,
                source TEXT,
                metrics_json TEXT NOT NULL,
                vector TEXT NOT NULL,
                base_score REAL NOT NULL,
                severity TEXT NOT NULL,
                created_at TEXT NOT NULL
            );
            """
        )
        conn.commit()
    finally:
        conn.close()


def insert_evaluation(
    db_path: Path,
    title: str,
    cve_id: str,
    source: str,
    metrics: Dict[str, str],
    vector: str,
    base_score: float,
    severity: str,
) -> int:
    """Insert a new evaluation record into the database.

    Args:
        db_path: Path to the database file.
        title: Optional title or description of the vulnerability.
        cve_id: Optional CVE identifier.
        source: Optional source tag (e.g. "Internal" or "NVD").
        metrics: Mapping of metric names to values.
        vector: CVSS vector string.
        base_score: The computed base score.
        severity: Severity string.

    Returns:
        The integer ID of the inserted row.
    """
    created_at = datetime.utcnow().isoformat()
    metrics_json = json.dumps(metrics, sort_keys=True)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO evaluations
                (title, cve_id, source, metrics_json, vector, base_score, severity, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                title or "",
                cve_id or "",
                source or "",
                metrics_json,
                vector,
                base_score,
                severity,
                created_at,
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def fetch_evaluations(db_path: Path) -> List[Dict[str, Any]]:
    """Fetch all evaluations from the database.

    Returns a list of dictionaries with keys matching the database columns.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM evaluations ORDER BY created_at DESC")
        rows = cur.fetchall()
        evaluations: List[Dict[str, Any]] = []
        for row in rows:
            evaluations.append({k: row[k] for k in row.keys()})
        return evaluations
    finally:
        conn.close()


def fetch_evaluation_by_id(db_path: Path, eval_id: int) -> Dict[str, Any]:
    """Fetch a single evaluation by its ID.

    Returns an empty dict if the record does not exist.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM evaluations WHERE id = ?", (eval_id,))
        row = cur.fetchone()
        return {k: row[k] for k in row.keys()} if row else {}
    finally:
        conn.close()


def summary_counts_and_top(db_path: Path, top_n: int = 10) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
    """Compute counts per severity and return the top N records by score.

    Args:
        db_path: Path to the database.
        top_n: Number of top records to return.

    Returns:
        A tuple ``(counts, top_list)`` where ``counts`` is a dict mapping
        severity strings to integer counts, and ``top_list`` is a list
        of the top N evaluation dictionaries ordered by score descending.
    """
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cur = conn.cursor()
        # Count by severity
        cur.execute(
            "SELECT severity, COUNT(*) as count FROM evaluations GROUP BY severity"
        )
        counts = {row["severity"]: row["count"] for row in cur.fetchall()}

        # Get top N by base_score descending
        cur.execute(
            """
            SELECT * FROM evaluations
            ORDER BY base_score DESC, created_at DESC
            LIMIT ?
            """,
            (top_n,),
        )
        rows = cur.fetchall()
        top_list: List[Dict[str, Any]] = []
        for row in rows:
            top_list.append({k: row[k] for k in row.keys()})
        return counts, top_list
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Helper functions for HTML generation
# ---------------------------------------------------------------------------


def html_page(title: str, body: str) -> bytes:
    """Wrap a body string in a simple HTML template.

    Args:
        title: The page title shown in the <title> tag.
        body: Raw HTML content to insert into the <body>.

    Returns:
        Byte string of the complete HTML page encoded as UTF-8.
    """
    html = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="utf-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{title}</title>
        <style>
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                margin: 0; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
            }}
            .container {{ 
                max-width: 1000px; 
                margin: 0 auto; 
                padding: 2rem;
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                margin-top: 2rem;
                margin-bottom: 2rem;
            }}
            h1 {{ 
                color: #2c3e50; 
                text-align: center;
                margin-bottom: 2rem;
                font-size: 2.5rem;
                font-weight: 300;
                text-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            h2 {{ 
                color: #34495e; 
                border-bottom: 3px solid #3498db;
                padding-bottom: 0.5rem;
                margin-top: 2rem;
            }}
            label {{ 
                display: block; 
                margin-top: 1rem; 
                font-weight: 600;
                color: #2c3e50;
                font-size: 0.95rem;
            }}
            select, input[type=text] {{ 
                width: 100%; 
                padding: 0.75rem; 
                margin-top: 0.5rem; 
                border: 2px solid #e0e6ed; 
                border-radius: 8px; 
                font-size: 1rem;
                transition: all 0.3s ease;
                background: #fff;
            }}
            select:focus, input[type=text]:focus {{ 
                outline: none; 
                border-color: #3498db; 
                box-shadow: 0 0 0 3px rgba(52, 152, 219, 0.1);
            }}
            button {{ 
                margin-top: 1.5rem; 
                padding: 1rem 2rem; 
                background: linear-gradient(45deg, #3498db, #2980b9); 
                color: #fff; 
                border: none; 
                border-radius: 8px; 
                cursor: pointer; 
                font-size: 1.1rem;
                font-weight: 600;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
            }}
            button:hover {{ 
                background: linear-gradient(45deg, #2980b9, #1f5f8b);
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
            }}
            .result {{ 
                margin-top: 1.5rem; 
                padding: 1.5rem; 
                background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                border-radius: 12px;
                border-left: 5px solid #3498db;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            }}
            .severity-badge {{
                display: inline-block;
                padding: 0.5rem 1rem;
                border-radius: 20px;
                font-weight: 600;
                font-size: 0.9rem;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            .severity-critical {{ background: linear-gradient(45deg, #e74c3c, #c0392b); color: white; }}
            .severity-high {{ background: linear-gradient(45deg, #e67e22, #d35400); color: white; }}
            .severity-medium {{ background: linear-gradient(45deg, #f39c12, #e67e22); color: white; }}
            .severity-low {{ background: linear-gradient(45deg, #27ae60, #229954); color: white; }}
            .severity-none {{ background: linear-gradient(45deg, #95a5a6, #7f8c8d); color: white; }}
            .dashboard {{ display: flex; flex-direction: column; gap: 2rem; }}
            .kpi {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1.5rem; }}
            .kpi div {{ 
                background: linear-gradient(135deg, #fff, #f8f9fa); 
                border: 1px solid #e0e6ed; 
                border-radius: 12px; 
                padding: 1.5rem; 
                text-align: center; 
                box-shadow: 0 4px 15px rgba(0,0,0,0.08);
                transition: transform 0.3s ease;
            }}
            .kpi div:hover {{ transform: translateY(-5px); }}
            .kpi h3 {{ 
                margin: 0 0 0.5rem 0; 
                font-size: 1.2rem; 
                font-weight: 600;
                color: #2c3e50;
            }}
            .kpi p {{ 
                margin: 0; 
                font-size: 2rem; 
                font-weight: 700;
                color: #3498db;
            }}
            .chart-bar-container {{ 
                display: flex; 
                align-items: flex-end; 
                height: 250px; 
                gap: 15px; 
                padding: 2rem; 
                background: linear-gradient(135deg, #fff, #f8f9fa); 
                border: 1px solid #e0e6ed; 
                border-radius: 12px; 
                box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            }}
            .chart-bar {{ 
                flex: 1; 
                display: flex; 
                flex-direction: column; 
                align-items: center; 
                justify-content: flex-end; 
            }}
            .bar {{ 
                width: 80%; 
                border-radius: 8px 8px 0 0; 
                transition: all 0.3s ease;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            }}
            .bar:hover {{ transform: scaleY(1.05); }}
            .bar-label {{ 
                margin-top: 0.5rem; 
                font-size: 0.85rem; 
                color: #555; 
                font-weight: 600;
                text-align: center;
            }}
            table {{ 
                width: 100%; 
                border-collapse: collapse; 
                margin-top: 1.5rem;
                background: #fff;
                border-radius: 12px;
                overflow: hidden;
                box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            }}
            th, td {{ 
                padding: 1rem; 
                border: 1px solid #e0e6ed; 
                text-align: left; 
            }}
            th {{ 
                background: linear-gradient(135deg, #3498db, #2980b9); 
                color: white;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }}
            tr:nth-child(even) {{ background-color: #f8f9fa; }}
            tr:hover {{ background-color: #e3f2fd; }}
            .nav-links {{
                text-align: center;
                margin: 2rem 0;
            }}
            .nav-links a {{
                display: inline-block;
                margin: 0 1rem;
                padding: 0.75rem 1.5rem;
                background: linear-gradient(45deg, #3498db, #2980b9);
                color: white;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 600;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
            }}
            .nav-links a:hover {{
                background: linear-gradient(45deg, #2980b9, #1f5f8b);
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
            }}
            footer {{ 
                margin-top: 3rem; 
                font-size: 0.9rem; 
                color: #7f8c8d; 
                text-align: center;
                padding: 1rem;
                border-top: 1px solid #e0e6ed;
            }}
            .score-display {{
                font-size: 3rem;
                font-weight: 700;
                text-align: center;
                margin: 1rem 0;
                text-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            .vector-display {{
                background: #2c3e50;
                color: #ecf0f1;
                padding: 1rem;
                border-radius: 8px;
                font-family: 'Courier New', monospace;
                font-size: 0.9rem;
                word-break: break-all;
                margin: 1rem 0;
            }}
        </style>
    </head>
    <body>
        <div class="container">
        {body}
        </div>
        <footer>
            <p>CVSS Scoring System - MVP using Python Standard Library &amp; SQLite</p>
        </footer>
    </body>
    </html>
    """
    return html.encode("utf-8")


def render_form() -> bytes:
    """Generate the HTML for the evaluation form."""
    # Options for each metric according to CVSS v3.1 specification.
    av_options = [("N", "Network (N)"), ("A", "Adjacent (A)"), ("L", "Local (L)"), ("P", "Physical (P)")]
    ac_options = [("L", "Low (L)"), ("H", "High (H)")]
    pr_options = [("N", "None (N)"), ("L", "Low (L)"), ("H", "High (H)")]
    ui_options = [("N", "None (N)"), ("R", "Required (R)")]
    s_options = [("U", "Unchanged (U)"), ("C", "Changed (C)")]
    impact_options = [("N", "None (N)"), ("L", "Low (L)"), ("H", "High (H)")]

    def options_html(options: List[Tuple[str, str]]) -> str:
        return "".join([f"<option value=\"{val}\">{label}</option>" for val, label in options])

    form_html = f"""
    <h1>CVSS v3.1 Evaluation</h1>
    <p style="text-align: center; color: #7f8c8d; margin-bottom: 2rem;">
        Enter the details of a vulnerability and select the appropriate CVSS v3.1 base metrics.
    </p>
    
    <form method="post" action="/evaluate">
        <h2>Vulnerability Information</h2>
        <label for="title">Title / Description (optional)</label>
        <input type="text" id="title" name="title" placeholder="Example: Remote Code Execution in Module X" />

        <label for="cve_id">CVE ID (optional)</label>
        <input type="text" id="cve_id" name="cve_id" placeholder="Example: CVE-2024-12345" />

        <label for="source">Source (optional)</label>
        <input type="text" id="source" name="source" placeholder="Internal, NVD, etc." />

        <h2>CVSS Base Metrics</h2>
        <label for="AV">Attack Vector (AV)</label>
        <select id="AV" name="AV" required>
            {options_html(av_options)}
        </select>

        <label for="AC">Attack Complexity (AC)</label>
        <select id="AC" name="AC" required>
            {options_html(ac_options)}
        </select>

        <label for="PR">Privileges Required (PR)</label>
        <select id="PR" name="PR" required>
            {options_html(pr_options)}
        </select>

        <label for="UI">User Interaction (UI)</label>
        <select id="UI" name="UI" required>
            {options_html(ui_options)}
        </select>

        <label for="S">Scope (S)</label>
        <select id="S" name="S" required>
            {options_html(s_options)}
        </select>

        <label for="C">Confidentiality Impact (C)</label>
        <select id="C" name="C" required>
            {options_html(impact_options)}
        </select>

        <label for="I">Integrity Impact (I)</label>
        <select id="I" name="I" required>
            {options_html(impact_options)}
        </select>

        <label for="A">Availability Impact (A)</label>
        <select id="A" name="A" required>
            {options_html(impact_options)}
        </select>

        <button type="submit">Calculate CVSS Score</button>
    </form>
    
    <div class="nav-links">
        <a href="/dashboard">View Dashboard</a>
    </div>
    """
    return html_page("CVSS Evaluation", form_html)


def render_result(title: str, cve_id: str, source: str, metrics: Dict[str, str], base_score: float, severity: str, vector: str) -> bytes:
    """Generate HTML showing the result of the evaluation."""
    # Compose human-readable summary of metrics
    metric_names = {
        "AV": "Attack Vector",
        "AC": "Attack Complexity",
        "PR": "Privileges Required",
        "UI": "User Interaction",
        "S": "Scope",
        "C": "Confidentiality Impact",
        "I": "Integrity Impact",
        "A": "Availability Impact",
    }
    rows = "".join(
        [
            f"<tr><th>{metric_names[k]}</th><td>{metrics[k]}</td></tr>"
            for k in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
        ]
    )
    
    # Get severity class for styling
    severity_class = f"severity-{severity.lower()}"
    
    result_html = f"""
    <h1>CVSS Evaluation Result</h1>
    
    <div class="result">
        <div class="score-display" style="color: {color_for_cat(severity)};">
            {base_score}
        </div>
        <div style="text-align: center; margin-bottom: 1rem;">
            <span class="severity-badge {severity_class}">{severity}</span>
        </div>
        <div class="vector-display">
            <strong>CVSS Vector:</strong><br>
            {vector}
        </div>
    </div>
    
    <h2>Vulnerability Details</h2>
    <table>
        <tr><th>Title</th><td>{title or '-'}</td></tr>
        <tr><th>CVE ID</th><td>{cve_id or '-'}</td></tr>
        <tr><th>Source</th><td>{source or '-'}</td></tr>
    </table>
    
    <h2>CVSS Base Metrics</h2>
    <table>
        {rows}
    </table>
    
    <div class="nav-links">
        <a href="/">&larr; Evaluate another vulnerability</a>
        <a href="/dashboard">View Dashboard</a>
    </div>
    """
    return html_page("CVSS Result", result_html)


def render_dashboard(counts: Dict[str, int], top_list: List[Dict[str, Any]]) -> bytes:
    """Generate HTML for the dashboard page.

    The dashboard shows KPIs for each severity category and a
    simple bar chart implemented with divs.  It also includes a
    table of the top vulnerabilities by score.

    Args:
        counts: Mapping of severity to counts.
        top_list: List of evaluation records sorted by score.
    """
    # Ensure all categories are present
    categories = ["Critical", "High", "Medium", "Low", "None"]
    counts_full = {cat: counts.get(cat, 0) for cat in categories}
    # Determine the maximum count for scaling the bars
    max_count = max(counts_full.values()) or 1
    
    # Generate HTML for KPIs with severity colors
    kpi_html = "".join(
        [
            f"<div style=\"border-left: 4px solid {color_for_cat(cat)};\">"
            f"<h3>{cat}</h3><p>{counts_full[cat]}</p></div>"
            for cat in categories
        ]
    )
    
    # Generate bar chart HTML
    bars_html = "".join(
        [
            f"<div class=\"chart-bar\">"
            f"<div class=\"bar\" style=\"height: {counts_full[cat] / max_count * 100:.1f}%; background: linear-gradient(to top, {color_for_cat(cat)}, {color_for_cat(cat)}dd);\"></div>"
            f"<div class=\"bar-label\">{cat}<br><strong>{counts_full[cat]}</strong></div></div>"
            for cat in categories
        ]
    )
    
    # Generate top table HTML with severity badges
    rows = "".join(
        [
            f"<tr>"
            f"<td>{rec['id']}</td>"
            f"<td>{rec['title'] or '-'}</td>"
            f"<td>{rec['cve_id'] or '-'}</td>"
            f"<td><strong>{rec['base_score']}</strong></td>"
            f"<td><span class=\"severity-badge severity-{rec['severity'].lower()}\">{rec['severity']}</span></td>"
            f"<td>{rec['created_at'][:19]}</td>"
            f"</tr>"
            for rec in top_list
        ]
    )
    
    top_table = f"""
    <h2>Top Evaluations (by Base Score)</h2>
    <table>
        <tr><th>ID</th><th>Title</th><th>CVE ID</th><th>Base Score</th><th>Severity</th><th>Created At (UTC)</th></tr>
        {rows if rows else '<tr><td colspan="6" style="text-align: center; color: #7f8c8d;">No evaluations yet.</td></tr>'}
    </table>
    """
    
    dashboard_html = f"""
    <h1>CVSS Dashboard</h1>
    <div class="dashboard">
        <div class="kpi">{kpi_html}</div>
        <div>
            <h2>Severity Distribution</h2>
            <div class="chart-bar-container">{bars_html}</div>
        </div>
        {top_table}
        <div class="nav-links">
            <a href="/">&larr; Evaluate another vulnerability</a>
        </div>
    </div>
    """
    return html_page("Dashboard", dashboard_html)


def color_for_cat(cat: str) -> str:
    """Assign a colour to each severity category for the bar chart."""
    return {
        "Critical": "#dc3545",  # red
        "High": "#fd7e14",     # orange
        "Medium": "#ffc107",   # yellow
        "Low": "#198754",      # green
        "None": "#6c757d",     # grey
    }.get(cat, "#0d6efd")  # default blue


# ---------------------------------------------------------------------------
# Request handler
# ---------------------------------------------------------------------------


class CVSSRequestHandler(http.server.BaseHTTPRequestHandler):
    """Custom request handler for our CVSS web server."""

    def log_message(self, format: str, *args: Any) -> None:
        """Override to suppress default logging to stderr."""
        # Print to console with timestamp
        print(
            f"[{datetime.utcnow().isoformat()}] {self.address_string()} - "
            + format % args
        )

    def send_json(self, data: Any, status: int = 200) -> None:
        """Send a JSON response."""
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:
        """Handle GET requests based on the request path."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        # Route handling
        if path == "/" or path == "/evaluate":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            form = render_form()
            self.send_header("Content-Length", str(len(form)))
            self.end_headers()
            self.wfile.write(form)
        elif path == "/dashboard":
            counts, top_list = summary_counts_and_top(DB_PATH)
            page = render_dashboard(counts, top_list)
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(page)))
            self.end_headers()
            self.wfile.write(page)
        elif path == "/api/dashboard/summary":
            counts, top_list = summary_counts_and_top(DB_PATH)
            # Convert top_list to include only relevant fields (avoid large JSON)
            top_minimal = [
                {
                    "id": rec["id"],
                    "title": rec["title"],
                    "cve_id": rec["cve_id"],
                    "base_score": rec["base_score"],
                    "severity": rec["severity"],
                    "created_at": rec["created_at"],
                }
                for rec in top_list
            ]
            self.send_json({"counts": counts, "top": top_minimal})
        elif path == "/api/vulns":
            # If there is an id parameter, return that record
            query_params = urllib.parse.parse_qs(parsed.query)
            if "id" in query_params:
                try:
                    eval_id = int(query_params["id"][0])
                except ValueError:
                    self.send_json({"error": "Invalid id"}, status=400)
                    return
                record = fetch_evaluation_by_id(DB_PATH, eval_id)
                if record:
                    self.send_json(record)
                else:
                    self.send_json({"error": "Not found"}, status=404)
            else:
                # Return all evaluations
                evals = fetch_evaluations(DB_PATH)
                self.send_json(evals)
        elif path.startswith("/api/vulns/"):
            # Path param variant: /api/vulns/<id>
            try:
                eval_id = int(path.split("/")[3])
            except (IndexError, ValueError):
                self.send_json({"error": "Invalid path"}, status=400)
                return
            record = fetch_evaluation_by_id(DB_PATH, eval_id)
            if record:
                self.send_json(record)
            else:
                self.send_json({"error": "Not found"}, status=404)
        elif path == "/api/export/csv":
            # Export all evaluations as CSV
            evals = fetch_evaluations(DB_PATH)
            # Build CSV header and rows
            header = [
                "id",
                "title",
                "cve_id",
                "source",
                "metrics_json",
                "vector",
                "base_score",
                "severity",
                "created_at",
            ]
            lines = ["\t".join(header)]
            for rec in evals:
                row = [str(rec[h] or "") for h in header]
                lines.append("\t".join(row))
            csv_data = "\n".join(lines).encode("utf-8")
            self.send_response(200)
            self.send_header(
                "Content-Type", "text/tab-separated-values; charset=utf-8"
            )
            self.send_header(
                "Content-Disposition", "attachment; filename=evaluations.tsv"
            )
            self.send_header("Content-Length", str(len(csv_data)))
            self.end_headers()
            self.wfile.write(csv_data)
        else:
            # Not found
            self.send_response(404)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            msg = f"404 Not Found: {path}".encode("utf-8")
            self.send_header("Content-Length", str(len(msg)))
            self.end_headers()
            self.wfile.write(msg)

    def do_POST(self) -> None:
        """Handle POST requests (form submissions)."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        if path != "/evaluate":
            self.send_response(404)
            self.end_headers()
            return
        # Read and parse form data
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
        form = urllib.parse.parse_qs(post_data.decode("utf-8"))

        def get_value(key: str) -> str:
            return form.get(key, [""])[0]

        # Extract metrics and metadata
        metrics = {}
        for key in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
            metrics[key] = get_value(key)
        title = get_value("title").strip()
        cve_id = get_value("cve_id").strip()
        source = get_value("source").strip()

        # Compute base score
        base_score, severity, vector = calculate_base_score(metrics)
        # Persist record
        eval_id = insert_evaluation(
            DB_PATH, title, cve_id, source, metrics, vector, base_score, severity
        )
        # Return result page
        result_page = render_result(
            title,
            cve_id,
            source,
            metrics,
            base_score,
            severity,
            vector,
        )
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(result_page)))
        self.end_headers()
        self.wfile.write(result_page)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_server(host: str = HOST, port: int = PORT) -> None:
    """Initialise the database and run the HTTP server indefinitely."""
    # Ensure database directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    init_db(DB_PATH)
    server_address = (host, port)
    with http.server.ThreadingHTTPServer(server_address, CVSSRequestHandler) as httpd:
        print(f"Serving CVSS app at http://{host}:{port}/")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer shutting down...")


if __name__ == "__main__":
    run_server()