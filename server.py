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
import cgi
import tempfile
import secrets
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

try:
    # When running as part of the cvss_server package (e.g., `python -m cvss_server.server`)
    from .cvss import calculate_base_score  # type: ignore
    from .document_processor import document_processor  # type: ignore
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
        from cvss_server.document_processor import document_processor  # type: ignore
    except ImportError:
        # As a last resort, import from relative path by adjusting sys.path again
        sys.path.append(str(parent_dir))
        from cvss import calculate_base_score  # type: ignore
        try:
            from document_processor import document_processor  # type: ignore
        except ImportError:
            document_processor = None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

# Host and port the server listens on.  Bind to all interfaces by default.
HOST = os.environ.get("HOST", "0.0.0.0")
PORT = int(os.environ.get("PORT", 8000))

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
                created_at TEXT NOT NULL,
                user_id INTEGER
            );
            """
        )
        
        # Add user_id column if it doesn't exist (for existing databases)
        try:
            cur.execute("ALTER TABLE evaluations ADD COLUMN user_id INTEGER")
        except sqlite3.OperationalError:
            # Column already exists, ignore
            pass
        
        # Create users table if it doesn't exist
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                full_name TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1
            );
            """
        )
        
        # Create user_sessions table if it doesn't exist
        cur.execute(
            """
            CREATE TABLE IF NOT EXISTS user_sessions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                session_token TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users (id)
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
    user_id: int = None,
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
        user_id: Optional user ID.

    Returns:
        The integer ID of the inserted row.
    """
    created_at = datetime.utcnow().isoformat()
    metrics_json = json.dumps(metrics, sort_keys=True)
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        
        # Check if user_id column exists
        cur.execute("PRAGMA table_info(evaluations)")
        columns = [col[1] for col in cur.fetchall()]
        has_user_id = 'user_id' in columns
        
        if has_user_id:
            cur.execute(
                """
                INSERT INTO evaluations
                    (title, cve_id, source, metrics_json, vector, base_score, severity, created_at, user_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    user_id,
                ),
            )
        else:
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


def summary_counts_and_top(db_path: Path, user_id: int = None, top_n: int = 10) -> Tuple[Dict[str, int], List[Dict[str, Any]]]:
    """Compute counts per severity and return the top N records by score.

    Args:
        db_path: Path to the database.
        user_id: Optional user ID to filter by.
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
        
        # Check if user_id column exists
        cur.execute("PRAGMA table_info(evaluations)")
        columns = [col[1] for col in cur.fetchall()]
        has_user_id = 'user_id' in columns
        
        # Count by severity (filter by user if provided and column exists)
        if user_id and has_user_id:
            cur.execute(
                "SELECT severity, COUNT(*) as count FROM evaluations WHERE user_id = ? GROUP BY severity",
                (user_id,)
            )
        else:
        cur.execute(
            "SELECT severity, COUNT(*) as count FROM evaluations GROUP BY severity"
        )
        counts = {row["severity"]: row["count"] for row in cur.fetchall()}

        # Get top N by base_score descending (filter by user if provided and column exists)
        if user_id and has_user_id:
            cur.execute(
                """
                SELECT * FROM evaluations
                WHERE user_id = ?
                ORDER BY base_score DESC, created_at DESC
                LIMIT ?
                """,
                (user_id, top_n),
            )
        else:
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
            /* Reset and base styles */
            * {{
                box-sizing: border-box;
            }}
            
            body {{ 
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
                margin: 0; 
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                color: #333;
                line-height: 1.6;
            }}
            
            .container {{ 
                max-width: 1200px; 
                margin: 0 auto; 
                padding: 1rem;
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                border-radius: 15px;
                box-shadow: 0 20px 40px rgba(0,0,0,0.1);
                margin-top: 1rem;
                margin-bottom: 1rem;
            }}
            
            h1 {{ 
                color: #2c3e50; 
                text-align: center;
                margin-bottom: 1.5rem;
                font-size: clamp(1.8rem, 4vw, 2.5rem);
                font-weight: 300;
                text-shadow: 0 2px 4px rgba(0,0,0,0.1);
                line-height: 1.2;
            }}
            
            h2 {{ 
                color: #34495e; 
                border-bottom: 3px solid #3498db;
                padding-bottom: 0.5rem;
                margin-top: 1.5rem;
                font-size: clamp(1.3rem, 3vw, 1.8rem);
            }}
            
            label {{ 
                display: block; 
                margin-top: 1rem; 
                font-weight: 600;
                color: #2c3e50;
                font-size: clamp(0.9rem, 2.5vw, 0.95rem);
            }}
            
            select, input[type=text] {{ 
                width: 100%; 
                padding: clamp(0.6rem, 2vw, 0.75rem); 
                margin-top: 0.5rem; 
                border: 2px solid #e0e6ed; 
                border-radius: 8px; 
                font-size: clamp(0.9rem, 2.5vw, 1rem);
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
                padding: clamp(0.8rem, 3vw, 1rem) clamp(1.5rem, 4vw, 2rem); 
                background: linear-gradient(45deg, #3498db, #2980b9); 
                color: #fff; 
                border: none; 
                border-radius: 8px; 
                cursor: pointer; 
                font-size: clamp(1rem, 2.5vw, 1.1rem);
                font-weight: 600;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
                width: 100%;
                max-width: 300px;
            }}
            
            button:hover {{ 
                background: linear-gradient(45deg, #2980b9, #1f5f8b);
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
            }}
            
            .result {{ 
                margin-top: 1.5rem; 
                padding: clamp(1rem, 3vw, 1.5rem); 
                background: linear-gradient(135deg, #f8f9fa, #e9ecef);
                border-radius: 12px;
                border-left: 5px solid #3498db;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            }}
            
            .severity-badge {{
                display: inline-block;
                padding: clamp(0.4rem, 2vw, 0.5rem) clamp(0.8rem, 2.5vw, 1rem);
                border-radius: 20px;
                font-weight: 600;
                font-size: clamp(0.8rem, 2.5vw, 0.9rem);
                text-transform: uppercase;
                letter-spacing: 0.5px;
                white-space: nowrap;
            }}
            
            .severity-critical {{ background: linear-gradient(45deg, #e74c3c, #c0392b); color: white; }}
            .severity-high {{ background: linear-gradient(45deg, #e67e22, #d35400); color: white; }}
            .severity-medium {{ background: linear-gradient(45deg, #f39c12, #e67e22); color: white; }}
            .severity-low {{ background: linear-gradient(45deg, #27ae60, #229954); color: white; }}
            .severity-none {{ background: linear-gradient(45deg, #95a5a6, #7f8c8d); color: white; }}
            
            .dashboard {{ display: flex; flex-direction: column; gap: clamp(1rem, 3vw, 2rem); }}
            
            .kpi {{ 
                display: grid; 
                grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); 
                gap: clamp(0.8rem, 2.5vw, 1.5rem); 
            }}
            
            .kpi div {{ 
                background: linear-gradient(135deg, #fff, #f8f9fa); 
                border: 1px solid #e0e6ed; 
                border-radius: 12px; 
                padding: clamp(1rem, 3vw, 1.5rem); 
                text-align: center; 
                box-shadow: 0 4px 15px rgba(0,0,0,0.08);
                transition: transform 0.3s ease;
            }}
            
            .kpi div:hover {{ transform: translateY(-5px); }}
            
            .kpi h3 {{ 
                margin: 0 0 0.5rem 0; 
                font-size: clamp(1rem, 2.5vw, 1.2rem); 
                font-weight: 600;
                color: #2c3e50;
            }}
            
            .kpi p {{ 
                margin: 0; 
                font-size: clamp(1.5rem, 4vw, 2rem); 
                font-weight: 700;
                color: #3498db;
            }}
            
            .chart-bar-container {{ 
                display: flex; 
                align-items: flex-end; 
                height: clamp(200px, 40vw, 250px); 
                gap: clamp(8px, 2vw, 15px); 
                padding: clamp(1rem, 3vw, 2rem); 
                background: linear-gradient(135deg, #fff, #f8f9fa); 
                border: 1px solid #e0e6ed; 
                border-radius: 12px; 
                box-shadow: 0 4px 15px rgba(0,0,0,0.08);
                overflow-x: auto;
            }}
            
            .chart-bar {{ 
                flex: 1; 
                min-width: 60px;
                display: flex; 
                flex-direction: column; 
                align-items: center; 
                justify-content: flex-end; 
            }}
            
            .bar {{ 
                width: 80%; 
                min-width: 40px;
                border-radius: 8px 8px 0 0; 
                transition: all 0.3s ease;
                box-shadow: 0 2px 8px rgba(0,0,0,0.2);
            }}
            
            .bar:hover {{ transform: scaleY(1.05); }}
            
            .bar-label {{ 
                margin-top: 0.5rem; 
                font-size: clamp(0.7rem, 2vw, 0.85rem); 
                color: #555; 
                font-weight: 600;
                text-align: center;
                word-wrap: break-word;
            }}
            
            /* Responsive table */
            .table-container {{
                overflow-x: auto;
                margin-top: 1.5rem;
                border-radius: 12px;
                box-shadow: 0 4px 15px rgba(0,0,0,0.08);
            }}
            
            table {{ 
                width: 100%; 
                min-width: 600px;
                border-collapse: collapse; 
                background: #fff;
            }}
            
            th, td {{ 
                padding: clamp(0.6rem, 2vw, 1rem); 
                border: 1px solid #e0e6ed; 
                text-align: left; 
                font-size: clamp(0.8rem, 2.5vw, 0.9rem);
            }}
            
            th {{ 
                background: linear-gradient(135deg, #3498db, #2980b9); 
                color: white;
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
                white-space: nowrap;
            }}
            
            tr:nth-child(even) {{ background-color: #f8f9fa; }}
            tr:hover {{ background-color: #e3f2fd; }}
            
            .nav-links {{
                text-align: center;
                margin: clamp(1rem, 3vw, 2rem) 0;
                display: flex;
                flex-direction: column;
                gap: 1rem;
                align-items: center;
            }}
            
            .nav-links a {{
                display: inline-block;
                padding: clamp(0.6rem, 2.5vw, 0.75rem) clamp(1rem, 3vw, 1.5rem);
                background: linear-gradient(45deg, #3498db, #2980b9);
                color: white;
                text-decoration: none;
                border-radius: 8px;
                font-weight: 600;
                transition: all 0.3s ease;
                box-shadow: 0 4px 15px rgba(52, 152, 219, 0.3);
                font-size: clamp(0.9rem, 2.5vw, 1rem);
                white-space: nowrap;
            }}
            
            .nav-links a:hover {{
                background: linear-gradient(45deg, #2980b9, #1f5f8b);
                transform: translateY(-2px);
                box-shadow: 0 6px 20px rgba(52, 152, 219, 0.4);
            }}
            
            footer {{ 
                margin-top: 3rem; 
                font-size: clamp(0.8rem, 2.5vw, 0.9rem); 
                color: #7f8c8d; 
                text-align: center;
                padding: 1rem;
                border-top: 1px solid #e0e6ed;
            }}
            
            .score-display {{
                font-size: clamp(2rem, 8vw, 3rem);
                font-weight: 700;
                text-align: center;
                margin: 1rem 0;
                text-shadow: 0 2px 4px rgba(0,0,0,0.1);
            }}
            
            .vector-display {{
                background: #2c3e50;
                color: #ecf0f1;
                padding: clamp(0.8rem, 2.5vw, 1rem);
                border-radius: 8px;
                font-family: 'Courier New', monospace;
                font-size: clamp(0.8rem, 2.5vw, 0.9rem);
                word-break: break-all;
                margin: 1rem 0;
                overflow-x: auto;
            }}
            
            /* Mobile-specific improvements */
            @media (max-width: 768px) {{
                .container {{
                    margin: 0.5rem;
                    padding: 0.8rem;
                    border-radius: 10px;
                }}
                
                .kpi {{
                    grid-template-columns: repeat(2, 1fr);
                }}
                
                .chart-bar-container {{
                    flex-direction: column;
                    height: auto;
                    align-items: stretch;
                }}
                
                .chart-bar {{
                    flex-direction: row;
                    align-items: center;
                    gap: 1rem;
                    margin-bottom: 1rem;
                }}
                
                .bar {{
                    width: 100px;
                    height: 20px;
                    border-radius: 10px;
                }}
                
                .bar-label {{
                    margin-top: 0;
                    text-align: left;
                    flex: 1;
                }}
                
                .nav-links {{
                    flex-direction: column;
                }}
                
                .nav-links a {{
                    width: 100%;
                    max-width: 250px;
                }}
                
                button {{
                    width: 100%;
                    max-width: none;
                }}
            }}
            
            @media (max-width: 480px) {{
                .kpi {{
                    grid-template-columns: 1fr;
                }}
                
                .kpi div {{
                    padding: 1rem;
                }}
                
                .chart-bar-container {{
                    padding: 1rem;
                }}
                
                .bar {{
                    width: 60px;
                }}
                
                .vector-display {{
                    font-size: 0.75rem;
                }}
            }}
            
            /* Tablet improvements */
            @media (min-width: 769px) and (max-width: 1024px) {{
                .container {{
                    max-width: 95%;
                }}
                
                .kpi {{
                    grid-template-columns: repeat(3, 1fr);
                }}
            }}
            
            /* Large screen improvements */
            @media (min-width: 1025px) {{
                .nav-links {{
                    flex-direction: row;
                    justify-content: center;
                }}
                
                .nav-links a {{
                    margin: 0 1rem;
                }}
            }}
            
            /* User info styles */
            .user-info {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 1rem;
                border-radius: 10px;
                margin-bottom: 1.5rem;
                display: flex;
                justify-content: space-between;
                align-items: center;
                box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            }}
            
            .user-info span {{
                font-size: 1rem;
            }}
            
            .logout-btn {{
                background: rgba(255,255,255,0.2);
                color: white;
                padding: 0.5rem 1rem;
                border-radius: 6px;
                text-decoration: none;
                font-weight: 500;
                transition: all 0.3s ease;
                border: 1px solid rgba(255,255,255,0.3);
            }}
            
            .logout-btn:hover {{
                background: rgba(255,255,255,0.3);
                transform: translateY(-1px);
            }}
            
            @media (max-width: 768px) {{
                .user-info {{
                    flex-direction: column;
                    gap: 1rem;
                    text-align: center;
                }}
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


def render_form(user: Dict[str, Any] = None) -> bytes:
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

    # Document upload section
    document_upload_section = ""
    if document_processor:
        document_upload_section = """
        <h2>📄 Document Analysis (Optional)</h2>
        <p style="text-align: center; color: #7f8c8d; margin-bottom: 1rem;">
            Upload a Word (.docx) or PDF document to automatically extract CVSS metrics from the text.
        </p>
        
        <div style="background: linear-gradient(135deg, #e8f5e8, #d4edda); border: 1px solid #28a745; border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem;">
            <h3 style="color: #155724; margin-top: 0;">📋 Document Analysis Guide</h3>
            
            <div style="text-align: center; margin-bottom: 1rem;">
                <h4 style="color: #155724; margin-bottom: 1rem;">📖 View Example Document</h4>
                <button type="button" onclick="showExample()" class="example-btn">
                    👁️ Show Example Document
                </button>
                <p style="font-size: 0.9rem; color: #155724; margin-top: 0.5rem;">
                    See how to structure your document for better CVSS metric detection
                </p>
            </div>
            
            <div style="background: #fff; border-radius: 8px; padding: 1rem; border-left: 4px solid #28a745;">
                <h4 style="color: #155724; margin-top: 0;">💡 Tips for Better Detection:</h4>
                <ul style="color: #155724; margin: 0.5rem 0; padding-left: 1.5rem;">
                    <li><strong>Use clear terms:</strong> "network attack", "low complexity", "no privileges"</li>
                    <li><strong>Include CVE ID:</strong> CVE-2024-12345 format</li>
                    <li><strong>Describe impact clearly:</strong> "high impact on confidentiality"</li>
                    <li><strong>Mention scope:</strong> "affects different components" or "within same component"</li>
                </ul>
            </div>
        </div>
        
        <label for="document">Upload Document</label>
        <input type="file" id="document" name="document" accept=".docx,.pdf" style="padding: 0.5rem; border: 2px solid #3498db; border-radius: 8px; background: #f8f9fa;" />
        <p style="font-size: 0.9rem; color: #7f8c8d; margin-top: 0.5rem;">
            Supported formats: .docx, .pdf<br>
            The system will analyze the document and pre-fill the CVSS metrics.
        </p>
        
        <!-- Example Document Modal -->
        <div id="exampleModal" class="modal" style="display: none;">
            <div class="modal-content">
                <span class="close" onclick="closeExample()">&times;</span>
                <h2>📄 Example Document Structure</h2>
                <div style="background: #f8f9fa; border-radius: 8px; padding: 1rem; font-family: monospace; font-size: 0.9rem; line-height: 1.6; max-height: 400px; overflow-y: auto;">
                    <strong>Vulnerability Report: Remote Code Execution</strong><br><br>
                    
                    <strong>CVE ID:</strong> CVE-2024-12345<br><br>
                    
                    <strong>DESCRIPTION:</strong><br>
                    This critical vulnerability allows remote attackers to execute arbitrary 
                    code over the network without requiring any user interaction. The attack 
                    complexity is low and requires no privileges. The vulnerability has high 
                    impact on confidentiality, integrity, and availability.<br><br>
                    
                    <strong>TECHNICAL DETAILS:</strong><br>
                    - The vulnerability is network accessible<br>
                    - Attack complexity is low and simple to exploit<br>
                    - No privileges are required for exploitation<br>
                    - No user interaction is needed<br>
                    - Scope is changed (affects different components)<br>
                    - Complete data disclosure is possible<br>
                    - Data modification can occur<br>
                    - Service disruption is complete<br><br>
                    
                    <strong>CVSS METRICS:</strong><br>
                    Attack Vector: Network<br>
                    Attack Complexity: Low<br>
                    Privileges Required: None<br>
                    User Interaction: None<br>
                    Scope: Changed<br>
                    Confidentiality Impact: High<br>
                    Integrity Impact: High<br>
                    Availability Impact: High<br><br>
                    
                    <strong>EXPECTED RESULT:</strong><br>
                    Base Score: 9.8 (Critical)<br>
                    Vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H
                </div>
            </div>
        </div>
        
        <style>
        .example-btn {
            display: inline-block;
            padding: 1rem 2rem;
            background: linear-gradient(45deg, #28a745, #20c997);
            color: white;
            text-decoration: none;
            border: none;
            border-radius: 12px;
            font-weight: 600;
            font-size: 1.1rem;
            transition: all 0.3s ease;
            box-shadow: 0 6px 20px rgba(40, 167, 69, 0.3);
            text-align: center;
            cursor: pointer;
            min-width: 200px;
        }
        
        .example-btn:hover {
            background: linear-gradient(45deg, #20c997, #17a2b8);
            transform: translateY(-3px);
            box-shadow: 0 8px 25px rgba(40, 167, 69, 0.4);
        }
        
        .modal {
            position: fixed;
            z-index: 1000;
            left: 0;
            top: 0;
            width: 100%;
            height: 100%;
            background-color: rgba(0,0,0,0.5);
        }
        
        .modal-content {
            background-color: #fff;
            margin: 5% auto;
            padding: 2rem;
            border-radius: 12px;
            width: 90%;
            max-width: 800px;
            max-height: 80vh;
            overflow-y: auto;
            box-shadow: 0 20px 40px rgba(0,0,0,0.3);
        }
        
        .close {
            color: #aaa;
            float: right;
            font-size: 28px;
            font-weight: bold;
            cursor: pointer;
        }
        
        .close:hover {
            color: #000;
        }
        
        @media (max-width: 768px) {
            .modal-content {
                width: 95%;
                margin: 10% auto;
                padding: 1rem;
            }
        }
        </style>
        
        <script>
        function showExample() {
            document.getElementById('exampleModal').style.display = 'block';
        }
        
        function closeExample() {
            document.getElementById('exampleModal').style.display = 'none';
        }
        
        // Close modal when clicking outside
        window.onclick = function(event) {
            var modal = document.getElementById('exampleModal');
            if (event.target == modal) {
                modal.style.display = 'none';
            }
        }
        </script>
        """

    # User info section
    user_info = ""
    if user:
        user_info = f"""
        <div class="user-info">
            <span>Welcome, <strong>{user['full_name']}</strong> ({user['email']})</span>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
        """

    form_html = f"""
    {user_info}
    <h1>CVSS v3.1 Evaluation</h1>
    <p style="text-align: center; color: #7f8c8d; margin-bottom: 2rem;">
        Enter the details of a vulnerability and select the appropriate CVSS v3.1 base metrics, or upload a document for automatic analysis.
    </p>
    
    <form method="post" action="/evaluate" enctype="multipart/form-data">
        <h2>Vulnerability Information</h2>
        <label for="title">Title / Description (optional)</label>
        <input type="text" id="title" name="title" placeholder="Example: Remote Code Execution in Module X" />

        <label for="cve_id">CVE ID (optional)</label>
        <input type="text" id="cve_id" name="cve_id" placeholder="Example: CVE-2024-12345" />

        <label for="source">Source (optional)</label>
        <input type="text" id="source" name="source" placeholder="Internal, NVD, etc." />

        {document_upload_section}

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


def render_result(title: str, cve_id: str, source: str, metrics: Dict[str, str], base_score: float, severity: str, vector: str, document_analysis: Dict[str, any] = None) -> bytes:
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
    
    # Document analysis section
    document_section = ""
    if document_analysis and document_analysis.get('success'):
        doc = document_analysis
        document_section = f"""
        <h2>📄 Document Analysis Results</h2>
        <div class="result" style="background: linear-gradient(135deg, #e8f5e8, #d4edda); border-left: 5px solid #28a745;">
            <h3>📋 Extracted Information</h3>
            <div class="table-container">
                <table>
                    <tr><th>Filename</th><td>{doc.get('filename', 'Unknown')}</td></tr>
                    <tr><th>Detected Title</th><td>{doc.get('title', 'Not detected')}</td></tr>
                    <tr><th>Detected CVE ID</th><td>{doc.get('cve_id', 'Not detected')}</td></tr>
                </table>
            </div>
            
            <h3>🔍 Detected CVSS Metrics</h3>
            <div class="table-container">
                <table>
                    <tr><th>Metric</th><th>Detected Value</th><th>Description</th></tr>
                    <tr><td>Attack Vector</td><td>{doc['metrics'].get('AV', 'N/A')}</td><td>{'Network' if doc['metrics'].get('AV') == 'N' else 'Adjacent' if doc['metrics'].get('AV') == 'A' else 'Local' if doc['metrics'].get('AV') == 'L' else 'Physical'}</td></tr>
                    <tr><td>Attack Complexity</td><td>{doc['metrics'].get('AC', 'N/A')}</td><td>{'Low' if doc['metrics'].get('AC') == 'L' else 'High'}</td></tr>
                    <tr><td>Privileges Required</td><td>{doc['metrics'].get('PR', 'N/A')}</td><td>{'None' if doc['metrics'].get('PR') == 'N' else 'Low' if doc['metrics'].get('PR') == 'L' else 'High'}</td></tr>
                    <tr><td>User Interaction</td><td>{doc['metrics'].get('UI', 'N/A')}</td><td>{'None' if doc['metrics'].get('UI') == 'N' else 'Required'}</td></tr>
                    <tr><td>Scope</td><td>{doc['metrics'].get('S', 'N/A')}</td><td>{'Unchanged' if doc['metrics'].get('S') == 'U' else 'Changed'}</td></tr>
                    <tr><td>Confidentiality Impact</td><td>{doc['metrics'].get('C', 'N/A')}</td><td>{'None' if doc['metrics'].get('C') == 'N' else 'Low' if doc['metrics'].get('C') == 'L' else 'High'}</td></tr>
                    <tr><td>Integrity Impact</td><td>{doc['metrics'].get('I', 'N/A')}</td><td>{'None' if doc['metrics'].get('I') == 'N' else 'Low' if doc['metrics'].get('I') == 'L' else 'High'}</td></tr>
                    <tr><td>Availability Impact</td><td>{doc['metrics'].get('A', 'N/A')}</td><td>{'None' if doc['metrics'].get('A') == 'N' else 'Low' if doc['metrics'].get('A') == 'L' else 'High'}</td></tr>
                </table>
            </div>
            
            <h3>📝 Extracted Text (Preview)</h3>
            <div style="background: #f8f9fa; padding: 1rem; border-radius: 8px; max-height: 200px; overflow-y: auto; font-family: monospace; font-size: 0.9rem;">
                {doc.get('text', 'No text extracted')}
            </div>
        </div>
        """
    elif document_analysis and not document_analysis.get('success'):
        document_section = f"""
        <h2>📄 Document Analysis Results</h2>
        <div class="result" style="background: linear-gradient(135deg, #ffeaea, #f8d7da); border-left: 5px solid #dc3545;">
            <h3>❌ Document Processing Error</h3>
            <p><strong>Error:</strong> {document_analysis.get('error', 'Unknown error')}</p>
            <p><strong>Filename:</strong> {document_analysis.get('filename', 'Unknown')}</p>
        </div>
        """

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
    
    {document_section}
    
    <h2>Vulnerability Details</h2>
    <div class="table-container">
    <table>
        <tr><th>Title</th><td>{title or '-'}</td></tr>
        <tr><th>CVE ID</th><td>{cve_id or '-'}</td></tr>
        <tr><th>Source</th><td>{source or '-'}</td></tr>
    </table>
    </div>
    
    <h2>CVSS Base Metrics</h2>
    <div class="table-container">
    <table>
        {rows}
    </table>
    </div>
    
    <div class="nav-links">
        <a href="/">&larr; Evaluate another vulnerability</a>
        <a href="/dashboard">View Dashboard</a>
    </div>
    """
    return html_page("CVSS Result", result_html)


def render_dashboard(counts: Dict[str, int], top_list: List[Dict[str, Any]], user: Dict[str, Any] = None) -> bytes:
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
    <div class="table-container">
    <table>
        <tr><th>ID</th><th>Title</th><th>CVE ID</th><th>Base Score</th><th>Severity</th><th>Created At (UTC)</th></tr>
            {rows if rows else '<tr><td colspan="6" style="text-align: center; color: #7f8c8d;">No evaluations yet.</td></tr>'}
    </table>
    </div>
    """
    
    # User info and logout button
    user_info = ""
    if user:
        user_info = f"""
        <div class="user-info">
            <span>Welcome, <strong>{user['full_name']}</strong> ({user['email']})</span>
            <a href="/logout" class="logout-btn">Logout</a>
        </div>
        """
    
    dashboard_html = f"""
    {user_info}
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

    def get_session_token(self) -> Optional[str]:
        """Extract session token from cookies."""
        cookie_header = self.headers.get('Cookie', '')
        if not cookie_header:
            return None
        
        for cookie in cookie_header.split(';'):
            cookie = cookie.strip()
            if cookie.startswith('session_token='):
                return cookie.split('=', 1)[1]
        return None

    def get_current_user(self) -> Optional[Dict[str, Any]]:
        """Get current authenticated user from session."""
        session_token = self.get_session_token()
        if not session_token:
            return None
        return self.auth_manager.validate_session(session_token)

    def require_auth(self) -> Optional[Dict[str, Any]]:
        """Check if user is authenticated, redirect to login if not."""
        user = self.get_current_user()
        if not user:
            self.send_redirect('/login')
            return None
        return user

    def send_redirect(self, location: str) -> None:
        """Send a redirect response."""
        self.send_response(302)
        self.send_header('Location', location)
        self.end_headers()

    def send_json(self, data: Any, status: int = 200) -> None:
        """Send a JSON response."""
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)
    
    def generate_cvss_example_pdf(self) -> bytes:
        """Generate a PDF example document for CVSS analysis."""
        # Create a simple PDF-like structure using text formatting
        # In a full implementation, you'd use a library like reportlab or fpdf
        
        example_text = """CVSS Analysis Example Document
===============================

VULNERABILITY TITLE
==================
Remote Code Execution in Web Application

CVE ID
======
CVE-2024-12345

DESCRIPTION
===========
This critical vulnerability allows remote attackers to execute arbitrary code 
over the network without requiring any user interaction. The attack complexity 
is low and requires no privileges. The vulnerability has high impact on 
confidentiality, integrity, and availability.

TECHNICAL DETAILS
=================
Attack Vector: Network
- The vulnerability is accessible over the network
- Attackers can exploit this remotely without physical access
- No local system access is required

Attack Complexity: Low
- The attack is simple to execute
- Exploitation requires minimal technical skill
- No complex conditions need to be met

Privileges Required: None
- No authentication is required
- No user privileges are needed
- Attackers can exploit this anonymously

User Interaction: None
- No user action is required
- The attack can be executed automatically
- Users don't need to click or interact

Scope: Changed
- The vulnerability affects different components
- Exploitation impacts other parts of the system
- The scope extends beyond the vulnerable component

Impact Assessment:
- Confidentiality: High - Complete data disclosure is possible
- Integrity: High - Data can be completely modified
- Availability: High - Service disruption is complete

CVSS METRICS DETECTED
======================
Attack Vector: N (Network)
Attack Complexity: L (Low)
Privileges Required: N (None)
User Interaction: N (None)
Scope: C (Changed)
Confidentiality Impact: H (High)
Integrity Impact: H (High)
Availability Impact: H (High)

EXPECTED RESULT
==============
Base Score: 9.8 (Critical)
Vector String: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

TIPS FOR BETTER DETECTION
=========================
1. Use clear, specific terms from the CVSS specification
2. Avoid ambiguous language like "medium" or "some"
3. Include technical details about the attack method
4. Describe the impact clearly and specifically
5. Mention the scope of the vulnerability
6. Use consistent terminology throughout

EXAMPLE PHRASES THAT WORK WELL:
- "This vulnerability allows remote attackers to execute code over the network"
- "The attack complexity is low and simple to exploit"
- "No privileges are required for exploitation"
- "No user interaction is needed"
- "The scope is changed and affects different components"
- "This results in complete data disclosure"
- "The vulnerability has high impact on confidentiality, integrity, and availability"

This document demonstrates the proper structure and terminology needed for 
accurate CVSS metric detection. Copy this format and modify the content 
for your specific vulnerability analysis.
"""
        
        # For now, return the text as bytes (in a real implementation, this would be actual PDF content)
        # Users can copy this text and create their own documents
        return example_text.encode('utf-8')

    def render_login_page(self) -> bytes:
        """Render the login page."""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVSS Server - Login</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        
        .login-container {{
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }}
        
        .logo {{
            text-align: center;
            margin-bottom: 30px;
        }}
        
        .logo h1 {{
            color: #333;
            font-size: 2rem;
            margin-bottom: 10px;
        }}
        
        .logo p {{
            color: #666;
            font-size: 0.9rem;
        }}
        
        .form-group {{
            margin-bottom: 20px;
        }}
        
        .form-group label {{
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }}
        
        .form-group input {{
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }}
        
        .form-group input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        .btn {{
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease;
        }}
        
        .btn:hover {{
            transform: translateY(-2px);
        }}
        
        .register-link {{
            text-align: center;
            margin-top: 20px;
        }}
        
        .register-link a {{
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }}
        
        .register-link a:hover {{
            text-decoration: underline;
        }}
        
        .error {{
            background: #fee;
            color: #c33;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid #fcc;
        }}
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h1>🔒 CVSS Server</h1>
            <p>Sign in to your account</p>
        </div>
        
        <form method="POST" action="/login">
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">Sign In</button>
        </form>
        
        <div class="register-link">
            <p>Don't have an account? <a href="/register">Sign up here</a></p>
        </div>
    </div>
</body>
</html>
        """
        return html.encode('utf-8')

    def render_register_page(self) -> bytes:
        """Render the registration page."""
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CVSS Server - Register</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }}
        
        .register-container {{
            background: white;
            padding: 40px;
            border-radius: 20px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            width: 100%;
            max-width: 400px;
        }}
        
        .logo {{
            text-align: center;
            margin-bottom: 30px;
        }}
        
        .logo h1 {{
            color: #333;
            font-size: 2rem;
            margin-bottom: 10px;
        }}
        
        .logo p {{
            color: #666;
            font-size: 0.9rem;
        }}
        
        .form-group {{
            margin-bottom: 20px;
        }}
        
        .form-group label {{
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
        }}
        
        .form-group input {{
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e1e5e9;
            border-radius: 10px;
            font-size: 1rem;
            transition: border-color 0.3s ease;
        }}
        
        .form-group input:focus {{
            outline: none;
            border-color: #667eea;
        }}
        
        .btn {{
            width: 100%;
            padding: 12px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            border-radius: 10px;
            font-size: 1rem;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s ease;
        }}
        
        .btn:hover {{
            transform: translateY(-2px);
        }}
        
        .login-link {{
            text-align: center;
            margin-top: 20px;
        }}
        
        .login-link a {{
            color: #667eea;
            text-decoration: none;
            font-weight: 500;
        }}
        
        .login-link a:hover {{
            text-decoration: underline;
        }}
        
        .error {{
            background: #fee;
            color: #c33;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid #fcc;
        }}
        
        .success {{
            background: #efe;
            color: #3c3;
            padding: 10px;
            border-radius: 8px;
            margin-bottom: 20px;
            border: 1px solid #cfc;
        }}
    </style>
</head>
<body>
    <div class="register-container">
        <div class="logo">
            <h1>🔒 CVSS Server</h1>
            <p>Create your account</p>
        </div>
        
        <form method="POST" action="/register">
            <div class="form-group">
                <label for="full_name">Full Name</label>
                <input type="text" id="full_name" name="full_name" required>
            </div>
            
            <div class="form-group">
                <label for="email">Email Address</label>
                <input type="email" id="email" name="email" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required minlength="6">
            </div>
            
            <div class="form-group">
                <label for="confirm_password">Confirm Password</label>
                <input type="password" id="confirm_password" name="confirm_password" required minlength="6">
            </div>
            
            <button type="submit" class="btn">Create Account</button>
        </form>
        
        <div class="login-link">
            <p>Already have an account? <a href="/login">Sign in here</a></p>
        </div>
    </div>
</body>
</html>
        """
        return html.encode('utf-8')

    def do_GET(self) -> None:
        """Handle GET requests based on the request path."""
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        
        # Authentication routes (public)
        if path == "/login":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            login_page = self.render_login_page()
            self.send_header("Content-Length", str(len(login_page)))
            self.end_headers()
            self.wfile.write(login_page)
        elif path == "/register":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            register_page = self.render_register_page()
            self.send_header("Content-Length", str(len(register_page)))
            self.end_headers()
            self.wfile.write(register_page)
        elif path == "/logout":
            # Logout user and redirect to login
            session_token = self.get_session_token()
            if session_token:
                self.auth_manager.logout_user(session_token)
            self.send_redirect('/login')
        
        # Protected routes (require authentication)
        elif path == "/" or path == "/evaluate":
            user = self.require_auth()
            if not user:
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            form = render_form(user)
            self.send_header("Content-Length", str(len(form)))
            self.end_headers()
            self.wfile.write(form)
        elif path == "/dashboard":
            user = self.require_auth()
            if not user:
                return
            counts, top_list = summary_counts_and_top(DB_PATH, user['user_id'])
            page = render_dashboard(counts, top_list, user)
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
        elif path == "/download-example":
            # Download CVSS analysis example PDF
            pdf_content = self.generate_cvss_example_pdf()
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Disposition", "attachment; filename=CVSS_Analysis_Example.pdf")
            self.send_header("Content-Length", str(len(pdf_content)))
            self.end_headers()
            self.wfile.write(pdf_content)
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
        
        # Handle authentication routes
        if path == "/login":
            self.handle_login()
            return
        elif path == "/register":
            self.handle_register()
            return
        elif path == "/evaluate":
            # Require authentication for evaluation
            user = self.require_auth()
            if not user:
                return
            self.handle_evaluation(user)
            return
        else:
            self.send_response(404)
            self.end_headers()
            return

    def handle_login(self) -> None:
        """Handle user login."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            form_data = urllib.parse.parse_qs(post_data.decode('utf-8'))
            
            email = form_data.get('email', [''])[0]
            password = form_data.get('password', [''])[0]
            
            if not email or not password:
                self.send_redirect('/login?error=missing_fields')
                return
            
            result = self.auth_manager.authenticate_user(email, password)
            
            if result['success']:
                # Set session cookie and redirect to dashboard
                self.send_response(302)
                self.send_header('Set-Cookie', f'session_token={result["session_token"]}; HttpOnly; Path=/; Max-Age=604800')
                self.send_header('Location', '/dashboard')
                self.end_headers()
            else:
                self.send_redirect(f'/login?error={result["error"]}')
                
        except Exception as e:
            print(f"Login error: {e}")
            self.send_redirect('/login?error=server_error')

    def handle_register(self) -> None:
        """Handle user registration."""
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            post_data = self.rfile.read(content_length)
            form_data = urllib.parse.parse_qs(post_data.decode('utf-8'))
            
            full_name = form_data.get('full_name', [''])[0]
            email = form_data.get('email', [''])[0]
            password = form_data.get('password', [''])[0]
            confirm_password = form_data.get('confirm_password', [''])[0]
            
            if not all([full_name, email, password, confirm_password]):
                self.send_redirect('/register?error=missing_fields')
                return
            
            if password != confirm_password:
                self.send_redirect('/register?error=password_mismatch')
                return
            
            if len(password) < 6:
                self.send_redirect('/register?error=password_too_short')
                return
            
            result = self.auth_manager.register_user(email, password, full_name)
            
            if result['success']:
                self.send_redirect('/login?success=registered')
            else:
                self.send_redirect(f'/register?error={result["error"]}')
                
        except Exception as e:
            print(f"Registration error: {e}")
            self.send_redirect('/register?error=server_error')

    def handle_evaluation(self, user: Dict[str, Any]) -> None:
        
        # Check if this is a multipart form (file upload)
        content_type = self.headers.get("Content-Type", "")
        document_analysis = None
        
        if "multipart/form-data" in content_type:
            # Handle file upload
            try:
                # Parse multipart form data
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length)
                
                # Parse multipart data manually (simplified)
                boundary = content_type.split("boundary=")[1]
                parts = post_data.split(b"--" + boundary.encode())
                
                form_data = {}
                uploaded_file = None
                filename = None
                
                for part in parts:
                    if b"Content-Disposition: form-data" in part:
                        # Extract field name and value
                        if b'name="' in part:
                            name_start = part.find(b'name="') + 6
                            name_end = part.find(b'"', name_start)
                            field_name = part[name_start:name_end].decode()
                            
                            # Check if it's a file field
                            if b'filename="' in part:
                                # This is a file upload
                                filename_start = part.find(b'filename="') + 10
                                filename_end = part.find(b'"', filename_start)
                                filename = part[filename_start:filename_end].decode()
                                
                                # Extract file content
                                content_start = part.find(b'\r\n\r\n') + 4
                                content_end = part.rfind(b'\r\n')
                                if content_end > content_start:
                                    file_content = part[content_start:content_end]
                                    uploaded_file = file_content
                            else:
                                # This is a regular form field
                                value_start = part.find(b'\r\n\r\n') + 4
                                value_end = part.rfind(b'\r\n')
                                if value_end > value_start:
                                    field_value = part[value_start:value_end].decode()
                                    form_data[field_name] = field_value
                
                # Process uploaded document if present
                if uploaded_file and filename and document_processor:
                    try:
                        document_analysis = document_processor.process_document(uploaded_file, filename)
                        if document_analysis.get('success'):
                            # Pre-fill form with detected values
                            detected_metrics = document_analysis['metrics']
                            print(f"🔍 DEBUG - Document metrics detected: {detected_metrics}")
                            
                            for key in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
                                # Always use detected values if available, regardless of form_data
                                if key in detected_metrics:
                                    form_data[key] = detected_metrics[key]
                                    print(f"✅ DEBUG - Set {key} = {detected_metrics[key]}")
                                else:
                                    print(f"❌ DEBUG - No detection for {key}")
                            
                            print(f"🔍 DEBUG - Final form_data: {form_data}")
                            
                            # Pre-fill other fields
                            if document_analysis.get('title'):
                                form_data['title'] = document_analysis['title']
                            if document_analysis.get('cve_id'):
                                form_data['cve_id'] = document_analysis['cve_id']
                    except Exception as e:
                        print(f"❌ DEBUG - Error processing document: {e}")
                        document_analysis = {
                            'success': False,
                            'error': str(e),
                            'filename': filename
                        }
                
            except Exception as e:
                # Fallback to regular form processing
                content_length = int(self.headers.get("Content-Length", 0))
                post_data = self.rfile.read(content_length)
                form_data = urllib.parse.parse_qs(post_data.decode("utf-8"))
        else:
            # Regular form data (no file upload)
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            form_data = urllib.parse.parse_qs(post_data.decode("utf-8"))

        def get_value(key: str) -> str:
            return form_data.get(key, [""])[0]

        # Extract metrics and metadata
        metrics = {}
        for key in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
            metrics[key] = get_value(key)
            print(f"🔍 DEBUG - Final metric {key}: {metrics[key]}")
        
        title = get_value("title").strip()
        cve_id = get_value("cve_id").strip()
        source = get_value("source").strip()
        
        print(f"🔍 DEBUG - Final metrics for calculation: {metrics}")

        # Compute base score
        base_score, severity, vector = calculate_base_score(metrics)
        # Persist record
        eval_id = insert_evaluation(
            DB_PATH, title, cve_id, source, metrics, vector, base_score, severity, user['user_id']
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
            document_analysis
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
    print(f"🚀 Starting CVSS Server...")
    print(f"📡 Host: {host}")
    print(f"🔌 Port: {port}")
    print(f"🗄️  Database: {DB_PATH}")
    
    # Ensure database directory exists
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    init_db(DB_PATH)
    
    server_address = (host, port)
    with http.server.ThreadingHTTPServer(server_address, CVSSRequestHandler) as httpd:
        print(f"✅ CVSS Server running at http://{host}:{port}/")
        print(f"🔐 Authentication system enabled")
        print(f"📄 Document processing enabled")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n🛑 Server shutting down...")
        except Exception as e:
            print(f"❌ Server error: {e}")
            raise


if __name__ == "__main__":
    run_server()