"""
CyberPhish - Phishing URL Detection Web App
--------------------------------------------
A Flask application that lets authenticated analysts:
  - log in / log out
  - view a dashboard of scan statistics
  - check a single URL, or upload a CSV of URLs, for phishing detection
  - view/download a report of past scan results

The ML model (model.pkl / vectorizer.pkl) is produced by models/train_model.py
and consumed here to classify URLs as 'phishing' or 'legitimate'.
"""

import os
import io
import re
import csv
import sqlite3
import pickle
import uuid
from datetime import datetime

from pypdf import PdfReader
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter, landscape
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer

from flask import (
    Flask, render_template, request, redirect, url_for,
    session, flash, send_file, g
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "database", "phishing.db")
SCHEMA_PATH = os.path.join(BASE_DIR, "database", "phishing.sql")
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")
VECTORIZER_PATH = os.path.join(BASE_DIR, "vectorizer.pkl")
ALLOWED_EXTENSIONS = {"csv", "pdf"}
URL_REGEX = re.compile(r"(?:https?://|www\.)[^\s\"'<>\)\]]+", re.IGNORECASE)

app = Flask(__name__)
app.secret_key = os.environ.get("CYBERPHISH_SECRET_KEY", "dev-secret-change-me")
app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024  # 5 MB upload limit

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------
def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    first_time = not os.path.exists(DB_PATH)
    db = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH, "r") as f:
        db.executescript(f.read())
    db.commit()

    # Seed a default admin account if no users exist yet.
    cur = db.execute("SELECT COUNT(*) FROM users")
    if cur.fetchone()[0] == 0:
        db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", generate_password_hash("admin123"), "admin"),
        )
        db.commit()
        print("Seeded default account -> username: admin / password: admin123")
    db.close()
    return first_time


# ---------------------------------------------------------------------------
# ML model loading
# ---------------------------------------------------------------------------
_model = None
_vectorizer = None


def load_model():
    """Lazily load the pickled model + vectorizer. Returns (model, vectorizer)
    or (None, None) if artifacts haven't been trained yet."""
    global _model, _vectorizer
    if _model is None or _vectorizer is None:
        if os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH):
            with open(MODEL_PATH, "rb") as f:
                _model = pickle.load(f)
            with open(VECTORIZER_PATH, "rb") as f:
                _vectorizer = pickle.load(f)
    return _model, _vectorizer


def classify_url(url):
    """Returns (label, confidence) where label in {'phishing','legitimate'}."""
    model, vectorizer = load_model()
    if model is None or vectorizer is None:
        raise RuntimeError(
            "Model not found. Run `python models/train_model.py` first "
            "to generate model.pkl and vectorizer.pkl."
        )
    X = vectorizer.transform([url])
    pred = model.predict(X)[0]
    proba = model.predict_proba(X)[0]
    label = "phishing" if pred == 1 else "legitimate"
    confidence = float(proba[pred])
    return label, confidence


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------
def login_required(view):
    from functools import wraps

    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            flash("Please log in to continue.", "warning")
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped


def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS


def file_ext(filename):
    return filename.rsplit(".", 1)[1].lower() if "." in filename else ""


def extract_urls_from_pdf(path):
    """Pull every http(s)/www URL out of a PDF's text layer, de-duplicated
    but order-preserving."""
    reader = PdfReader(path)
    text = "\n".join(page.extract_text() or "" for page in reader.pages)
    found = URL_REGEX.findall(text)
    seen = set()
    urls = []
    for u in found:
        u = u.rstrip(".,;:!?")  # trim trailing punctuation caught by the regex
        if u not in seen:
            seen.add(u)
            urls.append(u)
    return urls


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route("/")
def index():
    return redirect(url_for("dashboard") if session.get("user_id") else url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        db = get_db()
        user = db.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

        if user and check_password_hash(user["password_hash"], password):
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash(f"Welcome back, {user['username']}!", "success")
            return redirect(url_for("dashboard"))

        flash("Invalid username or password.", "danger")

    return render_template("login.html")


@app.route("/logout")
def logout():
    session.clear()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = get_db()
    user_id = session["user_id"]

    total_scans = db.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id = ?", (user_id,)
    ).fetchone()[0]

    phishing_count = db.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id = ? AND prediction = 'phishing'",
        (user_id,),
    ).fetchone()[0]

    legit_count = total_scans - phishing_count

    recent = db.execute(
        """SELECT url, prediction, confidence, scanned_at
           FROM scan_history WHERE user_id = ?
           ORDER BY scanned_at DESC LIMIT 10""",
        (user_id,),
    ).fetchall()

    model_ready = os.path.exists(MODEL_PATH) and os.path.exists(VECTORIZER_PATH)

    return render_template(
        "dashboard.html",
        total_scans=total_scans,
        phishing_count=phishing_count,
        legit_count=legit_count,
        recent=recent,
        model_ready=model_ready,
    )


@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():
    db = get_db()
    user_id = session["user_id"]

    if request.method == "POST":
        model, vectorizer = load_model()
        if model is None:
            flash("Model not trained yet. Run models/train_model.py first.", "danger")
            return redirect(url_for("upload"))

        # --- Single URL check ---
        single_url = request.form.get("single_url", "").strip()
        if single_url:
            label, confidence = classify_url(single_url)
            db.execute(
                """INSERT INTO scan_history (user_id, url, prediction, confidence, source)
                   VALUES (?, ?, ?, ?, 'manual')""",
                (user_id, single_url, label, confidence),
            )
            db.commit()
            flash(f'"{single_url}" classified as {label.upper()} '
                  f"({confidence*100:.1f}% confidence)",
                  "danger" if label == "phishing" else "success")
            return redirect(url_for("upload"))

        # --- Bulk upload: CSV or PDF ---
        file = request.files.get("csv_file")
        if file and file.filename and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            ext = file_ext(filename)
            batch_id = uuid.uuid4().hex[:12]
            saved_name = f"{batch_id}_{filename}"
            save_path = os.path.join(UPLOAD_DIR, saved_name)
            file.save(save_path)

            # Gather candidate URLs depending on file type.
            url_list = []
            if ext == "csv":
                with open(save_path, newline="", encoding="utf-8", errors="ignore") as f:
                    reader = csv.reader(f)
                    for row in reader:
                        if not row:
                            continue
                        url_val = row[0].strip()
                        if not url_val or url_val.lower() in ("url", "urls"):
                            continue  # skip header / blank lines
                        url_list.append(url_val)
            elif ext == "pdf":
                try:
                    url_list = extract_urls_from_pdf(save_path)
                except Exception as e:
                    flash(f"Could not read PDF: {e}", "danger")
                    return redirect(url_for("upload"))
                if not url_list:
                    flash(
                        "No URLs were found in that PDF's text. If it's a "
                        "scanned/image-only PDF, text can't be extracted from it.",
                        "warning",
                    )
                    return redirect(url_for("upload"))

            row_count = 0
            phishing_hits = 0
            for url_val in url_list:
                label, confidence = classify_url(url_val)
                if label == "phishing":
                    phishing_hits += 1
                row_count += 1
                db.execute(
                    """INSERT INTO scan_history
                       (user_id, url, prediction, confidence, source, batch_id)
                       VALUES (?, ?, ?, ?, 'upload', ?)""",
                    (user_id, url_val, label, confidence, batch_id),
                )

            db.execute(
                """INSERT INTO uploads
                   (user_id, batch_id, filename, row_count, phishing_count)
                   VALUES (?, ?, ?, ?, ?)""",
                (user_id, batch_id, filename, row_count, phishing_hits),
            )
            db.commit()
            flash(
                f"Processed {row_count} URLs from {filename}: "
                f"{phishing_hits} flagged as phishing.",
                "info",
            )
            return redirect(url_for("report", batch_id=batch_id))
        else:
            flash("Please provide a URL or upload a valid .csv or .pdf file.", "warning")

    return render_template("upload.html")


@app.route("/report")
@login_required
def report():
    db = get_db()
    user_id = session["user_id"]
    batch_id = request.args.get("batch_id")

    if batch_id:
        rows = db.execute(
            """SELECT url, prediction, confidence, scanned_at
               FROM scan_history WHERE user_id = ? AND batch_id = ?
               ORDER BY scanned_at DESC""",
            (user_id, batch_id),
        ).fetchall()
    else:
        rows = db.execute(
            """SELECT url, prediction, confidence, scanned_at
               FROM scan_history WHERE user_id = ?
               ORDER BY scanned_at DESC LIMIT 200""",
            (user_id,),
        ).fetchall()

    batches = db.execute(
        """SELECT batch_id, filename, row_count, phishing_count, uploaded_at
           FROM uploads WHERE user_id = ? ORDER BY uploaded_at DESC""",
        (user_id,),
    ).fetchall()

    return render_template("report.html", rows=rows, batches=batches, active_batch=batch_id)


def _get_report_rows(user_id, batch_id):
    db = get_db()
    if batch_id:
        return db.execute(
            """SELECT url, prediction, confidence, scanned_at
               FROM scan_history WHERE user_id = ? AND batch_id = ?
               ORDER BY scanned_at DESC""",
            (user_id, batch_id),
        ).fetchall()
    return db.execute(
        """SELECT url, prediction, confidence, scanned_at
           FROM scan_history WHERE user_id = ?
           ORDER BY scanned_at DESC""",
        (user_id,),
    ).fetchall()


@app.route("/report/download")
@app.route("/report/download/pdf")
@login_required
def download_report_pdf():
    user_id = session["user_id"]
    batch_id = request.args.get("batch_id")
    rows = _get_report_rows(user_id, batch_id)

    mem = io.BytesIO()
    doc = SimpleDocTemplate(
        mem,
        pagesize=landscape(letter),
        title="CyberPhish Report",
        topMargin=36, bottomMargin=36, leftMargin=36, rightMargin=36,
    )
    styles = getSampleStyleSheet()
    elements = [
        Paragraph("CyberPhish Scan Report", styles["Title"]),
        Paragraph(
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
            + (f" &nbsp;|&nbsp; Batch: {batch_id}" if batch_id else ""),
            styles["Normal"],
        ),
        Spacer(1, 12),
    ]

    table_data = [["URL", "Prediction", "Risk %", "Scanned At"]]
    for r in rows:
        table_data.append([r["url"], r["prediction"], f'{r["confidence"] * 100:.1f}%', r["scanned_at"]])

    table = Table(table_data, repeatRows=1, colWidths=[320, 90, 80, 130])
    style_commands = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#d1d5db")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#f3f4f6")]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]
    # Color the Prediction and Risk % columns by result (red = phishing, green = legitimate)
    for i, r in enumerate(rows, start=1):
        risk_color = colors.HexColor("#dc2626") if r["prediction"] == "phishing" else colors.HexColor("#16a34a")
        style_commands.append(("TEXTCOLOR", (1, i), (2, i), risk_color))
        style_commands.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
    table.setStyle(TableStyle(style_commands))
    elements.append(table)
    doc.build(elements)

    mem.seek(0)
    fname = f"cyberphish_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    return send_file(mem, mimetype="application/pdf", as_attachment=True, download_name=fname)


@app.route("/report/download/csv")
@login_required
def download_report_csv():
    user_id = session["user_id"]
    batch_id = request.args.get("batch_id")
    rows = _get_report_rows(user_id, batch_id)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["URL", "Prediction", "Risk %", "Scanned At"])
    for r in rows:
        writer.writerow([r["url"], r["prediction"], f'{r["confidence"] * 100:.1f}%', r["scanned_at"]])

    mem = io.BytesIO(buffer.getvalue().encode("utf-8"))
    mem.seek(0)
    fname = f"cyberphish_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return send_file(mem, mimetype="text/csv", as_attachment=True, download_name=fname)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
# Runs on import too (not just `python app.py`) so gunicorn/production
# servers also get the DB created and seeded.
init_db()

if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "1") == "1"
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=debug_mode, host="0.0.0.0", port=port)
