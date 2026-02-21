from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import random
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = "quickconnect-secret-key-change-in-production"

DB = "quickconnect.db"

# ─── DB Schema (matches actual QuickConnectDB.xlsx) ───────────────────────────
#
# users:            id, name, phone, password, role, verified, created_at, job
# jobs:             id, client_id, worker_id, service, otp_start, otp_end, status, created_at
# ratings:          id, job_id, client_id, worker_id, rating, feedback, created_at
# sos_logs:         id, user_id, role, job_id, message, timestamp
# worker_documents: id, worker_id, id_proof, skill_proof, photo, status, submitted_at

def get_db():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS users (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                name       TEXT    NOT NULL,
                phone      TEXT    NOT NULL UNIQUE,
                password   TEXT    NOT NULL,
                role       TEXT    NOT NULL CHECK(role IN ('client','worker')),
                verified   INTEGER DEFAULT 0,
                created_at TEXT    DEFAULT (datetime('now')),
                job        TEXT
            );

            CREATE TABLE IF NOT EXISTS jobs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                client_id  INTEGER NOT NULL,
                worker_id  INTEGER NOT NULL,
                service    TEXT    NOT NULL,
                otp_start  TEXT,
                otp_end    TEXT,
                status     TEXT    DEFAULT 'booked',
                created_at TEXT    DEFAULT (datetime('now')),
                FOREIGN KEY(client_id) REFERENCES users(id),
                FOREIGN KEY(worker_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS ratings (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id     INTEGER NOT NULL,
                client_id  INTEGER NOT NULL,
                worker_id  INTEGER NOT NULL,
                rating     INTEGER NOT NULL CHECK(rating BETWEEN 1 AND 5),
                feedback   TEXT,
                created_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(job_id)    REFERENCES jobs(id),
                FOREIGN KEY(client_id) REFERENCES users(id),
                FOREIGN KEY(worker_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sos_logs (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id   INTEGER NOT NULL,
                role      TEXT    NOT NULL,
                job_id    TEXT,
                message   TEXT,
                timestamp TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS worker_documents (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                worker_id    INTEGER NOT NULL,
                id_proof     TEXT,
                skill_proof  TEXT,
                photo        TEXT,
                status       TEXT DEFAULT 'pending',
                submitted_at TEXT DEFAULT (datetime('now')),
                FOREIGN KEY(worker_id) REFERENCES users(id)
            );
        """)

init_db()

# ─── Helpers ──────────────────────────────────────────────────────────────────

def generate_otp():
    return str(random.randint(100000, 999999))

def get_worker_stats(worker_id):
    """Compute jobs_done and avg rating from the ratings table."""
    with get_db() as conn:
        row = conn.execute(
            """SELECT COUNT(*) AS jobs_done, ROUND(AVG(rating), 1) AS avg_rating
               FROM ratings WHERE worker_id = ?""",
            (worker_id,)
        ).fetchone()
    return row["jobs_done"], row["avg_rating"] or 0

def login_required(role=None):
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if "user_id" not in session:
                flash("Please log in first.", "error")
                return redirect(url_for("login"))
            if role and session.get("role") != role:
                flash("Access denied.", "error")
                return redirect(url_for("login"))
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ─── Auth Routes ──────────────────────────────────────────────────────────────

@app.route("/")
@app.route("/home")
def home():
    if "user_id" in session:
        return redirect(url_for("client_dashboard") if session["role"] == "client"
                        else url_for("worker_dashboard"))
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        phone    = request.form["phone"].strip()
        password = request.form["password"]

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE phone = ?", (phone,)
            ).fetchone()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["name"]    = user["name"]
            session["role"]    = user["role"]
            return redirect(url_for("client_dashboard") if user["role"] == "client"
                            else url_for("worker_dashboard"))

        flash("Invalid phone number or password.", "error")
        return redirect(url_for("login"))

    return render_template("login.html")

@app.route("/register", defaults={"role": "client"}, methods=["GET", "POST"])
@app.route("/register/<role>", methods=["GET", "POST"])
def register(role):
    if role not in ("client", "worker"):
        role = "client"

    if request.method == "POST":
        name     = request.form["name"].strip()
        phone    = request.form["phone"].strip()
        password = generate_password_hash(request.form["password"])
        job      = request.form.get("job", "").strip() if role == "worker" else None

        try:
            with get_db() as conn:
                conn.execute(
                    """INSERT INTO users (name, phone, password, role, verified, created_at, job)
                       VALUES (?, ?, ?, ?, 0, ?, ?)""",
                    (name, phone, password, role, datetime.now().isoformat(), job)
                )
            flash("Registration successful! Please log in.", "success")
            return redirect(url_for("login"))
        except Exception as e:
            if "UNIQUE" in str(e):
                flash("Phone number already registered.", "error")
            else:
                flash(f"Registration failed: {e}", "error")
            return redirect(url_for("register", role=role))

    return render_template("register.html", role=role)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

# ─── Client Routes ────────────────────────────────────────────────────────────

@app.route("/client_dashboard")
@login_required(role="client")
def client_dashboard():
    return render_template("client_dashboard.html")

@app.route("/search_workers", methods=["POST"])
@login_required(role="client")
def search_workers():
    service = request.form.get("service", "").strip()

    if not service:
        flash("Please enter a service to search.", "error")
        return redirect(url_for("client_dashboard"))

    with get_db() as conn:
        workers_raw = conn.execute(
            """SELECT * FROM users
               WHERE role = 'worker'
                 AND job IS NOT NULL
                 AND job != ''
                 AND lower(job) LIKE lower(?)""",
            (f"%{service}%",)
        ).fetchall()

    # Enrich each worker with computed stats
    workers = []
    for w in workers_raw:
        jobs_done, avg_rating = get_worker_stats(w["id"])
        workers.append({
            "id":        w["id"],
            "name":      w["name"],
            "phone":     w["phone"],
            "job":       w["job"],
            "verified":  w["verified"],
            "jobs_done": jobs_done,
            "rating":    avg_rating,
        })

    return render_template("search_workers.html", workers=workers, service=service)

@app.route("/select_worker", methods=["POST"])
@login_required(role="client")
def select_worker():
    worker_id = request.form.get("worker_id")
    service   = request.form.get("service", "").strip()

    with get_db() as conn:
        worker = conn.execute(
            "SELECT * FROM users WHERE id = ? AND role = 'worker'", (worker_id,)
        ).fetchone()

        if not worker:
            flash("Worker not found.", "error")
            return redirect(url_for("client_dashboard"))

        otp_start = generate_otp()
        otp_end   = generate_otp()

        conn.execute(
            """INSERT INTO jobs (client_id, worker_id, service, otp_start, otp_end, status, created_at)
               VALUES (?, ?, ?, ?, ?, 'booked', ?)""",
            (session["user_id"], worker_id, service, otp_start, otp_end,
             datetime.now().isoformat())
        )

    jobs_done, avg_rating = get_worker_stats(worker_id)
    worker_data = {
        "name":      worker["name"],
        "phone":     worker["phone"],
        "job":       worker["job"],
        "jobs_done": jobs_done,
        "rating":    avg_rating,
    }
    return render_template("match.html", worker=worker_data, otp=otp_start)

# ─── Worker Routes ────────────────────────────────────────────────────────────

@app.route("/worker_dashboard")
@login_required(role="worker")
def worker_dashboard():
    jobs_done, avg_rating = get_worker_stats(session["user_id"])
    return render_template("worker_dashboard.html",
                           jobs_done=jobs_done, avg_rating=avg_rating)

@app.route("/my_jobs")
@login_required(role="worker")
def my_jobs():
    with get_db() as conn:
        jobs = conn.execute(
            """SELECT j.*, u.name AS client_name
               FROM jobs j
               JOIN users u ON j.client_id = u.id
               WHERE j.worker_id = ?
               ORDER BY j.created_at DESC""",
            (session["user_id"],)
        ).fetchall()
    return render_template("worker_jobs.html", jobs=jobs)

@app.route("/complete_job/<int:job_id>", methods=["POST"])
@login_required(role="worker")
def complete_job(job_id):
    otp_end  = request.form.get("otp_end", "").strip()
    rating   = request.form.get("rating")
    feedback = request.form.get("feedback", "").strip()

    with get_db() as conn:
        job = conn.execute(
            "SELECT * FROM jobs WHERE id = ? AND worker_id = ?",
            (job_id, session["user_id"])
        ).fetchone()

        if not job:
            flash("Job not found.", "error")
            return redirect(url_for("my_jobs"))

        if job["otp_end"] != otp_end:
            flash("Invalid completion OTP.", "error")
            return redirect(url_for("my_jobs"))

        if job["status"] == "completed":
            flash("This job is already completed.", "error")
            return redirect(url_for("my_jobs"))

        conn.execute(
            "UPDATE jobs SET status = 'completed' WHERE id = ?", (job_id,)
        )

        if rating:
            conn.execute(
                """INSERT INTO ratings (job_id, client_id, worker_id, rating, feedback, created_at)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (job_id, job["client_id"], session["user_id"],
                 int(rating), feedback, datetime.now().isoformat())
            )

    jobs_done, avg_rating = get_worker_stats(session["user_id"])
    return render_template("success.html",
                           worker={"jobs_done": jobs_done, "rating": avg_rating})

# ─── SOS Route ────────────────────────────────────────────────────────────────

@app.route("/sos", methods=["POST"])
@login_required()
def sos():
    job_id  = request.form.get("job_id", "")
    message = request.form.get("message", "SOS Triggered")

    with get_db() as conn:
        conn.execute(
            """INSERT INTO sos_logs (user_id, role, job_id, message, timestamp)
               VALUES (?, ?, ?, ?, ?)""",
            (session["user_id"], session["role"], job_id,
             message, datetime.now().isoformat())
        )

    flash("SOS alert sent! Our team has been notified.", "success")
    if session.get("role") == "worker":
        return redirect(url_for("worker_dashboard"))
    return redirect(url_for("client_dashboard"))

if __name__ == "__main__":
    app.run(debug=True)
