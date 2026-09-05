"""
app.py
------

SecureVote
OTP-Authenticated Blockchain Online Voting System

Run:
    python app.py

Open:
    http://127.0.0.1:5000

Environment variables supported:

    FLASK_SECRET_KEY
    FLASK_DEBUG

    ADMIN_USERNAME
    ADMIN_PASSWORD

    SMTP_HOST
    SMTP_PORT
    SMTP_USER
    SMTP_PASS

Without SMTP configuration, SecureVote runs in DEV MODE
and displays OTPs on-screen and in the terminal.
"""

import hashlib
import os
import secrets
import smtplib
import sqlite3
import time

from email.message import EmailMessage
from functools import wraps
from pathlib import Path

from cryptography.fernet import Fernet

from flask import (
    Flask,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)

from flask_wtf.csrf import (
    CSRFError,
    CSRFProtect,
)

from werkzeug.security import (
    check_password_hash,
    generate_password_hash,
)
from werkzeug.middleware.proxy_fix import ProxyFix

from blockchain import Blockchain


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = Path(
    os.environ.get(
        "DATA_DIR",
        str(BASE_DIR),
    )
).expanduser().resolve()

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

DB_PATH = DATA_DIR / "voting.db"
KEY_PATH = DATA_DIR / "secret.key"
CHAIN_PATH = DATA_DIR / "chain_data.json"

IS_PRODUCTION = bool(
    os.environ.get("RAILWAY_ENVIRONMENT")
    or os.environ.get("APP_ENV", "").lower()
    == "production"
)

ALLOW_DEV_OTP = (
    os.environ.get(
        "ALLOW_DEV_OTP",
        "0" if IS_PRODUCTION else "1",
    )
    == "1"
)


# OTP security settings

OTP_VALIDITY_SECONDS = 5 * 60
OTP_MAX_ATTEMPTS = 5
OTP_RESEND_COOLDOWN_SECONDS = 30


# ---------------------------------------------------------------------------
# Candidates
# ---------------------------------------------------------------------------

CANDIDATES = [
    {
        "id": "C1",
        "name": "Aarav Sharma",
        "party": "Party Alpha",
    },
    {
        "id": "C2",
        "name": "Priya Nair",
        "party": "Party Beta",
    },
    {
        "id": "C3",
        "name": "Rohan Iyer",
        "party": "Party Gamma",
    },
    {
        "id": "NOTA",
        "name": "None of the Above",
        "party": "-",
    },
]


# ---------------------------------------------------------------------------
# Admin configuration
# ---------------------------------------------------------------------------

ADMIN_USERNAME = os.environ.get(
    "ADMIN_USERNAME",
    "admin",
)

ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD"
)

if not ADMIN_PASSWORD:

    if IS_PRODUCTION:
        raise RuntimeError(
            "ADMIN_PASSWORD must be configured in production."
        )

    ADMIN_PASSWORD = secrets.token_urlsafe(18)

    print(
        "[DEV] ADMIN_PASSWORD was not configured. "
        f"Temporary admin password: {ADMIN_PASSWORD}"
    )

ADMIN_PASSWORD_HASH = generate_password_hash(
    ADMIN_PASSWORD
)


# ---------------------------------------------------------------------------
# Flask application
# ---------------------------------------------------------------------------

app = Flask(__name__)

app.wsgi_app = ProxyFix(
    app.wsgi_app,
    x_for=1,
    x_proto=1,
    x_host=1,
)


# Use environment secret when available.
# Generate a temporary secure secret for local development otherwise.

app.secret_key = os.environ.get(
    "FLASK_SECRET_KEY"
)

if not app.secret_key:

    if IS_PRODUCTION:
        raise RuntimeError(
            "FLASK_SECRET_KEY must be configured in production."
        )

    app.secret_key = secrets.token_hex(32)

    print(
        "[WARNING] FLASK_SECRET_KEY is not configured. "
        "Using a temporary secure key for this run."
    )


# ---------------------------------------------------------------------------
# Session cookie security
# ---------------------------------------------------------------------------

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=(
        os.environ.get(
            "SESSION_COOKIE_SECURE",
            "1" if IS_PRODUCTION else "0",
        )
        == "1"
    ),
)


# ---------------------------------------------------------------------------
# CSRF protection
# ---------------------------------------------------------------------------

csrf = CSRFProtect(app)


@app.errorhandler(CSRFError)
def handle_csrf_error(error):
    """
    Handle missing, expired or invalid CSRF tokens.
    """

    flash(
        "Security token expired or invalid. "
        "Please try again.",
        "error",
    )

    return redirect(
        url_for("index")
    )


@app.after_request
def add_security_headers(response):
    """Add a conservative baseline of browser security headers."""

    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "style-src 'self'; "
        "img-src 'self' data:; "
        "form-action 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'",
    )
    response.headers.setdefault(
        "X-Content-Type-Options",
        "nosniff",
    )
    response.headers.setdefault(
        "X-Frame-Options",
        "DENY",
    )
    response.headers.setdefault(
        "Referrer-Policy",
        "strict-origin-when-cross-origin",
    )

    if IS_PRODUCTION:
        response.headers.setdefault(
            "Strict-Transport-Security",
            "max-age=31536000; includeSubDomains",
        )

    return response


# ---------------------------------------------------------------------------
# Blockchain
# ---------------------------------------------------------------------------

blockchain = Blockchain(
    chain_file=CHAIN_PATH
)


# ---------------------------------------------------------------------------
# Ballot encryption
# ---------------------------------------------------------------------------

def _load_or_create_key():
    """
    Load the existing Fernet encryption key.

    If secret.key does not exist,
    create a new key.
    """

    configured_key = os.environ.get(
        "FERNET_KEY"
    )

    if configured_key:
        return configured_key.encode("utf-8")

    if KEY_PATH.exists():

        with open(
            KEY_PATH,
            "rb",
        ) as file:

            return file.read()


    key = Fernet.generate_key()


    with open(
        KEY_PATH,
        "wb",
    ) as file:

        file.write(key)

    os.chmod(
        KEY_PATH,
        0o600,
    )


    return key


fernet = Fernet(
    _load_or_create_key()
)


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_db():
    """
    Return the SQLite connection
    for the current Flask request.
    """

    if "db" not in g:

        g.db = sqlite3.connect(
            DB_PATH,
            timeout=10,
        )

        g.db.row_factory = sqlite3.Row

        g.db.execute(
            "PRAGMA busy_timeout = 10000"
        )


    return g.db


@app.teardown_appcontext
def close_db(exception=None):
    """
    Close SQLite connection after
    each Flask request.
    """

    db = g.pop(
        "db",
        None,
    )

    if db is not None:
        db.close()


def init_db():
    """
    Create SecureVote database tables.

    Also upgrades an older voting.db
    by adding missing OTP security fields.
    """

    conn = sqlite3.connect(
        DB_PATH,
        timeout=10,
    )


    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS voters (
            id INTEGER PRIMARY KEY AUTOINCREMENT,

            voter_id TEXT UNIQUE,

            full_name TEXT NOT NULL,

            email TEXT UNIQUE NOT NULL,

            is_verified INTEGER DEFAULT 0,

            has_voted INTEGER DEFAULT 0,

            otp_code TEXT,

            otp_expiry REAL,

            otp_purpose TEXT,

            otp_attempts INTEGER DEFAULT 0,

            otp_last_sent REAL,

            created_at REAL
        );


        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
        """
    )


    # -----------------------------------------------------------------------
    # Existing database migration
    # -----------------------------------------------------------------------

    existing_columns = {
        row[1]
        for row in conn.execute(
            "PRAGMA table_info(voters)"
        ).fetchall()
    }


    if "otp_attempts" not in existing_columns:

        conn.execute(
            """
            ALTER TABLE voters
            ADD COLUMN otp_attempts INTEGER DEFAULT 0
            """
        )


    if "otp_last_sent" not in existing_columns:

        conn.execute(
            """
            ALTER TABLE voters
            ADD COLUMN otp_last_sent REAL
            """
        )


    conn.execute(
        """
        INSERT OR IGNORE INTO settings
        (key, value)

        VALUES ('voting_open', '1')
        """
    )


    conn.commit()
    conn.close()


def get_setting(
    key,
    default=None,
):
    """
    Read an application setting.
    """

    row = get_db().execute(
        """
        SELECT value
        FROM settings
        WHERE key = ?
        """,
        (key,),
    ).fetchone()


    if row:
        return row["value"]


    return default


def set_setting(
    key,
    value,
):
    """
    Create or update an application setting.
    """

    db = get_db()


    db.execute(
        """
        INSERT INTO settings
        (key, value)

        VALUES (?, ?)

        ON CONFLICT(key)
        DO UPDATE SET
            value = excluded.value
        """,
        (
            key,
            value,
        ),
    )


    db.commit()


# Initialize the database when imported by Gunicorn or another WSGI server.
init_db()


@app.get("/health")
def health():
    """Readiness endpoint for Railway deployment health checks."""

    try:
        connection = sqlite3.connect(
            DB_PATH,
            timeout=3,
        )
        connection.execute("SELECT 1")
        connection.close()

        chain_valid, _ = blockchain.is_valid()

        return (
            jsonify(
                status=(
                    "healthy"
                    if chain_valid
                    else "unhealthy"
                ),
                ledger_valid=chain_valid,
            ),
            200 if chain_valid else 503,
        )

    except (
        OSError,
        sqlite3.Error,
    ):

        return (
            jsonify(
                status="unhealthy",
                ledger_valid=False,
            ),
            503,
        )


# ---------------------------------------------------------------------------
# OTP helpers
# ---------------------------------------------------------------------------

def generate_otp():
    """
    Generate a cryptographically secure
    six-digit OTP.
    """

    return (
        f"{secrets.randbelow(1000000):06d}"
    )


def send_otp_email(
    to_email,
    otp,
    purpose="verification",
):
    """
    Send OTP using SMTP.

    When SMTP is not configured,
    use DEV MODE.
    """

    host = os.environ.get(
        "SMTP_HOST"
    )

    user = os.environ.get(
        "SMTP_USER"
    )

    password = os.environ.get(
        "SMTP_PASS"
    )

    port = int(
        os.environ.get(
            "SMTP_PORT",
            "587",
        )
    )


    # -----------------------------------------------------------------------
    # DEV MODE
    # -----------------------------------------------------------------------

    if not (
        host
        and user
        and password
    ):

        if ALLOW_DEV_OTP:

            print(
                f"[DEV OTP] "
                f"{purpose} code "
                f"for {to_email}: {otp}"
            )

            return False

        print(
            "[OTP ERROR] SMTP is not configured."
        )

        return None


    # -----------------------------------------------------------------------
    # Real SMTP
    # -----------------------------------------------------------------------

    try:

        message = EmailMessage()


        message["Subject"] = (
            f"Your SecureVote OTP for {purpose}"
        )

        message["From"] = user

        message["To"] = to_email


        message.set_content(
            f"Your OTP code is {otp}. "
            f"It expires in 5 minutes."
        )


        with smtplib.SMTP(
            host,
            port,
        ) as server:

            server.starttls()

            server.login(
                user,
                password,
            )

            server.send_message(
                message
            )


        return True


    except Exception as exc:

        print(
            f"[SMTP ERROR] {type(exc).__name__}"
        )

        if ALLOW_DEV_OTP:

            print(
                f"[DEV OTP] "
                f"{purpose} code "
                f"for {to_email}: {otp}"
            )

            return False

        return None


def issue_otp(
    voter_row_id,
    email,
    purpose,
    enforce_cooldown=False,
):
    """
    Generate and issue an OTP.

    Security features:

    - secrets-based generation
    - hashed storage
    - five-minute expiration
    - maximum attempt tracking
    - resend cooldown
    """

    db = get_db()


    voter = db.execute(
        """
        SELECT otp_last_sent
        FROM voters
        WHERE id = ?
        """,
        (
            voter_row_id,
        ),
    ).fetchone()


    current_time = time.time()


    # -----------------------------------------------------------------------
    # Resend cooldown
    # -----------------------------------------------------------------------

    if (
        enforce_cooldown
        and voter
        and voter["otp_last_sent"]
    ):

        elapsed = (
            current_time
            - voter["otp_last_sent"]
        )


        if (
            elapsed
            < OTP_RESEND_COOLDOWN_SECONDS
        ):

            remaining = int(
                OTP_RESEND_COOLDOWN_SECONDS
                - elapsed
            ) + 1


            return (
                False,
                f"Please wait {remaining} seconds "
                f"before requesting another OTP.",
            )


    # -----------------------------------------------------------------------
    # Generate secure OTP
    # -----------------------------------------------------------------------

    otp = generate_otp()


    # Store only its hash.

    otp_hash = generate_password_hash(
        otp
    )


    otp_expiry = (
        current_time
        + OTP_VALIDITY_SECONDS
    )


    db.execute(
        """
        UPDATE voters

        SET
            otp_code = ?,
            otp_expiry = ?,
            otp_purpose = ?,
            otp_attempts = 0,
            otp_last_sent = ?

        WHERE id = ?
        """,
        (
            otp_hash,
            otp_expiry,
            purpose,
            current_time,
            voter_row_id,
        ),
    )


    db.commit()


    delivered = send_otp_email(
        email,
        otp,
        purpose,
    )


    if (
        delivered is False
        and ALLOW_DEV_OTP
    ):

        flash(
            f"DEV MODE: no SMTP configured, "
            f"your OTP is {otp}",
            "otp-dev",
        )

    elif delivered is not True:

        db.execute(
            """
            UPDATE voters

            SET
                otp_code = NULL,
                otp_expiry = NULL,
                otp_purpose = NULL,
                otp_attempts = 0,
                otp_last_sent = NULL

            WHERE id = ?
            """,
            (
                voter_row_id,
            ),
        )

        db.commit()

        return (
            False,
            "Unable to send the OTP. "
            "Please try again later.",
        )


    return True, None


def verify_otp(
    voter_row,
    submitted_otp,
    purpose,
):
    """
    Securely verify an OTP.

    Maximum incorrect attempts:
    5
    """

    db = get_db()


    stored_otp_hash = (
        voter_row["otp_code"]
    )


    # -----------------------------------------------------------------------
    # No active OTP
    # -----------------------------------------------------------------------

    if not stored_otp_hash:

        return (
            False,
            "No active OTP exists. "
            "Please request a new OTP.",
        )


    # -----------------------------------------------------------------------
    # Purpose check
    # -----------------------------------------------------------------------

    if (
        voter_row["otp_purpose"]
        != purpose
    ):

        return (
            False,
            "This OTP is not valid "
            "for this step.",
        )


    # -----------------------------------------------------------------------
    # Expiration
    # -----------------------------------------------------------------------

    if time.time() > (
        voter_row["otp_expiry"]
        or 0
    ):

        db.execute(
            """
            UPDATE voters

            SET
                otp_code = NULL,
                otp_expiry = NULL,
                otp_purpose = NULL,
                otp_attempts = 0

            WHERE id = ?
            """,
            (
                voter_row["id"],
            ),
        )


        db.commit()


        return (
            False,
            "OTP has expired. "
            "Please request a new one.",
        )


    attempts = (
        voter_row["otp_attempts"]
        or 0
    )


    # -----------------------------------------------------------------------
    # Attempt limit
    # -----------------------------------------------------------------------

    if attempts >= OTP_MAX_ATTEMPTS:

        return (
            False,
            "Maximum OTP attempts reached. "
            "Please request a new OTP.",
        )


    # -----------------------------------------------------------------------
    # Verify OTP hash
    # -----------------------------------------------------------------------

    try:

        otp_matches = check_password_hash(
            stored_otp_hash,
            submitted_otp,
        )


    except (
        ValueError,
        TypeError,
    ):

        return (
            False,
            "Invalid OTP data. "
            "Please request a new OTP.",
        )


    # -----------------------------------------------------------------------
    # Wrong OTP
    # -----------------------------------------------------------------------

    if not otp_matches:

        new_attempts = (
            attempts + 1
        )


        if (
            new_attempts
            >= OTP_MAX_ATTEMPTS
        ):

            db.execute(
                """
                UPDATE voters

                SET
                    otp_code = NULL,
                    otp_expiry = NULL,
                    otp_purpose = NULL,
                    otp_attempts = ?

                WHERE id = ?
                """,
                (
                    new_attempts,
                    voter_row["id"],
                ),
            )


            db.commit()


            return (
                False,
                "Too many incorrect OTP attempts. "
                "The OTP has been invalidated. "
                "Please request a new OTP.",
            )


        db.execute(
            """
            UPDATE voters

            SET otp_attempts = ?

            WHERE id = ?
            """,
            (
                new_attempts,
                voter_row["id"],
            ),
        )


        db.commit()


        remaining = (
            OTP_MAX_ATTEMPTS
            - new_attempts
        )


        return (
            False,
            f"Incorrect OTP. "
            f"{remaining} attempts remaining.",
        )


    return True, None


# ---------------------------------------------------------------------------
# Voter identity helpers
# ---------------------------------------------------------------------------

def hash_voter_id(
    voter_id,
):
    """
    Hash Voter ID before placing
    it in the blockchain.
    """

    return hashlib.sha256(
        voter_id.encode(
            "utf-8"
        )
    ).hexdigest()


def generate_voter_id(
    email,
):
    """
    Generate an unpredictable Voter ID.
    """

    random_part = (
        secrets.token_hex(16)
    )


    raw = (
        f"{email}-"
        f"{time.time()}-"
        f"{random_part}"
    )


    digest = hashlib.sha256(
        raw.encode(
            "utf-8"
        )
    ).hexdigest()


    return (
        "VOT"
        + digest[:16].upper()
    )


# ---------------------------------------------------------------------------
# Authentication decorators
# ---------------------------------------------------------------------------

def voter_login_required(
    view,
):

    @wraps(view)
    def wrapped(
        *args,
        **kwargs,
    ):

        if not session.get(
            "voter_row_id"
        ):

            flash(
                "Please log in first.",
                "error",
            )


            return redirect(
                url_for(
                    "login"
                )
            )


        return view(
            *args,
            **kwargs,
        )


    return wrapped


def admin_login_required(
    view,
):

    @wraps(view)
    def wrapped(
        *args,
        **kwargs,
    ):

        if not session.get(
            "is_admin"
        ):

            flash(
                "Admin login required.",
                "error",
            )


            return redirect(
                url_for(
                    "admin_login"
                )
            )


        return view(
            *args,
            **kwargs,
        )


    return wrapped


# ---------------------------------------------------------------------------
# Home
# ---------------------------------------------------------------------------

@app.route("/")
def index():

    return render_template(
        "index.html"
    )


# ---------------------------------------------------------------------------
# Registration
# ---------------------------------------------------------------------------

@app.route(
    "/register",
    methods=[
        "GET",
        "POST",
    ],
)
def register():

    if request.method == "POST":

        full_name = (
            request.form.get(
                "full_name",
                "",
            )
            .strip()
        )


        email = (
            request.form.get(
                "email",
                "",
            )
            .strip()
            .lower()
        )


        if (
            not full_name
            or not email
        ):

            flash(
                "Full name and email are required.",
                "error",
            )


            return render_template(
                "register.html"
            )


        db = get_db()


        existing = db.execute(
            """
            SELECT *
            FROM voters
            WHERE email = ?
            """,
            (
                email,
            ),
        ).fetchone()


        # -------------------------------------------------------------------
        # Already verified
        # -------------------------------------------------------------------

        if (
            existing
            and existing["is_verified"]
        ):

            flash(
                "This email is already registered. "
                "Please log in instead.",
                "error",
            )


            return redirect(
                url_for(
                    "login"
                )
            )


        # -------------------------------------------------------------------
        # Existing but unverified voter
        # -------------------------------------------------------------------

        if existing:

            voter_row_id = (
                existing["id"]
            )


            db.execute(
                """
                UPDATE voters

                SET full_name = ?

                WHERE id = ?
                """,
                (
                    full_name,
                    voter_row_id,
                ),
            )


            db.commit()


        # -------------------------------------------------------------------
        # New voter
        # -------------------------------------------------------------------

        else:

            cursor = db.execute(
                """
                INSERT INTO voters
                (
                    full_name,
                    email,
                    created_at
                )

                VALUES (?, ?, ?)
                """,
                (
                    full_name,
                    email,
                    time.time(),
                ),
            )


            db.commit()


            voter_row_id = (
                cursor.lastrowid
            )


        # -------------------------------------------------------------------
        # Registration OTP
        # -------------------------------------------------------------------

        sent, message = issue_otp(
            voter_row_id,
            email,
            purpose="register",
            enforce_cooldown=True,
        )


        session[
            "pending_voter_row_id"
        ] = voter_row_id


        if sent:

            flash(
                "An OTP has been sent. "
                "Enter it below to complete registration.",
                "info",
            )

        else:

            flash(
                message,
                "error",
            )


        return redirect(
            url_for(
                "verify_registration_otp"
            )
        )


    return render_template(
        "register.html"
    )


# ---------------------------------------------------------------------------
# Registration OTP verification
# ---------------------------------------------------------------------------

@app.route(
    "/verify-registration-otp",
    methods=[
        "GET",
        "POST",
    ],
)
def verify_registration_otp():

    voter_row_id = session.get(
        "pending_voter_row_id"
    )


    if not voter_row_id:

        return redirect(
            url_for(
                "register"
            )
        )


    db = get_db()


    voter = db.execute(
        """
        SELECT *
        FROM voters
        WHERE id = ?
        """,
        (
            voter_row_id,
        ),
    ).fetchone()


    if not voter:

        session.pop(
            "pending_voter_row_id",
            None,
        )


        return redirect(
            url_for(
                "register"
            )
        )


    if request.method == "POST":


        # -------------------------------------------------------------------
        # Resend OTP
        # -------------------------------------------------------------------

        if "resend" in request.form:

            sent, message = issue_otp(
                voter_row_id,
                voter["email"],
                purpose="register",
                enforce_cooldown=True,
            )


            if sent:

                flash(
                    "A new OTP has been sent.",
                    "info",
                )

            else:

                flash(
                    message,
                    "error",
                )


            return redirect(
                url_for(
                    "verify_registration_otp"
                )
            )


        # -------------------------------------------------------------------
        # Verify OTP
        # -------------------------------------------------------------------

        submitted = (
            request.form.get(
                "otp",
                "",
            )
            .strip()
        )


        ok, error = verify_otp(
            voter,
            submitted,
            purpose="register",
        )


        if not ok:

            flash(
                error,
                "error",
            )


            return render_template(
                "verify_otp.html",
                voter=voter,
            )


        # -------------------------------------------------------------------
        # Generate Voter ID
        # -------------------------------------------------------------------

        voter_id = generate_voter_id(
            voter["email"]
        )


        db.execute(
            """
            UPDATE voters

            SET
                is_verified = 1,
                voter_id = ?,
                otp_code = NULL,
                otp_expiry = NULL,
                otp_purpose = NULL,
                otp_attempts = 0,
                otp_last_sent = NULL

            WHERE id = ?
            """,
            (
                voter_id,
                voter_row_id,
            ),
        )


        db.commit()


        session.pop(
            "pending_voter_row_id",
            None,
        )


        flash(
            f"Registration complete! "
            f"Your Voter ID is {voter_id}. "
            f"Save it because you need it to log in.",
            "success",
        )


        return redirect(
            url_for(
                "login"
            )
        )


    return render_template(
        "verify_otp.html",
        voter=voter,
    )


# ---------------------------------------------------------------------------
# Voter login
# ---------------------------------------------------------------------------

@app.route(
    "/login",
    methods=[
        "GET",
        "POST",
    ],
)
def login():

    if request.method == "POST":

        voter_id = (
            request.form.get(
                "voter_id",
                "",
            )
            .strip()
            .upper()
        )


        email = (
            request.form.get(
                "email",
                "",
            )
            .strip()
            .lower()
        )


        db = get_db()


        voter = db.execute(
            """
            SELECT *
            FROM voters

            WHERE
                voter_id = ?
                AND email = ?
                AND is_verified = 1
            """,
            (
                voter_id,
                email,
            ),
        ).fetchone()


        if not voter:

            flash(
                "No verified voter matches "
                "that Voter ID and email.",
                "error",
            )


            return render_template(
                "login.html"
            )


        sent, message = issue_otp(
            voter["id"],
            voter["email"],
            purpose="login",
            enforce_cooldown=True,
        )


        session[
            "pending_login_row_id"
        ] = voter["id"]


        if sent:

            flash(
                "An OTP has been sent "
                "to complete login.",
                "info",
            )

        else:

            flash(
                message,
                "error",
            )


        return redirect(
            url_for(
                "login_otp"
            )
        )


    return render_template(
        "login.html"
    )


# ---------------------------------------------------------------------------
# Login OTP
# ---------------------------------------------------------------------------

@app.route(
    "/login-otp",
    methods=[
        "GET",
        "POST",
    ],
)
def login_otp():

    voter_row_id = session.get(
        "pending_login_row_id"
    )


    if not voter_row_id:

        return redirect(
            url_for(
                "login"
            )
        )


    db = get_db()


    voter = db.execute(
        """
        SELECT *
        FROM voters
        WHERE id = ?
        """,
        (
            voter_row_id,
        ),
    ).fetchone()


    if not voter:

        session.clear()


        return redirect(
            url_for(
                "login"
            )
        )


    if request.method == "POST":


        # -------------------------------------------------------------------
        # Resend OTP
        # -------------------------------------------------------------------

        if "resend" in request.form:

            sent, message = issue_otp(
                voter_row_id,
                voter["email"],
                purpose="login",
                enforce_cooldown=True,
            )


            if sent:

                flash(
                    "A new OTP has been sent.",
                    "info",
                )

            else:

                flash(
                    message,
                    "error",
                )


            return redirect(
                url_for(
                    "login_otp"
                )
            )


        # -------------------------------------------------------------------
        # Verify OTP
        # -------------------------------------------------------------------

        submitted = (
            request.form.get(
                "otp",
                "",
            )
            .strip()
        )


        ok, error = verify_otp(
            voter,
            submitted,
            purpose="login",
        )


        if not ok:

            flash(
                error,
                "error",
            )


            return render_template(
                "login_otp.html",
                voter=voter,
            )


        # -------------------------------------------------------------------
        # Destroy used OTP
        # -------------------------------------------------------------------

        db.execute(
            """
            UPDATE voters

            SET
                otp_code = NULL,
                otp_expiry = NULL,
                otp_purpose = NULL,
                otp_attempts = 0,
                otp_last_sent = NULL

            WHERE id = ?
            """,
            (
                voter_row_id,
            ),
        )


        db.commit()


        # -------------------------------------------------------------------
        # Establish clean authenticated session
        # -------------------------------------------------------------------

        session.clear()

        session[
            "voter_row_id"
        ] = voter_row_id


        flash(
            f"Welcome, {voter['full_name']}.",
            "success",
        )


        return redirect(
            url_for(
                "vote"
            )
        )


    return render_template(
        "login_otp.html",
        voter=voter,
    )


# ---------------------------------------------------------------------------
# Voting
# ---------------------------------------------------------------------------

@app.route(
    "/vote",
    methods=[
        "GET",
        "POST",
    ],
)
@voter_login_required
def vote():

    db = get_db()


    voter = db.execute(
        """
        SELECT *
        FROM voters
        WHERE id = ?
        """,
        (
            session["voter_row_id"],
        ),
    ).fetchone()


    if not voter:

        session.clear()


        flash(
            "Voter account could not be found.",
            "error",
        )


        return redirect(
            url_for(
                "login"
            )
        )


    voting_open = (
        get_setting(
            "voting_open",
            "1",
        )
        == "1"
    )


    # -----------------------------------------------------------------------
    # Prevent double voting
    # -----------------------------------------------------------------------

    if voter["has_voted"]:

        return render_template(
            "voted.html",
            voter=voter,
        )


    # -----------------------------------------------------------------------
    # Voting paused
    # -----------------------------------------------------------------------

    if not voting_open:

        flash(
            "Voting has been paused by the administrator.",
            "error",
        )


        return render_template(
            "vote.html",
            voter=voter,
            candidates=CANDIDATES,
            voting_open=False,
        )


    # -----------------------------------------------------------------------
    # Cast vote
    # -----------------------------------------------------------------------

    if request.method == "POST":

        candidate_id = (
            request.form.get(
                "candidate_id"
            )
        )


        if not any(
            candidate["id"] == candidate_id
            for candidate in CANDIDATES
        ):

            flash(
                "Invalid candidate selection.",
                "error",
            )


            return render_template(
                "vote.html",
                voter=voter,
                candidates=CANDIDATES,
                voting_open=True,
            )


        # -------------------------------------------------------------------
        # Encrypt candidate selection
        # -------------------------------------------------------------------

        encrypted_choice = (
            fernet.encrypt(
                candidate_id.encode(
                    "utf-8"
                )
            )
            .decode(
                "utf-8"
            )
        )


        block_data = {

            "voter_hash":
                hash_voter_id(
                    voter["voter_id"]
                ),

            "encrypted_vote":
                encrypted_choice,
        }


        # -------------------------------------------------------------------
        # Add vote to blockchain
        # -------------------------------------------------------------------

        new_block = blockchain.add_block(
            block_data
        )


        # -------------------------------------------------------------------
        # Mark voter as voted
        # -------------------------------------------------------------------

        db.execute(
            """
            UPDATE voters

            SET has_voted = 1

            WHERE id = ?
            """,
            (
                voter["id"],
            ),
        )


        db.commit()


        return render_template(
            "voted.html",
            voter=voter,
            block=new_block.to_dict(),
        )


    return render_template(
        "vote.html",
        voter=voter,
        candidates=CANDIDATES,
        voting_open=True,
    )


# ---------------------------------------------------------------------------
# Voter logout
# ---------------------------------------------------------------------------

@app.route("/logout")
def logout():

    session.clear()


    flash(
        "You have been logged out.",
        "info",
    )


    return redirect(
        url_for(
            "index"
        )
    )


# ---------------------------------------------------------------------------
# Public results
# ---------------------------------------------------------------------------

@app.route("/result")
def result():

    tally = tally_votes()


    voting_open = (
        get_setting(
            "voting_open",
            "1",
        )
        == "1"
    )


    return render_template(
        "result.html",
        tally=tally,
        candidates=CANDIDATES,
        voting_open=voting_open,
    )


# ---------------------------------------------------------------------------
# Admin login
# ---------------------------------------------------------------------------

@app.route(
    "/admin/login",
    methods=[
        "GET",
        "POST",
    ],
)
def admin_login():

    if request.method == "POST":

        username = (
            request.form.get(
                "username",
                "",
            )
            .strip()
        )


        password = (
            request.form.get(
                "password",
                "",
            )
        )


        if (
            username == ADMIN_USERNAME

            and check_password_hash(
                ADMIN_PASSWORD_HASH,
                password,
            )
        ):

            session.clear()

            session[
                "is_admin"
            ] = True


            flash(
                "Welcome, admin.",
                "success",
            )


            return redirect(
                url_for(
                    "admin_dashboard"
                )
            )


        flash(
            "Invalid admin credentials.",
            "error",
        )


    return render_template(
        "admin_login.html"
    )


# ---------------------------------------------------------------------------
# Admin logout
# ---------------------------------------------------------------------------

@app.route("/admin/logout")
def admin_logout():

    session.clear()


    return redirect(
        url_for(
            "index"
        )
    )


# ---------------------------------------------------------------------------
# Vote tally
# ---------------------------------------------------------------------------

def tally_votes():
    """
    Decrypt valid blockchain votes
    and calculate totals.
    """

    counts = {
        candidate["id"]: 0
        for candidate in CANDIDATES
    }


    for block in (
        blockchain.all_vote_blocks()
    ):

        token = block.data.get(
            "encrypted_vote"
        )


        if not token:
            continue


        try:

            candidate_id = (
                fernet.decrypt(
                    token.encode(
                        "utf-8"
                    )
                )
                .decode(
                    "utf-8"
                )
            )


            if candidate_id in counts:

                counts[
                    candidate_id
                ] += 1


        except Exception:

            # Invalid or corrupted encrypted vote.
            continue


    return counts


# ---------------------------------------------------------------------------
# Admin dashboard
# ---------------------------------------------------------------------------

@app.route(
    "/admin/dashboard"
)
@admin_login_required
def admin_dashboard():

    db = get_db()


    voters = db.execute(
        """
        SELECT
            voter_id,
            full_name,
            email,
            is_verified,
            has_voted

        FROM voters

        ORDER BY created_at DESC
        """
    ).fetchall()


    total_registered = sum(
        1
        for voter in voters
        if voter["is_verified"]
    )


    total_voted = sum(
        1
        for voter in voters
        if voter["has_voted"]
    )


    tally = tally_votes()


    voting_open = (
        get_setting(
            "voting_open",
            "1",
        )
        == "1"
    )


    chain_valid, chain_message = (
        blockchain.is_valid()
    )


    return render_template(
        "admin_dashboard.html",

        voters=voters,

        total_registered=total_registered,

        total_voted=total_voted,

        tally=tally,

        candidates=CANDIDATES,

        voting_open=voting_open,

        chain_valid=chain_valid,

        chain_message=chain_message,
    )


# ---------------------------------------------------------------------------
# Pause / Resume election
# ---------------------------------------------------------------------------

@app.route(
    "/admin/toggle-voting",
    methods=[
        "POST",
    ],
)
@admin_login_required
def toggle_voting():

    current = get_setting(
        "voting_open",
        "1",
    )


    set_setting(
        "voting_open",
        "0"
        if current == "1"
        else "1",
    )


    return redirect(
        url_for(
            "admin_dashboard"
        )
    )


# ---------------------------------------------------------------------------
# Blockchain ledger
# ---------------------------------------------------------------------------

@app.route(
    "/admin/chain"
)
@admin_login_required
def admin_chain():

    chain_valid, chain_message = (
        blockchain.is_valid()
    )


    blocks = [
        block.to_dict()
        for block in blockchain.chain
    ]


    return render_template(
        "admin_chain.html",

        blocks=blocks,

        chain_valid=chain_valid,

        chain_message=chain_message,
    )


# ---------------------------------------------------------------------------
# Start application
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    debug_mode = (
        os.environ.get(
            "FLASK_DEBUG",
            "0",
        )
        == "1"
    )


    app.run(
        host=os.environ.get(
            "HOST",
            "0.0.0.0",
        ),
        port=int(
            os.environ.get(
                "PORT",
                "5000",
            )
        ),
        debug=debug_mode
    )
