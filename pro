import hmac
import os
import secrets
import sqlite3
from functools import wraps

from flask import Flask, abort, g, redirect, render_template_string, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get("SECRET_KEY") or secrets.token_hex(32),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_SECURE_COOKIE", "0") == "1",
)
DATABASE = os.environ.get("DATABASE_PATH", "users.db")


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """
    )
    db.commit()


def csrf_token():
    token = session.get("csrf_token")
    if token is None:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


@app.context_processor
def inject_csrf_token():
    return {"csrf_token": csrf_token}


@app.before_request
def protect_forms():
    if request.method == "POST":
        submitted = request.form.get("csrf_token", "")
        expected = session.get("csrf_token", "")
        if not expected or not hmac.compare_digest(submitted, expected):
            abort(400, "Invalid CSRF token")


def login_required(view):
    @wraps(view)
    def wrapped_view(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return view(*args, **kwargs)

    return wrapped_view


FORM = """
<!doctype html>
<title>{{ title }}</title>
<h1>{{ title }}</h1>
{% with messages = get_flashed_messages() %}
  {% for message in messages %}<p>{{ message }}</p>{% endfor %}
{% endwith %}
{{ body|safe }}
"""


@app.route("/")
def home():
    if "user_id" in session:
        return redirect(url_for("dashboard"))
    return render_template_string(
        FORM,
        title="Secure Login System",
        body='<p><a href="/login">Log in</a> or <a href="/register">Register</a></p>',
    )


@app.route("/register", methods=["GET", "POST"])
def register():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if len(username) < 3 or len(username) >  fifty:
            error = "Username must be between 3 and 50 characters."
        elif len(password) < 12:
            error = "Password must be at least 12 characters."
        else:
            try:
                db = get_db()
                db.execute(
                    "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                    (username, generate_password_hash(password)),
                )
                db.commit()
            except sqlite3.IntegrityError:
                error = "That username is already registered."
            else:
                return redirect(url_for("login"))
    body = f"""
    <p>{error or ''}</p>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{csrf_token()}">
      <label>Username <input name="username" required maxlength="50"></label><br>
      <label>Password <input type="password" name="password" required minlength="12"></label><br>
      <button type="submit">Register</button>
    </form>
    <p><a href="/login">Log in</a></p>
    """
    return render_template_string(FORM, title="Register", body=body)


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        user = get_db().execute(
            "SELECT id, username, password_hash FROM users WHERE username = ?", (username,)
        ).fetchone()
        if user is None or not check_password_hash(user["password_hash"], password):
            error = "Invalid username or password."
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["csrf_token"] = secrets.token_urlsafe(32)
            return redirect(url_for("dashboard"))
    body = f"""
    <p>{error or ''}</p>
    <form method="post">
      <input type="hidden" name="csrf_token" value="{csrf_token()}">
      <label>Username <input name="username" required maxlength="50"></label><br>
      <label>Password <input type="password" name="password" required></label><br>
      <button type="submit">Log in</button>
    </form>
    <p><a href="/register">Register</a></p>
    """
    return render_template_string(FORM, title="Log in", body=body)


@app.route("/dashboard")
@login_required
def dashboard():
    body = f"""
    <p>Welcome, {session['username']}.</p>
    <form method="post" action="/logout">
      <input type="hidden" name="csrf_token" value="{csrf_token()}">
      <button type="submit">Log out</button>
    </form>
    """
    return render_template_string(FORM, title="Dashboard", body=body)


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    session.clear()
    return redirect(url_for("home"))


with app.app_context():
    init_db()


if __name__ == "__main__":
    # Never use Flask's debug server in production.
    app.run(debug=False)
