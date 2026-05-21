import hmac
import os
import secrets
from functools import wraps

from flask import flash, redirect, request, session, url_for


def get_admin_usernames():
    raw = os.environ.get("NOC_ADMIN_USERS", "admin")
    usernames = {name.strip() for name in raw.split(",") if name.strip()}
    return usernames or {"admin"}


def is_admin_user(username):
    return bool(username) and username in get_admin_usernames()


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))

        if not is_admin_user(session.get("username")):
            flash("Admin access required.", "danger")
            return redirect(url_for("dashboard"))

        return f(*args, **kwargs)

    return decorated_function


def csrf_token():
    token = session.get("_csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["_csrf_token"] = token
    return token


def validate_csrf():
    if request.method not in {"POST", "PUT", "PATCH", "DELETE"}:
        return True

    session_token = session.get("_csrf_token")
    request_token = (
        request.form.get("csrf_token")
        or request.headers.get("X-CSRFToken")
        or request.headers.get("X-CSRF-Token")
    )

    return bool(
        session_token
        and request_token
        and hmac.compare_digest(session_token, request_token)
    )
