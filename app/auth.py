"""Authentication routes: signup, login, 2FA, sudo re-auth, password reset."""

import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from hashlib import sha256

from flask import (Blueprint, current_app, flash, redirect, render_template,
                   request, session, url_for)

from app import services
from app.extensions import db
from app.models import User
from app.security import (consume_backup_code, current_user, dummy_verify,
                          grant_sudo, hash_password, is_sudo, log_event,
                          login_user, logout_user, needs_rehash,
                          new_backup_codes, new_totp_secret, throttle,
                          totp_match, totp_uri, verify_password)
from app.utils import client_ip, is_valid_username, password_problems, qr_svg_data_uri

log = logging.getLogger("btcwallet.auth")
auth_bp = Blueprint("auth", __name__)

PENDING_2FA_TTL = 300       # seconds a half-finished login stays valid
MAX_2FA_ATTEMPTS = 6


def admin_2fa_notice(user):
    """Admins are not forced into 2FA, so they are told about it at every sign-in."""
    if user is not None and user.is_admin and not user.totp_enabled:
        log_event("admin_login_without_2fa", user=user)
        flash("Two-factor authentication is OFF on this administrator account. "
              "You can turn it on in Admin \u2192 Settings.", "warning")


def verify_sudo_credentials(user, password: str, code: str = ""):
    """Shared re-auth check. Returns (ok, error_message).

    Used by /confirm AND by pages that confirm inline: bouncing a form POST through
    /confirm loses the submitted body, so the action the admin asked for silently
    never happens. Callers with a form render the confirmation fields themselves.
    """
    if not verify_password(user.password_hash, password or ""):
        log_event("sudo_fail", user=user, success=False, detail="bad password")
        return False, "Incorrect password."
    if user.totp_enabled and user.totp_secret_enc:
        secret = services.vault().open_str(user.totp_secret_enc)
        # Deliberately NOT replay-checked here (last_step=None) and not recorded:
        # sudo already requires the password, and recording the step would create a
        # dead-end where signing in and then confirming inside the same 30-second
        # window can never succeed.
        step = totp_match(secret, code or "", None)
        if step is None and not consume_backup_code(user, code or ""):
            log_event("sudo_fail_2fa", user=user, success=False)
            return False, "That authentication code is not correct."
    return True, None


# ------------------------------------------------------------------- helpers
def _safe_next(default_endpoint: str = "views.dashboard"):
    """Only ever redirect to a local path — an open redirect on a wallet
    login page is a phishing primitive."""
    nxt = request.values.get("next") or session.pop("next", None)
    if nxt and isinstance(nxt, str) and nxt.startswith("/") and not nxt.startswith("//"):
        return nxt
    return url_for(default_endpoint)


def _already_in():
    return current_user() is not None


# -------------------------------------------------------------------- signup
@auth_bp.route("/signup", methods=["GET", "POST"])
def signup():
    if _already_in():
        return redirect(url_for("views.dashboard"))
    if not services.get_bool_setting("signups_enabled"):
        flash("New signups are paused right now.", "warning")
        return render_template("signup.html", closed=True)

    if request.method == "POST":
        ip = client_ip(request)
        # honeypot: a real browser never fills a hidden field
        if (request.form.get("website") or "").strip():
            log_event("signup_honeypot", success=False, detail=ip)
            flash("Signup could not be completed.", "error")
            return redirect(url_for("auth.signup"))

        if not throttle(f"signup:try:{ip}", current_app.config["SIGNUP_IP_MAX_ATTEMPTS"], 3600):
            flash("Too many attempts from this connection. Try again later.", "error")
            return render_template("signup.html")

        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        confirm = request.form.get("password2") or ""

        errors = []
        if not is_valid_username(username):
            errors.append("Username must be 3–20 characters: letters, numbers, underscore.")
        if password != confirm:
            errors.append("The two passwords do not match.")
        errors += password_problems(
            password, username, "", current_app.config["PASSWORD_MIN_LENGTH"]
        )
        if not request.form.get("agree"):
            errors.append("Please accept the terms to continue.")

        if not errors:
            existing = (db.session.query(User)
                        .filter(db.func.lower(User.username) == username.lower())
                        .first())
            if existing:
                errors.append("That username is already taken.")
            elif not throttle(f"signup:made:{ip}",
                              current_app.config["SIGNUP_IP_MAX_PER_HOUR"], 3600):
                # Charged only when an account would actually be created, so a
                # mistyped form costs nothing but bulk registration is still
                # capped per source address.
                errors.append("Too many accounts created from this connection. "
                              "Try again later.")

        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("signup.html", username=username)

        user = User(
            username=username,
            email=None,
            password_hash=hash_password(password),
            signup_ip=ip,
            role="user",
            status="active",
        )
        db.session.add(user)
        db.session.commit()

        # every user gets a deposit wallet immediately
        try:
            services.create_address(user, label="Main wallet", make_primary=True)
        except Exception as exc:
            log.error("could not create address for new user %s: %s", username, exc)
            flash("Account created, but generating your wallet failed. "
                  "An operator has been notified.", "warning")
            services.raise_alert("address_creation_failed",
                                 f"Address creation failed for {username}", str(exc),
                                 severity="critical", user=user)

        log_event("signup", user=user, detail=f"ip={ip}")
        login_user(user)
        flash("Welcome. Your wallet is ready.", "success")
        return redirect(url_for("views.dashboard"))

    return render_template("signup.html")


# --------------------------------------------------------------------- login
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if _already_in():
        return redirect(url_for("views.dashboard"))

    if request.method == "POST":
        ip = client_ip(request)
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""

        if not throttle(f"login:ip:{ip}", current_app.config["LOGIN_IP_MAX_PER_10MIN"], 600):
            log_event("login_throttled", success=False, username=username, detail=ip)
            flash("Too many attempts from this connection. Wait a few minutes.", "error")
            return render_template("login.html", username=username), 429

        user = (db.session.query(User)
                .filter(db.func.lower(User.username) == username.lower())
                .first())

        if user is None:
            # burn equivalent CPU so a missing account is not faster than a
            # wrong password (which would leak which usernames exist)
            dummy_verify()
            log_event("login_fail", success=False, username=username,
                      detail="no such user")
            flash("Invalid username or password.", "error")
            return render_template("login.html", username=username), 401

        if user.locked_until and user.locked_until > datetime.now(timezone.utc):
            wait = int((user.locked_until - datetime.now(timezone.utc)).total_seconds() // 60) + 1
            log_event("login_locked", user=user, success=False, detail=f"{wait} min left")
            flash(f"Too many failed attempts. Try again in about {wait} minute(s).", "error")
            return render_template("login.html", username=username), 429

        if user.deleted_at is not None:
            dummy_verify()
            log_event("login_deleted", success=False, username=username)
            flash("Invalid username or password.", "error")
            return render_template("login.html", username=username), 401

        if not verify_password(user.password_hash, password):
            user.failed_logins = (user.failed_logins or 0) + 1
            limit = current_app.config["LOGIN_MAX_FAILS"]
            if user.failed_logins >= limit:
                user.locked_until = datetime.now(timezone.utc) + timedelta(
                    minutes=current_app.config["LOGIN_LOCK_MINUTES"]
                )
                user.failed_logins = 0
                log_event("account_locked", user=user, success=False,
                          detail=f"after {limit} failures")
                services.raise_alert(
                    "account_locked", f"{user.username} was locked out",
                    f"{limit} failed logins from {ip}.", severity="warning", user=user,
                )
            db.session.commit()
            log_event("login_fail", user=user, success=False, detail="bad password")
            flash("Invalid username or password.", "error")
            return render_template("login.html", username=username), 401

        if user.is_banned:
            log_event("login_banned", user=user, success=False)
            flash("This account has been suspended.", "error")
            return render_template("login.html", username=username), 403

        # password ok → rehash if the cost parameters have moved on
        if needs_rehash(user.password_hash):
            user.password_hash = hash_password(password)
            db.session.commit()

        if user.totp_enabled and user.totp_secret_enc:
            session.clear()
            session["pending_2fa_uid"] = user.id
            session["pending_2fa_at"] = int(time.time())
            session["pending_2fa_tries"] = 0
            session.permanent = True
            log_event("password_ok_2fa_pending", user=user)
            return redirect(url_for("auth.login_2fa"))

        login_user(user)
        log_event("login_ok", user=user)
        flash("Signed in.", "success")
        admin_2fa_notice(user)
        return redirect(_safe_next())

    return render_template("login.html")


@auth_bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    uid = session.get("pending_2fa_uid")
    started = int(session.get("pending_2fa_at") or 0)
    if not uid or (time.time() - started) > PENDING_2FA_TTL:
        session.clear()
        flash("That sign-in attempt expired. Please sign in again.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, uid)
    if user is None:
        session.clear()
        return redirect(url_for("auth.login"))
    if user.is_banned:
        session.clear()
        log_event("login_banned", user=user, success=False, detail="at 2FA step")
        flash("This account has been suspended.", "error")
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        tries = int(session.get("pending_2fa_tries") or 0) + 1
        session["pending_2fa_tries"] = tries
        if tries > MAX_2FA_ATTEMPTS:
            session.clear()
            log_event("2fa_too_many", user=user, success=False)
            flash("Too many incorrect codes. Please sign in again.", "error")
            return redirect(url_for("auth.login"))

        ip = client_ip(request)
        if not throttle(f"2fa:ip:{ip}", 20, 600):
            flash("Too many attempts. Wait a few minutes.", "error")
            return render_template("twofa.html", backup=False), 429

        code = (request.form.get("code") or "").strip()
        secret = services.vault().open_str(user.totp_secret_enc)

        step = totp_match(secret, code, user.totp_last_step)
        if step is not None:
            user.totp_last_step = int(step)
            db.session.commit()
            session.pop("pending_2fa_uid", None)
            login_user(user)
            log_event("login_ok_2fa", user=user)
            flash("Signed in.", "success")
            return redirect(_safe_next())

        if consume_backup_code(user, code):
            session.pop("pending_2fa_uid", None)
            login_user(user)
            log_event("login_ok_backup_code", user=user, detail="backup code used")
            import json

            try:
                remaining = len(json.loads(user.backup_codes_json or "[]"))
            except Exception:
                remaining = 0
            flash(f"Signed in with a backup code. {remaining} left — generate new ones soon.",
                  "warning")
            return redirect(_safe_next())

        log_event("2fa_fail", user=user, success=False)
        flash("That code is not correct.", "error")

    return render_template("twofa.html", backup=False)


# -------------------------------------------------------------- sudo / reauth
@auth_bp.route("/confirm", methods=["GET", "POST"])
def confirm():
    """Re-enter the password before a sensitive action (send, disable 2FA...)."""
    user = current_user()
    if user is None:
        return redirect(url_for("auth.login"))

    if request.method == "POST":
        if not throttle(f"sudo:{user.id}", 12, 600):
            flash("Too many attempts. Wait a few minutes.", "error")
            return render_template("confirm.html"), 429

        password = request.form.get("password") or ""
        code = (request.form.get("code") or "").strip()
        ok, err = verify_sudo_credentials(user, password, code)
        if not ok:
            flash(err, "error")
            return render_template("confirm.html"), 401

        grant_sudo()
        log_event("sudo_granted", user=user)
        flash("Confirmed. You have a few minutes to finish this action.", "success")
        return redirect(_safe_next())

    return render_template("confirm.html")


@auth_bp.route("/logout", methods=["POST"])
def logout():
    logout_user("user")
    flash("Signed out.", "success")
    return redirect(url_for("auth.login"))


# ---------------------------------------------------------------------- 2FA
@auth_bp.route("/security/2fa", methods=["GET", "POST"])
def setup_2fa():
    """Enable TOTP. The secret is held in the session until a code proves the
    authenticator app actually has it — otherwise a mistyped QR would lock the
    account out permanently."""
    user = current_user()
    if user is None:
        return redirect(url_for("auth.login"))
    if user.totp_enabled:
        return redirect(url_for("views.security"))

    if "pending_totp" not in session:
        session["pending_totp"] = new_totp_secret()

    secret = session["pending_totp"]
    uri = totp_uri(secret, user.username, current_app.config["SITE_NAME"])

    if request.method == "POST":
        code = (request.form.get("code") or "").strip()
        step = totp_match(secret, code, None)
        if step is None:
            log_event("2fa_setup_fail", user=user, success=False)
            flash("That code did not match. Check your authenticator's clock and try again.",
                  "error")
            return render_template("setup_2fa.html", secret=secret, uri=uri,
                                   qr=qr_svg_data_uri(uri))

        user.totp_secret_enc = services.vault().seal_str(secret)
        user.totp_enabled = True
        user.totp_confirmed_at = datetime.now(timezone.utc)
        user.totp_last_step = int(step)
        plain, hashed = new_backup_codes()
        user.backup_codes_json = hashed
        # a new 2FA enrolment invalidates other sessions
        user.session_version = (user.session_version or 0) + 1
        db.session.commit()
        session.pop("pending_totp", None)
        session["sv"] = user.session_version
        log_event("2fa_enabled", user=user)
        flash("Two-factor authentication is on. Save your backup codes now — "
              "they are shown only once.", "success")
        return render_template("backup_codes.html", codes=plain)

    return render_template("setup_2fa.html", secret=secret, uri=uri,
                           qr=qr_svg_data_uri(uri))


@auth_bp.route("/security/2fa/disable", methods=["POST"])
def disable_2fa():
    user = current_user()
    if user is None:
        return redirect(url_for("auth.login"))
    if user.require_2fa and not user.is_admin:
        # An operator requirement outranks the account's own preference — otherwise
        # the admin toggle would be decorative.
        log_event("2fa_disable_blocked", user=user, success=False,
                  detail="2FA is required on this account")
        flash("An administrator requires two-factor authentication on this account, so it "
              "cannot be turned off. Ask them to lift the requirement first.", "error")
        return redirect(url_for("views.security"))
    if not is_sudo():
        session["next"] = url_for("views.security")
        return redirect(url_for("auth.confirm"))

    code = (request.form.get("code") or "").strip()
    secret = services.vault().open_str(user.totp_secret_enc) if user.totp_secret_enc else None
    ok = False
    if secret:
        step = totp_match(secret, code, user.totp_last_step)
        if step is not None:
            user.totp_last_step = int(step)
            ok = True
    if not ok:
        ok = consume_backup_code(user, code)

    if not ok:
        log_event("2fa_disable_fail", user=user, success=False)
        flash("Incorrect code — two-factor authentication was not disabled.", "error")
        return redirect(url_for("views.security"))

    user.totp_enabled = False
    user.totp_secret_enc = None
    user.backup_codes_json = None
    user.session_version = (user.session_version or 0) + 1
    db.session.commit()
    session["sv"] = user.session_version
    log_event("2fa_disabled", user=user)
    flash("Two-factor authentication disabled.", "warning")
    return redirect(url_for("views.security"))


@auth_bp.route("/security/2fa/backup-codes", methods=["POST"])
def regenerate_backup_codes():
    user = current_user()
    if user is None:
        return redirect(url_for("auth.login"))
    if not is_sudo():
        session["next"] = url_for("views.security")
        return redirect(url_for("auth.confirm"))
    if not user.totp_enabled:
        flash("Turn on two-factor authentication first.", "warning")
        return redirect(url_for("views.security"))

    code = (request.form.get("code") or "").strip()
    secret = services.vault().open_str(user.totp_secret_enc)
    step = totp_match(secret, code, user.totp_last_step)
    if step is None:
        flash("Enter a current authenticator code to regenerate backup codes.", "error")
        return redirect(url_for("views.security"))
    user.totp_last_step = int(step)
    plain, hashed = new_backup_codes()
    user.backup_codes_json = hashed
    db.session.commit()
    log_event("backup_codes_regenerated", user=user)
    flash("New backup codes generated. The old ones no longer work.", "success")
    return render_template("backup_codes.html", codes=plain)


# ------------------------------------------------------------ password reset
# There is no self-service password reset: accounts are username + password
# only, so there is no verified out-of-band channel to send a reset link to.
# Recovery is an administrator setting a new password (admin/user_password),
# which also signs the account's existing sessions out.
@auth_bp.route("/reset", methods=["GET", "POST"])
def reset_request():
    flash("Password resets are handled by an administrator — ask them to set you "
          "a new one.", "warning")
    return redirect(url_for("auth.login"))



@auth_bp.route("/reset/<token>", methods=["GET", "POST"])
def reset_do(token):
    """Kept as a redirect so old mailed links land somewhere sensible."""
    flash("Reset links are no longer used — ask an administrator to set your "
          "password.", "warning")
    return redirect(url_for("auth.login"))

