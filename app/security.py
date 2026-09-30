"""Authentication, authorisation and abuse-control primitives."""

import hmac
import logging
import secrets
import time
from datetime import datetime, timedelta, timezone
from functools import wraps

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError
from flask import abort, current_app, flash, g, redirect, request, session, url_for
from pyotp import HOTP

from app.extensions import db
from app.models import AdminAudit, Alert, SecurityEvent, Throttle, User
from app.utils import client_ip

log = logging.getLogger("btcwallet.security")

# Argon2id at the OWASP-recommended minimum (19 MiB / t=2 / p=1): strong enough
# to make offline cracking expensive, cheap enough that a 2-core box still
# answers logins quickly.
_ph = PasswordHasher(time_cost=2, memory_cost=19456, parallelism=1, hash_len=32, salt_len=16)

# hash of a throwaway password, used to burn the same CPU time when the
# username does not exist (defeats timing-based account enumeration)
_DUMMY_HASH = _ph.hash("timing-equalisation-placeholder")


# ------------------------------------------------------------------ passwords
def hash_password(password: str) -> str:
    return _ph.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    try:
        return _ph.verify(stored_hash, password)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def dummy_verify():
    """Consume equivalent time when there is no user to verify against."""
    try:
        _ph.verify(_DUMMY_HASH, "not-the-password")
    except Exception:
        pass


def needs_rehash(stored_hash: str) -> bool:
    try:
        return _ph.check_needs_rehash(stored_hash)
    except Exception:
        return False


# ----------------------------------------------------------------------- 2FA
def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, username: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def totp_now(secret: str) -> str:
    return pyotp.TOTP(secret).now()


def totp_match(secret: str, code: str, last_step=None):
    """Return the matched time-step, or None.

    Accepts the previous/current/next 30-second window (clock drift on a phone
    is normal) but refuses any step already used, so a code cannot be replayed
    if it is captured from the network or a shoulder-surfed screen.

    Note: ``pyotp.hotp`` is a module in this version, not an instance, so the
    code must be derived through the HOTP class — ``pyotp.hotp.at()`` does not
    exist and would silently reject every valid code.
    """
    code = str(code or "").strip().replace(" ", "").replace("-", "")
    if not code.isdigit() or len(code) != 6:
        return None
    counter = int(time.time()) // 30
    for offset in (-1, 0, 1):
        step = counter + offset
        try:
            expected = str(HOTP(secret).at(step))
        except Exception:
            return None
        if hmac.compare_digest(expected, code):
            if last_step is not None and step <= int(last_step):
                return None
            return step
    return None


# ------------------------------------------------------------- backup codes
BACKUP_CODE_COUNT = 10


def new_backup_codes():
    """Returns (plaintext_codes, json_of_hashes). Plaintext is shown once."""
    plain = []
    for _ in range(BACKUP_CODE_COUNT):
        raw = secrets.token_hex(5).upper()
        plain.append(f"{raw[:5]}-{raw[5:]}")
    import json

    return plain, json.dumps([hash_password(c) for c in plain])


def consume_backup_code(user: User, code: str) -> bool:
    """Single-use: a matching code is removed from the stored set."""
    import json

    if not user.backup_codes_json:
        return False
    code = (code or "").strip().upper().replace(" ", "")
    try:
        hashes = json.loads(user.backup_codes_json)
    except Exception:
        return False
    for i, h in enumerate(hashes):
        if verify_password(h, code):
            del hashes[i]
            user.backup_codes_json = json.dumps(hashes)
            db.session.commit()
            return True
    return False


# ------------------------------------------------------------------ throttle
def throttle(bucket: str, limit: int, window_seconds: int) -> bool:
    """DB-backed rate limit. Returns True if the action is ALLOWED.

    Counted in Postgres rather than memory so it stays exact across restarts
    and worker processes — a limiter that resets when the container restarts is
    not a limiter. All rows for a bucket expire together, so the table stays
    small (one prune query per call).
    """
    if limit <= 0:
        return True
    cutoff = datetime.now(timezone.utc) - timedelta(seconds=window_seconds)
    # prune this bucket's expired rows
    db.session.query(Throttle).filter(
        Throttle.bucket == bucket, Throttle.created_at < cutoff
    ).delete(synchronize_session=False)
    used = db.session.query(Throttle).filter(Throttle.bucket == bucket).count()
    if used >= limit:
        db.session.commit()
        return False
    db.session.add(Throttle(bucket=bucket))
    db.session.commit()
    return True


def throttle_clear(bucket: str):
    db.session.query(Throttle).filter(Throttle.bucket == bucket).delete(
        synchronize_session=False
    )
    db.session.commit()


# ------------------------------------------------------------------- events
def log_event(kind: str, user: User = None, success: bool = True, detail: str = None,
              username: str = None):
    """Security event. Never raises — logging must not break a request."""
    try:
        db.session.add(SecurityEvent(
            user_id=user.id if user else None,
            username=(user.username if user else username) or None,
            kind=kind,
            success=success,
            ip=client_ip(request) if request else None,
            user_agent=(request.user_agent.string[:250] if request else None),
            detail=detail,
        ))
        db.session.commit()
    except Exception as exc:
        log.warning("could not record security event %s: %s", kind, exc)
        db.session.rollback()


def audit(admin: User, action: str, target: User = None, detail: str = None):
    try:
        db.session.add(AdminAudit(
            admin_id=admin.id if admin else None,
            admin_username=admin.username if admin else None,
            target_user_id=target.id if target else None,
            target_username=target.username if target else None,
            action=action,
            detail=detail,
            ip=client_ip(request) if request else None,
        ))
        db.session.commit()
    except Exception as exc:
        log.warning("could not record audit %s: %s", action, exc)
        db.session.rollback()


def raise_alert(kind: str, title: str, body: str = None, severity: str = "warning",
                user: User = None):
    """Flag something for the admin. Deduplicates identical open alerts so a
    repeat condition cannot bury the dashboard."""
    try:
        existing = (
            db.session.query(Alert)
            .filter(Alert.kind == kind, Alert.user_id == (user.id if user else None),
                    Alert.ack_at.is_(None))
            .first()
        )
        if existing:
            return existing
        alert = Alert(kind=kind, title=title[:160], body=body, severity=severity,
                      user_id=user.id if user else None,
                      username=user.username if user else None)
        db.session.add(alert)
        db.session.commit()
        return alert
    except Exception as exc:
        log.warning("could not raise alert %s: %s", kind, exc)
        db.session.rollback()
        return None


# ---------------------------------------------------------------- auth state
def load_user(user_id):
    return db.session.get(User, user_id)


def current_user():
    """The logged-in user for this request, or None.

    Every request re-checks ``session_version``: banning a user, changing their
    password or hitting "log out everywhere" bumps it, which kills their
    existing cookies immediately instead of waiting for expiry.
    """
    if getattr(g, "_cached_user", "unset") != "unset":
        return g._cached_user
    uid = session.get("uid")
    user = None
    if uid:
        user = db.session.get(User, uid)
        if user is None:
            session.clear()
        elif user.session_version != session.get("sv"):
            session.clear()
            user = None
        elif user.deleted_at is not None:
            session.clear()
            user = None
    g._cached_user = user
    return user


def login_user(user: User, remember_ip: bool = True):
    """Establish a fresh session. Session rotation on login prevents fixation."""
    session.clear()
    session["uid"] = user.id
    session["sv"] = user.session_version
    session["login_at"] = int(time.time())
    session.permanent = True
    user.last_login_at = datetime.now(timezone.utc)
    if remember_ip:
        user.last_login_ip = client_ip(request)
    user.failed_logins = 0
    user.locked_until = None
    db.session.commit()
    g._cached_user = user


def logout_user(reason: str = "user"):
    uid = session.get("uid")
    user = db.session.get(User, uid) if uid else None
    session.clear()
    g._cached_user = None
    if user:
        log_event("logout", user=user, detail=reason)


def is_sudo() -> bool:
    return float(session.get("sudo_until", 0) or 0) > time.time()


def grant_sudo():
    session["sudo_until"] = time.time() + current_app.config["SUDO_WINDOW_SECONDS"]


def revoke_sudo():
    session.pop("sudo_until", None)


def sudo_remaining() -> int:
    return max(0, int(float(session.get("sudo_until", 0) or 0) - time.time()))


# --------------------------------------------------------------- decorators
def gate_exempt(request_obj) -> bool:
    """True for the endpoints an account can still reach while an
    operator-imposed gate is outstanding.

    The gate must always be satisfiable: the user has to be able to enrol 2FA,
    change the password an admin demanded, look at their own security page and
    sign out. Without this the account would be trapped behind a wall with no
    door.
    """
    return (request_obj.endpoint or "") in (
        "static", "views.health", "auth.logout", "auth.setup_2fa",
        "views.security", "views.force_password_change",
    )


def account_gate(user):
    """Redirect while something an administrator required is still outstanding.

    Returns a response, or None when the account may proceed. Applied per
    request (not at login) so a requirement switched on mid-session takes effect
    immediately, and so a half-finished enrolment cannot be bypassed by an old
    cookie.

    Administrators are exempt — forcing 2FA or a password change on the operator
    turned a missing enrolment into a lockout of their own panel, which is worse
    than not having the control.
    """
    if user is None or user.is_admin or gate_exempt(request):
        return None
    if user.must_change_password:
        flash("An administrator requires a new password on this account before "
              "you can use the wallet again.", "warning")
        return redirect(url_for("views.force_password_change"))
    if user.require_2fa and not user.totp_enabled:
        flash("Two-factor authentication is required on this account. Set it up "
              "to continue.", "warning")
        return redirect(url_for("auth.setup_2fa"))
    return None


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        user = current_user()
        if user is None:
            session["next"] = request.full_path if request.method == "GET" else None
            return redirect(url_for("auth.login"))
        if user.is_banned:
            # a banned account must not keep browsing even with a valid cookie
            logout_user("banned")
            flash("This account has been suspended.", "error")
            return redirect(url_for("auth.login"))
        # Two-factor is NOT forced on administrators. Forcing it turned a missing
        # enrolment into a hard lockout of the operator's own panel, so instead the
        # admin gets a notice at every sign-in plus a standing banner (base.html)
        # and can turn it on from Admin -> Settings, Account -> Security. The same
        # exemption covers requirements an admin puts on *user* accounts.
        gate = account_gate(user)
        if gate is not None:
            return gate
        return view(*args, **kwargs)

    return wrapper


def active_required(view):
    """Blocks actions (not browsing) on frozen accounts."""

    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user.can_spend:
            flash("Your account is frozen — sending and withdrawing are disabled.", "error")
            return redirect(url_for("views.dashboard"))
        return view(*args, **kwargs)

    return wrapper


def admin_required(view):
    @wraps(view)
    @login_required
    def wrapper(*args, **kwargs):
        user = current_user()
        if not user.is_admin:
            log_event("admin_denied", user=user, success=False,
                      detail=f"{request.method} {request.path}")
            abort(403)
        return view(*args, **kwargs)

    return wrapper


def sudo_required(view):
    """Require a recent password re-entry for a sensitive action."""

    @wraps(view)
    def wrapper(*args, **kwargs):
        if not is_sudo():
            if request.method == "GET":
                session["next"] = request.full_path
            return redirect(url_for("auth.confirm"))
        return view(*args, **kwargs)

    return wrapper
