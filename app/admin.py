"""Admin panel: holdings, users, withdrawals, ledger, audit, settings."""

import csv
import io
import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import (Blueprint, Response, current_app, flash, redirect,
                   render_template, request, url_for)

from app import services
from app.auth import verify_sudo_credentials
from app.chain import ChainError
from app.crypto_vault import VaultError
from app.extensions import db
from app.models import (Address, AdminAudit, Alert, LedgerEntry, SecurityEvent,
                        Transaction, User, Withdrawal)
from app.price import get_price
from app.security import (admin_required, audit, current_user, grant_sudo,
                          hash_password, is_sudo, log_event, sudo_remaining,
                          throttle)
from app.services import SendError
from app.utils import btc_str_to_sats_signed, password_problems, sats_to_btc_str

log = logging.getLogger("btcwallet.admin")
admin_bp = Blueprint("admin", __name__, url_prefix="/admin")

PER_PAGE = 25


def _need_sudo(next_endpoint=None, **kw):
    """Every destructive admin action funnels through here. Returns a redirect
    when a fresh password confirmation is required, else None."""
    if is_sudo():
        return None
    nxt = url_for(next_endpoint, **kw) if next_endpoint else request.full_path
    flash("Confirm your password to perform that action.", "warning")
    return redirect(url_for("auth.confirm", next=nxt))


BOOL_SETTINGS = ("signups_enabled", "deposits_enabled", "withdrawals_enabled",
                 "net_fee_passthrough", "testnet_faucet_enabled")


def _settings_values(posted=None):
    """Current settings, overlaid with what was just submitted when given, so an
    inline password confirmation never throws away the admin's edits."""
    values = {k: services.get_setting(k) for k in services.SETTING_LABELS}
    if posted is not None:
        for key in services.SETTING_LABELS:
            if key not in posted and f"{key}__bool" not in posted:
                continue
            if key in BOOL_SETTINGS:
                values[key] = "1" if posted.get(key) else "0"
            else:
                values[key] = (posted.get(key) or "").strip()
    return values


def _render_settings(admin, need_sudo=False, posted=None):
    return render_template(
        "admin/settings.html", user=admin, values=_settings_values(posted),
        labels=services.SETTING_LABELS, sudo=sudo_remaining(),
        need_sudo=need_sudo or not is_sudo(), resubmitted=posted is not None,
        network=services.network().name,
        mismatch=services.seed_network_mismatch(),
        twofa=bool(admin.totp_enabled))


# ---------------------------------------------------------------- dashboard
@admin_bp.route("/")
@admin_required
def index():
    user = current_user()
    price, price_source = get_price()

    users_total = db.session.query(db.func.count()).select_from(User).filter(
        User.deleted_at.is_(None)).scalar() or 0
    active_total = db.session.query(db.func.count()).select_from(User).filter(
        User.status == "active", User.deleted_at.is_(None)).scalar() or 0
    frozen_total = db.session.query(db.func.count()).select_from(User).filter(
        User.status == "frozen", User.deleted_at.is_(None)).scalar() or 0
    banned_total = db.session.query(db.func.count()).select_from(User).filter(
        User.status == "banned", User.deleted_at.is_(None)).scalar() or 0
    negative = (db.session.query(User)
                .filter(User.negative_balance.is_(True), User.deleted_at.is_(None))
                .order_by(User.balance_sat.asc()).all())
    no_2fa = db.session.query(db.func.count()).select_from(User).filter(
        User.totp_enabled.is_(False), User.deleted_at.is_(None)).scalar() or 0
    now = datetime.now(timezone.utc)
    must_enrol = db.session.query(db.func.count()).select_from(User).filter(
        User.require_2fa.is_(True), User.totp_enabled.is_(False),
        User.deleted_at.is_(None)).scalar() or 0
    must_change = db.session.query(db.func.count()).select_from(User).filter(
        User.must_change_password.is_(True),
        User.deleted_at.is_(None)).scalar() or 0
    locked_out = db.session.query(db.func.count()).select_from(User).filter(
        User.locked_until.isnot(None), User.locked_until > now,
        User.deleted_at.is_(None)).scalar() or 0

    holdings = None
    holdings_error = None
    try:
        holdings = services.global_holdings()
    except Exception as exc:   # a flaky explorer must not blank the dashboard
        holdings_error = f"{type(exc).__name__}: {exc}"
        log.warning("holdings failed on admin dashboard: %s", exc)

    queued = (db.session.query(Withdrawal)
              .filter(Withdrawal.status == "queued")
              .order_by(Withdrawal.created_at.asc()).all())
    open_alerts = (db.session.query(Alert)
                   .filter(Alert.ack_at.is_(None))
                   .order_by(Alert.created_at.desc()).limit(25).all())
    recent_admin = (db.session.query(AdminAudit)
                    .order_by(AdminAudit.created_at.desc()).limit(12).all())
    recent_users = (db.session.query(User)
                    .filter(User.deleted_at.is_(None))
                    .order_by(User.created_at.desc()).limit(8).all())

    # 24h activity
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    sent_24h = (db.session.query(db.func.coalesce(db.func.sum(Transaction.amount_sat), 0))
                .filter(Transaction.category == "withdrawal",
                        Transaction.created_at >= since).scalar() or 0)
    dep_24h = (db.session.query(db.func.coalesce(db.func.sum(Transaction.amount_sat), 0))
               .filter(Transaction.category == "deposit",
                       Transaction.created_at >= since).scalar() or 0)

    mismatch = services.seed_network_mismatch()
    return render_template(
        "admin/index.html", user=user, price=price, price_source=price_source,
        users_total=users_total, active_total=active_total, frozen_total=frozen_total,
        banned_total=banned_total, negative=negative, no_2fa=no_2fa,
        must_enrol=must_enrol, must_change=must_change, locked_out=locked_out,
        holdings=holdings, holdings_error=holdings_error, queued=queued,
        alerts=open_alerts, recent_admin=recent_admin, recent_users=recent_users,
        sent_24h=sent_24h, dep_24h=dep_24h, mismatch=mismatch,
        signups_open=services.get_bool_setting("signups_enabled"),
        network=services.network().name, sudo=sudo_remaining(),
    )


# -------------------------------------------------------------------- users
@admin_bp.route("/users")
@admin_required
def users():
    user = current_user()
    q = (request.args.get("q") or "").strip()
    status = (request.args.get("status") or "all").strip()
    flag = (request.args.get("flag") or "").strip()
    page = max(1, request.args.get("page", type=int) or 1)

    query = db.session.query(User)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(db.func.lower(User.username).like(like))
    if status in ("active", "frozen", "banned"):
        query = query.filter(User.status == status)
    if flag == "negative":
        query = query.filter(User.negative_balance.is_(True))
    elif flag == "no2fa":
        query = query.filter(User.totp_enabled.is_(False))
    elif flag == "require2fa":
        query = query.filter(User.require_2fa.is_(True))
    elif flag == "pending2fa":
        # required to use 2FA but not enrolled yet: the accounts currently gated
        query = query.filter(User.require_2fa.is_(True), User.totp_enabled.is_(False))
    elif flag == "mustchange":
        query = query.filter(User.must_change_password.is_(True))
    elif flag == "locked":
        query = query.filter(User.locked_until.isnot(None),
                             User.locked_until > datetime.now(timezone.utc))
    elif flag == "nodeleted":
        query = query.filter(User.deleted_at.is_(None))

    total = query.count()
    rows = (query.order_by(User.created_at.desc())
            .offset((page - 1) * PER_PAGE).limit(PER_PAGE).all())
    price, _src = get_price()
    return render_template("admin/users.html", user=user, rows=rows, q=q,
                           status=status, flag=flag, page=page,
                           pages=max(1, (total + PER_PAGE - 1) // PER_PAGE),
                           total=total, price=price)


@admin_bp.route("/users/<int:uid>")
@admin_required
def user_detail(uid):
    admin = current_user()
    target = db.session.get(User, uid)
    if target is None:
        flash("No such user.", "error")
        return redirect(url_for("admin.users"))

    ledger = (db.session.query(LedgerEntry)
              .filter(LedgerEntry.user_id == uid)
              .order_by(LedgerEntry.created_at.desc()).limit(40).all())
    txs = (db.session.query(Transaction)
           .filter(Transaction.user_id == uid)
           .order_by(Transaction.created_at.desc()).limit(40).all())
    wds = (db.session.query(Withdrawal)
           .filter(Withdrawal.user_id == uid)
           .order_by(Withdrawal.created_at.desc()).limit(20).all())
    events = (db.session.query(SecurityEvent)
              .filter(SecurityEvent.user_id == uid)
              .order_by(SecurityEvent.created_at.desc()).limit(25).all())
    audits = (db.session.query(AdminAudit)
              .filter(AdminAudit.target_user_id == uid)
              .order_by(AdminAudit.created_at.desc()).limit(25).all())
    price, _src = get_price()

    utxos = None
    utxo_error = None
    try:
        utxos = services.user_utxos(target)
    except Exception as exc:
        utxo_error = str(exc)

    return render_template("admin/user_detail.html", user=admin, target=target,
                           ledger=ledger, txs=txs, wds=wds, events=events,
                           audits=audits, price=price, utxos=utxos,
                           utxo_error=utxo_error, sudo=sudo_remaining(),
                           admins=(db.session.query(User)
                                   .filter(User.role == "admin",
                                           User.deleted_at.is_(None))
                                   .order_by(User.username).all()),
                           auto_max=services.get_int_setting("instant_send_max_sat"))


@admin_bp.route("/users/<int:uid>/status", methods=["POST"])
@admin_required
def user_status(uid):
    admin = current_user()
    target = db.session.get(User, uid)
    if target is None:
        flash("No such user.", "error")
        return redirect(url_for("admin.users"))

    action = (request.form.get("action") or "").strip()
    reason = (request.form.get("reason") or "").strip()[:300]

    if action == "ban" and target.id == admin.id:
        flash("You cannot ban your own account.", "error")
        return redirect(url_for("admin.user_detail", uid=uid))
    if action in ("ban", "delete") and target.is_admin and target.id != admin.id:
        flash("Demote that administrator before banning or deleting them.", "error")
        return redirect(url_for("admin.user_detail", uid=uid))

    redirect_resp = _need_sudo("admin.user_detail", uid=uid)
    if redirect_resp:
        return redirect_resp

    if action == "freeze":
        target.status = "frozen"
        target.session_version = (target.session_version or 0) + 1
        audit(admin, "user_freeze", target, reason)
        log_event("admin_freeze", user=target, detail=f"by {admin.username}: {reason}")
        flash(f"{target.username} frozen — they can still sign in and deposit, "
              f"but cannot send or withdraw.", "success")
    elif action == "unfreeze":
        target.status = "active"
        audit(admin, "user_unfreeze", target, reason)
        log_event("admin_unfreeze", user=target, detail=f"by {admin.username}")
        flash(f"{target.username} unfrozen.", "success")
    elif action == "ban":
        target.status = "banned"
        target.session_version = (target.session_version or 0) + 1
        audit(admin, "user_ban", target, reason)
        log_event("admin_ban", user=target, detail=f"by {admin.username}: {reason}")
        flash(f"{target.username} banned and signed out everywhere.", "success")
    elif action == "unban":
        target.status = "active"
        audit(admin, "user_unban", target, reason)
        flash(f"{target.username} unbanned.", "success")
    elif action == "force_logout":
        target.session_version = (target.session_version or 0) + 1
        audit(admin, "force_logout", target, reason)
        flash(f"All sessions for {target.username} were invalidated.", "success")
    else:
        flash("Unknown action.", "error")

    db.session.commit()
    return redirect(url_for("admin.user_detail", uid=uid))


@admin_bp.route("/users/<int:uid>/balance", methods=["POST"])
@admin_required
def user_balance(uid):
    """Set an absolute balance, or credit/debit by an amount.

    A resulting negative balance is allowed but deliberately loud: the account
    is flagged and a critical alert is raised, because it means the ledger no
    longer matches what the wallet can pay out.
    """
    admin = current_user()
    target = db.session.get(User, uid)
    if target is None:
        flash("No such user.", "error")
        return redirect(url_for("admin.users"))
    redirect_resp = _need_sudo("admin.user_detail", uid=uid)
    if redirect_resp:
        return redirect_resp

    mode = (request.form.get("mode") or "set").strip()
    raw = (request.form.get("amount") or "").strip()
    note = (request.form.get("note") or "").strip()[:300]

    try:
        value = btc_str_to_sats_signed(raw) if raw else None
    except ValueError as exc:
        flash(f"Amount problem: {exc}", "error")
        return redirect(url_for("admin.user_detail", uid=uid))

    before = int(target.balance_sat or 0)
    try:
        if mode == "set":
            if value is None:
                flash("Enter a balance to set.", "error")
                return redirect(url_for("admin.user_detail", uid=uid))
            if not request.form.get("allow_negative") and value < 0:
                flash("Tick 'allow negative' to force a negative balance.", "error")
                return redirect(url_for("admin.user_detail", uid=uid))
            entry, delta = services.set_balance_absolute(target, value, admin, note)
            audit(admin, "balance_set", target,
                  f"{before} -> {value} (delta {delta}); {note}")
            flash(f"Balance set to {sats_to_btc_str(value)} BTC "
                  f"({value} sats), change {delta:+d} sats.", "success")
        elif mode in ("credit", "debit"):
            if not value or value <= 0:
                flash("Enter a positive amount.", "error")
                return redirect(url_for("admin.user_detail", uid=uid))
            delta = value if mode == "credit" else -value
            services.apply_ledger(target, delta,
                                  "admin_credit" if mode == "credit" else "admin_debit",
                                  ref=f"admin:{admin.id}",
                                  note=note or f"{mode} by {admin.username}",
                                  created_by=admin.id)
            audit(admin, f"balance_{mode}", target, f"{delta:+d} sats; {note}")
            flash(f"{'Credited' if delta > 0 else 'Debited'} "
                  f"{abs(delta)} sats ({'credit' if delta > 0 else 'debit'}).", "success")
        else:
            flash("Unknown balance operation.", "error")
    except Exception as exc:
        db.session.rollback()
        log.exception("balance change failed")
        flash(f"Could not change the balance: {exc}", "error")

    return redirect(url_for("admin.user_detail", uid=uid))


@admin_bp.route("/users/<int:uid>/password", methods=["POST"])
@admin_required
def user_password(uid):
    """Set a user's password: either generated, or chosen by the admin.

    The result is shown once on a dedicated page rather than as a flash
    message, because a flash would sit in the session until consumed. Every
    existing session for that account is signed out.
    """
    admin = current_user()
    target = db.session.get(User, uid)
    if target is None:
        flash("No such user.", "error")
        return redirect(url_for("admin.users"))
    redirect_resp = _need_sudo("admin.user_detail", uid=uid)
    if redirect_resp:
        return redirect_resp

    mode = (request.form.get("mode") or "generate").strip()
    if mode == "set":
        chosen = request.form.get("password") or ""
        confirm = request.form.get("password2") or ""
        if chosen != confirm:
            flash("The two passwords do not match.", "error")
            return redirect(url_for("admin.user_detail", uid=uid))
        problems = password_problems(
            chosen, target.username, "",
            current_app.config["PASSWORD_MIN_LENGTH"],
        )
        if problems:
            for p in problems:
                flash(p, "error")
            return redirect(url_for("admin.user_detail", uid=uid))
        new_password = chosen
        action = "password_set"
        detail = f"password set by {admin.username}"
    else:
        new_password = "btc-" + secrets.token_urlsafe(9)
        action = "password_reset"
        detail = f"temporary password issued by {admin.username}"

    target.password_hash = hash_password(new_password)
    target.session_version = (target.session_version or 0) + 1
    target.failed_logins = 0
    target.locked_until = None
    db.session.commit()
    audit(admin, action, target, detail)
    log_event(action, user=target, detail=f"by {admin.username}")
    return render_template("admin/password_set.html", user=admin, target=target,
                           password=new_password, generated=(mode != "set"))


@admin_bp.route("/users/<int:uid>/sweep", methods=["POST"])
@admin_required
def user_sweep(uid):
    """Move a user's whole balance onto an administrator account.

    Nothing moves on-chain — the BTC is already in the hot wallet; this moves
    the ledger claim on it. Used to empty an account, and called automatically
    before an account is deleted, so a balance can never simply evaporate.
    """
    admin = current_user()
    target = db.session.get(User, uid)
    if target is None:
        flash("No such user.", "error")
        return redirect(url_for("admin.users"))
    redirect_resp = _need_sudo("admin.user_detail", uid=uid)
    if redirect_resp:
        return redirect_resp

    recipient = _sweep_recipient(request, admin)
    if recipient is None:
        flash("Choose an administrator account as the destination.", "error")
        return redirect(url_for("admin.user_detail", uid=uid))
    if recipient.id == target.id:
        flash("Source and destination are the same account.", "error")
        return redirect(url_for("admin.user_detail", uid=uid))

    before = int(target.balance_sat or 0)
    if before == 0:
        flash(f"{target.username} has a zero balance — nothing to move.", "warning")
        return redirect(url_for("admin.user_detail", uid=uid))

    try:
        amount, _out, _in = services.sweep_balance(
            target, recipient, admin,
            note=(request.form.get("note") or "").strip()[:300] or None,
        )
    except Exception as exc:
        db.session.rollback()
        log.exception("balance sweep failed")
        flash(f"Could not move the balance: {exc}", "error")
        return redirect(url_for("admin.user_detail", uid=uid))

    audit(admin, "balance_swept", target,
          f"{before} -> 0 sats, {amount} sats moved to {recipient.username}")
    log_event("balance_swept", user=target,
              detail=f"{amount} sats to {recipient.username} by {admin.username}")
    flash(f"Moved {amount} sats from {target.username} to {recipient.username}."
          + (" (negative balance — the debt was absorbed.)" if amount < 0 else ""),
          "success")
    return redirect(url_for("admin.user_detail", uid=uid))


def _sweep_recipient(request_obj, acting_admin):
    """Resolve the destination account for a balance sweep (default: the actor)."""
    rid = request_obj.form.get("recipient", type=int)
    if not rid:
        return acting_admin
    candidate = db.session.get(User, rid)
    if candidate and candidate.is_admin and candidate.deleted_at is None:
        return candidate
    return None


def _clear_totp(admin, target):
    """Wipe an account's 2FA enrolment (lost or broken authenticator)."""
    target.totp_enabled = False
    target.totp_secret_enc = None
    target.backup_codes_json = None
    target.session_version = (target.session_version or 0) + 1
    db.session.commit()
    audit(admin, "totp_reset", target, "2FA cleared")
    log_event("admin_totp_reset", user=target, detail=f"by {admin.username}")


@admin_bp.route("/users/<int:uid>/totp", methods=["POST"])
@admin_required
def user_totp_reset(uid):
    """Clear a user's 2FA when they have lost their authenticator and codes."""
    admin = current_user()
    target = db.session.get(User, uid)
    if target is None:
        flash("No such user.", "error")
        return redirect(url_for("admin.users"))
    redirect_resp = _need_sudo("admin.user_detail", uid=uid)
    if redirect_resp:
        return redirect_resp

    _clear_totp(admin, target)
    if target.require_2fa:
        flash(f"Two-factor authentication cleared for {target.username}. They are "
              f"still required to use it, so they must enrol again at the next "
              f"sign-in.", "warning")
    else:
        flash(f"Two-factor authentication cleared for {target.username}.", "success")
    return redirect(url_for("admin.user_detail", uid=uid))


def _inline_sudo(admin, uid):
    """Inline password confirmation for the account-security card.

    Returns a redirect when the confirmation is still outstanding, else None.
    The confirmation is collected on the user page itself: bouncing this POST to
    /confirm would return as a GET, so the clicked action would silently never
    happen — the exact failure the settings page already had to fix.
    """
    if is_sudo():
        return None
    back = redirect(url_for("admin.user_detail", uid=uid))
    password = request.form.get("sudo_password") or ""
    code = (request.form.get("sudo_code") or "").strip()
    if not password and not code:
        flash("Confirm your password in the box at the top of the security card, "
              "then click the action again — nothing has changed yet.", "warning")
        return back
    if not throttle(f"sudo:{admin.id}", 12, 600):
        flash("Too many attempts. Wait a few minutes.", "error")
        return back
    ok, err = verify_sudo_credentials(admin, password, code)
    if not ok:
        flash(err, "error")
        return back
    grant_sudo()
    log_event("sudo_granted", user=admin, detail="account security confirmation")
    return None


@admin_bp.route("/users/<int:uid>/security", methods=["POST"])
@admin_required
def user_security(uid):
    """Account requirements and housekeeping an operator needs on a live wallet.

    The gates (require 2FA, require a new password) apply to USER accounts only.
    Forcing either on an administrator is a self-lockout: a missing 2FA enrolment
    or a forgotten password would leave the operator unable to reach the panel
    that could undo it. That policy is enforced here, not just in the template.
    """
    admin = current_user()
    target = db.session.get(User, uid)
    if target is None:
        flash("No such user.", "error")
        return redirect(url_for("admin.users"))
    back = redirect(url_for("admin.user_detail", uid=uid))

    action = (request.form.get("action") or "").strip()
    if action not in ("require_2fa_on", "require_2fa_off", "clear_2fa",
                      "require_password_on", "require_password_off", "unlock",
                      "clear_negative"):
        flash("Unknown action.", "error")
        return back

    redirect_resp = _inline_sudo(admin, uid)
    if redirect_resp is not None:
        return redirect_resp

    if action in ("require_2fa_on", "require_password_on") and target.is_admin:
        flash("Administrator accounts are exempt: forcing 2FA or a password change "
              "on the operator would lock them out of the panel that toggles it. "
              "Manage 2FA from Account → Security instead.", "error")
        return back

    if action == "require_2fa_on":
        if target.require_2fa and target.totp_enabled:
            flash(f"{target.username} already has 2FA enabled and required.", "info")
        elif target.totp_enabled:
            target.require_2fa = True
            db.session.commit()
            audit(admin, "require_2fa_on", target, "2FA required (already enrolled)")
            flash(f"{target.username} already has 2FA enabled — it is now required, "
                  f"so they cannot switch it off.", "success")
        else:
            target.require_2fa = True
            db.session.commit()
            audit(admin, "require_2fa_on", target, "2FA required, not yet enrolled")
            log_event("admin_require_2fa", user=target, detail=f"by {admin.username}")
            flash(f"{target.username} must now enrol 2FA. Their next request — "
                  f"including any open session — lands on the setup page and the "
                  f"rest of the wallet stays blocked until they finish.", "success")

    elif action == "require_2fa_off":
        if not target.require_2fa:
            flash(f"2FA is not required for {target.username}.", "info")
        else:
            target.require_2fa = False
            db.session.commit()
            audit(admin, "require_2fa_off", target, "2FA requirement lifted")
            flash(f"{target.username} is no longer required to use 2FA"
                  + (" (they are still enrolled — you can clear that separately)."
                     if target.totp_enabled else "."), "success")

    elif action == "clear_2fa":
        if target.is_admin:
            flash("Administrator 2FA is managed by the account itself, from "
                  "Account → Security.", "error")
            return back
        if not target.totp_enabled:
            flash(f"{target.username} does not have 2FA enabled.", "info")
        else:
            _clear_totp(admin, target)
            if target.require_2fa:
                flash(f"2FA cleared for {target.username}. They are still required to "
                      f"use it, so they must enrol again at their next sign-in.",
                      "warning")
            else:
                flash(f"2FA cleared for {target.username} — they can sign in with just "
                      f"their password until they enrol again.", "success")

    elif action == "require_password_on":
        if target.must_change_password:
            flash(f"{target.username} is already required to change their password.",
                  "info")
        else:
            target.must_change_password = True
            db.session.commit()
            audit(admin, "require_password_on", target, "password change required")
            log_event("admin_require_password", user=target, detail=f"by {admin.username}")
            flash(f"{target.username} must set a new password. Their next request — "
                  f"including any open session — lands on the change-password page; "
                  f"they keep the balance and everything else.", "success")

    elif action == "require_password_off":
        if not target.must_change_password:
            flash(f"{target.username} is not required to change their password.", "info")
        else:
            target.must_change_password = False
            db.session.commit()
            audit(admin, "require_password_off", target, "password requirement lifted")
            flash(f"Password-change requirement lifted for {target.username}.", "success")

    elif action == "unlock":
        was_locked = bool(target.is_locked_out)
        target.failed_logins = 0
        target.locked_until = None
        db.session.commit()
        audit(admin, "unlock", target,
              "lockout cleared" if was_locked else "counters cleared (no active lockout)")
        log_event("admin_unlock", user=target, detail=f"by {admin.username}")
        flash(f"{target.username} can sign in again — failed attempts and the "
              f"lockout are cleared." if was_locked else
              f"Counters cleared for {target.username} (no active lockout).", "success")

    elif action == "clear_negative":
        if int(target.balance_sat or 0) < 0:
            flash(f"{target.username} is still at a negative balance "
                  f"({target.balance_sat} sats) — fix the balance first. The flag "
                  f"only exists to match reality.", "error")
            return back
        if not target.negative_balance:
            flash(f"{target.username} is not flagged.", "info")
        else:
            target.negative_balance = False
            db.session.commit()
            audit(admin, "negative_flag_cleared", target,
                  f"cleared at balance {target.balance_sat} sats")
            log_event("negative_flag_cleared", user=target, detail=f"by {admin.username}")
            flash(f"Negative-balance flag cleared for {target.username} "
                  f"(balance {target.balance_sat} sats).", "success")

    return back


@admin_bp.route("/users/<int:uid>/role", methods=["POST"])
@admin_required
def user_role(uid):
    admin = current_user()
    target = db.session.get(User, uid)
    if target is None:
        flash("No such user.", "error")
        return redirect(url_for("admin.users"))
    if target.id == admin.id:
        flash("You cannot change your own role.", "error")
        return redirect(url_for("admin.user_detail", uid=uid))
    redirect_resp = _need_sudo("admin.user_detail", uid=uid)
    if redirect_resp:
        return redirect_resp

    new_role = (request.form.get("role") or "user").strip()
    if new_role not in ("user", "admin"):
        flash("Unknown role.", "error")
        return redirect(url_for("admin.user_detail", uid=uid))

    target.role = new_role
    target.session_version = (target.session_version or 0) + 1
    db.session.commit()
    audit(admin, "role_change", target, f"-> {new_role}")
    flash(f"{target.username} is now {new_role}.", "success")
    return redirect(url_for("admin.user_detail", uid=uid))


@admin_bp.route("/users/<int:uid>/notes", methods=["POST"])
@admin_required
def user_notes(uid):
    admin = current_user()
    target = db.session.get(User, uid)
    if target is None:
        flash("No such user.", "error")
        return redirect(url_for("admin.users"))
    target.notes = (request.form.get("notes") or "").strip()[:4000]
    db.session.commit()
    audit(admin, "notes_updated", target, "admin notes edited")
    flash("Notes saved.", "success")
    return redirect(url_for("admin.user_detail", uid=uid))


@admin_bp.route("/users/<int:uid>/delete", methods=["POST"])
@admin_required
def user_delete(uid):
    """Delete an account, moving any balance out first.

    Value is never destroyed: if the account holds anything, it is swept onto an
    administrator account BEFORE the row is removed. If that sweep cannot be
    completed, the delete is abandoned — an un-swept balance would become
    unattributable coins still sitting in the hot wallet.
    """
    admin = current_user()
    target = db.session.get(User, uid)
    if target is None:
        flash("No such user.", "error")
        return redirect(url_for("admin.users"))
    if target.id == admin.id:
        flash("You cannot delete your own account.", "error")
        return redirect(url_for("admin.user_detail", uid=uid))
    if target.is_admin:
        flash("Demote that administrator before deleting them.", "error")
        return redirect(url_for("admin.user_detail", uid=uid))
    redirect_resp = _need_sudo("admin.user_detail", uid=uid)
    if redirect_resp:
        return redirect_resp

    confirm_name = (request.form.get("confirm") or "").strip()
    if confirm_name != target.username:
        flash(f"Type the username exactly ({target.username}) to confirm deletion.",
              "error")
        return redirect(url_for("admin.user_detail", uid=uid))

    recipient = _sweep_recipient(request, admin)
    if recipient is None:
        flash("Choose an administrator account to receive the balance.", "error")
        return redirect(url_for("admin.user_detail", uid=uid))

    username = target.username
    balance = int(target.balance_sat or 0)
    addr_count = len(target.addresses)
    swept = 0

    if balance != 0:
        try:
            swept, _out, _in = services.sweep_balance(
                target, recipient, admin,
                note=f"Recovered from {username} on account deletion",
            )
        except Exception as exc:
            db.session.rollback()
            log.exception("refusing to delete %s: balance sweep failed", username)
            flash(f"Nothing was deleted: the {balance} sat balance could not be "
                  f"moved to {recipient.username} ({exc}). Fix that first — "
                  f"deleting now would strand those coins.", "error")
            return redirect(url_for("admin.user_detail", uid=uid))
        audit(admin, "balance_swept", target,
              f"{balance} sats -> {recipient.username} before deletion")
        log.warning("swept %s sats from %s to %s before deleting the account",
                    swept, username, recipient.username)

    db.session.delete(target)
    db.session.commit()
    audit(admin, "user_delete", None,
          f"deleted {username} ({addr_count} addresses, {swept} sats swept to "
          f"{recipient.username})")
    log.warning("admin %s deleted user %s (swept %s sats to %s)",
                admin.username, username, swept, recipient.username)

    if swept:
        flash(f"Deleted {username}. {swept} sats were moved to "
              f"{recipient.username} — nothing was lost.", "success")
    else:
        flash(f"Deleted {username} (zero balance).", "success")
    return redirect(url_for("admin.users"))


# ------------------------------------------------------------- withdrawals
@admin_bp.route("/withdrawals")
@admin_required
def withdrawals():
    status = (request.args.get("status") or "queued").strip()
    q = db.session.query(Withdrawal)
    if status != "all":
        q = q.filter(Withdrawal.status == status)
    rows = q.order_by(Withdrawal.created_at.desc()).limit(200).all()
    price, _src = get_price()
    return render_template("admin/withdrawals.html", user=current_user(), rows=rows,
                           status=status, price=price, sudo=sudo_remaining())


@admin_bp.route("/withdrawals/<int:wid>/decide", methods=["POST"])
@admin_required
def withdrawal_decide(wid):
    admin = current_user()
    w = db.session.get(Withdrawal, wid)
    if w is None:
        flash("No such withdrawal.", "error")
        return redirect(url_for("admin.withdrawals"))
    redirect_resp = _need_sudo("admin.withdrawals")
    if redirect_resp:
        return redirect_resp

    decision = (request.form.get("decision") or "").strip()
    reason = (request.form.get("reason") or "").strip()[:300]
    try:
        if decision == "approve":
            txid = services.approve_withdrawal(w, admin)
            audit(admin, "withdrawal_approve", db.session.get(User, w.user_id),
                  f"wd:{w.id} {w.amount_sat} sats txid={txid}")
            flash(f"Withdrawal #{w.id} broadcast: {txid}", "success")
        elif decision == "reject":
            services.reject_withdrawal(w, admin, reason)
            audit(admin, "withdrawal_reject", db.session.get(User, w.user_id),
                  f"wd:{w.id} {w.amount_sat} sats: {reason}")
            flash(f"Withdrawal #{w.id} rejected and the funds returned to the user.",
                  "success")
        else:
            flash("Unknown decision.", "error")
    except (SendError, ChainError) as exc:
        flash(str(exc), "error")
    except Exception as exc:
        db.session.rollback()
        log.exception("withdrawal decision failed")
        flash(f"Something went wrong: {exc}", "error")
    return redirect(url_for("admin.withdrawals"))


# ------------------------------------------------------------- transactions
@admin_bp.route("/transactions")
@admin_required
def transactions():
    kind = (request.args.get("kind") or "all").strip()
    q = (request.args.get("q") or "").strip()
    page = max(1, request.args.get("page", type=int) or 1)

    query = db.session.query(Transaction).join(User, Transaction.user_id == User.id)
    if kind in ("deposit", "withdrawal", "admin"):
        query = query.filter(Transaction.category == kind)
    if q:
        like = f"%{q.lower()}%"
        query = query.filter(db.or_(db.func.lower(User.username).like(like),
                                    db.func.lower(Transaction.address).like(like),
                                    db.func.lower(Transaction.txid).like(like)))
    total = query.count()
    rows = (query.order_by(Transaction.created_at.desc())
            .offset((page - 1) * PER_PAGE).limit(PER_PAGE).all())
    price, _src = get_price()
    return render_template("admin/transactions.html", user=current_user(), rows=rows,
                           kind=kind, q=q, page=page,
                           pages=max(1, (total + PER_PAGE - 1) // PER_PAGE),
                           total=total, price=price)


@admin_bp.route("/ledger")
@admin_required
def ledger():
    page = max(1, request.args.get("page", type=int) or 1)
    q = (db.session.query(LedgerEntry).join(User, LedgerEntry.user_id == User.id))
    total = q.count()
    rows = (q.order_by(LedgerEntry.created_at.desc())
            .offset((page - 1) * PER_PAGE).limit(PER_PAGE).all())
    return render_template("admin/ledger.html", user=current_user(), rows=rows,
                           page=page, pages=max(1, (total + PER_PAGE - 1) // PER_PAGE),
                           total=total)


# ------------------------------------------------------------------- wallet
@admin_bp.route("/wallet")
@admin_required
def wallet():
    admin = current_user()
    addresses = db.session.query(Address).order_by(Address.idx.asc()).all()
    by_user = {}
    for a in addresses:
        by_user.setdefault(a.user_id, []).append(a)
    users_by_id = {u.id: u for u in db.session.query(User).all()}
    holdings = None
    error = None
    try:
        holdings = services.global_holdings()
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        log.warning("holdings failed on wallet page: %s", exc)
    price, _src = get_price()
    return render_template("admin/wallet.html", user=admin, addresses=addresses,
                           by_user=by_user, users_by_id=users_by_id,
                           holdings=holdings, error=error, price=price,
                           network=services.network().name,
                           mismatch=services.seed_network_mismatch(),
                           revealed=request.args.get("revealed") == "1")


@admin_bp.route("/wallet/seed", methods=["POST"])
@admin_required
def wallet_seed():
    """Reveal the hot wallet recovery phrase. Password + 2FA required, the
    action is audited, and it is rate limited — this is the single most
    sensitive thing in the system."""
    admin = current_user()
    redirect_resp = _need_sudo("admin.wallet")
    if redirect_resp:
        return redirect_resp
    from app.security import throttle

    if not throttle(f"seed_reveal:{admin.id}", 3, 3600):
        flash("Too many seed reveals. Try again later.", "error")
        return redirect(url_for("admin.wallet"))
    try:
        mnemonic = services.reveal_mnemonic()
    except VaultError as exc:
        flash(f"Could not decrypt the seed: {exc}", "error")
        return redirect(url_for("admin.wallet"))
    audit(admin, "seed_revealed", None, "hot wallet mnemonic displayed")
    log_event("seed_revealed", user=admin)
    log.warning("admin %s revealed the hot wallet seed", admin.username)
    return render_template("admin/seed.html", user=admin, mnemonic=mnemonic,
                           network=services.network().name)


@admin_bp.route("/wallet/sync", methods=["POST"])
@admin_required
def wallet_sync():
    admin = current_user()
    admin_name = admin.username
    try:
        summary = services.sync_once(verbose=True)
        audit(admin, "manual_sync", None, str(summary))
        flash(f"Chain scan complete: {summary['deposits_credited']} new deposit(s) "
              f"credited across {summary['addresses_checked']} address(es) at "
              f"block {summary['tip']}.", "success")
    except ChainError as exc:
        flash(f"Chain scan failed: {exc}", "error")
    except Exception as exc:
        log.exception("manual sync failed for %s", admin_name)
        flash(f"Chain scan failed: {exc}", "error")
    return redirect(url_for("admin.wallet"))


# -------------------------------------------------------------- audit/misc
@admin_bp.route("/audit")
@admin_required
def audit_log():
    page = max(1, request.args.get("page", type=int) or 1)
    q = db.session.query(AdminAudit)
    total = q.count()
    rows = (q.order_by(AdminAudit.created_at.desc())
            .offset((page - 1) * PER_PAGE).limit(PER_PAGE).all())
    return render_template("admin/audit.html", user=current_user(), rows=rows,
                           page=page, pages=max(1, (total + PER_PAGE - 1) // PER_PAGE),
                           total=total)


@admin_bp.route("/alerts", methods=["GET"])
@admin_required
def alerts():
    show = (request.args.get("show") or "open").strip()
    q = db.session.query(Alert)
    if show == "open":
        q = q.filter(Alert.ack_at.is_(None))
    rows = q.order_by(Alert.created_at.desc()).limit(200).all()
    return render_template("admin/alerts.html", user=current_user(), rows=rows, show=show)


@admin_bp.route("/alerts/<int:aid>/ack", methods=["POST"])
@admin_required
def alert_ack(aid):
    admin = current_user()
    a = db.session.get(Alert, aid)
    if a is None:
        flash("No such alert.", "error")
        return redirect(url_for("admin.alerts"))
    a.ack_at = datetime.now(timezone.utc)
    a.ack_by = admin.id
    db.session.commit()
    audit(admin, "alert_ack", None, f"alert {aid}: {a.title}")
    flash("Alert acknowledged.", "success")
    return redirect(request.form.get("back") or url_for("admin.alerts"))


@admin_bp.route("/alerts/ack-all", methods=["POST"])
@admin_required
def alerts_ack_all():
    admin = current_user()
    n = (db.session.query(Alert).filter(Alert.ack_at.is_(None))
         .update({"ack_at": datetime.now(timezone.utc), "ack_by": admin.id},
                 synchronize_session=False))
    db.session.commit()
    audit(admin, "alerts_ack_all", None, f"{n} alerts")
    flash(f"Acknowledged {n} alert(s).", "success")
    return redirect(url_for("admin.alerts"))


@admin_bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    admin = current_user()
    if request.method == "POST":
        if not is_sudo():
            # Confirm here, on the page itself. Bouncing this POST to /confirm
            # would lose the submitted form (a GET comes back), so the setting the
            # admin just changed silently never saved.
            password = request.form.get("sudo_password") or ""
            code = (request.form.get("sudo_code") or "").strip()
            if not password and not code:
                flash("Confirm your password to save these settings.", "warning")
                return _render_settings(admin, need_sudo=True, posted=request.form)
            if not throttle(f"sudo:{admin.id}", 12, 600):
                flash("Too many attempts. Wait a few minutes.", "error")
                return _render_settings(admin, need_sudo=True,
                                        posted=request.form), 429
            ok, err = verify_sudo_credentials(admin, password, code)
            if not ok:
                flash(err, "error")
                return _render_settings(admin, need_sudo=True,
                                        posted=request.form), 401
            grant_sudo()
            log_event("sudo_granted", user=admin, detail="settings confirmation")

        changed = []
        for key in services.SETTING_LABELS:
            # A checkbox contributes only "<key>" when ticked. The "__bool"
            # marker sent alongside it is what distinguishes "deliberately off"
            # from "this field was not part of the form at all".
            is_bool = key in BOOL_SETTINGS
            if key not in request.form and f"{key}__bool" not in request.form:
                continue
            if is_bool:
                value = "1" if request.form.get(key) else "0"
            else:
                value = (request.form.get(key) or "").strip()
            if value == "" and key != "maintenance_message":
                continue
            old = services.get_setting(key)
            if old != value:
                services.set_setting(key, value)
                changed.append(f"{key}: {old!r} → {value!r}")
        if changed:
            audit(admin, "settings_changed", None, "; ".join(changed))
            flash(f"Saved {len(changed)} setting(s).", "success")
        else:
            flash("No changes to save.", "info")
        return redirect(url_for("admin.settings"))

    return _render_settings(admin)


# ------------------------------------------------------------------ exports
@admin_bp.route("/export/<what>.csv")
@admin_required
def export_csv(what):
    admin = current_user()
    buf = io.StringIO()
    w = csv.writer(buf)

    if what == "users":
        w.writerow(["id", "username", "role", "status", "balance_sat",
                    "balance_btc", "negative", "2fa", "created_at", "last_login_at",
                    "last_login_ip", "signup_ip"])
        for u in db.session.query(User).order_by(User.id.asc()).all():
            w.writerow([u.id, u.username, u.role, u.status,
                        int(u.balance_sat or 0), sats_to_btc_str(u.balance_sat),
                        "yes" if u.negative_balance else "no",
                        "yes" if u.totp_enabled else "no",
                        u.created_at, u.last_login_at, u.last_login_ip, u.signup_ip])
    elif what == "transactions":
        w.writerow(["id", "user", "category", "direction", "status", "amount_sat",
                    "amount_btc", "service_fee_sat", "network_fee_sat", "txid",
                    "address", "confirmations", "created_at", "confirmed_at"])
        rows = (db.session.query(Transaction).join(User, Transaction.user_id == User.id)
                .order_by(Transaction.created_at.desc()).limit(20000).all())
        for t in rows:
            w.writerow([t.id, t.user_id, t.category, t.direction, t.status,
                        t.amount_sat, sats_to_btc_str(t.amount_sat),
                        t.service_fee_sat, t.network_fee_sat, t.txid or "",
                        t.address or "", t.confirmations, t.created_at,
                        t.confirmed_at or ""])
    elif what == "ledger":
        w.writerow(["id", "user", "delta_sat", "balance_after_sat", "kind", "ref",
                    "note", "created_at"])
        rows = (db.session.query(LedgerEntry).order_by(LedgerEntry.created_at.desc())
                .limit(20000).all())
        for e in rows:
            w.writerow([e.id, e.user_id, e.delta_sat, e.balance_after_sat, e.kind,
                        e.ref or "", (e.note or "").replace("\n", " "), e.created_at])
    else:
        flash("Unknown export.", "error")
        return redirect(url_for("admin.index"))

    audit(admin, "export_csv", None, what)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return Response(
        buf.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment; filename={what}-{stamp}.csv"},
    )
