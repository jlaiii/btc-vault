"""User-facing wallet views."""

import logging
from datetime import datetime, timedelta, timezone

from flask import (Blueprint, current_app, flash, jsonify, redirect,
                   render_template, request, url_for)

from app import btc, services
from app.chain import ChainError, default_esplora_urls
from app.extensions import db
from app.models import Address, TestnetFaucetRequest, Transaction, User, Withdrawal
from app.price import get_price
from app.security import (active_required, current_user, hash_password,
                          is_sudo, log_event, login_required, logout_user,
                          sudo_remaining, throttle, verify_password)
from app.services import SendError
from app.utils import (btc_str_to_sats, client_ip, is_valid_username,
                       password_problems, qr_svg_data_uri, sats_to_btc_trim)

log = logging.getLogger("btcwallet.views")
views_bp = Blueprint("views", __name__)


# --------------------------------------------------------------- healthcheck
@views_bp.route("/health")
def health():
    return jsonify(ok=True, service="btcwallet")


# ------------------------------------------------------------------ landing
@views_bp.route("/")
def index():
    user = current_user()
    if user is None:
        price, _src = get_price()
        return render_template("landing.html", price=price,
                               signups=services.get_bool_setting("signups_enabled"),
                               network=services.network().name)
    return redirect(url_for("views.dashboard"))


def _dashboard_context(user):
    price, source = get_price()
    rates, meta = services.get_fee_rates()
    pending = (
        db.session.query(Transaction)
        .filter(Transaction.user_id == user.id, Transaction.category == "deposit",
                Transaction.status == "pending")
        .order_by(Transaction.created_at.desc()).limit(10).all()
    )
    recent = (
        db.session.query(Transaction)
        .filter(Transaction.user_id == user.id)
        .order_by(Transaction.created_at.desc()).limit(8).all()
    )
    queued = (
        db.session.query(Withdrawal)
        .filter(Withdrawal.user_id == user.id, Withdrawal.status == "queued")
        .order_by(Withdrawal.created_at.desc()).all()
    )
    return {
        "price": price, "price_source": source,
        "rates": rates, "rates_meta": meta,
        "pending": pending, "recent": recent, "queued": queued,
        "addresses": user.addresses,
        "usd_total": services.usd_value(user.balance_sat, price),
        "pending_total": sum(t.amount_sat for t in pending),
        "network": services.network().name,
        "maintenance": services.get_setting("maintenance_message"),
    }


@views_bp.route("/wallet")
@login_required
def dashboard():
    user = current_user()
    # guarantee every account has somewhere to receive funds, even one created
    # by the CLI before it ever opened this page
    try:
        services.ensure_primary_address(user)
        db.session.refresh(user)
    except Exception as exc:
        log.warning("could not ensure a deposit address for %s: %s", user.username, exc)
    return render_template("dashboard.html", user=user, **_dashboard_context(user))


# ------------------------------------------------------------------ receive
@views_bp.route("/receive")
@login_required
def receive():
    user = current_user()
    services.ensure_primary_address(user)
    db.session.refresh(user)
    price, _src = get_price()
    net = services.network()
    faucet = None
    if net.name == "testnet" and services.get_bool_setting("testnet_faucet_enabled"):
        last = (
            db.session.query(TestnetFaucetRequest)
            .filter(TestnetFaucetRequest.user_id == user.id)
            .order_by(TestnetFaucetRequest.created_at.desc()).first()
        )
        cooldown_h = services.get_int_setting("testnet_faucet_cooldown_hours")
        ready_at = None
        if last and cooldown_h:
            ready_at = last.created_at + timedelta(hours=cooldown_h)
        faucet = {
            "amount_sat": services.get_int_setting("testnet_faucet_amount_sat"),
            "cooldown_hours": cooldown_h,
            "last": last,
            "ready_at": ready_at,
            "ready": (ready_at is None or ready_at <= datetime.now(timezone.utc)),
        }
    return render_template("receive.html", user=user, addresses=user.addresses,
                           network=net.name, price=price, faucet=faucet)


@views_bp.route("/receive/new", methods=["POST"])
@active_required
def new_address():
    user = current_user()
    if len(user.addresses) >= 20:
        flash("You have reached the maximum number of wallets (20).", "error")
        return redirect(url_for("views.receive"))
    addr = services.create_address(user, label=f"Wallet #{user.next_address_index}")
    log_event("address_created", user=user, detail=addr.address)
    flash("New deposit wallet created.", "success")
    return redirect(url_for("views.receive") + f"#w{addr.id}")


@views_bp.route("/receive/qr/<int:address_id>")
@login_required
def address_qr(address_id):
    """QR as an SVG image, so it can be opened directly or long-pressed to save."""
    from flask import Response

    user = current_user()
    addr = db.session.get(Address, address_id)
    if addr is None or addr.user_id != user.id:
        return "", 404
    uri = f"bitcoin:{addr.address}"
    data_uri = qr_svg_data_uri(uri)
    from urllib.parse import unquote

    svg = unquote(data_uri.split(",", 1)[1])
    return Response(svg, mimetype="image/svg+xml")


# ---------------------------------------------------------------- testnet faucet
@views_bp.route("/faucet", methods=["POST"])
@active_required
def faucet_request():
    """Testnet only: send a little play money from the wallet's own testnet
    coins so a new user can try a real send end to end."""
    user = current_user()
    net = services.network()
    if net.name != "testnet":
        flash("The faucet only exists on testnet.", "error")
        return redirect(url_for("views.dashboard"))
    if not services.get_bool_setting("testnet_faucet_enabled"):
        flash("The testnet faucet is turned off.", "warning")
        return redirect(url_for("views.receive"))

    cooldown_h = services.get_int_setting("testnet_faucet_cooldown_hours")
    last = (
        db.session.query(TestnetFaucetRequest)
        .filter(TestnetFaucetRequest.user_id == user.id,
                TestnetFaucetRequest.status.in_(("sent", "queued")))
        .order_by(TestnetFaucetRequest.created_at.desc()).first()
    )
    if last and cooldown_h and last.created_at + timedelta(hours=cooldown_h) > datetime.now(timezone.utc):
        wait = last.created_at + timedelta(hours=cooldown_h) - datetime.now(timezone.utc)
        flash(f"You already used the faucet. Try again in {int(wait.total_seconds()//3600)}h "
              f"{int((wait.total_seconds()%3600)//60)}m.", "warning")
        return redirect(url_for("views.receive"))

    if not throttle(f"faucet:{user.id}", 3, 86400):
        flash("Faucet limit reached for today.", "warning")
        return redirect(url_for("views.receive"))

    amount = services.get_int_setting("testnet_faucet_amount_sat")
    addr = services.ensure_primary_address(user)
    req = TestnetFaucetRequest(user_id=user.id, amount_sat=amount, status="queued",
                               ip=client_ip(request))
    db.session.add(req)
    db.session.commit()

    try:
        txid = _send_from_wallet(addr.address, amount)
        req.status = "sent"
        req.txid = txid
        db.session.commit()
        log_event("faucet_sent", user=user, detail=f"{amount} sats {txid}")
        flash(f"Sent {sats_to_btc_trim(amount)} testnet BTC to your wallet. "
              f"It shows up after one confirmation.", "success")
    except Exception as exc:
        req.status = "failed"
        req.error = str(exc)[:400]
        db.session.commit()
        log.warning("faucet send failed: %s", exc)
        flash("The faucet could not send right now. An operator has been notified.", "error")
        services.raise_alert("faucet_failed", "Testnet faucet send failed", str(exc)[:600],
                             severity="warning", user=user)

    return redirect(url_for("views.receive"))


def _send_from_wallet(dest_address: str, amount_sat: int):
    """Spend the wallet's own on-chain coins to an external address (faucet,
    manual payout). No ledger entry: this is the operator moving their float."""
    net = services.network()
    canonical, dest_script, dest_type = btc.validate_destination(dest_address, net)
    root = services.root_key()

    addresses = db.session.query(Address).all()
    utxos = []
    for addr in addresses:
        derived = btc.derive_address(root, net, addr.idx)
        for u in services.explorer().address_utxos(addr.address):
            if not (u.get("status") or {}).get("confirmed"):
                continue
            utxos.append(btc.Utxo(txid=u["txid"], vout=int(u["vout"]),
                                  value_sat=int(u["value"]), address=addr.address,
                                  script=derived.script, index=addr.idx,
                                  pubkey=derived.pubkey))
    if not utxos:
        raise RuntimeError("wallet has no confirmed on-chain funds")

    rates, _meta = services.get_fee_rates()
    rate = rates["normal"]
    selected, fee, _vsize = btc.select_coins(utxos, amount_sat, [dest_type, "p2wpkh"], rate)
    change_index = max(selected, key=lambda u: u.value_sat).index
    built = btc.build_signed_tx(root, net, selected, [(amount_sat, dest_script, dest_type)],
                                rate, change_index, fee)
    if not btc.verify_signed_tx(built["raw_hex"], net, selected):
        raise RuntimeError("signature self-check failed")
    from app.models import OurTx

    db.session.add(OurTx(txid=built["txid"], user_id=None, kind="faucet"))
    db.session.commit()
    return services.explorer().broadcast(built["raw_hex"])


# --------------------------------------------------------------------- send
@views_bp.route("/send", methods=["GET"])
@login_required
def send():
    user = current_user()
    rates, meta = services.get_fee_rates()
    price, _src = get_price()
    return render_template(
        "send.html", user=user, rates=rates, rates_meta=meta, price=price,
        min_amount=services.get_int_setting("withdraw_min_sat"),
        can_send=services.get_bool_setting("withdrawals_enabled"),
        usd_total=services.usd_value(user.balance_sat, price),
        fee_pct=services.get_float_setting("service_fee_pct"),
    )


@views_bp.route("/send/quote", methods=["POST"])
@active_required
def send_quote():
    user = current_user()
    dest = (request.form.get("address") or "").strip()
    amount_raw = (request.form.get("amount") or "").strip()
    priority = (request.form.get("priority") or "normal").strip()

    try:
        amount_sat = btc_str_to_sats(amount_raw)
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("views.send"))

    try:
        quote = services.quote_send(user, dest, amount_sat, priority)
    except SendError as exc:
        flash(str(exc), "error")
        return redirect(url_for("views.send"))
    except btc.BitcoinError as exc:
        # belt and braces: any other address/amount problem reads as a message
        flash(str(exc), "error")
        return redirect(url_for("views.send"))
    except ChainError:
        flash("The blockchain network is unreachable right now. Try again shortly.", "error")
        return redirect(url_for("views.send"))

    return redirect(url_for("views.send_review", quote_id=quote.id))


@views_bp.route("/send/review/<int:quote_id>")
@login_required
def send_review(quote_id):
    user = current_user()
    from app.models import SendQuote

    quote = db.session.get(SendQuote, quote_id)
    if quote is None or quote.user_id != user.id:
        flash("That send could not be found.", "error")
        return redirect(url_for("views.send"))
    if quote.used_at is not None:
        flash("That send was already submitted.", "warning")
        return redirect(url_for("views.activity"))

    p = quote.payload
    price, _src = get_price()
    expires_at = quote.created_at + timedelta(minutes=10)
    return render_template(
        "send_review.html", user=user, quote=quote, p=p, price=price,
        usd_amount=services.usd_value(p["amount_sat"], price),
        usd_total=services.usd_value(p["total_sat"], price),
        usd_balance=services.usd_value(user.balance_sat, price),
        expires_at=expires_at,
        sudo=sudo_remaining(),
        auto_max=services.get_int_setting("instant_send_max_sat"),
    )


@views_bp.route("/send/confirm/<int:quote_id>", methods=["POST"])
@active_required
def send_confirm(quote_id):
    user = current_user()
    from app.models import SendQuote

    quote = db.session.get(SendQuote, quote_id)
    if quote is None or quote.user_id != user.id:
        flash("That send could not be found.", "error")
        return redirect(url_for("views.send"))

    if not is_sudo():
        flash("Confirm your password to send funds.", "warning")
        return redirect(url_for("auth.confirm", next=url_for("views.send_review",
                                                             quote_id=quote_id)))

    try:
        w, outcome = services.execute_send(user, quote)
    except SendError as exc:
        flash(str(exc), "error")
        return redirect(url_for("views.send"))
    except ChainError:
        flash("The blockchain network is unreachable. Nothing was sent.", "error")
        return redirect(url_for("views.send"))

    if outcome == "queued":
        log_event("withdrawal_queued", user=user, detail=f"wd:{w.id} {w.amount_sat}")
        flash("Your withdrawal was submitted and is waiting for approval because it is "
              "larger than the automatic limit. The amount is on hold.", "warning")
    else:
        log_event("withdrawal_sent", user=user, detail=f"wd:{w.id} {w.txid}")
        flash(f"Sent {sats_to_btc_trim(w.amount_sat)} BTC. "
              f"Transaction {w.txid[:16]}… is on its way.", "success")
    return redirect(url_for("views.activity"))


# ----------------------------------------------------------------- activity
@views_bp.route("/activity")
@login_required
def activity():
    user = current_user()

    kind = (request.args.get("kind") or "all").strip()
    page = max(1, request.args.get("page", type=int) or 1)
    per_page = current_app.config["ITEMS_PER_PAGE"]

    q = db.session.query(Transaction).filter(Transaction.user_id == user.id)
    if kind in ("in", "out"):
        q = q.filter(Transaction.direction == kind)
    elif kind in ("deposit", "withdrawal", "admin"):
        q = q.filter(Transaction.category == kind)

    total = q.count()
    rows = (q.order_by(Transaction.created_at.desc())
            .offset((page - 1) * per_page).limit(per_page).all())
    price, _src = get_price()

    return render_template(
        "activity.html", user=user, rows=rows, kind=kind, page=page,
        pages=max(1, (total + per_page - 1) // per_page), total=total,
        price=price,
    )


@views_bp.route("/activity/<int:tx_id>")
@login_required
def activity_detail(tx_id):
    user = current_user()
    tx = db.session.get(Transaction, tx_id)
    if tx is None or tx.user_id != user.id:
        flash("That transaction was not found.", "error")
        return redirect(url_for("views.activity"))
    price, _src = get_price()
    explorer_base = (current_app.config.get("ESPLORA_URLS")
                     or default_esplora_urls(current_app.config["BTC_NETWORK"]))[0]
    explorer_url = f"{explorer_base}/tx/{tx.txid}" if tx.txid else None
    return render_template("activity_detail.html", user=user, tx=tx, price=price,
                           explorer_url=explorer_url)


# ------------------------------------------------------------------ account
@views_bp.route("/account")
@login_required
def account():
    user = current_user()
    price, _src = get_price()
    return render_template("account.html", user=user, price=price,
                           usd_total=services.usd_value(user.balance_sat, price),
                           sudo=sudo_remaining())


@views_bp.route("/account/username", methods=["POST"])
@active_required
def change_username():
    user = current_user()
    new = (request.form.get("username") or "").strip()

    if not is_valid_username(new):
        flash("Username must be 3–20 characters: letters, numbers, underscore.", "error")
        return redirect(url_for("views.account"))
    clash = (
        db.session.query(User)
        .filter(db.func.lower(User.username) == new.lower(), User.id != user.id)
        .first()
    )
    if clash:
        flash("That username is taken.", "error")
        return redirect(url_for("views.account"))
    old = user.username
    user.username = new
    db.session.commit()
    log_event("username_changed", user=user, detail=f"{old} -> {new}")
    flash("Username updated.", "success")
    return redirect(url_for("views.account"))


@views_bp.route("/account/password", methods=["POST"])
@active_required
def change_password():
    user = current_user()
    if not is_sudo():
        flash("Confirm your password first.", "warning")
        return redirect(url_for("auth.confirm", next=url_for("views.account")))

    current = request.form.get("current") or ""
    new = request.form.get("password") or ""
    confirm = request.form.get("password2") or ""

    if not verify_password(user.password_hash, current):
        log_event("password_change_fail", user=user, success=False)
        flash("Your current password is not correct.", "error")
        return redirect(url_for("views.account"))

    errors = []
    if new != confirm:
        errors.append("The two new passwords do not match.")
    errors += password_problems(new, user.username, user.email,
                                current_app.config["PASSWORD_MIN_LENGTH"])
    if errors:
        for e in errors:
            flash(e, "error")
        return redirect(url_for("views.account"))
    if verify_password(user.password_hash, new):
        flash("That is your current password — pick a different one.", "error")
        return redirect(url_for("views.account"))

    user.password_hash = hash_password(new)
    user.session_version = (user.session_version or 0) + 1
    db.session.commit()
    # keep the current device signed in, drop every other session
    from flask import session as flask_session

    flask_session["sv"] = user.session_version
    log_event("password_changed", user=user)
    flash("Password changed. Other devices have been signed out.", "success")
    return redirect(url_for("views.account"))


@views_bp.route("/account/password/required", methods=["GET", "POST"])
@login_required
def force_password_change():
    """Forced password change when an administrator requires one.

    Reached by the account gate rather than by choice, so it deliberately does
    NOT sit behind the usual sudo confirmation: the user is already stopped here,
    and asking for the same password twice would only add a way to fail. They
    still have to know the current password, and every other session is signed
    out when the new one is set.
    """
    user = current_user()
    if not user.must_change_password:
        return redirect(url_for("views.account"))

    if request.method == "POST":
        if not throttle(f"pwchange:{user.id}", 12, 600):
            flash("Too many attempts. Wait a few minutes.", "error")
            return render_template("password_required.html", user=user), 429

        current = request.form.get("current") or ""
        new = request.form.get("password") or ""
        confirm = request.form.get("password2") or ""

        if not verify_password(user.password_hash, current):
            log_event("password_change_fail", user=user, success=False,
                      detail="required change: wrong current password")
            flash("Your current password is not correct.", "error")
            return render_template("password_required.html", user=user), 401

        errors = []
        if new != confirm:
            errors.append("The two new passwords do not match.")
        errors += password_problems(new, user.username, user.email,
                                    current_app.config["PASSWORD_MIN_LENGTH"])
        if verify_password(user.password_hash, new):
            errors.append("That is your current password — pick a different one.")
        if errors:
            for e in errors:
                flash(e, "error")
            return render_template("password_required.html", user=user)

        user.password_hash = hash_password(new)
        user.must_change_password = False
        user.session_version = (user.session_version or 0) + 1
        db.session.commit()
        from flask import session as flask_session

        flask_session["sv"] = user.session_version
        log_event("password_changed_required", user=user)
        flash("Password changed. Your account is clear — carry on.", "success")
        return redirect(url_for("views.dashboard"))

    return render_template("password_required.html", user=user)


@views_bp.route("/account/logout-all", methods=["POST"])
@active_required
def logout_all():
    user = current_user()
    user.session_version = (user.session_version or 0) + 1
    db.session.commit()
    log_event("logout_all", user=user)
    logout_user("logged out everywhere")
    flash("Signed out of every device.", "success")
    return redirect(url_for("auth.login"))


# ----------------------------------------------------------------- security
@views_bp.route("/security")
@login_required
def security():
    user = current_user()
    from app.models import SecurityEvent

    events = (db.session.query(SecurityEvent)
              .filter(SecurityEvent.user_id == user.id)
              .order_by(SecurityEvent.created_at.desc()).limit(30).all())
    import json

    try:
        codes_left = len(json.loads(user.backup_codes_json or "[]"))
    except Exception:
        codes_left = 0
    return render_template("security.html", user=user, events=events,
                           codes_left=codes_left, sudo=sudo_remaining())


@views_bp.route("/security/sessions", methods=["POST"])
@active_required
def kill_other_sessions():
    user = current_user()
    user.session_version = (user.session_version or 0) + 1
    db.session.commit()
    from flask import session as flask_session

    flask_session["sv"] = user.session_version
    log_event("sessions_killed", user=user)
    flash("Signed out of all other sessions.", "success")
    return redirect(url_for("views.security"))
