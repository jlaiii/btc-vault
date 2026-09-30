"""BTC Vault application factory."""

import logging
import time

from flask import Flask, jsonify, render_template, request
from sqlalchemy import text
from sqlalchemy.exc import DataError
from werkzeug.middleware.proxy_fix import ProxyFix
from flask_wtf.csrf import CSRFError

from app.config import Config
from app.extensions import csrf, db

log = logging.getLogger("btcwallet")


def _wants_json() -> bool:
    return request.path.startswith("/api/") or request.path == "/health"


def create_app(config_object=Config, **overrides) -> Flask:
    app = Flask(__name__, static_folder="static", template_folder="templates")
    app.config.from_object(config_object)
    app.config.update(overrides)

    # Caddy terminates TLS in front of us — trust exactly one proxy hop.
    # x_for=1 means remote_addr becomes the value Caddy appended, i.e. the real
    # client, so a forged X-Forwarded-For cannot choose its own rate-limit id.
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

    db.init_app(app)
    csrf.init_app(app)

    from app import admin as admin_module
    from app import auth as auth_module
    from app import views as views_module

    app.register_blueprint(views_module.views_bp)
    app.register_blueprint(auth_module.auth_bp)
    app.register_blueprint(admin_module.admin_bp)

    register_error_handlers(app)
    register_request_guards(app)
    register_abuse_guard(app)
    register_network_guard(app)
    register_template_helpers(app)
    bootstrap_database(app)

    return app


# ------------------------------------------------------------------- boot
def _ensure_columns(session, table: str, columns: dict) -> list:
    """Add model columns the live table is missing, one column per transaction.

    Guarded by an information_schema lookup first: ``ALTER TABLE`` takes an
    ACCESS EXCLUSIVE lock even when it is a no-op, and boot runs it every time.
    ``lock_timeout`` keeps a blocked migration from wedging startup — if a column
    cannot be added now it is retried on the next boot rather than blocking the
    whole app. Each column commits on its own so one failure cannot roll back a
    sibling that already succeeded.
    """
    try:
        present = {row[0] for row in session.execute(text(
            "SELECT column_name FROM information_schema.columns WHERE table_name = :t"
        ), {"t": table}).fetchall()}
    except Exception as exc:
        log.warning("could not inspect %s columns: %s", table, exc)
        session.rollback()
        return []

    added = []
    for name, ddl in columns.items():
        if name in present:
            continue
        try:
            session.execute(text("SET lock_timeout = '5s'"))
            session.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
            session.commit()
            added.append(name)
            log.warning("schema drift: added %s.%s", table, name)
        except Exception as exc:
            log.error("could not add %s.%s — fix this before using the feature: %s",
                      table, name, exc)
            session.rollback()
    return added


def bootstrap_database(app: Flask) -> None:
    """Create tables/sequence/defaults if missing (idempotent)."""
    if not app.config.get("AUTO_CREATE_TABLES"):
        return
    from app import models  # noqa: F401  (registers metadata)
    from app import services

    for attempt in range(1, 11):
        try:
            with app.app_context():
                db.create_all()
                # global derivation counter — a sequence cannot double-issue
                # an index even under concurrency
                db.session.execute(text(
                    "CREATE SEQUENCE IF NOT EXISTS address_index_seq START WITH 1"
                ))
                db.session.commit()
                # ---- idempotent schema drift ----
                # Check the catalogue FIRST, and only alter when it is actually
                # needed. ALTER TABLE takes an ACCESS EXCLUSIVE lock even when
                # it changes nothing, and create_app() runs on every boot (and
                # dozens of times inside the test harness), so an unconditional
                # ALTER here blocks the entire app behind a lock it does not
                # need — it deadlocked the wallet during development.
                _ensure_columns(db.session, "users", {
                    # admin-imposed account gates, added after users existed
                    "require_2fa": "BOOLEAN NOT NULL DEFAULT FALSE",
                    "must_change_password": "BOOLEAN NOT NULL DEFAULT FALSE",
                })
                email_nullable = db.session.execute(text(
                    "SELECT is_nullable FROM information_schema.columns "
                    "WHERE table_name = 'users' AND column_name = 'email'"
                )).scalar()
                if email_nullable == "NO":
                    # and if we do have to alter, never wait forever for it
                    db.session.execute(text("SET lock_timeout = '5s'"))
                    try:
                        db.session.execute(text(
                            "ALTER TABLE users ALTER COLUMN email DROP NOT NULL"
                        ))
                    except Exception as exc:
                        log.warning("schema drift step skipped (lock timeout?): %s", exc)
                        db.session.rollback()
                        db.session.execute(text(
                            "CREATE SEQUENCE IF NOT EXISTS address_index_seq START WITH 1"
                        ))
                db.session.commit()
                services.bootstrap_settings()
                try:
                    created = services.ensure_seed()
                    if created:
                        log.warning(
                            "New hot wallet seed generated. Retrieve it with "
                            "'python -m app.cli show-seed' and back it up offline."
                        )
                except Exception as exc:
                    # The seed is the one thing we cannot proceed without, but a
                    # missing master key must not stop the rest of the schema
                    # from being created — surface it loudly instead.
                    log.error("WALLET SEED UNAVAILABLE: %s", exc)
            log.info("database ready")
            return
        except Exception as exc:
            log.warning("db not ready (attempt %s): %s", attempt, exc)
            time.sleep(3)
    log.error("could not initialise database after retries")


# ------------------------------------------------------------- error pages
def register_error_handlers(app: Flask) -> None:
    def err(code, message, detail):
        if _wants_json():
            return jsonify(ok=False, error=message, code=code), code
        return render_template("error.html", code=code, message=message,
                               detail=detail), code

    @app.errorhandler(400)
    def bad_request(e):
        detail = getattr(e, "description", "") or "The request could not be understood."
        return err(400, "Bad request", detail)

    @app.errorhandler(403)
    def forbidden(e):
        return err(403, "Forbidden",
                   "You do not have access to that. If you think this is wrong, "
                   "sign in again — sessions expire after a period of inactivity.")

    @app.errorhandler(404)
    def not_found(e):
        return err(404, "Not found", "That page does not exist.")

    @app.errorhandler(413)
    def too_large(e):
        return err(413, "Too large", "That request was bigger than this app accepts.")

    @app.errorhandler(429)
    def rate_limited(e):
        if _wants_json():
            return jsonify(ok=False, error="rate limit reached", code="rate_limited"), 429
        return err(429, "Slow down",
                   getattr(e, "description", "") or
                   "Too many requests from this connection. Wait a moment and try again.")

    @app.errorhandler(CSRFError)
    def csrf_error(e):
        log.warning("CSRF failure on %s %s: %s", request.method, request.path, e.description)
        return err(400, "Session expired",
                   "That form was submitted with a stale or missing security token. "
                   "Reload the page and try again.")

    @app.errorhandler(DataError)
    def data_error(e):
        app.logger.warning("database rejected a value: %s", e)
        return err(400, "Bad request",
                   "The request contained characters that cannot be stored.")

    @app.errorhandler(500)
    def server_error(e):  # pragma: no cover
        app.logger.exception("unhandled error")
        db.session.rollback()
        return err(500, "Server error", "Something broke on our side. Nothing was sent.")

    @app.errorhandler(Exception)
    def unhandled(e):  # pragma: no cover
        from werkzeug.exceptions import HTTPException

        if isinstance(e, HTTPException):
            return e
        app.logger.exception("unhandled exception")
        try:
            db.session.rollback()
        except Exception:
            pass
        return err(500, "Server error", "Something broke on our side. Nothing was sent.")


# ----------------------------------------------------------- abuse guard
def register_abuse_guard(app: Flask) -> None:
    """Coarse, DB-backed cap on state-changing requests per IP.

    This is the backstop for endpoints that have no specific throttle of their
    own. It is deliberately generous — a real person never approaches it —
    because the precise limits that matter (login, signup, 2FA, sudo, sends,
    faucet) are applied individually inside those views via
    ``security.throttle``.

    Counted in Postgres so it survives restarts and is identical across
    workers, unlike an in-memory limiter.
    """
    from app.security import throttle
    from app.utils import client_ip

    skip = {"static", "views.health", "auth.logout"}

    @app.before_request
    def _abuse_guard():
        if request.method not in ("POST", "PUT", "PATCH", "DELETE"):
            return None
        if request.endpoint in skip:
            return None
        limit = app.config["GLOBAL_IP_MAX_WRITES_PER_10MIN"]
        if throttle(f"global:{client_ip(request)}", limit, 600):
            return None
        log.warning("global write cap hit for %s on %s", client_ip(request),
                    request.path)
        if _wants_json():
            return jsonify(ok=False, error="rate limit reached",
                           code="rate_limited"), 429
        return render_template(
            "error.html", code=429, message="Slow down",
            detail="Too many requests from this connection. Wait a few minutes "
                   "and try again."), 429


# ----------------------------------------------------------- network guard
def register_network_guard(app: Flask) -> None:
    """Refuse to serve while the wallet points at a network its data does not
    belong to.

    Changing the network changes BIP84 derivation, so every stored address
    belongs to the other chain. Serving in that state would hand users deposit
    addresses that cannot receive and show balances nothing backs on-chain.
    Being down with a clear message beats being quietly wrong with money.
    """
    from app import services

    @app.before_request
    def _network_guard():
        if request.endpoint in ("static", "views.health"):
            return None
        try:
            pending = services.network_transition_required()
        except Exception:
            # a broken check must not take the whole site down
            return None
        if not pending:
            return None
        log.error("refusing to serve: data is %s but configured for %s",
                  pending["recorded"], pending["configured"])
        if _wants_json():
            return jsonify(ok=False, error="network transition pending",
                           code="network_transition"), 503
        return render_template(
            "error.html", code=503, message="Wallet is moving networks",
            detail=(f"This wallet holds {pending['recorded']} data but is "
                    f"configured for {pending['configured']}. It will not serve "
                    f"requests until the migration is completed. Run: "
                    f"python -m app.cli launch-network")), 503


# ----------------------------------------------------------- request guards
def register_request_guards(app: Flask) -> None:
    @app.before_request
    def reject_nul_bytes():
        """PostgreSQL refuses NUL in text; without this an anonymous visitor
        could turn any field into a 500."""
        bad = False
        if b"\x00" in (request.query_string or b""):
            bad = True
        elif request.method in ("POST", "PUT", "PATCH", "DELETE"):
            for value in request.form.values():
                if "\x00" in (value or ""):
                    bad = True
                    break
        if bad:
            if _wants_json():
                return jsonify(ok=False, error="invalid characters",
                               code="invalid_characters"), 400
            return render_template("error.html", code=400, message="Bad request",
                                   detail="The request contained characters that "
                                          "cannot be stored."), 400
        return None

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault(
            "Permissions-Policy",
            "geolocation=(), camera=(), microphone=(), payment=(), usb=()",
        )
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; font-src 'self'; connect-src 'self'; "
            "object-src 'none'; base-uri 'self'; form-action 'self'; "
            "frame-ancestors 'none'",
        )
        # never let a wallet page sit in a shared/proxy cache
        if request.path.startswith("/admin") or request.path in (
            "/", "/wallet", "/receive", "/send", "/activity", "/account", "/security"
        ):
            response.headers.setdefault("Cache-Control",
                                        "no-store, no-cache, must-revalidate, private")
            response.headers.setdefault("Pragma", "no-cache")
        if request.is_secure:
            response.headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains"
            )
        return response

    @app.after_request
    def no_index(response):
        response.headers.setdefault("X-Robots-Tag", "noindex, nofollow, noarchive")
        return response


# ----------------------------------------------------------- template helpers
def register_template_helpers(app: Flask) -> None:
    from app import services
    from app.price import get_price
    from app.security import current_user, sudo_remaining
    from app.utils import (full_time, sats_to_btc_str, sats_to_btc_trim, time_ago,
                           usd_str)

    @app.template_filter("btc")
    def _btc(sats):
        return sats_to_btc_trim(sats)

    @app.template_filter("btc8")
    def _btc8(sats):
        return sats_to_btc_str(sats)

    @app.template_filter("sats")
    def _sats(value):
        try:
            return f"{int(value):,}"
        except (TypeError, ValueError):
            return value

    @app.template_filter("usd")
    def _usd(sats):
        price, _src = get_price()
        return usd_str(sats, price)

    @app.template_filter("timeago")
    def _timeago(dt):
        return time_ago(dt)

    @app.template_filter("fulltime")
    def _fulltime(dt):
        return full_time(dt)

    @app.template_filter("short")
    def _short(text, head=14, tail=8):
        t = str(text or "")
        if len(t) <= head + tail + 3:
            return t
        return f"{t[:head]}…{t[-tail:]}"

    @app.context_processor
    def inject_globals():
        price, price_source = get_price()
        user = current_user()
        try:
            network_name = services.network().name
        except Exception:
            network_name = app.config["BTC_NETWORK"]
        return {
            "site_name": app.config["SITE_NAME"],
            "site_url": app.config["SITE_URL"],
            "network": network_name,
            "is_mainnet": network_name == "mainnet",
            "price": price,
            "price_source": price_source,
            "current_user": user,
            "sudo_left": sudo_remaining() if user else 0,
            "signups_enabled": services.get_bool_setting("signups_enabled"),
            "deposits_enabled": services.get_bool_setting("deposits_enabled"),
            "withdrawals_enabled": services.get_bool_setting("withdrawals_enabled"),
            "maintenance_message": services.get_setting("maintenance_message"),
        }
