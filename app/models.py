"""Data model.

Money is ALWAYS integer satoshis. There is no float anywhere in this file.

Balance architecture
--------------------
``users.balance_sat`` is the authoritative *spendable* balance and is what the
user can withdraw. It is maintained transactionally alongside an append-only
``ledger_entries`` row (delta + balance_after), which gives a full audit trail
and lets an admin adjust a balance without corrupting on-chain accounting.

Chain-derived value lives separately: ``chain_credits`` records every deposit
output we have already credited (unique on txid+vout, so a re-scan can never
double-credit), and ``our_txs`` records transactions we broadcast ourselves so
their change outputs are never mistaken for a new deposit.
"""

from datetime import datetime, timezone

from sqlalchemy import (
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB

from app.extensions import db


def _now():
    return datetime.now(timezone.utc)


# --------------------------------------------------------------------- users
class User(db.Model):
    __tablename__ = "users"

    id = db.Column(Integer, primary_key=True)
    username = db.Column(String(32), unique=True, nullable=False, index=True)
    # Optional and unused by the app: accounts are username + password only.
    # Kept as a nullable column so existing rows and admin tooling do not break.
    email = db.Column(String(255), unique=True, nullable=True, index=True)
    password_hash = db.Column(String(255), nullable=False)

    role = db.Column(String(16), nullable=False, default="user")      # user | admin
    status = db.Column(String(16), nullable=False, default="active")  # active | frozen | banned

    # spendable balance in satoshis (see module docstring)
    balance_sat = db.Column(BigInteger, nullable=False, default=0)
    # set when a balance adjustment pushed the account below zero
    negative_balance = db.Column(Boolean, nullable=False, default=False)

    # derived from the hot wallet seed at m/84'/coin'/0'/0/<index>
    next_address_index = db.Column(Integer, nullable=False, default=0)

    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)
    last_login_at = db.Column(DateTime(timezone=True))
    last_login_ip = db.Column(String(45))
    signup_ip = db.Column(String(45))

    # bumped to invalidate every outstanding session for this user instantly
    session_version = db.Column(Integer, nullable=False, default=0)

    # --- 2FA (TOTP) ---
    totp_secret_enc = db.Column(Text)
    totp_enabled = db.Column(Boolean, nullable=False, default=False)
    totp_confirmed_at = db.Column(DateTime(timezone=True))
    # last accepted time-step: blocks replaying the same 6-digit code
    totp_last_step = db.Column(BigInteger)
    backup_codes_json = db.Column(Text)

    # --- operator-imposed gates (admin panel, USER accounts only) ---
    # Both are switched on by an administrator and must be satisfiable by the
    # account itself: the gate lets the user reach the enrolment / change-password
    # page and nothing else, so it blocks the wallet without trapping them.
    # Deliberately never applied to administrator accounts — forcing either one on
    # the operator locked them out of their own panel (see README, 2FA policy).
    require_2fa = db.Column(Boolean, nullable=False, default=False)
    must_change_password = db.Column(Boolean, nullable=False, default=False)

    # --- brute force ---
    failed_logins = db.Column(Integer, nullable=False, default=0)
    locked_until = db.Column(DateTime(timezone=True))

    # --- admin notes ---
    notes = db.Column(Text)
    deleted_at = db.Column(DateTime(timezone=True))

    addresses = db.relationship("Address", backref="user", lazy="selectin",
                                cascade="all, delete-orphan")

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    @property
    def is_banned(self) -> bool:
        return self.status == "banned"

    @property
    def is_frozen(self) -> bool:
        return self.status == "frozen"

    @property
    def can_spend(self) -> bool:
        return self.status == "active" and self.deleted_at is None

    @property
    def is_locked_out(self) -> bool:
        if not self.locked_until:
            return False
        return self.locked_until > datetime.now(timezone.utc)

    def __repr__(self):
        return f"<User {self.username} {self.status}>"


# ----------------------------------------------------------------- addresses
class Address(db.Model):
    """A deposit wallet: one HD-derived address belonging to a user."""

    __tablename__ = "addresses"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    # global derivation index — unique across all users, so no two users can
    # ever share a private key
    idx = db.Column(Integer, nullable=False, unique=True)
    address = db.Column(String(90), nullable=False, unique=True, index=True)
    label = db.Column(String(64))
    is_primary = db.Column(Boolean, nullable=False, default=False)
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)
    last_activity_at = db.Column(DateTime(timezone=True))

    def __repr__(self):
        return f"<Address #{self.idx} {self.address[:12]}…>"


# -------------------------------------------------------------------- ledger
LEDGER_KINDS = (
    "deposit",        # confirmed on-chain deposit credited
    "withdrawal",     # on-chain send debited
    "service_fee",    # operator fee taken on a send
    "network_fee",    # miner fee passed to the user
    "admin_credit",
    "admin_debit",
    "admin_set",      # admin forced an absolute balance
    "reversal",       # manual correction
    "faucet_credit",  # testnet-only helper credit
)


class LedgerEntry(db.Model):
    __tablename__ = "ledger_entries"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    delta_sat = db.Column(BigInteger, nullable=False)
    balance_after_sat = db.Column(BigInteger, nullable=False)
    kind = db.Column(String(24), nullable=False, index=True)
    ref = db.Column(String(128))          # txid, withdrawal id, etc.
    note = db.Column(Text)
    created_by = db.Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)

    __table_args__ = (Index("ix_ledger_user_created", "user_id", "created_at"),)


# -------------------------------------------------------------- transactions
# direction: in | out        status: pending | confirmed | failed | rejected
class Transaction(db.Model):
    __tablename__ = "transactions"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)

    category = db.Column(String(24), nullable=False)   # deposit | withdrawal | admin
    direction = db.Column(String(8), nullable=False)
    status = db.Column(String(16), nullable=False, default="pending", index=True)

    amount_sat = db.Column(BigInteger, nullable=False)          # what moved to/from the user
    service_fee_sat = db.Column(BigInteger, nullable=False, default=0)
    network_fee_sat = db.Column(BigInteger, nullable=False, default=0)
    total_sat = db.Column(BigInteger, nullable=False, default=0)  # signed effect on balance

    txid = db.Column(String(64), index=True)
    vout = db.Column(Integer)
    address = db.Column(String(90))       # counterparty address
    confirmations = db.Column(Integer, nullable=False, default=0)
    block_height = db.Column(Integer)
    fee_rate = db.Column(Integer)
    priority = db.Column(String(12))      # fast | normal | economy
    label = db.Column(String(120))
    note = db.Column(Text)
    raw_hex = db.Column(Text)
    withdrawal_id = db.Column(Integer, ForeignKey("withdrawals.id", ondelete="SET NULL"))
    created_by = db.Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)
    confirmed_at = db.Column(DateTime(timezone=True))

    __table_args__ = (Index("ix_tx_user_created", "user_id", "created_at"),)


# ---------------------------------------------------------------- withdrawals
WITHDRAWAL_STATUSES = ("queued", "approved", "sent", "failed", "rejected", "cancelled")


class Withdrawal(db.Model):
    __tablename__ = "withdrawals"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)

    address = db.Column(String(90), nullable=False)
    amount_sat = db.Column(BigInteger, nullable=False)
    service_fee_sat = db.Column(BigInteger, nullable=False, default=0)
    network_fee_sat = db.Column(BigInteger, nullable=False, default=0)
    total_sat = db.Column(BigInteger, nullable=False)
    fee_rate = db.Column(Integer)
    priority = db.Column(String(12))
    vsize_est = db.Column(Integer)

    status = db.Column(String(16), nullable=False, default="queued", index=True)
    txid = db.Column(String(64), index=True)
    raw_hex = db.Column(Text)
    error = db.Column(Text)

    quote_json = db.Column(JSONB)
    note = db.Column(Text)
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)
    decided_at = db.Column(DateTime(timezone=True))
    decided_by = db.Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    broadcast_at = db.Column(DateTime(timezone=True))

    __table_args__ = (Index("ix_wd_status_created", "status", "created_at"),)


# ------------------------------------------------------- chain accounting
class ChainCredit(db.Model):
    """Every deposit output already credited. unique(txid, vout) makes the
    watcher idempotent — re-scanning the chain can never double-credit."""

    __tablename__ = "chain_credits"

    id = db.Column(Integer, primary_key=True)
    txid = db.Column(String(64), nullable=False)
    vout = db.Column(Integer, nullable=False)
    address_id = db.Column(Integer, ForeignKey("addresses.id", ondelete="CASCADE"),
                           nullable=False)
    value_sat = db.Column(BigInteger, nullable=False)
    ledger_id = db.Column(Integer, ForeignKey("ledger_entries.id", ondelete="SET NULL"))
    block_height = db.Column(Integer)
    credited_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)

    __table_args__ = (UniqueConstraint("txid", "vout", name="uq_chain_credit_outpoint"),)


class OurTx(db.Model):
    """Transactions we broadcast. Their outputs (change) must never be
    mistaken for a fresh deposit, or every send would credit the user twice."""

    __tablename__ = "our_txs"

    txid = db.Column(String(64), primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    kind = db.Column(String(16), nullable=False, default="withdrawal")
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)


# -------------------------------------------------------------- admin / audit
class AdminAudit(db.Model):
    __tablename__ = "admin_audit"

    id = db.Column(Integer, primary_key=True)
    admin_id = db.Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    admin_username = db.Column(String(32))
    target_user_id = db.Column(Integer, ForeignKey("users.id", ondelete="SET NULL"),
                               index=True)
    target_username = db.Column(String(32))
    action = db.Column(String(48), nullable=False, index=True)
    detail = db.Column(Text)
    ip = db.Column(String(45))
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)


class SecurityEvent(db.Model):
    """Login history + notable account events (users can see their own)."""

    __tablename__ = "security_events"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), index=True)
    username = db.Column(String(64))
    kind = db.Column(String(32), nullable=False)   # login_ok | login_fail | 2fa_* | ...
    success = db.Column(Boolean, nullable=False, default=True)
    ip = db.Column(String(45))
    user_agent = db.Column(String(255))
    detail = db.Column(Text)
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now, index=True)


class Alert(db.Model):
    """Things an admin must look at: negative balances, float shortfalls,
    failed broadcasts, users holding more than the hot wallet can pay."""

    __tablename__ = "alerts"

    id = db.Column(Integer, primary_key=True)
    kind = db.Column(String(32), nullable=False, index=True)
    severity = db.Column(String(12), nullable=False, default="warning")  # info|warning|critical
    user_id = db.Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))
    username = db.Column(String(32))
    title = db.Column(String(160), nullable=False)
    body = db.Column(Text)
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)
    ack_at = db.Column(DateTime(timezone=True))
    ack_by = db.Column(Integer, ForeignKey("users.id", ondelete="SET NULL"))


class Setting(db.Model):
    __tablename__ = "settings"

    key = db.Column(String(64), primary_key=True)
    value = db.Column(Text)
    updated_at = db.Column(DateTime(timezone=True), nullable=False, default=_now,
                           onupdate=_now)


class PasswordReset(db.Model):
    __tablename__ = "password_resets"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    token_hash = db.Column(String(64), nullable=False, unique=True, index=True)
    expires_at = db.Column(DateTime(timezone=True), nullable=False)
    used_at = db.Column(DateTime(timezone=True))
    ip = db.Column(String(45))
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)


class SendQuote(db.Model):
    """A server-side priced send. The browser only ever sends back a quote id,
    never amounts — so a tampered form cannot change what is paid."""

    __tablename__ = "send_quotes"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    payload = db.Column(JSONB, nullable=False)
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)
    used_at = db.Column(DateTime(timezone=True))


class Throttle(db.Model):
    """DB-backed rate limiting. Exact and survives restarts/workers."""

    __tablename__ = "throttles"

    id = db.Column(Integer, primary_key=True)
    bucket = db.Column(String(96), nullable=False, index=True)
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now, index=True)


class TestnetFaucetRequest(db.Model):
    """Anti-abuse ledger for the built-in testnet faucet."""

    __tablename__ = "faucet_requests"

    id = db.Column(Integer, primary_key=True)
    user_id = db.Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    txid = db.Column(String(64))
    amount_sat = db.Column(BigInteger)
    status = db.Column(String(16), nullable=False, default="queued")
    error = db.Column(Text)
    ip = db.Column(String(45))
    created_at = db.Column(DateTime(timezone=True), nullable=False, default=_now)
