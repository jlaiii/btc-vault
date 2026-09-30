"""Wallet service layer: settings, ledger, addresses, the send engine and the
chain watcher.

Accounting model (this is the part worth reading before changing anything):

* ``users.balance_sat`` is the spendable balance, mirrored by append-only
  ``ledger_entries``. It is authoritative — an admin can credit or debit it,
  which on-chain data alone could never express.
* A confirmed deposit credits the ledger exactly once (guarded by
  ``chain_credits``, unique on txid+vout).
* A send debits the ledger by amount + service fee + the ACTUAL miner fee, and
  the change output returns to our own wallet *without* being credited again —
  ``our_txs`` marks transactions we broadcast so their outputs are never read
  back as fresh deposits.
* Therefore: on-chain total − user ledger total = operator revenue (the
  service fees collected). The admin dashboard asserts that identity and raises
  an alert when it breaks, which is how a float shortfall (from an admin credit
  or an over-and-above manual debit) gets noticed.
"""

import logging
import math
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import current_app
from sqlalchemy import func, text

from app import btc
from app.chain import (
    PRIORITY_BLURBS,
    PRIORITY_LABELS,
    ChainError,
    EsploraClient,
    blend_fee_tiers,
    pick_fee_rates,
)
from app.crypto_vault import Vault, VaultError
from app.extensions import db
from app.models import (
    Address,
    ChainCredit,
    LedgerEntry,
    OurTx,
    SendQuote,
    Setting,
    TestnetFaucetRequest,
    Transaction,
    User,
    Withdrawal,
)
from app.security import raise_alert
from app.utils import sats_to_btc_str

log = logging.getLogger("btcwallet.services")

# --------------------------------------------------------------- settings
DEFAULT_SETTINGS = {
    "service_fee_pct": "0.5",              # percent of the send amount
    "service_fee_min_sat": "0",
    "instant_send_max_sat": "200000",      # above this an admin approves
    "withdraw_min_sat": "10000",
    "withdraw_daily_max_sat": "5000000",
    "min_confirmations": "1",
    "signups_enabled": "1",
    "deposits_enabled": "1",
    "withdrawals_enabled": "1",
    "maintenance_message": "",
    "net_fee_passthrough": "1",            # charge the miner fee to the user
    "testnet_faucet_enabled": "1",
    "testnet_faucet_amount_sat": "100000",
    "testnet_faucet_cooldown_hours": "6",
}

SETTING_LABELS = {
    "service_fee_pct": ("Service fee (%)", "Percentage taken on each send."),
    "service_fee_min_sat": ("Minimum service fee (sats)", "Floor for the service fee."),
    "instant_send_max_sat": ("Auto-send limit (sats)",
                            "Sends at or below this go out immediately; larger ones wait for admin approval."),
    "withdraw_min_sat": ("Minimum withdrawal (sats)", "Smallest send a user may make."),
    "withdraw_daily_max_sat": ("Daily withdrawal cap (sats)", "Per-user rolling 24h limit."),
    "min_confirmations": ("Deposit confirmations", "Confirmations before a deposit is credited."),
    "signups_enabled": ("Signups open", "Allow new accounts to register."),
    "deposits_enabled": ("Deposits enabled", "Show deposit addresses and credit incoming funds."),
    "withdrawals_enabled": ("Withdrawals enabled", "Allow users to send funds out."),
    "net_fee_passthrough": ("Charge miner fee to user", "If off, the service absorbs network fees."),
    "maintenance_message": ("Maintenance banner", "Shown across the app when set."),
    "testnet_faucet_enabled": ("Testnet faucet", "Built-in faucet helper (testnet only)."),
    "testnet_faucet_amount_sat": ("Faucet amount (sats)", "Per request."),
    "testnet_faucet_cooldown_hours": ("Faucet cooldown (hours)", "Between requests per user."),
}


def _sess():
    return db.session


# Fee-tier cache: see get_fee_rates() for why this exists.
FEE_CACHE_SECONDS = 60
_fee_cache = {"ts": 0.0, "rates": None, "meta": None}


def get_setting(key: str) -> str:
    row = _sess().get(Setting, key)
    if row is not None and row.value is not None:
        return row.value
    return DEFAULT_SETTINGS.get(key, "")


def get_int_setting(key: str) -> int:
    try:
        return int(float(get_setting(key)))
    except (TypeError, ValueError):
        return int(float(DEFAULT_SETTINGS.get(key, 0)))


def get_float_setting(key: str) -> float:
    try:
        return float(get_setting(key))
    except (TypeError, ValueError):
        return float(DEFAULT_SETTINGS.get(key, 0))


def get_bool_setting(key: str) -> bool:
    return str(get_setting(key)).strip().lower() in ("1", "true", "yes", "on")


def set_setting(key: str, value: str):
    row = _sess().get(Setting, key)
    if row is None:
        row = Setting(key=key, value=str(value))
        _sess().add(row)
    else:
        row.value = str(value)
        row.updated_at = datetime.now(timezone.utc)
    _sess().commit()


def bootstrap_settings():
    for key, value in DEFAULT_SETTINGS.items():
        if _sess().get(Setting, key) is None:
            _sess().add(Setting(key=key, value=value))
    _sess().commit()


# ------------------------------------------------------------------ network
def network() -> btc.Network:
    return btc.get_network(current_app.config["BTC_NETWORK"])


def explorer() -> EsploraClient:
    return EsploraClient(
        urls=current_app.config.get("ESPLORA_URLS") or None,
        network=current_app.config["BTC_NETWORK"],
    )


def vault() -> Vault:
    return Vault(current_app.config["MASTER_KEY_FILE"])


# --------------------------------------------------------------- wallet seed
SEED_SETTING_KEY = "wallet_seed_enc"
SEED_NETWORK_KEY = "wallet_seed_network"


def seed_exists() -> bool:
    row = _sess().get(Setting, SEED_SETTING_KEY)
    return bool(row and row.value)


def ensure_seed():
    """Create the hot wallet seed on first run. Returns the mnemonic ONCE
    (for the operator to back up) or None if a seed already exists."""
    if seed_exists():
        return None
    mnemonic = btc.generate_mnemonic(24)
    v = vault()
    _sess().add(Setting(key=SEED_SETTING_KEY, value=v.seal_str(mnemonic)))
    _sess().add(Setting(key=SEED_NETWORK_KEY, value=network().name))
    _sess().commit()
    log.warning("New hot wallet seed generated — back it up now.")
    return mnemonic


def reveal_mnemonic() -> str:
    row = _sess().get(Setting, SEED_SETTING_KEY)
    if row is None or not row.value:
        raise VaultError("No hot wallet seed has been created yet.")
    return vault().open_str(row.value)


def root_key():
    """The HD root key, decrypted in memory for this call only."""
    return btc.root_from_mnemonic(reveal_mnemonic(), network())


def seed_network_mismatch():
    row = _sess().get(Setting, SEED_NETWORK_KEY)
    if row is None or not row.value:
        return None
    if row.value != network().name:
        return row.value
    return None


# ------------------------------------------------- network launch / migration
def launch_network():
    """The network this database was built on (recorded when the seed was made)."""
    row = _sess().get(Setting, SEED_NETWORK_KEY)
    return (row.value or None) if row is not None else None


def network_transition_required():
    """The configured network differs from the one this wallet was built on.

    Serving requests in that state is actively dangerous rather than merely
    untidy: BIP84 derivation differs per network, so every stored address
    belongs to the other chain. Users would be handed deposit addresses that
    cannot receive here, and the ledger would still claim balances nothing
    backs on-chain.
    """
    recorded = launch_network()
    if recorded is None or recorded == network().name:
        return None
    return {"recorded": recorded, "configured": network().name}


def reset_for_network_launch(mnemonic_out_path: str = None):
    """Re-point this wallet at a different network. Destructive on purpose.

    - Worthless balances from the old network are zeroed with a recorded ledger
      entry per account, never silently, so the history explains itself.
    - The old network's addresses are REMOVED. Their derivation paths are
      unreachable on the new network, and because every call site reads
      addresses through the user relationship, removing them is what makes the
      rest of the app correct without adding a network filter in a dozen places.
    - A brand new seed is generated for the new network. The caller must have
      the operator back it up before any real funds arrive.
    """
    target = network().name
    recorded = launch_network() or "(none)"
    if recorded == target:
        return {"changed": False, "from": recorded, "to": target}

    result = {"changed": True, "from": recorded, "to": target,
              "accounts_zeroed": 0, "sats_cleared": 0,
              "addresses_removed": 0, "mnemonic_file": None}

    for u in _sess().query(User).all():
        bal = int(u.balance_sat or 0)
        if bal:
            apply_ledger(
                u, -bal, "network_reset", ref=f"network:{target}",
                note=(f"Balance cleared moving from {recorded} to {target}. "
                      f"{recorded} coins are a different chain and are worth "
                      f"nothing here."),
                commit=False,
            )
            result["accounts_zeroed"] += 1
            result["sats_cleared"] += bal
    _sess().query(User).update({"negative_balance": False},
                               synchronize_session=False)
    _sess().commit()

    # the other network's addresses can never receive here, and their
    # deposit-dedup guard rows (chain_credits) hang off them
    result["addresses_removed"] = _sess().query(Address).delete(
        synchronize_session=False)
    _sess().query(TestnetFaucetRequest).delete(synchronize_session=False)
    _sess().commit()

    mnemonic = btc.generate_mnemonic(24)
    set_setting(SEED_SETTING_KEY, vault().seal_str(mnemonic))
    set_setting(SEED_NETWORK_KEY, target)

    if mnemonic_out_path:
        path = Path(mnemonic_out_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            f"Bitcoin {target} hot wallet recovery phrase\n"
            f"network:   {target}\n"
            f"generated: {datetime.now(timezone.utc).isoformat()}\n\n"
            f"{mnemonic}\n\n"
            "Write these words down on paper and store them offline. Anyone who\n"
            "has them can spend every coin in this wallet. Then DELETE this file.\n",
            encoding="utf-8",
        )
        path.chmod(0o600)
        result["mnemonic_file"] = str(path)

    log.warning("wallet moved %s -> %s: %s sats cleared over %s account(s), "
                "%s address(es) removed, fresh seed generated",
                recorded, target, result["sats_cleared"],
                result["accounts_zeroed"], result["addresses_removed"])
    return result


# ----------------------------------------------------------------- addresses
def next_address_index() -> int:
    """Global monotonic derivation index. A Postgres sequence makes it
    race-free, so two simultaneous signups can never derive the same key."""
    return int(_sess().execute(text("SELECT nextval('address_index_seq')")).scalar())


def create_address(user: User, label: str = None, make_primary: bool = False):
    idx = next_address_index()
    derived = btc.derive_address(root_key(), network(), idx)
    addr = Address(
        user_id=user.id,
        idx=idx,
        address=derived.address,
        label=label or f"Wallet #{idx}",
        is_primary=make_primary or not user.addresses,
    )
    _sess().add(addr)
    user.next_address_index = idx + 1
    _sess().commit()
    return addr


def ensure_primary_address(user: User):
    if user.addresses:
        return user.addresses[0]
    return create_address(user, label="Main wallet", make_primary=True)


def address_index_map(user: User):
    return {a.address: a.idx for a in user.addresses}


def user_utxos(user: User, client: EsploraClient = None):
    """Every spendable output across the user's addresses, with the key
    material needed to sign them."""
    client = client or explorer()
    net = network()
    root = root_key()
    out = []
    for addr in user.addresses:
        try:
            raw = client.address_utxos(addr.address)
        except ChainError as exc:
            log.warning("utxo fetch failed for %s: %s", addr.address, exc)
            raise
        derived = btc.derive_address(root, net, addr.idx)
        for u in raw:
            status = u.get("status") or {}
            out.append(btc.Utxo(
                txid=u["txid"],
                vout=int(u["vout"]),
                value_sat=int(u["value"]),
                address=addr.address,
                script=derived.script,
                index=addr.idx,
                pubkey=derived.pubkey,
                confirmed=bool(status.get("confirmed")),
            ))
    return out


# -------------------------------------------------------------------- money
def service_fee_for(amount_sat: int) -> int:
    pct = get_float_setting("service_fee_pct")
    minimum = get_int_setting("service_fee_min_sat")
    fee = int(math.ceil(amount_sat * (pct / 100.0)))
    return max(fee, minimum) if pct > 0 else max(0, minimum)


def get_fee_rates(user_facing: bool = True):
    """Fee tiers, served from a short-lived cache.

    The fee oracle is a third-party HTTP call sitting on the render path of
    every wallet page. Without caching, an explorer slowdown turns into a
    multi-second (or worse) page load, so: cache for 60s, short timeout,
    and fall back to the last known good rates, then to static defaults.
    Never raises.
    """
    now = time.time()
    cached = _fee_cache.get("rates")
    if cached and (now - _fee_cache.get("ts", 0)) < FEE_CACHE_SECONDS:
        return cached, _fee_cache["meta"]

    cfg = current_app.config
    client = explorer()
    try:
        all_est = client.all_fee_estimates()
        if all_est:
            rates = blend_fee_tiers(all_est, cfg["MIN_FEE_RATE"], cfg["MAX_FEE_RATE"],
                                    cfg["FALLBACK_FEE_RATES"])
            meta = {"source": "live", "labels": PRIORITY_LABELS,
                    "blurbs": PRIORITY_BLURBS, "providers": len(all_est)}
            if len(all_est) > 1:
                meta["source"] = "live+checked"
        else:
            rates = pick_fee_rates({}, cfg["MIN_FEE_RATE"], cfg["MAX_FEE_RATE"],
                                   cfg["FALLBACK_FEE_RATES"])
            meta = {"source": "default", "labels": PRIORITY_LABELS,
                    "blurbs": PRIORITY_BLURBS, "providers": 0}
    except Exception as exc:
        log.warning("fee oracle unavailable: %s", exc)
        if cached:
            # keep showing the last good rates rather than regressing
            return cached, _fee_cache["meta"]
        rates = pick_fee_rates({}, cfg["MIN_FEE_RATE"], cfg["MAX_FEE_RATE"],
                               cfg["FALLBACK_FEE_RATES"])
        meta = {"source": "default", "labels": PRIORITY_LABELS,
                "blurbs": PRIORITY_BLURBS, "providers": 0}

    if meta["source"].startswith("live"):
        _fee_cache["rates"] = rates
        _fee_cache["meta"] = meta
        _fee_cache["ts"] = now
    return rates, meta


def usd_value(sats: int, price):
    if price is None:
        return None
    return (int(sats) / btc.SATS) * float(price)


# ------------------------------------------------------------------- ledger
def _lock_user(user_id: int) -> User:
    return _sess().query(User).filter(User.id == user_id).with_for_update().one()


def apply_ledger(user: User, delta_sat: int, kind: str, ref: str = None,
                 note: str = None, created_by: int = None, commit: bool = True):
    """Move a balance and record why. Locks the user row so concurrent
    requests cannot interleave and lose an update."""
    locked = _lock_user(user.id)
    new_balance = int(locked.balance_sat or 0) + int(delta_sat)
    locked.balance_sat = new_balance
    if new_balance < 0:
        locked.negative_balance = True
    entry = LedgerEntry(
        user_id=locked.id,
        delta_sat=int(delta_sat),
        balance_after_sat=new_balance,
        kind=kind,
        ref=ref,
        note=note,
        created_by=created_by,
    )
    _sess().add(entry)
    if commit:
        _sess().commit()
    else:
        _sess().flush()
    if new_balance < 0:
        raise_alert(
            "negative_balance",
            f"{locked.username} is at a negative balance",
            f"Balance is {new_balance} sats after a {kind} of {delta_sat} sats.",
            severity="critical",
            user=locked,
        )
    return entry


def set_balance_absolute(user: User, new_balance_sat: int, admin: User, note: str = None):
    """Admin override. Going negative is allowed but is deliberately loud: it
    is flagged on the account and raised as a critical alert."""
    locked = _lock_user(user.id)
    delta = int(new_balance_sat) - int(locked.balance_sat or 0)
    entry = apply_ledger(
        user, delta, "admin_set", ref=f"admin:{admin.id}",
        note=note or f"Balance set to {new_balance_sat} sats by {admin.username}",
        created_by=admin.id,
    )
    locked = _sess().get(User, user.id)
    locked.negative_balance = int(locked.balance_sat) < 0
    _sess().commit()
    return entry, delta


def sweep_balance(source: User, recipient: User, admin: User, note: str = None):
    """Move a user's entire balance to another account, atomically.

    The point of this is that value is never destroyed: deleting an account, or
    emptying one, must not make BTC disappear from the books. The BTC itself
    never moves on-chain — it stays in the hot wallet — only the ledger claim
    on it changes hands.

    A NEGATIVE source balance is allowed and transfers the debt: the recipient
    (an admin) absorbs it. That is deliberate, because a negative balance is
    already the operator's liability, and silently zeroing it would hide it.

    Returns (amount_moved, out_entry, in_entry).
    """
    if source.id == recipient.id:
        raise SendError("Cannot move a balance to the same account.")

    locked = _lock_user(source.id)
    amount = int(locked.balance_sat or 0)
    if amount == 0:
        return 0, None, None

    out_entry = apply_ledger(
        source, -amount, "sweep_out", ref=f"admin:{admin.id}",
        note=note or f"Balance moved to {recipient.username} by {admin.username}",
        created_by=admin.id, commit=False,
    )
    in_entry = apply_ledger(
        recipient, amount, "sweep_in", ref=f"admin:{admin.id}",
        note=note or f"Recovered from {source.username} by {admin.username}",
        created_by=admin.id, commit=True,
    )
    # a now-zero account is no longer flagged negative
    fresh = _sess().get(User, source.id)
    fresh.negative_balance = int(fresh.balance_sat) < 0
    _sess().commit()
    if amount < 0:
        log.warning("swept NEGATIVE balance %s sats from %s to %s (debt absorbed)",
                    amount, source.username, recipient.username)
    return amount, out_entry, in_entry


def user_send_total_last_24h(user: User) -> int:
    since = datetime.now(timezone.utc) - timedelta(hours=24)
    total = (
        _sess().query(func.coalesce(func.sum(Withdrawal.total_sat), 0))
        .filter(Withdrawal.user_id == user.id,
                Withdrawal.status.in_(("queued", "approved", "sent")),
                Withdrawal.created_at >= since)
        .scalar()
    )
    return int(total or 0)


# --------------------------------------------------------------- send engine
class SendError(ValueError):
    pass


def quote_send(user: User, dest_address: str, amount_sat: int, priority: str):
    """Price a send and persist it server-side.

    The browser gets back only a quote id, so the amount, fee and destination
    that actually get signed cannot be altered by editing the form.
    """
    net = network()
    if not get_bool_setting("withdrawals_enabled"):
        raise SendError("Withdrawals are temporarily disabled.")
    if not user.can_spend:
        raise SendError("Your account is frozen — withdrawals are disabled.")

    minimum = get_int_setting("withdraw_min_sat")
    if amount_sat < minimum:
        raise SendError(
            f"Minimum withdrawal is {minimum} sats "
            f"({sats_to_btc_str(minimum)} BTC)."
        )

    priority = priority if priority in ("fast", "normal", "economy") else "normal"
    try:
        canonical, script, script_type = btc.validate_destination(dest_address, net)
    except btc.BitcoinError as exc:
        # A malformed address, or one belonging to the other network, is a user
        # error and must read like one. Letting it escape here surfaced as an
        # HTTP 500 instead of a message — while still (correctly) refusing to
        # sign anything.
        raise SendError(str(exc)) from exc

    # refuse to send to one of our own deposit addresses — that is almost always
    # a paste error and it would silently just move money to yourself
    own = {a.address for a in user.addresses}
    if canonical in own:
        raise SendError("That is one of your own deposit addresses.")

    service_fee = service_fee_for(amount_sat)
    rates, meta = get_fee_rates()
    rate = rates[priority]

    daily_cap = get_int_setting("withdraw_daily_max_sat")
    if daily_cap and user_send_total_last_24h(user) + amount_sat > daily_cap:
        raise SendError("That would exceed your 24-hour withdrawal limit.")

    if not user.negative_balance and amount_sat + service_fee > int(user.balance_sat):
        raise SendError("Insufficient balance for that amount plus fees.")

    # size the tx: recipient output + our change output
    output_types = [script_type, "p2wpkh"]
    try:
        utxos = user_utxos(user)
    except ChainError as exc:
        raise SendError("Could not reach the blockchain network. Try again shortly.") from exc

    spendable = [u for u in utxos if u.confirmed]
    if not spendable:
        raise SendError("No confirmed on-chain funds available to send.")

    try:
        selected, net_fee, vsize = btc.select_coins(
            spendable, amount_sat + service_fee, output_types, rate
        )
    except btc.BitcoinError as exc:
        # The user's ledger says they have funds, but the hot wallet cannot
        # cover them on-chain. That is an operator problem, not a user error.
        raise_alert(
            "float_shortfall",
            f"Cannot cover {user.username}'s send on-chain",
            f"Requested {amount_sat} sats but the addresses do not hold enough "
            f"confirmed UTXOs. Ledger balance is {user.balance_sat} sats.",
            severity="critical",
            user=user,
        )
        raise SendError(
            "Your funds are temporarily not available to send. "
            "This has been flagged to the operator — please try again later."
        ) from exc

    if not get_bool_setting("net_fee_passthrough"):
        net_fee = 0

    total = amount_sat + service_fee + net_fee

    if total > int(user.balance_sat):
        raise SendError(
            f"Insufficient balance. You need {total} sats "
            f"({amount_sat} + {service_fee} fee + {net_fee} network) "
            f"but hold {int(user.balance_sat)} sats."
        )

    # change goes back to whichever of the user's addresses funded this most
    by_addr = {}
    for u in selected:
        by_addr[u.address] = by_addr.get(u.address, 0) + u.value_sat
    change_address = max(by_addr.items(), key=lambda kv: kv[1])[0]
    change_index = address_index_map(user).get(change_address) or user.addresses[0].idx

    payload = {
        "dest": canonical,
        "amount_sat": int(amount_sat),
        "service_fee_sat": int(service_fee),
        "network_fee_sat": int(net_fee),
        "total_sat": int(total),
        "fee_rate": int(rate),
        "priority": priority,
        "vsize_est": int(vsize),
        "change_index": int(change_index),
        "utxos": [{"txid": u.txid, "vout": u.vout, "value_sat": u.value_sat,
                   "address": u.address} for u in selected],
        "fee_source": meta["source"],
        "network": net.name,
    }
    quote = SendQuote(user_id=user.id, payload=payload)
    _sess().add(quote)
    _sess().commit()
    return quote


def _revalidate_utxos(user: User, quoted_list):
    """Re-fetch the quoted outpoints and confirm they are all still unspent."""
    current = {(u.txid, u.vout): u for u in user_utxos(user)}
    utxos = []
    for item in quoted_list:
        key = (item["txid"], int(item["vout"]))
        live = current.get(key)
        if live is None or not live.confirmed:
            raise SendError(
                "Those funds moved while you were confirming. Nothing was sent — "
                "please start the send again."
            )
        utxos.append(live)
    return utxos


def execute_send(user: User, quote: SendQuote):
    """Sign and either broadcast or queue for approval.

    Order matters: we record the txid (in ``our_txs``) and debit the ledger
    BEFORE broadcasting, so a crash mid-flight can never lead the watcher to
    treat our own change output as a fresh deposit.
    """
    if quote.used_at is not None:
        raise SendError("This send was already submitted.")
    if (datetime.now(timezone.utc) - quote.created_at) > timedelta(minutes=10):
        raise SendError("This quote expired. Please review the send again.")

    payload = quote.payload
    net = network()
    if payload.get("network") != net.name:
        raise SendError("The wallet network changed — please start again.")

    amount_sat = int(payload["amount_sat"])
    service_fee = int(payload["service_fee_sat"])
    net_fee = int(payload["network_fee_sat"])
    rate = int(payload["fee_rate"])

    fresh = _sess().get(User, user.id)
    if not fresh.can_spend:
        raise SendError("Your account is frozen — withdrawals are disabled.")
    if amount_sat + service_fee + net_fee > int(fresh.balance_sat):
        raise SendError("Insufficient balance for that amount plus fees.")

    try:
        utxos = _revalidate_utxos(fresh, payload["utxos"])
    except ChainError as exc:
        raise SendError("Could not reach the blockchain network. Try again shortly.") from exc

    _, dest_script, dest_type = btc.validate_destination(payload["dest"], net)

    root = root_key()
    try:
        built = btc.build_signed_tx(
            root_key=root,
            net=net,
            utxos=utxos,
            outputs=[(amount_sat, dest_script, dest_type)],
            fee_rate=rate,
            change_index=int(payload["change_index"]),
            target_fee_sat=net_fee,
        )
    except btc.BitcoinError as exc:
        raise SendError(str(exc)) from exc

    # never broadcast something whose signatures we have not just re-verified
    if not btc.verify_signed_tx(built["raw_hex"], net, utxos):
        raise SendError(
            "Internal safety check failed: the transaction signature did not "
            "verify, so nothing was broadcast."
        )

    actual_fee = int(built["fee_sat"])
    total = amount_sat + service_fee + actual_fee

    auto_max = get_int_setting("instant_send_max_sat")
    needs_approval = auto_max >= 0 and amount_sat > auto_max

    from app.security import throttle

    if not needs_approval and not throttle(
        f"send:{fresh.id}", current_app.config["SEND_MAX_PER_HOUR"], 3600
    ):
        raise SendError("Too many sends in a short time. Please wait a bit.")

    w = Withdrawal(
        user_id=fresh.id,
        address=payload["dest"],
        amount_sat=amount_sat,
        service_fee_sat=service_fee,
        network_fee_sat=actual_fee,
        total_sat=total,
        fee_rate=rate,
        priority=payload["priority"],
        vsize_est=int(built["vsize"]),
        status="queued",
        raw_hex=built["raw_hex"],
        txid=built["txid"],
        quote_json=payload,
    )
    _sess().add(w)
    _sess().flush()

    # reserve the funds immediately so the balance cannot be spent twice
    apply_ledger(fresh, -total, "withdrawal", ref=f"wd:{w.id}",
                 note=f"Send {amount_sat} sats to {payload['dest'][:24]}…", commit=False)
    if service_fee:
        apply_ledger(fresh, 0, "service_fee", ref=f"wd:{w.id}",
                     note=f"Service fee {service_fee} sats", commit=False)

    # register the txid BEFORE it can possibly hit the network
    if _sess().get(OurTx, built["txid"]) is None:
        _sess().add(OurTx(txid=built["txid"], user_id=fresh.id, kind="withdrawal"))

    quote.used_at = datetime.now(timezone.utc)
    _sess().commit()

    if needs_approval:
        raise_alert(
            "withdrawal_queued",
            f"Withdrawal awaiting approval: {fresh.username}",
            f"{amount_sat} sats to {payload['dest']} exceeds the auto-send limit "
            f"of {auto_max} sats.",
            severity="warning",
            user=fresh,
        )
        return w, "queued"

    try:
        txid = explorer().broadcast(built["raw_hex"])
    except ChainError as exc:
        _sess().delete(_sess().get(OurTx, built["txid"]))
        apply_ledger(fresh, +total, "reversal", ref=f"wd:{w.id}",
                     note="Broadcast failed — funds returned")
        w.status = "failed"
        w.error = str(exc)[:500]
        _sess().commit()
        raise_alert("broadcast_failed", f"Broadcast failed for {fresh.username}",
                    str(exc)[:800], severity="critical", user=fresh)
        raise SendError(
            "The network rejected the transaction. Nothing was sent and your "
            "balance was restored. Please try again."
        ) from exc

    w.status = "sent"
    w.broadcast_at = datetime.now(timezone.utc)
    w.txid = txid
    _sess().add(Transaction(
        user_id=fresh.id, category="withdrawal", direction="out", status="pending",
        amount_sat=amount_sat, service_fee_sat=service_fee, network_fee_sat=actual_fee,
        total_sat=-total, txid=txid, address=payload["dest"],
        fee_rate=rate, priority=payload["priority"], withdrawal_id=w.id,
        raw_hex=built["raw_hex"], label=f"Sent to {payload['dest'][:16]}…",
    ))
    _sess().commit()
    return w, "sent"


def approve_withdrawal(w: Withdrawal, admin: User):
    """Admin approves a queued withdrawal: broadcast the already-signed tx."""
    if w.status != "queued":
        raise SendError("That withdrawal is not awaiting approval.")
    user = _sess().get(User, w.user_id)
    try:
        txid = explorer().broadcast(w.raw_hex)
    except ChainError as exc:
        w.status = "failed"
        w.error = str(exc)[:500]
        _sess().commit()
        raise_alert("broadcast_failed", f"Approved withdrawal failed for {user.username}",
                    str(exc)[:800], severity="critical", user=user)
        raise SendError(f"Broadcast failed: {exc}") from exc

    w.status = "sent"
    w.txid = txid
    w.decided_at = datetime.now(timezone.utc)
    w.decided_by = admin.id
    w.broadcast_at = datetime.now(timezone.utc)
    _sess().add(Transaction(
        user_id=w.user_id, category="withdrawal", direction="out", status="pending",
        amount_sat=w.amount_sat, service_fee_sat=w.service_fee_sat,
        network_fee_sat=w.network_fee_sat, total_sat=-w.total_sat, txid=txid,
        address=w.address, fee_rate=w.fee_rate, priority=w.priority,
        withdrawal_id=w.id, raw_hex=w.raw_hex,
        label=f"Sent to {w.address[:16]}…",
    ))
    _sess().commit()
    return txid


def reject_withdrawal(w: Withdrawal, admin: User, reason: str = None):
    if w.status not in ("queued", "approved"):
        raise SendError("That withdrawal cannot be rejected from its current state.")
    user = _sess().get(User, w.user_id)

    # if it was already broadcast we cannot reverse it on-chain
    if w.txid and w.status == "approved":
        try:
            status = explorer().tx_status(w.txid)
            if status and (status.get("confirmed") or status.get("block_height")):
                raise SendError("That transaction is already on the blockchain.")
        except ChainError:
            pass

    if w.txid:
        stale = _sess().get(OurTx, w.txid)
        if stale is not None:
            _sess().delete(stale)
    apply_ledger(user, +int(w.total_sat), "reversal", ref=f"wd:{w.id}",
                 note=f"Withdrawal rejected by {admin.username}"
                      + (f": {reason}" if reason else ""),
                 created_by=admin.id, commit=False)
    w.status = "rejected"
    w.error = reason
    w.decided_at = datetime.now(timezone.utc)
    w.decided_by = admin.id
    _sess().commit()
    return True


# ------------------------------------------------------------ chain watcher
def _confirmations(status: dict, tip: int) -> int:
    bh = status.get("block_height")
    if not status.get("confirmed") or not bh:
        return 0
    return max(1, tip - int(bh) + 1)


def record_pending_deposit(user: User, address: Address, txid: str, vout: int,
                           value_sat: int, tip: int, height=None):
    existing = (
        _sess().query(Transaction)
        .filter(Transaction.txid == txid, Transaction.vout == vout,
                Transaction.category == "deposit")
        .first()
    )
    if existing:
        return existing
    tx = Transaction(
        user_id=user.id, category="deposit", direction="in", status="pending",
        amount_sat=value_sat, total_sat=value_sat, txid=txid, vout=vout,
        address=address.address, confirmations=0, block_height=height,
        label=f"Deposit to {address.label or address.address[:12]}",
    )
    _sess().add(tx)
    _sess().commit()
    return tx


def credit_confirmed_deposit(user: User, address: Address, txid: str, vout: int,
                             value_sat: int, tip: int, height=None, confirmations: int = 1):
    """Credit exactly once. The unique (txid, vout) row is the guard, so a
    rescan, a restart or a reorg cannot double-credit a deposit."""
    guard = (
        _sess().query(ChainCredit)
        .filter(ChainCredit.txid == txid, ChainCredit.vout == vout)
        .first()
    )
    if guard is not None:
        return False, guard

    entry = apply_ledger(
        user, value_sat, "deposit", ref=f"{txid}:{vout}",
        note=f"Confirmed deposit to {address.address[:16]}…", commit=False,
    )
    credit = ChainCredit(txid=txid, vout=vout, address_id=address.id,
                         value_sat=value_sat, ledger_id=entry.id, block_height=height)
    _sess().add(credit)

    existing = (
        _sess().query(Transaction)
        .filter(Transaction.txid == txid, Transaction.vout == vout,
                Transaction.category == "deposit")
        .first()
    )
    now = datetime.now(timezone.utc)
    if existing:
        existing.status = "confirmed"
        existing.confirmations = confirmations
        existing.block_height = height
        existing.confirmed_at = now
    else:
        _sess().add(Transaction(
            user_id=user.id, category="deposit", direction="in", status="confirmed",
            amount_sat=value_sat, total_sat=value_sat, txid=txid, vout=vout,
            address=address.address, confirmations=confirmations,
            block_height=height, confirmed_at=now,
            label=f"Deposit to {address.label or address.address[:12]}",
        ))
    _sess().commit()
    return True, credit


def sync_once(verbose: bool = False):
    """One chain-watch pass. Returns a summary dict."""
    client = explorer()
    min_conf = get_int_setting("min_confirmations")
    deposits_enabled = get_bool_setting("deposits_enabled")
    tip = client.tip_height()
    our_txids = {t for (t,) in _sess().query(OurTx.txid).all()}

    credited = 0
    pending_new = 0
    checked = 0

    addresses = (
        _sess().query(Address).join(User, Address.user_id == User.id)
        .filter(User.deleted_at.is_(None))
        .order_by(Address.last_activity_at.asc().nullsfirst())
        .limit(500).all()
    )

    for addr in addresses:
        user = _sess().get(User, addr.user_id)
        if user is None:
            continue
        checked += 1
        try:
            txs = client.address_txs(addr.address)
        except ChainError as exc:
            log.warning("sync: %s unreachable (%s) — skipping rest of pass", addr.address, exc)
            break

        for tx in txs:
            txid = tx.get("txid")
            if not txid:
                continue
            status = tx.get("status") or {}
            confirmations = _confirmations(status, tip)
            height = status.get("block_height")

            # a transaction we broadcast ourselves: its change output is not a
            # deposit. Still track confirmations for the user's timeline.
            if txid in our_txids:
                _sess().query(Transaction).filter(
                    Transaction.txid == txid, Transaction.status == "pending"
                ).update({"confirmations": confirmations,
                          "block_height": height,
                          "status": "confirmed" if confirmations >= min_conf else "pending",
                          "confirmed_at": datetime.now(timezone.utc) if confirmations >= min_conf else None},
                         synchronize_session=False)
                _sess().commit()
                continue

            for vout, out in enumerate(tx.get("vout") or []):
                if out.get("scriptpubkey_address") != addr.address:
                    continue
                value = int(out.get("value") or 0)
                if value <= 0:
                    continue
                if confirmations >= min_conf and deposits_enabled:
                    did, _c = credit_confirmed_deposit(
                        user, addr, txid, vout, value, tip, height, confirmations
                    )
                    if did:
                        credited += 1
                        addr.last_activity_at = datetime.now(timezone.utc)
                elif confirmations < min_conf:
                    before = (
                        _sess().query(Transaction)
                        .filter(Transaction.txid == txid, Transaction.vout == vout,
                                Transaction.category == "deposit")
                        .count()
                    )
                    if not before:
                        pending_new += 1
                    existing = record_pending_deposit(
                        user, addr, txid, vout, value, tip, height
                    )
                    existing.confirmations = confirmations

        _sess().commit()
        if current_app.config["SYNC_ADDRESS_DELAY_MS"]:
            time.sleep(current_app.config["SYNC_ADDRESS_DELAY_MS"] / 1000.0)

    # confirmations on the user's outgoing transactions
    open_out = (
        _sess().query(Transaction)
        .filter(Transaction.category == "withdrawal", Transaction.status == "pending")
        .limit(200).all()
    )
    for tx in open_out:
        if not tx.txid:
            continue
        try:
            st = client.tx_status(tx.txid)
        except ChainError:
            continue
        if not st:
            continue
        conf = _confirmations(st, tip)
        tx.confirmations = conf
        tx.block_height = st.get("block_height")
        if conf >= min_conf:
            tx.status = "confirmed"
            tx.confirmed_at = datetime.now(timezone.utc)
    _sess().commit()

    return {
        "tip": tip,
        "addresses_checked": checked,
        "deposits_credited": credited,
        "pending_seen": pending_new,
    }


# ------------------------------------------------------------ global holdings
def global_holdings():
    """Operator view: what the wallet holds on-chain vs what users are owed.

    Coverage is measured against CONFIRMED funds only. Unconfirmed outputs
    cannot be spent (coin selection requires a confirmed input) and can still
    disappear in a reorg or be RBF'd away, so counting them as backing for
    someone else's balance would overstate the wallet's position.
    """
    client = explorer()
    ledger_total = int(_sess().query(func.coalesce(func.sum(User.balance_sat), 0))
                       .filter(User.deleted_at.is_(None)).scalar() or 0)

    # transactions we broadcast ourselves: their unconfirmed change is OUR funds
    # in flight, not an unconfirmed third-party deposit
    our_txids = {t for (t,) in _sess().query(OurTx.txid).all()}

    addresses = _sess().query(Address).all()
    onchain = 0
    unconfirmed = 0
    spendable = 0
    in_flight = 0
    errors = []
    for addr in addresses:
        try:
            utxos = client.address_utxos(addr.address)
        except ChainError as exc:
            errors.append(f"{addr.address[:14]}…: {exc}")
            continue
        for u in utxos:
            v = int(u.get("value") or 0)
            onchain += v
            if (u.get("status") or {}).get("confirmed"):
                spendable += v
            else:
                unconfirmed += v
                # Our own change is already accounted for by the ledger debit on
                # the send that created it, and it will confirm. Counting it as
                # backing avoids a false "shortfall" alert on every send.
                if u.get("txid") in our_txids:
                    spendable += v
                    in_flight += v

    # economic position, based on settled funds plus our own funds in flight
    fees_collected = spendable - ledger_total
    queued = int(
        _sess().query(func.coalesce(func.sum(Withdrawal.total_sat), 0))
        .filter(Withdrawal.status == "queued").scalar() or 0
    )
    return {
        "onchain_sat": onchain,
        "onchain_confirmed_sat": spendable - in_flight,
        "onchain_unconfirmed_sat": unconfirmed,
        "in_flight_sat": in_flight,
        # what the wallet can pay out: settled funds plus our own change that is
        # still confirming. Third-party unconfirmed deposits are excluded.
        "spendable_sat": spendable,
        "user_ledger_sat": ledger_total,
        "fees_collected_sat": fees_collected,
        "queued_withdrawals_sat": queued,
        "address_count": len(addresses),
        "errors": errors,
        # the invariant: the wallet must be able to pay what users are owed
        "float_shortfall": max(0, ledger_total - spendable),
    }


def check_invariant():
    """Raise an alert if the wallet cannot back user balances on-chain."""
    try:
        h = global_holdings()
    except Exception as exc:
        log.warning("invariant check failed: %s", exc)
        return None
    if h["float_shortfall"] > 0:
        raise_alert(
            "float_shortfall_global",
            "Wallet cannot cover all user balances on-chain",
            f"Users are owed {h['user_ledger_sat']} sats but only "
            f"{h['spendable_sat']} sats are spendable "
            f"(shortfall {h['float_shortfall']} sats).",
            severity="critical",
        )
    return h
