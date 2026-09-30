# Architecture

## Components

| Component | What it is | Why it is separate |
|---|---|---|
| `web` | Flask app under gunicorn (1 worker, 8 threads), listening on `127.0.0.1:8810` | One worker keeps the process small on a 2-core box; the rate limiting that matters is counted in Postgres, so it does not depend on worker count |
| `syncer` | `python -m app.sync --loop`, one pass per `SYNC_INTERVAL_SECONDS` (60) | The chain watcher must never run twice inside gunicorn, and it must survive web deploys. It writes a heartbeat file; its container healthcheck watches that file's mtime, so a *wedged* loop is caught, not just a dead process |
| `db` | PostgreSQL 16 | The ledger is the source of truth for who owns what |
| host Caddy | TLS terminator, reverse proxy to `127.0.0.1:8810` | The session cookie is `Secure`; TLS also keeps 2FA codes and session tokens off the wire. See `deploy/caddy-btc.conf` |

Watches: mempool.space (primary) → blockstream.info (failover). If every provider
fails, the chain watcher logs and skips the pass rather than crediting nothing silently.

## Request flow (a page render)

1. Caddy terminates TLS and proxies to gunicorn.
2. `ProxyFix` trusts exactly one hop, so `remote_addr` is the real client and a forged
   `X-Forwarded-For` cannot pick its own rate-limit identity.
3. `before_request` guards run in order: NUL-byte rejection, the global per-IP write
   cap, then the **network guard** (`network_transition_required()` — refuse to serve
   while the configured network does not match the network recorded with the seed).
4. The view runs behind a decorator: `login_required`, `active_required`,
   `admin_required` or `sudo_required`. `current_user()` re-checks `session_version`
   on every request, so banning, a password change or "sign out everywhere" kills live
   cookies immediately.
5. `login_required` also applies the **account gate** (an operator-imposed requirement
   on a user account), which can redirect to 2FA enrolment or a forced password change.
6. `after_request` sets security headers, `Cache-Control: no-store` on wallet and admin
   pages, and `X-Robots-Tag: noindex`.

## Money flows

### Deposit

```
Esplora: address utxos (per address, 250 ms apart)
   └─ unconfirmed  → a Transaction row, pending (never counted as backing)
   └─ confirmed    → credit exactly once
        ├─ INSERT chain_credits(txid, vout) — unique; a rescan cannot double-credit
        ├─ services.apply_ledger(user, +value, "deposit")  → balance_sat + ledger row
        └─ Transaction row → confirmed
```

### Send (withdrawal)

```
POST /send/quote        → services.quote_send()  → fee oracle, coin selection, dust checks
                          stored server-side as a SendQuote; the browser only gets an id
GET  /send/review/<id>  → the breakdown, from the stored quote
POST /send/confirm/<id> → sudo (password re-entry) → services.execute_send()
                          ├─ coin selection → build → sign → verify every input
                          ├─ within the auto-send limit → broadcast now
                          └─ above it → Withdrawal row, status queued, amount held
admin approve           → services.approve_withdrawal() → broadcast → txid recorded
```

The debit is re-derived from the **signed** transaction's actual fee, never from the
estimate, so a fee spike cannot leave the books short.

### Sweep (moving a balance between accounts)

Balances live in the ledger, so moving one is a database operation, not a transaction.
`sweep_balance(source, recipient, admin)` writes `sweep_out` on the source and
`sweep_in` on the recipient in one transaction. Deleting an account runs this first and
**abandons the delete** if the sweep fails. A negative balance transfers as debt, so the
loss stays visible instead of being zeroed.

## Accounting model

- `users.balance_sat` = spendable balance, authoritative, integer satoshis.
- `ledger_entries` = append-only, every row carries `delta_sat` **and** `balance_after_sat`.
- `chain_credits` = every deposit output already credited (unique on `txid, vout`).
- `our_txs` = transactions we broadcast, marked **before** the broadcast, so our own
  change outputs are never re-read as fresh deposits.
- **The invariant**: `spendable_onchain − sum(user_balances) = operator_revenue`.
  The admin dashboard asserts it on every load and raises a critical alert when it
  breaks (`services.global_holdings()`); the syncer re-checks it every 5 minutes.

Only **confirmed** funds count as backing — a third-party unconfirmed deposit can still
disappear (reorg or RBF) and coin selection cannot spend it. Our *own* unconfirmed change
does count, because it is ours; not counting it would fire a false shortfall alert on
every send and train the operator to ignore alerts.

## The chain watcher

Each pass, `app/sync.py`:

1. Compares its own `BTC_NETWORK` against the network recorded with the seed. On
   mismatch it logs CRITICAL, raises a critical alert and skips the pass **without
   touching chain data** (a watcher left on the other network otherwise credits nothing,
   forever, quietly).
2. Reads the tip height and walks every deposit address.
3. Credits confirmed, uncredited outputs (bounded by `min_confirmations`).
4. Advances confirmations on pending deposits and transactions.
5. Retries queued withdrawals that were approved but never broadcast.
6. `check_invariant()` — raises an alert on a float shortfall.
7. Writes `/tmp/syncer-heartbeat`.

## Data-model notes that matter

- `Setting` is a key/value table for admin-editable policy; `SETTING_LABELS` in
  `app/services.py` is the registry (label + help text) that both the settings page and
  the generated docs read.
- `AdminAudit` denormalises `admin_username` and `target_username` and sets the FKs to
  `ON DELETE SET NULL`, so **audit rows outlive the accounts they name**. Ledger rows
  cascade away with the user, which is why the audit trail matters.
- `SecurityEvent` is the per-account history the user sees on their own Security page.
- `Throttle` is the DB-backed rate limiter: exact across restarts and workers. Buckets
  are split so *attempts* (lenient) and *successes* (strict) count separately — charging
  typos against a signup cap locks out honest users.
- `Address.idx` (the BIP84 index) is allocated from a Postgres **sequence**, so two
  simultaneous signups can never derive the same key.

## Why it is shaped this way

- **One seed, one wallet, ledger claims.** Simplest thing that can custody balances
  without a transaction per user. The cost is that the operator is trusted — which is why
  every operator action is audited and the invariant is on screen.
- **Server-side quotes.** Amounts never round-trip through the browser, so a tampered
  form cannot change what is paid.
- **Gates instead of hidden buttons.** Anything the operator can do to an account is
  visible on the account page, explainable in one line, and reversible.
- **Refuse over guess.** Wrong network, absurd fee, unbacked credit, pending network
  migration: the app stops with a message rather than doing something plausible.
