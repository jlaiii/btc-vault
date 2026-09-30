# BTC Vault

A custodial Bitcoin wallet you host yourself. Users sign up, get a real deposit
address with a QR code, receive and send BTC with a fee speed they choose, and
see their full history. An admin panel covers users, balances, global holdings,
withdrawal approvals and an audit trail.

**[Interactive demo →](https://jlaiii.github.io/btc-vault/)** — the whole wallet and
admin panel as a static walkthrough on GitHub Pages. Simulated data, no backend, no
real bitcoin, nothing to sign up for.

Network-agnostic by configuration: `BTC_NETWORK=testnet` (default) or `mainnet`.
Testnet coins are real coins on a test network and worth nothing. Read
*Going to mainnet* before you switch — it is a data migration, not a config toggle.

- Stack: Flask + gunicorn + PostgreSQL, Docker Compose, behind the host Caddy
- Chain data: Esplora REST APIs (mempool.space primary, blockstream.info failover)
- Addresses: BIP39 seed → BIP84 (native segwit), one derivation index per user

**Building on this with an AI agent?** Start at [`llms.txt`](llms.txt) — a short index of
every document, in the order worth reading — then [`docs/generated/context.md`](docs/generated/context.md)
for a generated map of every route, model, setting and environment variable (regenerate
it with `scripts/build_agent_docs.py` so it cannot drift). `docs/security.md` and the
rules in `README.md` are the parts an agent must not break; the verification section
below is how it proves it did not. [`llms-full.txt`](llms-full.txt) is the whole set
concatenated into one file for a single-context read.

---

## What it does

### For users
- **Signup / login** with a **username and password only** — no email is collected
  anywhere, and there is no self-service password reset (an admin sets a new one)
- **Receive**: one or more deposit addresses, QR code, copy button, faucet button on testnet
- **Send**: paste address, enter amount (live USD conversion), pick **Fast / Normal /
  Economy** from live network fees, then review the exact breakdown before confirming
- **History**: every deposit, withdrawal and fee with confirmations and an explorer link
- **Account**: change username/password, sign out everywhere, view login history

### For the admin
- **Overview**: on-chain holdings vs. what users are owed, operator fees earned,
  24h in/out, open alerts, negative balances, accounts without 2FA
- **Signups on/off**: close registration from Settings — the signup page, the login
  page link and the landing-page button all follow it
- **Users**: search/filter, freeze, ban, force sign-out, clear 2FA, promote/demote,
  private notes
- **Security & access** (per account, at the top of the user page): require 2FA,
  remove 2FA (lost device), require a new password, unlock a locked-out account,
  clear a stale negative-balance flag — all confirmed **inline in the card**, so the
  button you press is the one that runs. See *Account gates* below
- **Set passwords**: generate one for a user, or choose a specific password. Shown
  once, and every session for that account is signed out
- **Balances**: set an absolute balance, or credit/debit by an amount — negative
  balances are allowed but flagged on the account and raised as critical alerts
- **Sweep a balance**: move a user's whole balance onto an admin account in one
  action (see *Nothing is ever lost* below)
- **Withdrawals**: approve or reject sends above the auto-send limit
- **Wallet**: hot wallet holdings, per-address list, reveal recovery phrase, manual chain scan
- **Ledger, transactions, audit log, alerts, CSV exports**
- **Settings**: service fee, send limits, confirmations, signups/deposits/withdrawals
  toggles. Saving requires a fresh password confirmation, entered **on the settings
  page itself** (nothing is lost if you are asked for it)
- **Administrator security**: 2FA state with a one-click enable/manage link

### Account gates (admin-imposed requirements)

A per-account control, not a global switch: an operator can require things of *one*
user without changing the rules for anybody else.

| Control | What it does | How the user gets out |
|---|---|---|
| **Require 2FA** | The account is gated until TOTP is enrolled. Every page except the 2FA setup, the security page and sign-out redirects to setup — **including a session that is already open**, since the check runs per request. Deposits still land on-chain; the user just cannot get into the wallet | Enrol an authenticator. Self-service 2FA disable is refused while the requirement stands |
| **Remove 2FA** | Wipes the secret and backup codes and signs the account out everywhere. For a lost phone *and* lost backup codes | They can sign in with the password and enrol again (immediately, if 2FA is still required) |
| **Require a new password** | The account is gated until it chooses a new password — the password change page is the only way through, and it needs the current password | Set a new password. Balance, addresses and history are untouched, and the operator never sees the new password |
| **Unlock** | Clears the failed-attempt counter and the lockout timer, so a locked-out user is not stuck for 15 minutes | Nothing — instant sign-in with the password they already have |
| **Clear negative-balance flag** | Removes the account flag once the books really are settled. **Refused while the balance is negative** — the flag is supposed to match reality | n/a |

Rules that are enforced in code, not just in the template:

- **Administrator accounts are exempt and cannot be gated.** Forcing 2FA or a password
  change on the operator turned a missing enrolment into a lockout of the panel that
  toggles it, so the panel refuses both on an admin target and says why. An admin turns
  their own 2FA on from Account → Security.
- **Every gate is satisfiable.** The exempt endpoints exist so a gated account can always
  finish the thing it was asked to do, then sign out if it wants. A gate that cannot be
  cleared is a dead end, and dead ends with money behind them become support incidents.
- **Confirmations happen inline on the card.** Enter the password (and a code, if 2FA is
  on) in the card and click the action: a POST is never bounced to `/confirm`, because
  the redirect comes back as a GET and the clicked action would silently never happen.
  With no password nothing changes, and the page says so.
- Everything is written to the audit log and the account's own security-event history.

---

## Security

### Accounts
| Control | Detail |
|---|---|
| Password hashing | Argon2id (19 MiB, t=2, p=1), per-user salt |
| Password policy | 10+ chars, 3+ character classes, rejects username/email inside the password and a common-password list |
| Login throttling | Per-IP (20 / 10 min) **and** per-account lockout (5 fails → 15 min), both counted in PostgreSQL |
| User enumeration | Unknown username and wrong password are indistinguishable, including timing (a dummy Argon2 verify is burned) |
| 2FA | TOTP with ±1 window, replay protection, 10 single-use Argon2-hashed backup codes. Optional for everyone, **including admins**: an admin without it gets a notice at every sign-in, a standing banner, and a control in Admin → Settings. An operator can require it of an individual *user* account (*Account gates* above); the requirement outranks the account's own preference, so self-service disable is refused while it stands |
| Admin re-auth | Settings changes and destructive actions need the password (plus a code if 2FA is on), entered inline on the page that asked for it |
| Chain-watcher guard | The watcher refuses to run if its configured network does not match the wallet's data, and raises a critical alert instead of silently crediting nothing |
| Sessions | Signed cookies, `Secure` + `HttpOnly` + `SameSite=Lax`, 30-min idle expiry, rotated on login |
| Instant revoke | `session_version` is re-checked every request — banning, password change or "sign out everywhere" kills live sessions immediately |
| Sudo mode | Sending money, changing your password, setting another user's password, sweeping a balance, and every destructive admin action require the password again (15-min window) |
| CSRF | Flask-WTF on every form |
| Password reset | **None by design** — accounts are username + password only, so there is no verified out-of-band channel. An admin sets a new password instead (which signs the account's sessions out). Losing your password means contacting the operator |
| Rate limits | Login, signup, 2FA, sudo, sends, faucet — plus a global per-IP cap on state-changing requests |

### Funds
- Hot wallet seed is **AES-256-GCM encrypted at rest**, master key in a separate
  file outside the database (`secrets/master.key`, `0600`, uid-matched to the
  container user) — a stolen DB dump alone is useless
- Address validation rejects malformed addresses, mixed-case bech32, and
  **wrong-network addresses** (sending testnet coins to a `bc1…` address destroys them)
- Every transaction is **signed, then re-verified** against the BIP143 sighash of the
  exact bytes about to be broadcast; a failed self-check aborts before broadcasting
- **No double-crediting**: deposits are credited once, guarded by a unique
  `(txid, vout)` row; our own change outputs are never mistaken for deposits
- Deposit credited only after N confirmations (default 1)
- Withdrawals above the auto-send limit are held for admin approval, with the
  amount reserved from the balance immediately
- Ledger is append-only with `balance_after` on every row; balances are integers
  in satoshis — there is no floating point anywhere in the money path

### Nothing is ever lost (balance sweeps)

Bitcoin that users deposit sits in the shared hot wallet; the ledger is what says who
owns how much. That means a balance can be *moved* without any on-chain transaction —
and it must never be *destroyed*:

- **Sweep a balance**: an admin can move a user's whole balance onto an admin account
  in one action. Nothing moves on-chain; only the ledger claim changes hands.
- **Deleting an account sweeps first.** If the account holds anything, it is moved to
  an admin account *before* the row is removed. If that sweep fails, the delete is
  abandoned — otherwise those coins would still be in the hot wallet with nobody
  entitled to them.
- **Negative balances transfer as debt.** Sweeping a negative balance moves the
  liability onto the admin who receives it, rather than quietly zeroing it, so the
  books still balance and the loss is visible.
- Every sweep writes **both sides** to the ledger (`sweep_out` / `sweep_in`) plus an
  admin audit entry naming the account and amount, so the trail survives the deletion.

The test suite asserts this directly: the sum of all user balances is compared before
and after a sweep and before and after a delete, and must be **identical**.

### Transport / hosting
- TLS 1.2+ with a real Let's Encrypt cert; HSTS, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy`, `Permissions-Policy`,
  `X-Robots-Tag: noindex`, and a strict CSP (`script-src 'self'`)
- App listens on **loopback only** (`127.0.0.1:8810`); only Caddy is public
- Client IP taken from the proxy hop Caddy appends — a forged `X-Forwarded-For`
  cannot choose its own audit identity or rate-limit bucket
- Container runs as a non-root user; NUL-byte guard so Postgres cannot be made to 500
- `no-store` on every authenticated page

---

## Architecture

```
Caddy (TLS, :443)
  └── 127.0.0.1:8810  web (gunicorn, Flask)     ──┐
  └── syncer (python -m app.sync --loop, 60s)   ──┤
                                                   └── PostgreSQL (docker volume)
```

The chain watcher is a **separate process**, so it can never run twice inside
gunicorn. It credits confirmed deposits, tracks confirmations, and re-checks the
global float invariant every 5 minutes.

### Accounting model
Worth reading before changing anything:

- `users.balance_sat` is the **spendable** balance (mirrored by append-only
  `ledger_entries`). It is authoritative, because an admin can move it in a way
  on-chain data alone cannot express.
- A confirmed deposit credits it once (guarded by `chain_credits`).
- A send debits amount + service fee + the **actual** miner fee, and the change
  returns to our wallet **without** being credited again (`our_txs` marks
  transactions we broadcast).
- Therefore: **on-chain total − user ledger total = operator revenue**. The admin
  dashboard asserts that identity every time it loads and raises a critical alert
  when a float shortfall exists — which is how an unbacked admin credit gets noticed.
- The miner fee is paid from the user's balance; the service fee stays in the
  hot wallet as operator revenue.

---

## Operations

```bash
cd /path/to/btc-vault

# status / logs
docker compose ps
docker compose logs -f web syncer

# the app's own checks
docker compose exec -T web python /app/scripts/verify_crypto.py     # offline crypto + fees
docker compose exec -T web python /app/scripts/e2e_test.py          # full behavioural suite
docker compose exec -T web python /app/scripts/mainnet_check.py     # mainnet-safe, cleans up
docker compose exec -T web python /app/scripts/check_admin_settings.py  # admin 2FA notice + settings save
docker compose exec -T web python /app/scripts/check_admin_user_controls.py  # require/clear 2FA, forced password change, unlock
python3 scripts/ci_smoke.py                        # boot + behaviour on a throwaway DB (what CI runs)
python3 scripts/build_agent_docs.py --llms-full llms-full.txt   # refresh the concatenated docs
docker compose exec -T web python -m app.cli preflight              # GO/NO-GO for real money

# money
docker compose exec web python -m app.cli holdings              # on-chain vs owed
docker compose exec web python -m app.cli sync                  # force a chain scan
docker compose exec web python -m app.cli settings              # current policy
docker compose exec web python -m app.cli show-seed             # recovery phrase

# create another admin
docker compose exec web python -m app.cli create-admin --username NAME --email you@example.com
```

The syncer also runs `check_invariant()` every 5 minutes and raises an alert if
the wallet cannot cover user balances.

### Backups
The only irreplaceable things are:
1. `secrets/master.key` — without it the seed cannot be decrypted
2. `secrets/HOTWALLET_MNEMONIC.txt` — the wallet recovery phrase (write it down, then delete)
3. the `btcwallet-db` Docker volume — user, ledger and audit data

Back up the master key **separately** from the database; storing them together
defeats the point of encrypting the seed.

---

## Going to mainnet

Changing the network changes BIP84 derivation (`m/84'/1'/…` → `m/84'/0'/…`), so
every stored address belongs to the other chain. The app therefore **refuses to
serve** while a transition is pending — a 503 with an explanation, while `/health`
still answers — rather than handing out addresses that cannot receive and showing
balances nothing backs on-chain.

The procedure, in order:

```bash
# 1. point the wallet at mainnet
sed -i 's/^BTC_NETWORK=testnet$/BTC_NETWORK=mainnet/' .env
docker compose stop web && docker compose rm -f web \
  && docker compose create web && docker start btcwallet-web
#    (a plain `restart` does NOT re-read .env — env changes need a recreate)

# 2. do the migration: zeroes the old network's balances (recorded in the ledger),
#    removes unreachable addresses, generates a fresh seed, applies mainnet defaults
docker compose exec -T web python -m app.cli launch-network --confirm \
    --seed-out /tmp/mainnet-seed.txt

# 3. get the seed OFF the container, then copy it out (it is ephemeral inside there)
docker cp btcwallet-web:/tmp/mainnet-seed.txt /root/mainnet-seed.txt
chmod 600 /root/mainnet-seed.txt
docker compose exec -T web rm -f /tmp/mainnet-seed.txt

# 4. write the 24 words on paper, store them offline, delete the file, then:
docker compose exec -T web python -m app.cli ack-seed-backup

# 5. gate on the checklist — it exits non-zero until nothing is blocking
docker compose exec -T web python -m app.cli preflight
```

`launch-network` refuses to run without `--confirm`. Deposits stay as configured
(on by default, so the site is usable immediately after a network move);
`ack-seed-backup` records that you wrote the phrase down and reports it in
`preflight`, which is where an un-backed-up seed shows up as a blocker.

After any network change, **recreate every container in the stack**, not just the
web one — `docker compose restart` re-reads neither `.env` nor a changed config, so
the chain watcher keeps the OLD network and 400s on every lookup while never failing
loudly. The watcher now detects that itself and raises a critical alert:

`preflight` is the honest gate. It verifies, among other things, that the explorer
is really serving this chain (by checking the genesis block hash), that the seed
decrypts, that every admin is not still on a password that appeared in a transcript,
that the faucet is off, and that the books balance. It exits non-zero while anything
blocks.

Also before real money:

- **`MIN_CONFIRMATIONS` to 2–3** — at 1, a reorg can un-credit a deposit.
- **Keep the auto-send ceiling low.** Sends at or below `instant_send_max_sat`
  leave the wallet without an operator confirming them; everything above needs
  approval in Admin → Withdrawals.
- **Fund the float deliberately.** The holdings panel says exactly how much is owed.
- **A custodial wallet holding other people's bitcoin is regulated money
  transmission in the US** (FinCEN MSB registration plus state licensing, e.g.
  Texas Finance Code Ch. 151). This build is appropriate for self-hosting and for a
  personal or invite-only wallet. Running it as a public service is a legal
  decision, not a technical one — a small pilot with people you know is the sane
  first step, and signups are one toggle away from invite-only.
- **The hot wallet is the risk.** Real BTC held here is only as safe as the VPS; a
  compromise drains it. The architecture for real money is a small working float
  hot with the bulk in cold storage, which this build does not implement.

---

## Known limitations

- **The wallet is custodial.** The operator holds the keys. That is the design,
  not an oversight.
- **Deposit addresses are single-purpose** (one per user per wallet); the app polls
  Esplora for each address rather than running a full node. Fine at this scale,
  but a real node (or Electrum) is the right answer past a few hundred users.
- **Testnet faucet** is a convenience for trying the app; it drains the hot wallet's
  own testnet float and is rate limited per user.
- **No self-service password recovery.** With no email addresses there is no verified
  channel to send a reset to; recovery means asking an admin. That is the deliberate
  trade-off for collecting no personal data, and it means an operator who disappears
  leaves users unable to regain access.
- **Signup rate limits** count successful account creations separately from form
  submissions, so typos are free but bulk registration is capped per source address.
- **Fee estimation** assumes P2WPKH inputs (all of ours are) and prices change
  between quote and confirm — the final numbers are re-derived from the signed
  transaction, so the fee shown is the fee paid.
- Reorgs deeper than the confirmation threshold are not automatically reversed.
