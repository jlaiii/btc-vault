# Security

What this app defends against, what it deliberately does not, and how to report a
problem. `README.md` lists the controls in table form; this file is the reasoning.

## Threat model

Assets, in order:

1. **The hot wallet seed.** Whoever has it can spend every coin the wallet holds.
2. **User balances.** Ledger claims on those coins.
3. **The operator's panel access** — an admin can move money by editing a balance.
4. **Account credentials** — a stolen password is a path to a balance.

| Adversary | What they can do | What stops them |
|---|---|---|
| Anonymous internet | Hit signup/login/2FA, probe for IDOR | Per-IP and per-account throttles counted in Postgres, generic error messages, timing-equalised login, `noindex`, CSRF on every form |
| User with an account | Try to read or spend someone else's balance | Every query is scoped to `current_user()`; wallet pages, activity rows and quotes are checked for ownership (an `id` in a URL is never trusted) |
| Stolen session cookie | Act as that user until the cookie dies | `Secure` + `HttpOnly` + `SameSite=Lax`, 30-minute idle expiry, and `session_version` re-checked **every request** so ban/password-change/sign-out kill live sessions instantly |
| Malicious form / XSS on the wallet origin | Change an amount, a destination, or an admin action | Server-side quotes (the browser only returns a quote id), CSRF tokens, CSP with `default-src 'self'` and no inline script |
| Shoulder-surfed or replayed TOTP code | Re-use a code seen once | Replay protection: the matched time-step is recorded and `step <= last_step` is refused |
| Stolen database dump | Read balances, hashes, TOTP secrets, the seed | Passwords are Argon2id; the seed and TOTP secrets are AES-256-GCM sealed under a master key that lives **outside** the database, on a read-only mount |
| Someone with the container filesystem | Read the key, dump memory | Out of scope — root on the host is game over. Use full-disk encryption and limit who has it |
| Malicious operator | Move money, adjust balances | Cannot be prevented in a custodial design. Mitigated by the audit trail, the on-screen invariant and the ledger's `balance_after_sat` on every row — the control is *detection*, not prevention |

## Notable decisions

- **No email, no self-service reset.** An email column would be the only out-of-band
  channel and would also become the recovery path. Instead an admin sets a new password
  (shown once, on a dedicated page, every session signed out). Less personal data, one
  fewer attack path, one more support step.
- **2FA is optional for administrators, enforced as a gate for users.** A hard gate on a
  missing enrolment locked the operator out of the panel that could undo it, which is
  worse than no 2FA. Admins get a notice at every sign-in, a standing banner and a
  preflight warning; user accounts can be *required* to enrol, and that requirement
  outranks the account's own preference.
- **Every gate is satisfiable.** A required-2FA account can still reach the enrolment
  page, the security page and sign-out; nothing else. A gate with no exit turns a
  security control into a support incident with money behind it.
- **Inline confirmations, never a re-auth bounce.** A POST redirected to `/confirm`
  returns as a GET: the submitted values are gone and the action silently never happens.
  Confirmation fields live on the page that asked.
- **Only confirmed funds count as backing.** An unconfirmed third-party deposit can
  vanish (reorg/RBF) and cannot be spent by coin selection.
- **Refuse over guess.** Wrong-network address, absurd fee, low achieved feerate, unbacked
  credit, pending network migration: stop with a message.

## Verification that backs these claims

Not aspirations — each of these is a script you can run:

| Claim | Check |
|---|---|
| Signing, vsize, fee math, outpoint byte order | `scripts/verify_crypto.py` (offline, independent ECDSA verification) |
| Wrong-network address is refused, addresses match the chain | `scripts/mainnet_check.py` |
| Admin panel works without forced 2FA; settings really save | `scripts/check_admin_settings.py` |
| Account gates block and can be satisfied; admins are exempt | `scripts/check_admin_user_controls.py` |
| Behaviour end-to-end (auth, IDOR, lockout, 2FA, sweeps, invariant) | `scripts/e2e_test.py`, `scripts/live_chain_test.py` |
| The books balance | `python -m app.cli holdings`, `python -m app.cli preflight` |

A change to the money path is not done until the relevant one of these has been run
against a live instance and its output quoted. A transaction can sign correctly, verify
against its own sighash, and still be rejected by the network — offline checks have to be
followed by a real broadcast on testnet.

## Deliberately absent

- No cold storage, no multisig, no hardware-wallet integration. The hot wallet holds
  everything.
- No per-user withdrawal address allowlist, no velocity/behaviour scoring.
- No audit log shipping or alerting to an external system; alerts are in-app.
- No background job queue — the syncer loop is the only background process.
- No rate limiting at the proxy (Caddy) level; it is all in the app.

## Deployment expectations

- TLS in front, always (the session cookie is `Secure`).
- One host, loopback app port, a firewall that exposes only 80/443 and SSH.
- `secrets/master.key` on a read-only mount, `0600`, owned by uid 1500 (the container
  user), backed up **separately** from the database.
- Full-disk encryption on the host: the database contains balances and the sealed seed.
- **Legal**: custodying other people's bitcoin is money transmission in the US (FinCEN
  MSB registration, state licences, and Texas Finance Code Ch. 151 in TX). Running this
  for yourself and a few people who trust you is a technical project. Holding strangers'
  funds publicly is a legal question, not a technical one — `cli preflight` puts that in
  the REVIEW section for exactly this reason.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md). Do not open a public issue for anything that could
move funds or read balances; email the maintainer with steps to reproduce.
