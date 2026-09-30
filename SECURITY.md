# Security policy

This project holds Bitcoin. Treat every report as if coins were at stake, because they
may be.

## Reporting a vulnerability

**Do not open a public issue for anything that could move funds, read balances, or
recover the wallet seed.**

- Email: `jlaiii@users.noreply.github.com` (subject prefix `BTC Vault security`)
- Include: what you found, the exact steps to reproduce, the version/commit, and what an
  attacker gains. A proof of concept against a throwaway testnet instance is ideal.
- If you cannot email, open a **private** security advisory on the repository
  (*Security → Report a vulnerability*).

## What to expect

- Acknowledgement within a few days.
- An honest assessment, including "this is by design" when it is — the design decisions
  are documented in `docs/security.md`.
- Credit in the fix commit and release notes unless you prefer otherwise.

## Please do not

- Test against someone else's deployment, including a live instance that is not yours.
- Move real funds, or access another person's account or data.
- Run denial-of-service tests, spam, or social engineering against operators.
- Publish details before a fix is available.

## Useful things to report

Everything is interesting, but these areas are the highest-value:

- Anything that lets a request credit a balance twice, or credit without a confirmed
  on-chain output (`chain_credits`, `our_txs`, the chain watcher).
- Anything that makes the wallet sign for the wrong network, the wrong amount, or the
  wrong destination — or that broadcasts without a verified signature.
- Anything that reveals the seed or the master key, or that reads another user's data
  through an `id` in a URL (IDOR).
- Anything that defeats the account gates: bypassing a required 2FA enrolment, escaping a
  forced password change, or being locked into a gate with no exit.
- Authentication bypasses: session fixation, `session_version` bypass, sudo-window
  abuse, TOTP replay, backup-code reuse.
- Admin-only actions reachable without `admin_required` + a fresh password confirmation.

## Out of scope

- Root access to the host, or a stolen master key file: by definition game over. See
  *Deliberately absent* in `docs/security.md`.
- A malicious operator adjusting balances: custodial designs cannot prevent it. The
  audit trail and the on-chain invariant exist to make it detectable.
- Missing features (cold storage, multisig) — those are scope, not vulnerabilities.
- Reports from automated scanners with no exploitable impact.
