# Data model

Money is always an **integer number of satoshis**. There is no float in this schema and
none in the code that writes to it.

`docs/generated/context.md` is the machine-generated column-by-column dump; this file
explains what the tables are *for* and the rules that keep them consistent.

## Tables

### `users`
The account and its spendable balance.

| Column group | Notes |
|---|---|
| `username`, `password_hash` | Argon2id. No email is collected; `email` exists as a nullable column for compatibility and is unused |
| `role` | `user` \| `admin` |
| `status` | `active` \| `frozen` (can sign in and deposit, cannot send) \| `banned` (cannot sign in) |
| `balance_sat` | **authoritative spendable balance**, integer sats |
| `negative_balance` | set when an adjustment pushed the account below zero. Only ever *set* by `apply_ledger`, which is why the admin panel has an explicit "clear flag" control |
| `next_address_index` | next BIP84 index for this user (the global allocator is a Postgres sequence) |
| `session_version` | bumped on ban, password change, 2FA change, "sign out everywhere". Checked on every request — that is what makes revocation instant |
| `totp_secret_enc`, `totp_enabled`, `totp_confirmed_at`, `totp_last_step`, `backup_codes_json` | TOTP state. The secret is sealed with the master key; backup codes are Argon2 hashes, single use; `totp_last_step` is the replay guard |
| `require_2fa`, `must_change_password` | **operator-imposed gates.** Both are satisfiable by the account itself and are never applied to administrators |
| `failed_logins`, `locked_until` | per-account lockout (default 5 fails → 15 min) |
| `notes` | operator notes, never shown to the user |
| `deleted_at` | soft-delete marker (login refuses it); admin delete removes the row |

### `addresses`
One HD-derived deposit address. `idx` is the BIP84 index, unique across **all** users
(allocated from `address_index_seq`), so no two accounts can share a key. Deleting an
account deletes its addresses, which is deliberate: after a network migration the old
addresses are unreachable.

### `ledger_entries`
Append-only. Every row has `delta_sat` **and** `balance_after_sat`, plus `kind`
(`deposit`, `withdrawal`, `service_fee`, `network_fee`, `admin_credit`, `admin_debit`,
`admin_set`, `reversal`, `faucet_credit`, `sweep_in`, `sweep_out`, `network_reset`,
`correction`) and optional `ref`/`note`/`created_by`.

This is what lets chain data and operator action coexist: the chain cannot express an
admin credit, a fee, or a negative balance.

### `transactions`
The user-visible history: `category` (deposit / withdrawal / admin), `direction`,
`status`, `amount_sat`, `service_fee_sat`, `network_fee_sat`, `total_sat`, `txid`,
`vout`, `address`, `confirmations`, `block_height`, `fee_rate`, `priority`, `raw_hex`.

### `withdrawals`
A send above the auto-send limit. `status`: `queued` → `approved` → `sent`, or `failed`,
`rejected`, `cancelled`. The amount is **held from the balance when queued**, so it
cannot be spent twice while it waits for approval. `quote_json` keeps the priced quote
the user actually saw.

### `chain_credits`
Every deposit output already credited. `UNIQUE(txid, vout)` is the idempotency guard:
a rescan, restart or reorg cannot double-credit.

### `our_txs`
Transactions **we** broadcast (withdrawals, faucet sends). The row is written before the
broadcast, so a crash mid-send is safe and our change outputs are never mistaken for new
deposits.

### `admin_audit`
Every operator action: `admin_username`, `target_username`, `action`, `detail`, `ip`.
`admin_id` and `target_user_id` are `ON DELETE SET NULL` and the usernames are
denormalised, so **the trail survives deleting the accounts it names.**

### `security_events`
Per-account history the user can see on their own Security page: logins, failures,
2FA changes, admin actions against the account.

### `alerts`
Things the operator must look at: negative balances, float shortfalls, failed
broadcasts, locked accounts, failed address creation, chain-watcher network mismatch.
Deduplicated on `(kind, user_id)` while unacknowledged so a repeating condition cannot
bury the dashboard. `severity`: `info` \| `warning` \| `critical`.

### `settings`
Key/value policy the admin edits: fees, limits, toggles, maintenance banner. Defaults
live in `DEFAULT_SETTINGS` and the registry with labels is `SETTING_LABELS`
(both in `app/services.py`).

### `send_quotes`
A priced send, stored server-side. The browser receives only the quote id — a tampered
form cannot change the amount, the fee or the destination.

### `throttles`
DB-backed rate limiting rows: `bucket`, `created_at`. Buckets are pruned as they are
read. Per-IP and per-account, for login, signup, 2FA, sudo, sends, faucet, and a global
write cap.

### `faucet_requests`
Testnet-only helper: one row per faucet request with status/txid, so the cooldown and
per-day cap are enforceable.

### `password_resets`
Legacy table kept so old rows and exports do not break. The app has **no** self-service
reset (there is no verified out-of-band channel), so nothing writes new rows.

## Invariants to preserve

1. `sum(users.balance_sat)` changes **only** through `services.apply_ledger()`, in the
   same transaction as the matching `ledger_entries` row.
2. `spendable_onchain − sum(user_balances) = operator_revenue` at all times; a break is a
   critical alert.
3. Every credited chain output has exactly one `chain_credits` row.
4. Every txid we broadcast has an `our_txs` row written before the broadcast.
5. A withdrawal that holds money is either `queued`/`approved` (held) or terminal
   (`sent`/`failed`/`rejected`/`cancelled`, released or spent). Never "lost".
6. Deleting a user never changes `sum(balance_sat)` — sweep first, or abandon.

## Cascade behaviour (check before deleting a table or row)

| Child table | On user delete | Consequence |
|---|---|---|
| `addresses` | CASCADE | their deposit addresses disappear — coins sent there later are unattributable |
| `ledger_entries` | CASCADE | the balance history goes; the surviving trail is the `sweep_in` entry plus the audit row |
| `transactions` | CASCADE | history goes |
| `withdrawals` | CASCADE | historical withdrawals go |
| `security_events` | CASCADE | their security log goes |
| `send_quotes`, `faucet_requests` | CASCADE | — |
| `admin_audit.target_user_id` | **SET NULL** | the audit row survives with the denormalised username |
| `alerts.user_id` | **SET NULL** | the alert survives |
| `chain_credits` | via `addresses` CASCADE | deliberate: those credits belong to addresses that no longer exist |
