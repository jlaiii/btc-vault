# Generated context

Regenerate with `python scripts/build_agent_docs.py`. Do not edit by hand —
this file is a snapshot of the code at the moment it was generated.

## Routes

| Rule | Methods | Endpoint | Guard |
|---|---|---|---|
| `/` | GET | `views.index` | public |
| `/account` | GET | `views.account` | login_required |
| `/account/logout-all` | POST | `views.logout_all` | active_required |
| `/account/password` | POST | `views.change_password` | active_required |
| `/account/password/required` | GET,POST | `views.force_password_change` | login_required |
| `/account/username` | POST | `views.change_username` | active_required |
| `/activity` | GET | `views.activity` | login_required |
| `/activity/<int:tx_id>` | GET | `views.activity_detail` | login_required |
| `/admin/` | GET | `admin.index` | admin_required |
| `/admin/alerts` | GET | `admin.alerts` | admin_required |
| `/admin/alerts/<int:aid>/ack` | POST | `admin.alert_ack` | admin_required |
| `/admin/alerts/ack-all` | POST | `admin.alerts_ack_all` | admin_required |
| `/admin/audit` | GET | `admin.audit_log` | admin_required |
| `/admin/export/<what>.csv` | GET | `admin.export_csv` | admin_required |
| `/admin/ledger` | GET | `admin.ledger` | admin_required |
| `/admin/settings` | GET,POST | `admin.settings` | admin_required |
| `/admin/transactions` | GET | `admin.transactions` | admin_required |
| `/admin/users` | GET | `admin.users` | admin_required |
| `/admin/users/<int:uid>` | GET | `admin.user_detail` | admin_required |
| `/admin/users/<int:uid>/balance` | POST | `admin.user_balance` | admin_required |
| `/admin/users/<int:uid>/delete` | POST | `admin.user_delete` | admin_required |
| `/admin/users/<int:uid>/notes` | POST | `admin.user_notes` | admin_required |
| `/admin/users/<int:uid>/password` | POST | `admin.user_password` | admin_required |
| `/admin/users/<int:uid>/role` | POST | `admin.user_role` | admin_required |
| `/admin/users/<int:uid>/security` | POST | `admin.user_security` | admin_required |
| `/admin/users/<int:uid>/status` | POST | `admin.user_status` | admin_required |
| `/admin/users/<int:uid>/sweep` | POST | `admin.user_sweep` | admin_required |
| `/admin/users/<int:uid>/totp` | POST | `admin.user_totp_reset` | admin_required |
| `/admin/wallet` | GET | `admin.wallet` | admin_required |
| `/admin/wallet/seed` | POST | `admin.wallet_seed` | admin_required |
| `/admin/wallet/sync` | POST | `admin.wallet_sync` | admin_required |
| `/admin/withdrawals` | GET | `admin.withdrawals` | admin_required |
| `/admin/withdrawals/<int:wid>/decide` | POST | `admin.withdrawal_decide` | admin_required |
| `/confirm` | GET,POST | `auth.confirm` | public |
| `/faucet` | POST | `views.faucet_request` | active_required |
| `/health` | GET | `views.health` | public |
| `/login` | GET,POST | `auth.login` | public |
| `/login/2fa` | GET,POST | `auth.login_2fa` | public |
| `/logout` | POST | `auth.logout` | public |
| `/receive` | GET | `views.receive` | login_required |
| `/receive/new` | POST | `views.new_address` | active_required |
| `/receive/qr/<int:address_id>` | GET | `views.address_qr` | login_required |
| `/reset` | GET,POST | `auth.reset_request` | public |
| `/reset/<token>` | GET,POST | `auth.reset_do` | public |
| `/security` | GET | `views.security` | login_required |
| `/security/2fa` | GET,POST | `auth.setup_2fa` | public |
| `/security/2fa/backup-codes` | POST | `auth.regenerate_backup_codes` | public |
| `/security/2fa/disable` | POST | `auth.disable_2fa` | public |
| `/security/sessions` | POST | `views.kill_other_sessions` | active_required |
| `/send` | GET | `views.send` | login_required |
| `/send/confirm/<int:quote_id>` | POST | `views.send_confirm` | active_required |
| `/send/quote` | POST | `views.send_quote` | active_required |
| `/send/review/<int:quote_id>` | GET | `views.send_review` | login_required |
| `/signup` | GET,POST | `auth.signup` | public |
| `/wallet` | GET | `views.dashboard` | login_required |

## Tables

### `addresses`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `user_id` | INTEGER → users.id | no |  |
| `idx` | INTEGER | no |  |
| `address` | VARCHAR(90) | no |  |
| `label` | VARCHAR(64) | yes |  |
| `is_primary` | BOOLEAN | no | False |
| `created_at` | DATETIME | no | <function _now at 0x77778e9cfd80> |
| `last_activity_at` | DATETIME | yes |  |
- index `ix_addresses_address` on (address)
- index `ix_addresses_user_id` on (user_id)
- unique `None` on (idx)

### `admin_audit`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `admin_id` | INTEGER → users.id | yes |  |
| `admin_username` | VARCHAR(32) | yes |  |
| `target_user_id` | INTEGER → users.id | yes |  |
| `target_username` | VARCHAR(32) | yes |  |
| `action` | VARCHAR(48) | no |  |
| `detail` | TEXT | yes |  |
| `ip` | VARCHAR(45) | yes |  |
| `created_at` | DATETIME | no | <function _now at 0x77778e5437e0> |
- index `ix_admin_audit_target_user_id` on (target_user_id)
- index `ix_admin_audit_action` on (action)

### `alerts`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `kind` | VARCHAR(32) | no |  |
| `severity` | VARCHAR(12) | no | warning |
| `user_id` | INTEGER → users.id | yes |  |
| `username` | VARCHAR(32) | yes |  |
| `title` | VARCHAR(160) | no |  |
| `body` | TEXT | yes |  |
| `created_at` | DATETIME | no | <function _now at 0x77778e571940> |
| `ack_at` | DATETIME | yes |  |
| `ack_by` | INTEGER → users.id | yes |  |
- index `ix_alerts_kind` on (kind)

### `chain_credits`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `txid` | VARCHAR(64) | no |  |
| `vout` | INTEGER | no |  |
| `address_id` | INTEGER → addresses.id | no |  |
| `value_sat` | BIGINT | no |  |
| `ledger_id` | INTEGER → ledger_entries.id | yes |  |
| `block_height` | INTEGER | yes |  |
| `credited_at` | DATETIME | no | <function _now at 0x77778e541d00> |
- unique `uq_chain_credit_outpoint` on (txid, vout)

### `faucet_requests`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `user_id` | INTEGER → users.id | no |  |
| `txid` | VARCHAR(64) | yes |  |
| `amount_sat` | BIGINT | yes |  |
| `status` | VARCHAR(16) | no | queued |
| `error` | TEXT | yes |  |
| `ip` | VARCHAR(45) | yes |  |
| `created_at` | DATETIME | no | <function _now at 0x77778e59a020> |
- index `ix_faucet_requests_user_id` on (user_id)

### `ledger_entries`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `user_id` | INTEGER → users.id | no |  |
| `delta_sat` | BIGINT | no |  |
| `balance_after_sat` | BIGINT | no |  |
| `kind` | VARCHAR(24) | no |  |
| `ref` | VARCHAR(128) | yes |  |
| `note` | TEXT | yes |  |
| `created_by` | INTEGER → users.id | yes |  |
| `created_at` | DATETIME | no | <function _now at 0x77778e508fe0> |
- index `ix_ledger_entries_kind` on (kind)
- index `ix_ledger_entries_user_id` on (user_id)
- index `ix_ledger_user_created` on (user_id, created_at)

### `our_txs`

| Column | Type | Null | Default |
|---|---|---|---|
| `txid` | VARCHAR(64) | no |  |
| `user_id` | INTEGER → users.id | yes |  |
| `kind` | VARCHAR(16) | no | withdrawal |
| `created_at` | DATETIME | no | <function _now at 0x77778e542ac0> |

### `password_resets`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `user_id` | INTEGER → users.id | no |  |
| `token_hash` | VARCHAR(64) | no |  |
| `expires_at` | DATETIME | no |  |
| `used_at` | DATETIME | yes |  |
| `ip` | VARCHAR(45) | yes |  |
| `created_at` | DATETIME | no | <function _now at 0x77778e573560> |
- index `ix_password_resets_user_id` on (user_id)
- index `ix_password_resets_token_hash` on (token_hash)

### `security_events`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `user_id` | INTEGER → users.id | yes |  |
| `username` | VARCHAR(64) | yes |  |
| `kind` | VARCHAR(32) | no |  |
| `success` | BOOLEAN | no | True |
| `ip` | VARCHAR(45) | yes |  |
| `user_agent` | VARCHAR(255) | yes |  |
| `detail` | TEXT | yes |  |
| `created_at` | DATETIME | no | <function _now at 0x77778e5709a0> |
- index `ix_security_events_created_at` on (created_at)
- index `ix_security_events_user_id` on (user_id)

### `send_quotes`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `user_id` | INTEGER → users.id | no |  |
| `payload` | JSONB | no |  |
| `created_at` | DATETIME | no | <function _now at 0x77778e5985e0> |
| `used_at` | DATETIME | yes |  |
- index `ix_send_quotes_user_id` on (user_id)

### `settings`

| Column | Type | Null | Default |
|---|---|---|---|
| `key` | VARCHAR(64) | no |  |
| `value` | TEXT | yes |  |
| `updated_at` | DATETIME | no | <function _now at 0x77778e572980> |

### `throttles`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `bucket` | VARCHAR(96) | no |  |
| `created_at` | DATETIME | no | <function _now at 0x77778e5993a0> |
- index `ix_throttles_created_at` on (created_at)
- index `ix_throttles_bucket` on (bucket)

### `transactions`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `user_id` | INTEGER → users.id | no |  |
| `category` | VARCHAR(24) | no |  |
| `direction` | VARCHAR(8) | no |  |
| `status` | VARCHAR(16) | no | pending |
| `amount_sat` | BIGINT | no |  |
| `service_fee_sat` | BIGINT | no | 0 |
| `network_fee_sat` | BIGINT | no | 0 |
| `total_sat` | BIGINT | no | 0 |
| `txid` | VARCHAR(64) | yes |  |
| `vout` | INTEGER | yes |  |
| `address` | VARCHAR(90) | yes |  |
| `confirmations` | INTEGER | no | 0 |
| `block_height` | INTEGER | yes |  |
| `fee_rate` | INTEGER | yes |  |
| `priority` | VARCHAR(12) | yes |  |
| `label` | VARCHAR(120) | yes |  |
| `note` | TEXT | yes |  |
| `raw_hex` | TEXT | yes |  |
| `withdrawal_id` | INTEGER → withdrawals.id | yes |  |
| `created_by` | INTEGER → users.id | yes |  |
| `created_at` | DATETIME | no | <function _now at 0x77778e50a5c0> |
| `confirmed_at` | DATETIME | yes |  |
- index `ix_transactions_txid` on (txid)
- index `ix_transactions_user_id` on (user_id)
- index `ix_tx_user_created` on (user_id, created_at)
- index `ix_transactions_status` on (status)

### `users`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `username` | VARCHAR(32) | no |  |
| `email` | VARCHAR(255) | yes |  |
| `password_hash` | VARCHAR(255) | no |  |
| `role` | VARCHAR(16) | no | user |
| `status` | VARCHAR(16) | no | active |
| `balance_sat` | BIGINT | no | 0 |
| `negative_balance` | BOOLEAN | no | False |
| `next_address_index` | INTEGER | no | 0 |
| `created_at` | DATETIME | no | <function _now at 0x77778e9cc7c0> |
| `last_login_at` | DATETIME | yes |  |
| `last_login_ip` | VARCHAR(45) | yes |  |
| `signup_ip` | VARCHAR(45) | yes |  |
| `session_version` | INTEGER | no | 0 |
| `totp_secret_enc` | TEXT | yes |  |
| `totp_enabled` | BOOLEAN | no | False |
| `totp_confirmed_at` | DATETIME | yes |  |
| `totp_last_step` | BIGINT | yes |  |
| `backup_codes_json` | TEXT | yes |  |
| `require_2fa` | BOOLEAN | no | False |
| `must_change_password` | BOOLEAN | no | False |
| `failed_logins` | INTEGER | no | 0 |
| `locked_until` | DATETIME | yes |  |
| `notes` | TEXT | yes |  |
| `deleted_at` | DATETIME | yes |  |
- index `ix_users_email` on (email)
- index `ix_users_username` on (username)

### `withdrawals`

| Column | Type | Null | Default |
|---|---|---|---|
| `id` | INTEGER | no |  |
| `user_id` | INTEGER → users.id | no |  |
| `address` | VARCHAR(90) | no |  |
| `amount_sat` | BIGINT | no |  |
| `service_fee_sat` | BIGINT | no | 0 |
| `network_fee_sat` | BIGINT | no | 0 |
| `total_sat` | BIGINT | no |  |
| `fee_rate` | INTEGER | yes |  |
| `priority` | VARCHAR(12) | yes |  |
| `vsize_est` | INTEGER | yes |  |
| `status` | VARCHAR(16) | no | queued |
| `txid` | VARCHAR(64) | yes |  |
| `raw_hex` | TEXT | yes |  |
| `error` | TEXT | yes |  |
| `quote_json` | JSONB | yes |  |
| `note` | TEXT | yes |  |
| `created_at` | DATETIME | no | <function _now at 0x77778e5400e0> |
| `decided_at` | DATETIME | yes |  |
| `decided_by` | INTEGER → users.id | yes |  |
| `broadcast_at` | DATETIME | yes |  |
- index `ix_withdrawals_user_id` on (user_id)
- index `ix_withdrawals_txid` on (txid)
- index `ix_wd_status_created` on (status, created_at)
- index `ix_withdrawals_status` on (status)

## Admin-editable settings

| Key | Current value | Label |
|---|---|---|
| `service_fee_pct` | `0.5` | Service fee (%) |
| `service_fee_min_sat` | `0` | Minimum service fee (sats) |
| `instant_send_max_sat` | `50000` | Auto-send limit (sats) |
| `withdraw_min_sat` | `10000` | Minimum withdrawal (sats) |
| `withdraw_daily_max_sat` | `5000000` | Daily withdrawal cap (sats) |
| `min_confirmations` | `2` | Deposit confirmations |
| `signups_enabled` | `1` | Signups open |
| `deposits_enabled` | `1` | Deposits enabled |
| `withdrawals_enabled` | `1` | Withdrawals enabled |
| `net_fee_passthrough` | `1` | Charge miner fee to user |
| `maintenance_message` | `` | Maintenance banner |
| `testnet_faucet_enabled` | `0` | Testnet faucet |
| `testnet_faucet_amount_sat` | `100000` | Faucet amount (sats) |
| `testnet_faucet_cooldown_hours` | `6` | Faucet cooldown (hours) |

Network: `mainnet`

## Environment variables

| Variable | Fallback default in code |
|---|---|
| `BTC_NETWORK` | `testnet` |
| `ESPLORA_URLS` | `` |
| `MAIL_FROM` | `vault@example.com` |
| `MAIL_HOST` | `host.docker.internal` |
| `MASTER_KEY_FILE` | `/run/secrets/master.key` |
| `SECRET_KEY` | `dev-secret-change-me` |
| `SEED_BACKUP_FILE` | `/run/secrets/HOTWALLET_MNEMONIC.txt` |
| `SERVICE_FEE_PCT` | `0.5` |
| `SITE_NAME` | `Vault` |
| `SITE_URL` | `http://localhost:8810` |
