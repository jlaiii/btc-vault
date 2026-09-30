"""Blockchain data via Esplora-compatible REST APIs.

We deliberately do not run a full node here: Esplora gives us UTXOs, fee
estimates, tx status and broadcast over plain HTTPS, with a second provider
for failover. Providers are interchangeable (mempool.space, blockstream.info).

Reads try each provider in order. Broadcast is special: a tx that was accepted
by one provider must not be re-broadcast as "failed" just because a second
provider was unreachable, so we stop at the first success and only report
failure when every provider actively rejects the transaction.
"""

import logging
import math
import time

import requests

log = logging.getLogger("btcwallet.chain")

# Per-request timeout. Deliberately short: these calls sit on the critical path
# of a page render, so a misbehaving explorer must fail fast and let the
# caller fall back to cached or default values.
TIMEOUT = 8
# One attempt per provider; failing over to the next provider IS the retry.
RETRIES_PER_PROVIDER = 1


def default_esplora_urls(network: str):
    if network == "mainnet":
        return ["https://mempool.space/api", "https://blockstream.info/api"]
    return ["https://mempool.space/testnet/api", "https://blockstream.info/testnet/api"]


class ChainError(RuntimeError):
    pass


class BroadcastRejected(ChainError):
    """Every provider actively refused the transaction (bad sig, double spend)."""


class EsploraClient:
    def __init__(self, urls=None, network="testnet"):
        self.urls = list(urls) if urls else default_esplora_urls(network)
        if not self.urls:
            raise ChainError("No explorer endpoints configured.")
        self.http = requests.Session()
        self.http.headers.update({"User-Agent": "btcwallet/1.0"})

    # ------------------------------------------------------------- plumbing
    def _get(self, path: str, timeout: int = TIMEOUT):
        last = None
        for base in self.urls:
            for attempt in range(RETRIES_PER_PROVIDER):
                try:
                    r = self.http.get(base + path, timeout=timeout)
                    if r.status_code == 200:
                        return r
                    if r.status_code == 404:
                        return r          # genuine "not found", not a failure
                    last = f"{base}{path} -> HTTP {r.status_code}"
                except Exception as exc:
                    last = f"{base}{path} -> {exc}"
                time.sleep(0.4 * (attempt + 1))
        raise ChainError(f"All explorers failed. Last error: {last}")

    def _get_json(self, path: str, default=None, timeout: int = None):
        r = self._get(path, timeout=timeout or TIMEOUT)
        if r.status_code == 404:
            return default
        try:
            return r.json()
        except Exception as exc:
            raise ChainError(f"Explorer returned non-JSON for {path}") from exc

    # ------------------------------------------------------------ read API
    def tip_height(self):
        r = self._get("/blocks/tip/height")
        try:
            return int(r.text.strip())
        except Exception as exc:
            raise ChainError("Could not read chain tip height.") from exc

    def fee_estimates(self, timeout: int = 6):
        """{"1": 22.0, "2": 15.1, ...} sat/vB keyed by confirmation target.

        Short timeout on purpose: fee tiers are displayed on the dashboard, and
        a slow fee oracle must not hold a page open.
        """
        data = self._get_json("/fee-estimates", default={}, timeout=timeout) or {}
        out = {}
        for key, value in data.items():
            try:
                out[int(key)] = float(value)
            except (TypeError, ValueError):
                continue
        return out

    def all_fee_estimates(self, timeout: int = 6):
        """Every provider's fee map that answers, in configured order.

        Used to cross-check providers rather than trusting whichever one
        happened to respond — see blend_fee_tiers().
        """
        out = []
        for base in self.urls:
            try:
                r = self.http.get(base + "/fee-estimates", timeout=timeout)
                if r.status_code != 200:
                    continue
                data = r.json()
            except Exception:
                continue
            est = {}
            for key, value in (data or {}).items():
                try:
                    est[int(key)] = float(value)
                except (TypeError, ValueError):
                    continue
            if est:
                out.append({"url": base, "estimates": est})
        return out

    def address_stats(self, address: str):
        return self._get_json(f"/address/{address}", default=None)

    def address_utxos(self, address: str):
        return self._get_json(f"/address/{address}/utxo", default=[]) or []

    def address_txs(self, address: str):
        """Most recent transactions touching this address (one page)."""
        return self._get_json(f"/address/{address}/txs", default=[]) or []

    def tx(self, txid: str):
        return self._get_json(f"/tx/{txid}", default=None)

    def tx_status(self, txid: str):
        data = self._get_json(f"/tx/{txid}/status", default=None)
        return data

    def outspend(self, txid: str, vout: int):
        return self._get_json(f"/tx/{txid}/outspend/{vout}", default=None)

    # --------------------------------------------------------- write path
    def broadcast(self, raw_hex: str):
        """Push a signed tx. Returns the txid on success.

        A 400 from a provider means it examined the tx and refused it (bad
        signature, missing inputs, already spent). If that happens everywhere
        the tx is genuinely bad, so we surface the provider's message — it
        tells the admin exactly why.
        """
        reasons = []
        for base in self.urls:
            try:
                r = self.http.post(
                    base + "/tx", data=raw_hex.encode(),
                    headers={"Content-Type": "text/plain"}, timeout=TIMEOUT,
                )
            except Exception as exc:
                reasons.append(f"{base}: {exc}")
                continue
            body = (r.text or "").strip()
            if r.status_code == 200 and len(body) == 64:
                return body
            # "already in mempool / already confirmed" is a SUCCESS for us
            low = body.lower()
            if r.status_code == 400 and ("already" in low or "txn-already" in low):
                try:
                    return _txid_from_hex(raw_hex)
                except Exception:
                    reasons.append(f"{base}: already known ({body[:80]})")
                    continue
            reasons.append(f"{base}: HTTP {r.status_code} {body[:120]}")
        raise BroadcastRejected("; ".join(reasons) or "broadcast failed")


def _txid_from_hex(raw_hex: str) -> str:
    from embit.transaction import Transaction

    return Transaction.parse(bytes.fromhex(raw_hex)).txid().hex()


# --------------------------------------------------------------- fee policy
PRIORITY_TARGETS = {"fast": 1, "normal": 3, "economy": 6}
PRIORITY_LABELS = {
    "fast": "Fast",
    "normal": "Normal",
    "economy": "Economy",
}
PRIORITY_BLURBS = {
    "fast": "Next block (~10 min)",
    "normal": "A few blocks (~30 min)",
    "economy": "Within an hour or so",
}


# Disagreement ratio at which we stop trusting the primary provider. Different
# explorers run different estimators and sometimes return nonsense — blockstream
# was observed returning an identical 264 sat/vB for every target while
# mempool.space correctly reported 1 sat/vB on the same (empty) testnet mempool.
# A 4x spread means one of them is wrong, and guessing wrong upward costs the
# user real money, so we deflect downward.
FEE_OUTLIER_RATIO = 4.0

# No tier may cost more than this many times the provider's own cheapest
# reported rate. See pick_fee_rates() for why. 16x is deliberately loose enough
# to preserve a genuine congestion spread (e.g. 120 sat/vB next-block vs
# 8 sat/vB eventually) while still rejecting a coarse estimator that reports
# hundreds of sat/vB against its own 1 sat/vB long-horizon rate.
FEE_ANCHOR_MULTIPLE = 16


def blend_fee_tiers(provider_estimates, min_rate, max_rate, fallbacks):
    """Turn several providers' fee maps into one trustworthy tier set.

    Overpaying is an immediate, unrecoverable loss to the user. Underpaying is
    recoverable: our inputs are RBF-enabled (sequence 0xfffffffd) and a
    low-fee transaction still confirms once the mempool clears. So when
    providers disagree materially we take the LOWER rate rather than averaging
    or trusting the first responder.
    """
    per_provider = []
    for entry in provider_estimates:
        if entry.get("estimates"):
            per_provider.append(
                pick_fee_rates(entry["estimates"], min_rate, max_rate, fallbacks)
            )
    if not per_provider:
        return pick_fee_rates({}, min_rate, max_rate, fallbacks)

    tiers = {}
    for tier in PRIORITY_TARGETS:
        values = [t[tier] for t in per_provider if tier in t]
        if not values:
            continue
        primary = values[0]              # configured order = preference order
        lowest = min(values)
        # Any >=4x disagreement resolves DOWNWARD, regardless of which provider
        # is high: underpaying is recoverable (RBF + it confirms eventually),
        # overpaying is money gone.
        if lowest > 0 and primary > 0 and (primary / lowest) >= FEE_OUTLIER_RATIO:
            chosen = lowest
        else:
            chosen = primary
        tiers[tier] = int(max(min_rate, min(max_rate, chosen)))
    tiers["normal"] = max(tiers["normal"], min_rate)
    tiers["fast"] = max(tiers["fast"], tiers["normal"])
    tiers["economy"] = min(tiers["economy"], tiers["normal"])
    return tiers


def pick_fee_rates(estimates: dict, min_rate: int, max_rate: int, fallbacks: dict,
                   anchor_multiple: int = None):
    """Turn an Esplora fee-estimate map into our three user-facing tiers.

    For each tier we take the estimate for its target, falling back to the next
    available target (an explorer under light load may not return every key),
    then to a static default if the oracle is unreachable entirely.

    Then a self-consistency anchor is applied: no tier may cost more than
    ``FEE_ANCHOR_MULTIPLE`` times the cheapest rate the SAME provider reports
    for any horizon. This matters because some estimators are coarse — one was
    observed reporting 264 sat/vB for targets 1 and 6 while reporting
    1.012 sat/vB for targets 19-24 on an essentially empty mempool. A provider
    that believes 1 sat/vB will confirm within hours cannot justify 264 to save
    a few blocks, and quietly paying that would cost the user real money.
    """
    anchor_multiple = anchor_multiple or FEE_ANCHOR_MULTIPLE
    out = {}
    for tier, target in PRIORITY_TARGETS.items():
        rate = None
        if estimates:
            # exact target, then progressively wider targets
            for cand in (target, target + 1, target + 2, target + 3, 2, 1):
                if cand in estimates:
                    rate = estimates[cand]
                    break
            if rate is None and estimates:
                rate = min(estimates.values())
        if rate is None:
            rate = fallbacks.get(tier, 5)
        out[tier] = int(max(min_rate, min(max_rate, round(float(rate)))))

    # anchor to the provider's own cheapest horizon
    if estimates:
        positive = [v for v in estimates.values() if v and v > 0]
        if positive:
            cap = max(min_rate, math.ceil(min(positive) * anchor_multiple))
            for tier in out:
                out[tier] = max(min_rate, min(out[tier], cap))

    # never let a slow tier be cheaper than the relay floor
    out["normal"] = max(out["normal"], min_rate)
    out["fast"] = max(out["fast"], out["normal"])
    out["economy"] = min(out["economy"], out["normal"])
    return out
