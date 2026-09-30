"""Chain watcher. Runs as its own container so it can never double-run inside
gunicorn.

    python -m app.sync --loop          # every SYNC_INTERVAL_SECONDS
    python -m app.sync --once          # single pass
"""

import argparse
import logging
import sys
import time

from app import create_app
from app.chain import ChainError
from app.config import Config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("btcwallet.sync")

# Written after every pass. The container healthcheck reads its mtime, which
# proves the watcher is still *making progress* — a plain PID check would pass
# even if the sync loop were wedged.
HEARTBEAT = "/tmp/syncer-heartbeat"


def beat():
    try:
        with open(HEARTBEAT, "w") as fh:
            fh.write(str(int(time.time())))
    except Exception as exc:  # never let monitoring break the watcher
        log.warning("could not write heartbeat: %s", exc)


def network_guard(app):
    """Refuse to watch a chain the wallet's data does not belong to.

    A container created before a network switch keeps the OLD `BTC_NETWORK` in its
    environment (`docker compose restart` does not re-read .env), and it fails
    quietly: every address lookup 400s on the wrong explorer and no deposit is ever
    credited. Seen for real. Alert the operator instead of skipping in silence.
    """
    from app import services

    with app.app_context():
        try:
            pending = services.network_transition_required()
        except Exception as exc:      # a broken check must not kill the watcher
            log.warning("network guard could not run: %s", exc)
            return False
        if not pending:
            return False
        log.critical(
            "WATCHER ON THE WRONG NETWORK: data is %s, this container is configured "
            "for %s. No deposits can be credited. Recreate the container so it "
            "re-reads .env: docker compose stop syncer && docker compose rm -f "
            "syncer && docker compose create syncer && docker compose start syncer",
            pending["recorded"], pending["configured"])
        try:
            services.raise_alert(
                "watcher_network_mismatch",
                "Chain watcher is on the wrong network",
                f"Wallet data is {pending['recorded']} but the watcher is configured "
                f"for {pending['configured']}. Deposits are NOT being credited. "
                f"Recreate the syncer container.", severity="critical")
        except Exception:
            log.exception("could not raise the mismatch alert")
    return True


def one_pass(app):
    from app import services

    if network_guard(app):
        beat()
        return None

    with app.app_context():
        try:
            summary = services.sync_once(verbose=True)
            log.info("sync: tip=%s addresses=%s credited=%s pending=%s",
                     summary["tip"], summary["addresses_checked"],
                     summary["deposits_credited"], summary["pending_seen"])
            return summary
        except ChainError as exc:
            log.warning("sync skipped — explorers unreachable: %s", exc)
        except Exception:
            log.exception("sync pass failed")
        finally:
            # beat even on failure: "reached the network" is the liveness signal
            beat()
    return None


def main():
    parser = argparse.ArgumentParser(description="BTC Vault chain watcher")
    parser.add_argument("--loop", action="store_true", help="run forever")
    parser.add_argument("--once", action="store_true", help="single pass then exit")
    parser.add_argument("--interval", type=int, default=None,
                        help="override the sync interval in seconds")
    args = parser.parse_args()

    app = create_app(Config)
    interval = args.interval or app.config["SYNC_INTERVAL_SECONDS"]

    if args.once or not args.loop:
        one_pass(app)
        _invariant_pass(app)
        return

    log.info("chain watcher starting (interval=%ss, network=%s)",
             interval, app.config["BTC_NETWORK"])
    network_guard(app)
    last_invariant = 0.0
    while True:
        started = time.time()
        one_pass(app)
        # the float invariant is heavier (one API call per address), so check
        # it every 5 minutes rather than every pass
        if time.time() - last_invariant > 300:
            _invariant_pass(app)
            last_invariant = time.time()
        elapsed = time.time() - started
        time.sleep(max(5, interval - elapsed))


def _invariant_pass(app):
    from app import services

    with app.app_context():
        try:
            services.check_invariant()
        except Exception:
            log.exception("invariant check failed")


if __name__ == "__main__":
    main()
