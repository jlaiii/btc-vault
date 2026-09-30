"""Bitcoin engine: HD derivation, address validation, coin selection,
fee calculation and transaction signing.

Every constant here was verified against a real signature check before being
written down (see scripts/verify_crypto.py). Two things that are easy to get
wrong and are handled explicitly:

1. embit 0.8 has NO psbt.finalize(). ``PSBT.sign_with()`` only fills
   ``partial_sigs``. The witness must be assembled by hand from
   ``partial_sigs[pubkey]`` — otherwise the serialized tx carries no witness
   and the network rejects it.

2. For a segwit tx, ``len(raw_bytes)`` is NOT the vsize. weight =
   base_size*3 + total_size, vsize = ceil(weight/4). Using the raw length
   overpays fees by ~35%.
"""

import math
from dataclasses import dataclass

from embit import bip32, bip39, script
from embit.networks import NETWORKS
from embit.psbt import PSBT, DerivationPath
from embit.transaction import (
    SIGHASH,
    Transaction,
    TransactionInput,
    TransactionOutput,
    Witness,
)

SATS = 100_000_000

# ---------------------------------------------------------------- constants
# script type -> serialized output size in bytes (8 value + 1 len + script)
OUTPUT_SCRIPT_SIZES = {
    "p2pkh": 25,
    "p2sh": 23,
    "p2wpkh": 22,
    "p2wsh": 34,
    "p2tr": 34,
}

# standard dust thresholds (sats) — an output below this is uneconomic to spend
DUST_LIMIT = {
    "p2pkh": 546,
    "p2sh": 540,
    "p2wpkh": 294,
    "p2wsh": 330,
    "p2tr": 330,
}
DEFAULT_DUST = 294

# conservative per-input witness footprint for a native segwit spend:
#   1 (item count) + 1+72 (DER sig + sighash byte) + 1+33 (compressed pubkey)
WITNESS_PER_INPUT = 108
# version + locktime. The input/output COUNT bytes are varints added per-tx
# below — they must not be baked in here or they get double-counted.
BASE_TX_OVERHEAD = 4 + 4
BASE_INPUT_BYTES = 36 + 1 + 4     # outpoint + empty scriptSig length + sequence
WITNESS_MARKER_FLAG = 2


class BitcoinError(ValueError):
    """Any user-facing problem building or validating a transaction."""


# ------------------------------------------------------------------ network
class Network:
    def __init__(self, name: str):
        self.name = name
        coin = 1 if name == "testnet" else 0
        self.coin_type = coin
        self.embit_net = NETWORKS["test" if coin == 1 else "main"]
        self.purpose = 84  # BIP84 → native segwit (bech32) addresses
        self.hrp = "tb1" if coin == 1 else "bc1"
        self.explorer_prefix = "testnet/" if coin == 1 else ""

    def path_str(self, index: int) -> str:
        return f"m/{self.purpose}'/{self.coin_type}'/0'/0/{index}"

    def path_ints(self, index: int) -> list:
        h = 0x80000000
        return [self.purpose | h, self.coin_type | h, 0 | h, 0, index]

    def __repr__(self):
        return f"<Network {self.name}>"


def get_network(name: str) -> Network:
    return Network("mainnet" if str(name).lower() == "mainnet" else "testnet")


def address_network(addr: str):
    """Best-effort network of a literal address. Returns 'mainnet'/'testnet'/None."""
    a = (addr or "").strip()
    low = a.lower()
    if low.startswith("bc1") or low.startswith("bcrt1"):
        return "mainnet" if low.startswith("bc1") else "testnet"
    if low.startswith("tb1"):
        return "testnet"
    if a[:1] in ("1", "3"):
        return "mainnet"
    if a[:1] in ("m", "n", "2"):
        return "testnet"
    return None


# ------------------------------------------------------------- derivation
@dataclass
class DerivedAddress:
    index: int
    path: str
    address: str
    script: object          # embit Script (the scriptPubKey)
    pubkey: object          # embit PublicKey
    private_key: object     # embit PrivateKey


def derive_address(root_key, net: Network, index: int) -> DerivedAddress:
    child = root_key.derive(net.path_str(index))
    spk = script.p2wpkh(child.key)
    return DerivedAddress(
        index=index,
        path=net.path_str(index),
        address=spk.address(net.embit_net),
        script=spk,
        pubkey=child.key.get_public_key(),
        private_key=child.key,
    )


def root_from_mnemonic(mnemonic: str, net: Network):
    seed = bip39.mnemonic_to_seed(mnemonic.strip())
    return bip32.HDKey.from_seed(seed, version=net.embit_net["xprv"])


def mnemonic_is_valid(mnemonic: str) -> bool:
    try:
        return bool(bip39.mnemonic_is_valid(mnemonic.strip()))
    except Exception:
        return False


def generate_mnemonic(words: int = 24) -> str:
    import secrets as pysecrets

    entropy_bytes = 32 if words == 24 else 16
    return bip39.mnemonic_from_bytes(pysecrets.token_bytes(entropy_bytes))


# -------------------------------------------------------- input validation
def validate_destination(addr: str, net: Network):
    """Parse an address, verify its checksum AND that it belongs to our
    network. Returns (canonical_address, script, script_type).

    Sending testnet coins to a mainnet address (or vice versa) destroys them,
    so a network mismatch is a hard error, not a warning.
    """
    addr = (addr or "").strip()
    if not addr:
        raise BitcoinError("Enter a destination address.")
    if len(addr) > 90:
        raise BitcoinError("That address is too long to be valid.")
    if any(c.isspace() for c in addr):
        raise BitcoinError("Addresses cannot contain spaces.")

    try:
        spk = script.Script.from_address(addr)
    except Exception as exc:
        raise BitcoinError(
            "That is not a valid Bitcoin address (checksum failed). "
            "Copy it again from the sending wallet."
        ) from exc
    if spk is None:
        raise BitcoinError("That is not a valid Bitcoin address.")

    found = address_network(addr)
    if found is None:
        raise BitcoinError("Unrecognised address format.")
    if found != net.name:
        raise BitcoinError(
            f"That is a {found} address but this wallet is on {net.name}. "
            f"Sending across networks would permanently lose the funds."
        )

    stype = spk.script_type()
    if stype not in OUTPUT_SCRIPT_SIZES:
        raise BitcoinError(f"Unsupported address type: {stype}.")
    # bech32 addresses must be single-case
    if addr != addr.lower() and addr != addr.upper():
        raise BitcoinError("Mixed-case bech32 address — copy it again exactly.")
    canonical = addr.lower() if addr.lower().startswith(("bc1", "tb1")) else addr
    return canonical, spk, stype


def dust_limit_for(script_type: str) -> int:
    return DUST_LIMIT.get(script_type, DEFAULT_DUST)


# ------------------------------------------------------------ fee / sizing
def varint_size(n: int) -> int:
    if n < 0xFD:
        return 1
    if n <= 0xFFFF:
        return 3
    if n <= 0xFFFFFFFF:
        return 5
    return 9


def estimate_vsize(n_inputs: int, output_script_types) -> int:
    """Predict vsize for a tx with n P2WPKH inputs and the given outputs.

    Exact model, verified against real signed transactions:
      1-in/2-out  = 141 vB   (industry-standard figure for native segwit)
      2-in/2-out  = 209 vB
    """
    n_out = len(output_script_types)
    base = BASE_TX_OVERHEAD
    base += varint_size(n_inputs) + n_inputs * BASE_INPUT_BYTES
    base += varint_size(n_out)
    for stype in output_script_types:
        base += 8 + 1 + OUTPUT_SCRIPT_SIZES.get(stype, 22)
    witness = WITNESS_MARKER_FLAG + n_inputs * WITNESS_PER_INPUT
    weight = base * 4 + witness
    return math.ceil(weight / 4)


def exact_vsize(tx: Transaction) -> int:
    """Exact vsize of a *signed* tx: weight = base*3 + total.

    Temporarily replacing each witness with an EMPTY one makes embit omit the
    segwit marker/flag and serialize the bare base transaction (setting it to
    None instead crashes: embit's is_segwit calls witness.serialize()). The
    marker/flag bytes and all witness data count at weight 1, which is exactly
    what base*3 + total accounts for.
    """
    saved = [vin.witness for vin in tx.vin]
    for vin in tx.vin:
        vin.witness = Witness([])
    base = len(tx.serialize())
    for vin, wit in zip(tx.vin, saved):
        vin.witness = wit
    total = len(tx.serialize())
    return math.ceil((base * 3 + total) / 4)


# ------------------------------------------------------- coin selection
@dataclass
class Utxo:
    txid: str
    vout: int
    value_sat: int
    address: str
    script: object      # embit Script (scriptPubKey we can spend)
    index: int          # derivation index, needed to sign
    pubkey: object      # embit PublicKey for the PSBT derivation
    confirmed: bool = True


def select_coins(utxos, target_sat: int, output_types, fee_rate: int, max_inputs: int = 60):
    """Largest-first selection.

    Grows the input set until the selected value covers the target PLUS the
    network fee for that many inputs, since each input makes the tx bigger and
    therefore more expensive. Returns (selected, fee_sat, vsize).
    """
    candidates = sorted(utxos, key=lambda u: u.value_sat, reverse=True)
    selected = []
    total = 0
    for utxo in candidates:
        selected.append(utxo)
        total += utxo.value_sat
        vsize = estimate_vsize(len(selected), output_types)
        fee = math.ceil(vsize * fee_rate)
        if total >= target_sat + fee:
            return selected, fee, vsize
        if len(selected) >= max_inputs:
            break
    # not enough: report what we'd need
    vsize = estimate_vsize(max(1, len(selected)), output_types)
    fee = math.ceil(vsize * fee_rate)
    raise BitcoinError(
        f"Not enough spendable on-chain funds. Available {total} sats, "
        f"needed {target_sat + fee} sats."
    )


# ------------------------------------------------------------ build + sign
def build_signed_tx(
    root_key,
    net: Network,
    utxos,
    outputs,
    fee_rate: int,
    change_index: int,
    target_fee_sat: int,
):
    """Build, sign and finalize. Returns dict(raw_hex, txid, vsize, fee_sat,
    change_sat, change_address).

    ``outputs`` is a list of (value_sat, destination_script). The change output
    is added automatically and adjusted so the achieved fee rate meets the
    target — never rounding up to a materially higher fee than the user picked.
    """
    if not utxos:
        raise BitcoinError("No inputs available.")

    # outputs: list of (value_sat, script, script_type)
    dest_total = sum(v for v, _s, _t in outputs)
    input_total = sum(u.value_sat for u in utxos)
    if input_total <= dest_total:
        raise BitcoinError("Inputs do not cover the outputs.")

    # change returns to the user's own derived address for this index
    change = derive_address(root_key, net, change_index)

    # size the tx WITH a change output; if the change would be dust we drop the
    # output and the remainder becomes extra miner fee
    types_with = [t for _v, _s, t in outputs] + ["p2wpkh"]
    fee_with = math.ceil(estimate_vsize(len(utxos), types_with) * fee_rate)
    change_sat = input_total - dest_total - fee_with
    include_change = change_sat >= dust_limit_for("p2wpkh")

    if include_change:
        final_outputs = [(v, s) for v, s, _t in outputs] + [(change_sat, change.script)]
    else:
        final_outputs = [(v, s) for v, s, _t in outputs]
        change_sat = 0

    # --- build
    # NOTE: embit's TransactionInput.txid is in the SAME byte order as the
    # txid hex string shown by block explorers (verified against a real
    # on-chain transaction: parsing a tx and reading vin[0].txid.hex() returns
    # the parent's display txid unchanged). Reversing it here produces a
    # syntactically valid but unspendable transaction, which the network
    # rejects with "bad-txns-inputs-missingorspent".
    tx = Transaction(
        version=2,
        vin=[TransactionInput(bytes.fromhex(u.txid), u.vout, sequence=0xFFFFFFFD)
             for u in utxos],
        vout=[TransactionOutput(value, spk) for value, spk in final_outputs],
    )

    psbt = PSBT(tx)
    for i, u in enumerate(utxos):
        inp = psbt.inputs[i]
        inp.witness_utxo = TransactionOutput(u.value_sat, u.script)
        inp.bip32_derivations[u.pubkey] = DerivationPath(
            root_key.my_fingerprint, net.path_ints(u.index)
        )

    signed = psbt.sign_with(root_key)
    if signed != len(utxos):
        raise BitcoinError(
            f"Signing failed: {signed} of {len(utxos)} inputs signed. "
            f"Aborting without broadcasting."
        )

    # --- finalize by hand (embit 0.8 has no finalize step)
    for i, u in enumerate(utxos):
        sig = psbt.inputs[i].partial_sigs.get(u.pubkey)
        if sig is None:
            raise BitcoinError(f"Missing signature for input {i}. Aborting.")
        tx.vin[i].witness = Witness([sig, u.pubkey.sec()])

    vsize = exact_vsize(tx)
    actual_fee = input_total - sum(v for v, _ in final_outputs)
    raw_hex = tx.serialize().hex()

    # --- sanity: never broadcast something absurd
    if actual_fee < 0:
        raise BitcoinError("Internal error: negative fee.")
    if actual_fee > max(target_fee_sat * 4, 200_000 + target_fee_sat):
        raise BitcoinError(
            f"Refusing to broadcast: fee {actual_fee} sats is unreasonably high."
        )
    achieved = actual_fee / max(1, vsize)
    if achieved < fee_rate * 0.85:
        raise BitcoinError(
            f"Could not reach the requested fee rate "
            f"({achieved:.1f} < {fee_rate} sat/vB). Try again."
        )

    return {
        "raw_hex": raw_hex,
        "txid": tx.txid().hex(),
        "vsize": vsize,
        "fee_sat": actual_fee,
        "fee_rate_achieved": round(achieved, 2),
        "change_sat": change_sat,
        "change_address": change.address if include_change else None,
    }


def verify_signed_tx(raw_hex: str, net: Network, utxos) -> bool:
    """Re-parse what we are about to broadcast and validate every signature
    against the network-correct BIP143 sighash.

    BIP143 rule: for a P2WPKH input the scriptCode is the legacy P2PKH form
    (76a914…88ac), NOT the witness script. Getting this wrong makes a valid
    signature look invalid.
    """
    from embit import ec

    try:
        final = Transaction.parse(bytes.fromhex(raw_hex))
    except Exception:
        return False
    if len(final.vin) != len(utxos):
        return False
    for i, u in enumerate(utxos):
        wit = final.vin[i].witness
        if not wit or len(wit.items) < 2:
            return False
        script_code = script.p2pkh_from_p2wpkh(u.script)
        sighash = final.sighash_segwit(i, script_code, u.value_sat, SIGHASH.ALL)
        try:
            pub = ec.PublicKey.parse(wit.items[1])
            sig = ec.Signature.parse(wit.items[0][:-1])
        except Exception:
            return False
        if not pub.verify(sig, sighash):
            return False
    return True
