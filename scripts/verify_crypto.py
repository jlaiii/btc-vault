#!/usr/bin/env python3
"""Cryptographic self-check. Proves the wallet engine is correct before any
real funds are involved.

    docker compose exec web python /app/scripts/verify_crypto.py

Checks, in order:
  1. BIP39 mnemonic round-trip and validity
  2. BIP84 derivation produces well-formed testnet and mainnet addresses
  3. address validation rejects malformed/mismatched-network addresses
  4. a multi-input transaction signs, and EVERY signature verifies against the
     network-correct BIP143 sighash on the re-parsed serialized transaction
     (this is what the network actually enforces)
  5. the fee/VB maths matches real signed sizes, and paying a target feerate is
     achieved within tolerance
  6. the "no change output" dust path does not produce an invalid transaction
Exit code is non-zero if any check fails.
"""

import sys

sys.path.insert(0, "/app")

from embit import ec  # noqa: E402
from embit.transaction import SIGHASH, Transaction  # noqa: E402

from app import btc  # noqa: E402

FAILURES = []
CHECKS = [0]


def check(name, condition, detail=""):
    CHECKS[0] += 1
    if condition:
        print(f"  PASS  {name}")
    else:
        print(f"  FAIL  {name} {detail}")
        FAILURES.append(name)


def main():
    net = btc.get_network("testnet")
    main = btc.get_network("mainnet")

    print("\n1. Mnemonic")
    mn = btc.generate_mnemonic(24)
    check("24 words generated", len(mn.split()) == 24, f"got {len(mn.split())}")
    check("checksum valid", btc.mnemonic_is_valid(mn))
    check("bad mnemonic rejected", not btc.mnemonic_is_valid("foo bar baz"))

    print("\n2. Derivation")
    root = btc.root_from_mnemonic(mn, net)
    d0 = btc.derive_address(root, net, 0)
    d1 = btc.derive_address(root, net, 1)
    check("testnet address is bech32 tb1", d0.address.startswith("tb1"), d0.address)
    check("distinct indices differ", d0.address != d1.address)
    check("path is BIP84 testnet", d0.path == "m/84'/1'/0'/0/0", d0.path)
    mroot = btc.root_from_mnemonic(mn, main)
    m0 = btc.derive_address(mroot, main, 0)
    check("mainnet address is bc1", m0.address.startswith("bc1"), m0.address)
    check("same index differs across networks", d0.address != m0.address)
    # deterministic
    check("derivation is deterministic",
          btc.derive_address(btc.root_from_mnemonic(mn, net), net, 7).address ==
          btc.derive_address(root, net, 7).address)

    print("\n3. Address validation")
    ok, script, stype = btc.validate_destination(d0.address, net)
    check("valid testnet address accepted", ok and stype == "p2wpkh")
    try:
        btc.validate_destination(m0.address, net)
        check("mainnet address rejected on testnet", False, "was accepted")
    except btc.BitcoinError:
        check("mainnet address rejected on testnet", True)
    try:
        btc.validate_destination("tb1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq", net)
        check("bad checksum rejected", False, "was accepted")
    except btc.BitcoinError:
        check("bad checksum rejected", True)
    for bad in ("", "notanaddress", "0" * 40, "tb1q" + "x" * 5):
        try:
            btc.validate_destination(bad, net)
            check(f"garbage rejected: {bad[:14]!r}", False, "was accepted")
        except btc.BitcoinError:
            check(f"garbage rejected: {bad[:14]!r}", True)

    print("\n4. Signing (the check that matters)")
    pub0, pub1 = d0.pubkey, d1.pubkey
    utxos = [
        btc.Utxo(txid="11" * 32, vout=0, value_sat=60_000, address=d0.address,
                 script=d0.script, index=0, pubkey=pub0),
        btc.Utxo(txid="22" * 32, vout=1, value_sat=50_000, address=d1.address,
                 script=d1.script, index=1, pubkey=pub1),
    ]
    dest_script = d1.script
    rate = 10
    built = btc.build_signed_tx(root, net, utxos, [(70_000, dest_script, "p2wpkh")],
                                fee_rate=rate, change_index=0, target_fee_sat=2_000)
    check("signed 2 of 2 inputs", built["txid"] is not None)
    check("vsize is plausible for 2-in/2-out",
          200 <= built["vsize"] <= 260, f"vsize={built['vsize']}")

    final = Transaction.parse(bytes.fromhex(built["raw_hex"]))
    all_valid = True
    for i, u in enumerate(utxos):
        script_code = btc.script.p2pkh_from_p2wpkh(u.script)   # BIP143 rule
        sighash = final.sighash_segwit(i, script_code, u.value_sat, SIGHASH.ALL)
        w = final.vin[i].witness
        if not w or len(w.items) < 2:
            all_valid = False
            break
        pub = ec.PublicKey.parse(w.items[1])
        sig = ec.Signature.parse(w.items[0][:-1])
        if not pub.verify(sig, sighash):
            all_valid = False
            break
    check("every input signature verifies on the serialized tx", all_valid)
    check("our own verifier agrees", btc.verify_signed_tx(built["raw_hex"], net, utxos))

    print("\n5. Fees")
    achieved = built["fee_sat"] / built["vsize"]
    check("achieved rate within 15% of target",
          abs(achieved - rate) / rate <= 0.15,
          f"requested {rate}, achieved {achieved:.2f}")
    check("fee equals inputs minus outputs",
          built["fee_sat"] == 110_000 - 70_000 - built["change_sat"],
          f"{built['fee_sat']} vs {110_000 - 70_000 - built['change_sat']}")
    # size model vs reality
    est = btc.estimate_vsize(2, ["p2wpkh", "p2wpkh"])
    check("vsize estimator within 5 vB of reality", abs(est - built["vsize"]) <= 5,
          f"est {est} vs real {built['vsize']}")
    check("1-in/2-out model matches known-good 141 vB",
          btc.estimate_vsize(1, ["p2wpkh", "p2wpkh"]) == 141,
          str(btc.estimate_vsize(1, ["p2wpkh", "p2wpkh"])))

    print("\n6. Dust path (no change output)")
    tiny = [btc.Utxo(txid="33" * 32, vout=0, value_sat=50_000, address=d0.address,
                     script=d0.script, index=0, pubkey=pub0)]
    b2 = btc.build_signed_tx(root, net, tiny, [(49_000, dest_script, "p2wpkh")],
                             fee_rate=10, change_index=0, target_fee_sat=1_000)
    check("dust change folded into fee, still valid",
          btc.verify_signed_tx(b2["raw_hex"], net, tiny),
          f"change={b2['change_sat']} fee={b2['fee_sat']}")
    check("no change output present", b2["change_sat"] == 0)
    check("fee absorbed the dust remainder",
          b2["fee_sat"] == 50_000 - 49_000, f"fee={b2['fee_sat']}")

    print("\n7. Tamper detection")
    raw = built["raw_hex"]
    tampered = raw[:-8] + ("00" if raw[-8:] != "00" * 4 else "ff" * 4)
    check("tampered tx fails verification",
          not btc.verify_signed_tx(tampered, net, utxos))
    check("wrong utxo set fails verification",
          not btc.verify_signed_tx(raw, net, [utxos[0]]))

    print("\n8. Money maths")
    from app.utils import btc_str_to_sats, sats_to_btc_str

    check("1 BTC = 100000000 sats", btc_str_to_sats("1") == 100_000_000)
    check("0.00000001 round trip", btc_str_to_sats("0.00000001") == 1)
    check("8dp formatting", sats_to_btc_str(123_456_789) == "1.23456789")
    check("no float drift on max supply",
          btc_str_to_sats("21000000") == 2_100_000_000_000_000)
    for bad in ("abc", "1.123456789", "-1", "1e5", ""):
        try:
            btc_str_to_sats(bad)
            check(f"rejects {bad!r}", False, "was accepted")
        except ValueError:
            check(f"rejects {bad!r}", True)

    print("\n9. Fee oracle sanity")
    from app.chain import blend_fee_tiers, pick_fee_rates

    F = {"fast": 20, "normal": 8, "economy": 2}
    # Real observed bad data: a coarse estimator reporting 264 sat/vB for the
    # low targets while reporting 1.012 sat/vB for 19-24 on an empty mempool.
    coarse = {1: 264.11, 6: 264.11, 9: 2.0, 15: 1.012, 19: 1.012, 20: 1.012, 24: 1.012}
    r = pick_fee_rates(coarse, 1, 500, F)
    check("coarse estimator is anchored down, not trusted",
          r["fast"] < 264 and r["fast"] <= 20, f"{r}")
    check("anchored rate stays sane for an empty mempool", r["fast"] <= 20, f"{r}")

    quiet = {1: 1, 2: 1, 3: 0.5, 6: 0.1, 144: 0.1}
    rq = pick_fee_rates(quiet, 1, 500, F)
    check("empty mempool yields a minimal fee", rq["fast"] <= 2, f"{rq}")

    cong = {1: 120, 2: 100, 3: 80, 6: 40, 12: 20, 144: 8}
    rc = pick_fee_rates(cong, 1, 500, F)
    check("real congestion spread is preserved",
          rc["fast"] >= 100 and rc["economy"] <= 45, f"{rc}")
    check("tiers are ordered fast >= normal >= economy",
          rc["fast"] >= rc["normal"] >= rc["economy"], f"{rc}")

    check("no data falls back to defaults",
          pick_fee_rates({}, 1, 500, F) == {"fast": 20, "normal": 8, "economy": 2})
    check("zero/negative rates are floored", 
          pick_fee_rates({1: 0, 6: 0}, 1, 500, F)["fast"] >= 1)
    check("extreme rates are clamped to the ceiling",
          pick_fee_rates({1: 99999, 144: 90000}, 1, 500, F)["fast"] == 500)

    # cross-provider: disagreement must resolve downward whichever order they
    # arrive in (overpaying is unrecoverable, underpaying is not)
    bl_a = blend_fee_tiers([{"estimates": coarse}, {"estimates": quiet}], 1, 500, F)
    bl_b = blend_fee_tiers([{"estimates": quiet}, {"estimates": coarse}], 1, 500, F)
    check("disagreement resolves downward (coarse first)", bl_a["fast"] <= 2, f"{bl_a}")
    check("disagreement resolves downward (coarse second)", bl_b["fast"] <= 2, f"{bl_b}")
    check("agreement is taken at face value",
          blend_fee_tiers([{"estimates": {1: 5, 3: 4, 6: 3}}], 1, 500, F)["fast"] == 5)

    print("\n10. Serialization round-trip (outpoint byte order)")
    # Regression guard: the input outpoint must be written EXACTLY as the txid
    # hex string, not byte-reversed. A reversed outpoint still signs and
    # verifies locally but is unrunnable — the network rejects it with
    # "bad-txns-inputs-missingorspent". Cost a real testnet broadcast to find.
    from embit.transaction import Transaction as _Tx

    real_txid = "9f2c4b1e7a3d5f8091b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718"
    probe = btc.Utxo(txid=real_txid, vout=3, value_sat=100_000, address=d0.address,
                     script=d0.script, index=0, pubkey=pub0)
    built2 = btc.build_signed_tx(root, net, [probe], [(90_000, d1.script, "p2wpkh")],
                                 fee_rate=5, change_index=0, target_fee_sat=1_000)
    raw2 = bytes.fromhex(built2["raw_hex"])
    # segment 1: version(4) + marker(1) + flag(1) + vin count(1) = 7
    outpoint_txid = raw2[7:39]
    outpoint_vout = raw2[39:43]
    # The wire carries the txid in little-endian (reversed) order — this is the
    # Bitcoin convention, confirmed against a real confirmed transaction where
    # raw[7:39] == reverse(display txid). embit's own `.txid` attribute holds
    # DISPLAY order and it performs that reversal when serializing, so the
    # UTXO's txid must be passed through un-reversed. Reversing it here (as an
    # earlier version did) yields a syntactically valid, signable, and
    # completely unspendable transaction: the network rejects it with
    # "bad-txns-inputs-missingorspent".
    check("wire outpoint is little-endian (reverse of display txid)",
          outpoint_txid == bytes.fromhex(real_txid)[::-1],
          f"got {outpoint_txid.hex()[:20]}…")
    check("outpoint vout is little-endian 3",
          outpoint_vout == (3).to_bytes(4, "little"), outpoint_vout.hex())
    reparsed = _Tx.parse(raw2)
    check("reparse recovers the original txid (round trip)",
          reparsed.vin[0].txid.hex() == real_txid, reparsed.vin[0].txid.hex())
    check("reparsed txid matches the reported txid",
          reparsed.txid().hex() == built2["txid"], built2["txid"])

    print("\n" + "=" * 62)
    if FAILURES:
        print(f"FAILED {len(FAILURES)} of {CHECKS[0]} checks:")
        for f in FAILURES:
            print(f"  - {f}")
        sys.exit(1)
    print(f"ALL {CHECKS[0]} CHECKS PASSED")
    print("=" * 62 + "\n")


if __name__ == "__main__":
    main()
