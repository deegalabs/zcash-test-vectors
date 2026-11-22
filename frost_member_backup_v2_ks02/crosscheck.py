#!/usr/bin/env python3
"""Independent cross-check (path 3) of the Rust generator's vectors, using the pure-Python
Bech32m and Pallas/Orchard code of zcash/zcash-test-vectors (master at 78321be) (no Rust, no crate shared).

Run (with -I so nothing is imported from the current directory):
    python3 -I crosscheck.py <path to a zcash-test-vectors checkout, tested at 78321be> <vectors dir>
"""
import json
import sys
from itertools import combinations

sys.path.insert(0, sys.argv[1])
from zcash_test_vectors.bech32m import Encoding, bech32_decode, bech32_encode, convertbits  # noqa: E402
from zcash_test_vectors.orchard.commitments import commit_ivk  # noqa: E402
from zcash_test_vectors.orchard.generators import SPENDING_KEY_BASE  # noqa: E402
from zcash_test_vectors.orchard.pallas import Fp, Point, Scalar  # noqa: E402
from zcash_test_vectors.unified_encoding import ORCHARD_ITEM, decode_unified  # noqa: E402

vdir = sys.argv[2]


def load(name):
    rows = json.load(open(f"{vdir}/{name}"))
    fields = [f.strip() for f in rows[1][0].split(",")]
    return [dict(zip(fields, r)) for r in rows[2:]]


def py_decode(s):
    hrp, data, spec = bech32_decode(s)
    if hrp is None or spec != Encoding.BECH32M:
        return None
    payload = convertbits(data, 5, 8, False)
    return None if payload is None else (hrp, bytes(payload))


checked = 0
groups = {}
for v in load("frost_member_backup_v2_ks02.json"):
    s, payload = v["encoding"], bytes.fromhex(v["payload"])
    hrp, p = py_decode(s)
    assert hrp == "zkfrost" and p == payload
    assert bech32_encode("zkfrost", convertbits(payload, 8, 5), Encoding.BECH32M) == s
    # field layout, as written on 2026-11-18 and revised on 2026-11-20 and 2026-11-21
    assert p[0] == 0x02 and p[1] == 0x02
    assert p[2] == {"mainnet": 0, "testnet": 1}[v["network"]]
    assert (p[3], p[4], p[5]) == (v["t"], v["n"], v["identifier_form"])
    idlen = 1 if p[5] == 0 else 32
    o = 6
    assert p[o:o + idlen].hex() == v["identifier"]; o += idlen
    share = p[o:o + 32]; o += 32
    assert share.hex() == v["signing_share"]
    assert int.from_bytes(p[o:o + 4], "little") == v["birthday_height"]; o += 4
    fvk = p[o:]
    assert len(fvk) == 96 and o + 96 == len(p)
    ak_b, nk_b, rivk_b = fvk[:32], fvk[32:64], fvk[64:]
    assert (ak_b.hex(), nk_b.hex(), rivk_b.hex()) == (v["ak"], v["nk"], v["rivk"])
    # ak: a Pallas point with sign bit 0, not the identity; nk, rivk canonical; ivk not bottom
    assert ak_b[31] & 0x80 == 0 and ak_b != bytes(32)
    akP = Point.from_bytes(ak_b)
    assert akP is not None
    nk, rivk = Fp.from_bytes(nk_b), Scalar.from_bytes(rivk_b)
    ivk = commit_ivk(rivk, akP.extract(), nk)
    assert ivk is not None and ivk != Fp(0)
    # verifying share = [share] G_SpendAuth
    sh = Scalar.from_bytes(share)
    assert bytes(SPENDING_KEY_BASE * sh).hex() == v["verifying_share"]
    x = Scalar.from_bytes(bytes.fromhex(v["identifier_scalar"]))
    if p[5] == 0:
        assert x == Scalar(p[6])
    groups.setdefault((v["ak"], v["network"]), []).append((x, sh, akP))
    assert len(s) == v["encoding_length"] and len(p) == v["payload_length"]
    uhrp = {"mainnet": "uview", "testnet": "uviewtest"}[v["network"]]
    assert decode_unified(v["ufvk"], uhrp, {ORCHARD_ITEM: 96})["orchard"] == fvk
    checked += 1

# any two members interpolate to ak, in Python
for key, members in groups.items():
    assert len(members) == 3
    for (xi, si, akP), (xj, sj, _) in combinations(members, 2):
        secret = si * (xj / (xj - xi)) + sj * (xi / (xi - xj))
        assert SPENDING_KEY_BASE * secret == akP, key

print(f"python cross-check: {checked} valid vectors decode, re-encode and verify "
      f"(ak point, sign bit, nk/rivk canonical, ivk, verifying shares, pair interpolation, UFVK)")

NETS = {"mainnet": 0, "testnet": 1}  # no Regtest value since the text of 2026-11-21
LENGTHS = {(0, 0): 107, (0, 1): 138, (1, 0): 107, (1, 1): 138, (2, 0): 139, (2, 1): 170}


def py_rule(s):
    """The decoding rules of the text of 2026-11-21, in its order, written again here in Python.
    Returns (None, payload) when the string decodes, or (rule number, None)."""
    hrp, data, spec = bech32_decode(s)  # case, charset, checksum
    if hrp is None or spec != Encoding.BECH32M:
        return 1, None
    payload = convertbits(data, 5, 8, False)  # leftover bits > 4 or not zero -> None
    if payload is None:
        return 1, None
    p = bytes(payload)
    if hrp != "zkfrost":
        return 2, None
    # rules 3 and 4 read only the bytes the payload has; a payload that ends before one fails rule 5
    if len(p) > 0 and p[0] != 0x02:
        return 3, None
    if (len(p) > 1 and p[1] > 2) or (len(p) > 2 and p[2] > 1) or (len(p) > 5 and p[5] > 1):
        return 4, None
    if len(p) < 6:
        return 5, None
    if len(p) != LENGTHS[(p[1], p[5])]:
        return 5, None
    t, n = p[3], p[4]
    if t < 2 or t > n:
        return 6, None
    if p[5] == 0:
        if p[6] == 0:
            return 7, None
    else:
        ident = p[6:38]
        try:
            Scalar.from_bytes(ident)
        except ValueError:
            return 7, None
        if ident[1:] == bytes(31):  # integers 0 to 255
            return 7, None
    return None, p


dec = load("frost_member_backup_v2_ks02_decoding.json")
by_rule = {}
for v in dec:
    rule, p = py_rule(v["encoding"])
    assert rule == v["rule"], (v["reason"], rule, v["rule"])
    if rule is None:
        assert p.hex() == v["payload"], v["reason"]
        assert v["payload"] is not None
    else:
        assert v["payload"] is None
    by_rule[rule] = by_rule.get(rule, 0) + 1
print(f"python cross-check: all {len(dec)} decoding cases give the same rule number in an independent Python "
      f"decoder of the revised text ({', '.join(f'rule {k}: {c}' for k, c in sorted(by_rule.items(), key=lambda kv: (kv[0] is None, kv[0])) if k)}; "
      f"{by_rule.get(None, 0)} decode)")

res = load("frost_member_backup_v2_ks02_restore.json")
steps = {}
for v in res:
    rule, p = py_rule(v["encoding"])
    wallet = NETS[v["wallet_network"]]
    step = None
    if rule is not None:
        step = 1
    elif p[2] != wallet:
        step = 2
    else:
        fvk_start = 43 if p[5] == 0 else 74
        share_start = 7 if p[5] == 0 else 38
        share, fvk = p[share_start:share_start + 32], p[fvk_start:]
        try:
            Scalar.from_bytes(share)
        except ValueError:
            step = 3
        if step is None:
            ak_b, nk_b, rivk_b = fvk[:32], fvk[32:64], fvk[64:]
            ok = ak_b[31] & 0x80 == 0 and ak_b != bytes(32)
            akP = Point.from_bytes(ak_b) if ok else None
            try:
                nk, rivk = Fp.from_bytes(nk_b), Scalar.from_bytes(rivk_b)
            except ValueError:
                ok = False
            if ok and akP is not None:
                ivk = commit_ivk(rivk, akP.extract(), nk)
                ok = ivk is not None and ivk != Fp(0)
            else:
                ok = False
            if not ok:
                step = 4
        if step is None and v["verifying_share"] is not None:
            if bytes(SPENDING_KEY_BASE * Scalar.from_bytes(share)).hex() != v["verifying_share"]:
                step = 5
    assert step == v["step"], (v["reason"], step, v["step"])
    assert (v["fvk"] is not None) == (step is None), v["reason"]
    if step is None:
        assert v["fvk"] == p[fvk_start:].hex(), v["reason"]
    steps[step] = steps.get(step, 0) + 1
print(f"python cross-check: all {len(res)} restore cases give the same step in Python "
      f"({', '.join(f'step {k}: {c}' for k, c in sorted(steps.items(), key=lambda kv: (kv[0] is None, kv[0])) if k)}; "
      f"{steps.get(None, 0)} accepted). Not re-implemented: the internal incoming viewing key condition of step 4")
