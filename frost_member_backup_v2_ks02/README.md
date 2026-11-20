# Provisional vectors: FROST member backup string, version 2, key source 0x02

**Provisional, and still so until the text settles.** These vectors follow the version 2 payload as
the draft's owner wrote it in zcash/zips#1413 on 2026-11-18 and **revised it on 2026-11-20**, in
answer to eight notes we sent. The payload is not part of zcash/zips#1432 and has not been answered
by the ZIP editors. If it changes, regenerate.

Key source `0x02` means "viewing key only (no sk)". The string carries the raw Orchard full viewing
key `ak || nk || rivk` and no `sk`, so it cannot recover the group's notes under ZIP 2005.

## What changed since the first version

The first version was built on the text of 2026-11-18. The author's answers (his numbering) and what
each did here:

1. **Offsets.** Our reading was the intended one. Unchanged. The offsets below are his table's, and
   a test checks them (viewing key at byte 43 short / 74 full; lengths 107, 138, 139, 170).
2. **Exact length.** The payload MUST be exactly 107, 138, 139 or 170 bytes by key source and
   identifier form. Unchanged: the same length vectors.
3. **Order.** Agreed, and the order is now written out as seven rules. **Changed:** the first
   version checked the padding after the prefix; the text puts it with Bech32m validity, as rule 1.
   A string with a wrong prefix and a bad padding bit is now rejected for the padding. Every
   rejection vector now names its rule in a `rule` column, and 13 of them break two or more rules at
   once to show that the first in order is the one reported (3 restore vectors do the same for steps).
4. **Decoding or restore.** The split we used is his. The identifier checks are decoding (rule 7),
   the canonical share is restore (step 3). Unchanged, now numbered.
5. **Validating the viewing key.** Restore step 4 MUST reject an invalid key. Unchanged (the same five
   cases), now labelled step 4. There is **no vector for the incoming viewing key condition** (the
   external or internal incoming viewing key being 0 or invalid): the author says he knows no way to
   find an `nk` and `rivk` that hit it, and neither do we.
6. **A changed viewing key.** The checksum catches only accidental changes, so the SHOULD carries
   over: before showing an address to receive funds, the wallet SHOULD check the restored viewing key
   against a source the member trusts (an address of the group recorded before, or the same key from
   at least two other members). **This is a note, not a vector**: it is a SHOULD about what the wallet
   does with a key it cannot know is the group's, so there is nothing a string can show. A string
   whose `rivk` was altered and encoded again restores another valid key without error, by design.
7. **Padding.** Leftover bits MUST be all zero. Unchanged (the same two vectors), now part of rule 1.
8. **Network.** A wallet MUST reject a string for a network other than its own (restore step 2) and
   SHOULD say which network the string is for. Regtest is for tests, with its own value so a test
   string is never restored on Mainnet or Testnet. **New:** restore vectors for network mismatch, all
   six pairs of string and wallet network (Mainnet, Testnet and Regtest each as string and as
   wallet), and a valid Regtest-on-Regtest and Mainnet-on-Mainnet restore.

Also new: restore vectors are numbered by the step they violate, and the restore file carries the
wallet's network. Steps 1 to 5 are the text's; step 6 is the SHOULD above.

| | first version | this version |
|---|---|---|
| valid strings (main file) | 9 | 9, **identical rows** |
| decoding cases | 32 (6 decode, 26 rejected) | 52 (9 decode, 43 rejected) |
| restore cases | 12 (4 accepted, 8 rejected) | 24 (6 accepted, 18 rejected) |

The seed is unchanged on purpose, so every valid vector is the same byte for byte. Only the header
line of the files (which names the text) differs, so the main file's hash differs from the first
version's.

## What is generated

Two synthetic 2-of-3 groups, made from a fixed seed. No real vault's material is used.

- Group A: identifiers 1, 2, 3 (short form). All three members on Testnet and on Mainnet.
- Group B: three identifiers from frost-core's `Identifier::derive` on fixed labels (full form, the
  way frost-client's DKG makes them). All three members on Testnet.

Output files (the row-per-line JSON layout of zcash/zcash-test-vectors, as in #136):

| File | Rows |
|---|---|
| `frost_member_backup_v2_ks02.json` | 9 valid strings, with every input and intermediate value |
| `frost_member_backup_v2_ks02_decoding.json` | 52 strings: 9 that decode, 43 that decoders must reject. Columns `encoding, payload, rule, reason` (`rule` is the decoding rule 1 to 7, null if it decodes) |
| `frost_member_backup_v2_ks02_restore.json` | 24 strings: 6 the restore accepts, 18 it must reject. Columns `encoding, wallet_network, verifying_share, fvk, step, reason` (`step` is the restore step 1 to 5, null if accepted) |

Where these files differ from #136's shape (because of what version 2 adds): the main file has
`key_source`, `network`, `identifier_form`, `identifier` as hex bytes as they sit in the payload
(1 or 32), `identifier_scalar` (32-byte LE), `birthday_height`, `payload_length`,
`encoding_length` and `leftover_bits`, and one `ufvk` for the string's network instead of
`ufvk_mainnet` and `ufvk_testnet`. It has no `sk`, `qsk`, `qk` or `derivation` columns. The
restore file takes the member's `verifying_share` (or null) as input instead of a UFVK, and
gives the `fvk` restored (or null), and the `wallet_network` the restore runs on.

The UFVKs are Orchard-only, ZIP 316 revision 0, with no birthday metadata item. They are for
comparison only; the string does not contain them.

## How the values are made

- Seed: every random value comes from ChaCha20 seeded with
  `BLAKE2b-256(personalization "KonclaveV2Vector", SEED_TAG || "/" || label)`, where `SEED_TAG` is
  `zips#1413 v2 key source 0x02 synthetic 2-of-3 (payload of 2026-11-18)` (kept after the revision) and the labels are
  `A/polynomial`, `A/sk`, `A/signing`, `B/polynomial`, `B/sk`, `B/signing`.
- Shares: a degree-1 polynomial `f(x) = a0 + a1 x`, with `a0`, `a1` each `LEOS2IP_512(64 stream
  bytes) mod q`. The shares are `f(identifier)`.
- Sign bit: if `[a0] G_SpendAuth` encodes with the sign bit set, `a0` and `a1` are negated, so the
  group key and every share are negated. This is reddsa's `EvenY` rule, which frost-client applies
  after the DKG. Both seeded groups needed it, so the vectors go through that branch. The generator
  checks its negation against reddsa's own `into_even_y`.
- Viewing key: as zcash-sign's `generate` does (frost-tools `06c0dbd`, `zcash-sign/src/generate.rs`):
  draw 32 bytes until they form a valid Orchard spending key, take `nk` and `rivk` from that `sk` by
  the legacy derivation, and use the group key as `ak`. zcash-sign does this with its orchard fork's
  `from_sk_ak_incompatible_with_quantum_recoverability_and_will_be_removed`, which sets
  `nk: sk.into(), rivk: sk.into()`. Released orchard 0.16 has no such public constructor, so the
  generator takes `nk` and `rivk` from orchard's `FullViewingKey::from(&SpendingKey)` and checks them
  against `PRF^expand` written here. The generator never writes or prints `sk`. **But it can be
  derived from the documented seed, as can every other value here. These keys must never hold
  funds.**
- Birthday heights: Testnet 4,465,026 and Mainnet 3,543,405 (the NU7 activation heights in
  ZIP 259). Chosen because their four bytes all differ, so a byte-order mistake shows.

## Checks the generator makes (it panics on any failure)

1. `ak` is accepted by orchard's `SpendValidatingKey::from_bytes`: not the identity, sign bit 0, on
   the curve.
2. orchard's `FullViewingKey::from_bytes` accepts `ak || nk || rivk` and round-trips it.
3. Every pair of shares reconstructs (frost-core `reconstruct`) a secret whose public key is `ak`.
4. Every verifying share equals `[share] G_SpendAuth` and passes the VSS commitment.
5. Every pair signs with rerandomized FROST (reddsa 0.5.2 / frost-rerandomized 3.0.0). The signature
   verifies in frost and under orchard's `SpendValidatingKey::randomize(alpha)` (reddsa 0.6,
   pasta_curves 0.6: a second crate, reached only through bytes).
6. The negation matches reddsa's `EvenY`.
7. For every string: the `bech32` crate and the BIP 350 code here give the same string, decoding
   gives back every field, the crate decodes the same bytes, and the counts are 139 bytes / 237
   characters (short form) or 170 / 286 (full form).
8. Every decoding and restore case gives exactly the expected result and the expected rule or step
   number, and the generator's Bech32m and the `bech32` crate agree on the checksum for every string.

`crosscheck.py` is a third path in Python. It uses zcash-test-vectors' pure-Python Bech32m, Pallas,
`CommitIvk` and unified encoding, and shares no code with the Rust generator. Since the revision it
also decodes every decoding case with its own seven-rule decoder and runs every restore case through
steps 1 to 5 in Python, and requires the same rule or step number as the file. It does not
re-implement the internal incoming viewing key condition of step 4.

## The payload (text of 2026-11-20), offsets in bytes

Key source `0x02` (no sk). Key sources `0x00` and `0x01` have the sk layouts: 107 / 138 bytes, `sk`
at 43 / 74 and `ak` at 75 / 106.

| Field | Short form | Full form |
|---|---|---|
| format version `0x02` | 0 | 0 |
| key source `0x02` | 1 | 1 |
| network (`0x00` Mainnet, `0x01` Testnet, `0x02` Regtest) | 2 | 2 |
| threshold t | 3 | 3 |
| group size n | 4 | 4 |
| identifier form (`0x00` short, `0x01` full) | 5 | 5 |
| identifier | 6 (1 byte) | 6..37 (32 bytes, LE scalar) |
| signing share | 7..38 | 38..69 |
| birthday height, u32 LE | 39..42 | 70..73 |
| `ak ‖ nk ‖ rivk` (`ak` 43..74, `nk` 75..106, `rivk` 107..138) | 43..138 | 74..169 (`ak` 74..105, `nk` 106..137, `rivk` 138..169) |
| total | 139 | 170 |

**Decoding rejections, in order** (the `rule` column; a vector that breaks several trips the first):

1. not valid Bech32m (including mixed case), or leftover bits more than 4 or not all zero;
2. human-readable part not `zkfrost`;
3. format version not `0x02`;
4. key source, network or identifier form not a known value;
5. payload not exactly the length its key source and identifier form give;
6. t < 2 or t > n;
7. identifier 0; or, in the full form, not a canonical Pallas scalar or an integer from 1 to 255.

There is no `i <= n` check, and the file has a vector that decodes with identifier 4 and n = 3.

**Restore steps** (the `step` column): 1 decode; 2 reject a string whose network is not the wallet's;
3 reject a signing share that is not a canonical Pallas scalar (for `0x00` and `0x01` also an sk that
is not a valid Orchard spending key; no vector, since these vectors are key source `0x02`);
4 build the full viewing key and reject it if invalid under the protocol's Orchard raw full viewing
key rule; 5 when the wallet knows the group's verifying shares, it SHOULD check the member's
(vectors for the mismatch are included, labelled step 5); 6 the SHOULD to compare the viewing key
with a source the member trusts (a note, no vector). For key source `0x02` the wallet MUST say the
string holds no sk.

Step 1 is reported as step 1 for any decoding rejection; the file's `reason` names the decoding rule.

## Ambiguities met while implementing the revised text

- A payload shorter than 6 bytes (its key source, network or identifier form cannot be read): the
  text gives no rule for it. The generator treats it as rule 4 (unknown values). No vector, since the
  text does not settle it.
- Rule 4 lists three checks as one rule and does not order them among themselves. Vectors break one
  at a time and one vector breaks all three; the generator reports the key source first.
- Step 5 of the restore is a SHOULD, but the vectors give a mismatch a rejection. A wallet that
  skips the SHOULD will accept those strings; the file marks them step 5 so it can tell.
- Step 1 says "Decode the string as above" and so inherits the order; whether a wallet reports the
  decoding rule or just "step 1" is not specified.
- Step 3 for key sources `0x00` and `0x01` (invalid sk) is not exercised here.
- "Leftover bits more than 4 or not zero" is read as the Bech32m data part before the checksum.

## Run

```
cargo run --release -- out             # writes the three JSON files and prints every check
cargo test --release                   # 11 tests: offsets, each rule, the order, each restore step
cargo run --release -- --red-check     # each check as built, then with one byte changed
python3 -I crosscheck.py <zcash-test-vectors checkout> out
```

The generator is deterministic: two runs give byte-identical files. The tests break one input of a
valid string per rule and require that rule's number, and break several at once to require the first
in order. With the order of the code changed (padding after the prefix, length before the unknown
values, the threshold before the length, the version after the length, no network check, no 1 to 255
rule) the matching test fails.

Crates: orchard 0.16.0 (`unstable-frost`), reddsa 0.5.2 (`frost`), frost-rerandomized 3.0.0,
bech32 0.11, zcash_address 0.14.0, zcash_protocol 0.11.0. The crate has its own `[workspace]`
table, so it is not part of any other workspace.

The generator, the Python check and a first draft of this README were written with Claude Code.

License: MIT OR Apache-2.0 (LICENSE-MIT, LICENSE-APACHE).
