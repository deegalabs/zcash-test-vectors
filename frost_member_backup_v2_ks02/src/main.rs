//! Provisional test vectors for key source 0x02 ("viewing key only, no sk") of the FROST member
//! backup string, version 2, as written in zcash/zips#1413 (the draft owner's comment of 2026-11-18,
//! revised in his comment of 2026-11-20, which this generator follows). That payload is a proposal
//! for discussion: it is not part of zcash/zips#1432 and has not been answered by the ZIP editors.
//! Regenerate these vectors if the payload changes.
//!
//! Everything here comes from a SYNTHETIC group made from a fixed, documented seed. No real vault's
//! material is used or read.
//!
//! Run:   cargo run --release -- <out_dir>          (writes three JSON files, prints the checks)
//!        cargo run --release -- --red-check        (each check, then the same check with one byte changed)

use std::collections::BTreeMap;
use std::fmt::Write as _;

use ff::{Field, FromUniformBytes, PrimeField};
use pasta_curves::pallas;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;
use reddsa::frost::redpallas::{
    self as frost,
    keys::{EvenY, KeyPackage, PublicKeyPackage, SecretShare, SigningShare, VerifyingShare,
           VerifiableSecretSharingCommitment},
    Identifier, SigningKey, VerifyingKey,
};

// ---------------------------------------------------------------------------------------------
// Constants of the proposed version 2 payload (zips#1413, revised text of 2026-11-20)
// ---------------------------------------------------------------------------------------------

const HRP: &str = "zkfrost";
const VERSION_2: u8 = 0x02;
const KS_ZIP2005: u8 = 0x00;
const KS_LEGACY: u8 = 0x01;
const KS_VIEWING_KEY_ONLY: u8 = 0x02;
const NET_MAINNET: u8 = 0x00;
const NET_TESTNET: u8 = 0x01;
const NET_REGTEST: u8 = 0x02;
const ID_SHORT: u8 = 0x00;
const ID_FULL: u8 = 0x01;

/// Arbitrary but documented birthday heights, chosen to have four distinct bytes so a byte-order
/// mistake shows: the NU7 activation heights of ZIP 259 (Mainnet 3,543,405; Testnet 4,465,026).
const BIRTHDAY_MAINNET: u32 = 3_543_405;
const BIRTHDAY_TESTNET: u32 = 4_465_026;

/// The seed every random value in this file is derived from (see `seeded_rng`). Deliberately NOT
/// changed for the 2026-11-20 revision (the date in it is that of the first payload text), so every
/// valid vector of the first version is reproduced byte for byte.
const SEED_TAG: &str = "zips#1413 v2 key source 0x02 synthetic 2-of-3 (payload of 2026-11-18)";

/// The Pallas scalar field modulus q, little-endian (not a canonical scalar encoding).
const Q_LE: [u8; 32] = hex32("0100000021eb468cdda89409fc98462200000000000000000000000000000040");
/// The Pallas base field modulus p, little-endian (not a canonical base field encoding).
const P_LE: [u8; 32] = hex32("01000000ed302d991bf94c09fc98462200000000000000000000000000000040");

const fn hex32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
        i += 1;
    }
    out
}
const fn nib(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("bad hex"),
    }
}

// ---------------------------------------------------------------------------------------------
// Deterministic randomness
// ---------------------------------------------------------------------------------------------

/// ChaCha20 seeded with BLAKE2b-256(personalization "KonclaveV2Vector", SEED_TAG || "/" || label).
fn seeded_rng(label: &str) -> ChaCha20Rng {
    let mut input = SEED_TAG.as_bytes().to_vec();
    input.push(b'/');
    input.extend_from_slice(label.as_bytes());
    let h = blake2b_simd::Params::new()
        .hash_length(32)
        .personal(b"KonclaveV2Vector")
        .hash(&input);
    ChaCha20Rng::from_seed(h.as_bytes().try_into().unwrap())
}

/// A Pallas scalar from 64 bytes of the stream: LEOS2IP_512(bytes) mod q.
fn scalar_from_stream(rng: &mut ChaCha20Rng) -> pallas::Scalar {
    use rand_core::RngCore;
    let mut wide = [0u8; 64];
    rng.fill_bytes(&mut wide);
    pallas::Scalar::from_uniform_bytes(&wide)
}

// ---------------------------------------------------------------------------------------------
// Bech32m, written here from BIP 350 (path 2; path 1 is the `bech32` crate)
// ---------------------------------------------------------------------------------------------

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const BECH32M_CONST: u32 = 0x2bc8_30a3;
const BECH32_CONST: u32 = 1;

fn polymod(values: &[u8]) -> u32 {
    const GEN: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];
    let mut chk: u32 = 1;
    for &v in values {
        let b = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ (v as u32);
        for (i, g) in GEN.iter().enumerate() {
            if (b >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> Vec<u8> {
    let mut v: Vec<u8> = hrp.bytes().map(|c| c >> 5).collect();
    v.push(0);
    v.extend(hrp.bytes().map(|c| c & 31));
    v
}

/// 8-to-5 bit conversion with zero padding (encoding side of BIP 173's convertbits).
fn to_5bit(data: &[u8]) -> Vec<u8> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for &b in data {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(((acc >> bits) & 31) as u8);
        }
    }
    if bits > 0 {
        out.push(((acc << (5 - bits)) & 31) as u8);
    }
    out
}

/// 5-to-8 bit conversion with ZIP 173's rule: at most 4 leftover bits, all zero.
fn from_5bit_strict(data: &[u8]) -> Result<Vec<u8>, &'static str> {
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for &v in data {
        acc = (acc << 5) | v as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits > 4 || (acc & ((1 << bits) - 1)) != 0 {
        return Err("invalid padding");
    }
    Ok(out)
}

fn encode_5bit(hrp: &str, data5: &[u8], constant: u32) -> String {
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(data5);
    values.extend_from_slice(&[0; 6]);
    let pm = polymod(&values) ^ constant;
    let mut s = String::from(hrp);
    s.push('1');
    for &d in data5 {
        s.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    s
}

fn encode_own(hrp: &str, payload: &[u8]) -> String {
    encode_5bit(hrp, &to_5bit(payload), BECH32M_CONST)
}

fn encode_crate(payload: &[u8]) -> String {
    bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse(HRP).unwrap(), payload).unwrap()
}

/// Bech32m decoding to (hrp, 5-bit data), with BIP 350's case rule. No length limit (as ZIP 316).
fn bech32m_decode(s: &str) -> Result<(String, Vec<u8>), &'static str> {
    let has_lower = s.bytes().any(|c| c.is_ascii_lowercase());
    let has_upper = s.bytes().any(|c| c.is_ascii_uppercase());
    if has_lower && has_upper {
        return Err("not Bech32m");
    }
    let s = s.to_ascii_lowercase();
    let pos = s.rfind('1').ok_or("not Bech32m")?;
    if pos == 0 || pos + 7 > s.len() || s.bytes().any(|c| !(33..=126).contains(&c)) {
        return Err("not Bech32m");
    }
    let hrp = &s[..pos];
    let mut data = Vec::new();
    for c in s[pos + 1..].bytes() {
        let v = CHARSET.iter().position(|&x| x == c).ok_or("not Bech32m")?;
        data.push(v as u8);
    }
    let mut values = hrp_expand(hrp);
    values.extend_from_slice(&data);
    if polymod(&values) != BECH32M_CONST {
        return Err("not Bech32m");
    }
    data.truncate(data.len() - 6);
    Ok((hrp.to_string(), data))
}

// ---------------------------------------------------------------------------------------------
// The payload, as written on 2026-11-18
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq)]
struct Payload {
    key_source: u8,
    network: u8,
    t: u8,
    n: u8,
    id_form: u8,
    id: Vec<u8>, // 1 byte (short) or 32 bytes (full), as it sits in the payload
    share: [u8; 32],
    birthday: u32,
    sk: Option<[u8; 32]>,
    key: Vec<u8>, // ak (32) for key sources 0x00/0x01, ak || nk || rivk (96) for 0x02
}

impl Payload {
    fn to_bytes(&self) -> Vec<u8> {
        let mut v = vec![VERSION_2, self.key_source, self.network, self.t, self.n, self.id_form];
        v.extend_from_slice(&self.id);
        v.extend_from_slice(&self.share);
        v.extend_from_slice(&self.birthday.to_le_bytes());
        if let Some(sk) = self.sk {
            v.extend_from_slice(&sk);
        }
        v.extend_from_slice(&self.key);
        v
    }
}

/// The length a reader expects, from the version, key source and identifier form. The comment
/// gives the four sizes, not this rule; this is the reading the vectors are built on (README,
/// "Reading of the payload").
fn expected_len(key_source: u8, id_form: u8) -> Option<usize> {
    let id = match id_form {
        ID_SHORT => 1,
        ID_FULL => 32,
        _ => return None,
    };
    let tail = match key_source {
        KS_ZIP2005 | KS_LEGACY => 32 + 32,
        KS_VIEWING_KEY_ONLY => 96,
        _ => return None,
    };
    Some(6 + id + 32 + 4 + tail)
}

fn is_canonical_scalar(b: &[u8; 32]) -> bool {
    bool::from(pallas::Scalar::from_repr(*b).is_some())
}

/// A rejection: the number of the rule that fired (decoding rules 1-7, or restore steps 1-5, as
/// numbered in the text of 2026-11-20) and a short name for it.
type Rej = (u8, &'static str);

/// Decoding, rejections in the order the text of 2026-11-20 gives:
///  1. not valid Bech32m (including mixed case), or leftover bits more than 4 or not all zero;
///  2. human-readable part not `zkfrost`;
///  3. format version not 0x02;
///  4. key source, network or identifier form not a known value;
///  5. payload not exactly the length its key source and identifier form give;
///  6. t < 2 or t > n;
///  7. identifier 0, or (full form) not a canonical Pallas scalar or an integer from 1 to 255.
/// Returns the fields, or the first rule that rejects.
fn decode(s: &str) -> Result<Payload, Rej> {
    // Rule 1: Bech32m, then the padding of the 8-to-5 bit conversion, before anything is read.
    let (hrp, data5) = bech32m_decode(s).map_err(|e| (1, e))?;
    let p = from_5bit_strict(&data5).map_err(|e| (1, e))?;
    if hrp != HRP {
        return Err((2, "wrong human-readable part"));
    }
    if p.first() != Some(&VERSION_2) {
        return Err((3, "unsupported version"));
    }
    // A payload too short to hold the three bytes cannot be told apart by value; the text does not
    // say (README, "Ambiguities"). Treated as an unknown key source, network or identifier form.
    if p.len() < 6 {
        return Err((4, "unknown key source, network or identifier form"));
    }
    let (ks, net, t, n, form) = (p[1], p[2], p[3], p[4], p[5]);
    if ![KS_ZIP2005, KS_LEGACY, KS_VIEWING_KEY_ONLY].contains(&ks) {
        return Err((4, "unknown key source"));
    }
    if ![NET_MAINNET, NET_TESTNET, NET_REGTEST].contains(&net) {
        return Err((4, "unknown network"));
    }
    if form != ID_SHORT && form != ID_FULL {
        return Err((4, "unknown identifier form"));
    }
    if Some(p.len()) != expected_len(ks, form) {
        return Err((5, "wrong payload length"));
    }
    if t < 2 || t > n {
        return Err((6, "invalid threshold or group size"));
    }
    let id_len = if form == ID_SHORT { 1 } else { 32 };
    let id = p[6..6 + id_len].to_vec();
    if form == ID_SHORT {
        if id[0] == 0 {
            return Err((7, "zero identifier"));
        }
    } else {
        let full: [u8; 32] = id.clone().try_into().unwrap();
        if !is_canonical_scalar(&full) {
            return Err((7, "non-canonical identifier"));
        }
        if full == [0; 32] {
            return Err((7, "zero identifier"));
        }
        if full[1..] == [0; 31] {
            // integer value 1 to 255 (0 is caught above)
            return Err((7, "full identifier that fits the short form"));
        }
    }
    let mut o = 6 + id_len;
    let share: [u8; 32] = p[o..o + 32].try_into().unwrap();
    o += 32;
    let birthday = u32::from_le_bytes(p[o..o + 4].try_into().unwrap());
    o += 4;
    let sk = if ks == KS_VIEWING_KEY_ONLY {
        None
    } else {
        let sk: [u8; 32] = p[o..o + 32].try_into().unwrap();
        o += 32;
        Some(sk)
    };
    let key = p[o..].to_vec();
    Ok(Payload { key_source: ks, network: net, t, n, id_form: form, id, share, birthday, sk, key })
}

/// Restore for key source 0x02, steps of the text of 2026-11-20:
///  1. decode (any decoding rejection; the rejection is reported as step 1);
///  2. reject a string whose network is not the wallet's;
///  3. reject a signing share that is not a canonical Pallas scalar (and, for 0x00/0x01, an sk that
///     is not a valid Orchard spending key: not reachable for 0x02);
///  4. build the full viewing key and reject it if invalid (for 0x02, taken from the string);
///  5. SHOULD, when the verifying shares are known: the member's verifying share must match.
/// Step 6 (compare the viewing key with a trusted source) is a SHOULD with no vector.
fn restore(s: &str, wallet_net: u8, known_vs: Option<&[u8; 32]>) -> Result<(Payload, orchard::keys::FullViewingKey), Rej> {
    let p = decode(s).map_err(|(_, m)| (1, m))?;
    if p.network != wallet_net {
        return Err((2, "network is not the wallet's"));
    }
    if p.key_source != KS_VIEWING_KEY_ONLY {
        return Err((3, "not key source 0x02"));
    }
    if !is_canonical_scalar(&p.share) {
        return Err((3, "non-canonical signing share"));
    }
    let fvk_bytes: [u8; 96] = p.key.clone().try_into().unwrap();
    let fvk = orchard::keys::FullViewingKey::from_bytes(&fvk_bytes).ok_or((4, "invalid viewing key"))?;
    if let Some(vs) = known_vs {
        let share = SigningShare::deserialize(&p.share).map_err(|_| (3, "non-canonical signing share"))?;
        let mine = VerifyingShare::from(share).serialize().unwrap();
        if mine.as_slice() != vs {
            return Err((5, "verifying share mismatch"));
        }
    }
    Ok((p, fvk))
}

// ---------------------------------------------------------------------------------------------
// The synthetic group
// ---------------------------------------------------------------------------------------------

struct Member {
    id_form: u8,
    id_payload: Vec<u8>,
    id_scalar: [u8; 32],
    identifier: Identifier,
    share: [u8; 32],
    verifying_share: [u8; 32],
}

struct Group {
    name: &'static str,
    t: u8,
    n: u8,
    ak: [u8; 32],
    nk: [u8; 32],
    rivk: [u8; 32],
    fvk: [u8; 96],
    negated: bool,
    commitments: Vec<[u8; 32]>,
    members: Vec<Member>,
}

fn ser32(v: Vec<u8>) -> [u8; 32] {
    v.try_into().expect("32 bytes")
}

/// G_SpendAuth * x, through frost's own conversion (a VerifyingShare of a SigningShare).
fn public_of(x: &pallas::Scalar) -> [u8; 32] {
    let s = SigningShare::deserialize(&x.to_repr()).unwrap();
    ser32(VerifyingShare::from(s).serialize().unwrap())
}

/// nk and rivk from sk, path 2: PRF^expand written here (BLAKE2b-512, "Zcash_ExpandSeed"),
/// then ToBase / ToScalar (LEOS2IP_512 mod p, mod q), domain bytes 0x07 and 0x08.
fn nk_rivk_manual(sk: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    let prf = |t: u8| {
        let mut st = blake2b_simd::Params::new().hash_length(64).personal(b"Zcash_ExpandSeed").to_state();
        st.update(sk).update(&[t]);
        let out: [u8; 64] = st.finalize().as_bytes().try_into().unwrap();
        out
    };
    let nk = pallas::Base::from_uniform_bytes(&prf(0x07)).to_repr();
    let rivk = pallas::Scalar::from_uniform_bytes(&prf(0x08)).to_repr();
    (nk, rivk)
}

/// nk and rivk from sk, path 1: orchard's own derivation. `FullViewingKey::from(&SpendingKey)`
/// gives (ak_sk, nk, rivk); nk and rivk are taken from it, and ak_sk is dropped. This is exactly
/// what zcash-sign's `generate` computes through its orchard fork's
/// `from_sk_ak_incompatible_with_quantum_recoverability_and_will_be_removed` (nk: sk.into(),
/// rivk: sk.into(), with the group's ak).
fn nk_rivk_orchard(sk: &orchard::keys::SpendingKey) -> ([u8; 32], [u8; 32]) {
    let b = orchard::keys::FullViewingKey::from(sk).to_bytes();
    (b[32..64].try_into().unwrap(), b[64..96].try_into().unwrap())
}

/// zcash-sign `generate`: draw 32 bytes until they are a valid Orchard spending key.
fn draw_sk(label: &str) -> [u8; 32] {
    use rand_core::RngCore;
    let mut rng = seeded_rng(label);
    loop {
        let mut b = [0u8; 32];
        rng.fill_bytes(&mut b);
        if bool::from(orchard::keys::SpendingKey::from_bytes(b).is_some()) {
            return b;
        }
    }
}

fn build_group(name: &'static str, full_ids: bool, log: &mut String) -> Group {
    let (t, n) = (2u8, 3u8);
    let mut rng = seeded_rng(&format!("{name}/polynomial"));
    let mut a0 = scalar_from_stream(&mut rng);
    let mut a1 = scalar_from_stream(&mut rng);
    assert!(a0 != pallas::Scalar::ZERO);

    let ak_raw = public_of(&a0);
    let negated = ak_raw[31] & 0x80 != 0;
    if negated {
        // The reference rule (reddsa's `EvenY`, applied by frost-client after the DKG and by
        // reddsa's trusted dealer): negate the group key and therefore every share.
        a0 = -a0;
        a1 = -a1;
    }
    let ak = public_of(&a0);
    assert_eq!(ak[31] & 0x80, 0);
    writeln!(log, "group {name}: raw group key sign bit {} -> {}", (ak_raw[31] >> 7), if negated { "negated" } else { "kept" }).unwrap();

    let identifiers: Vec<(u8, Vec<u8>, Identifier)> = (1..=n)
        .map(|k| {
            if full_ids {
                // As frost-client's DKG does, a derived identifier (here from a fixed label).
                let id = Identifier::derive(format!("{SEED_TAG}/{name}/identifier/{k}").as_bytes()).unwrap();
                let b = id.serialize();
                (ID_FULL, b, id)
            } else {
                (ID_SHORT, vec![k], Identifier::try_from(k as u16).unwrap())
            }
        })
        .collect();

    let commitments = vec![public_of(&a0), public_of(&a1)];
    let mut members = Vec::new();
    for (form, id_payload, identifier) in identifiers {
        let x = pallas::Scalar::from_repr(ser32(identifier.serialize())).unwrap();
        let share = (a0 + a1 * x).to_repr();
        let ss = SigningShare::deserialize(&share).unwrap();
        let vs = ser32(VerifyingShare::from(ss).serialize().unwrap());
        members.push(Member { id_form: form, id_payload, id_scalar: x.to_repr(), identifier, share, verifying_share: vs });
    }

    // The viewing key, as zcash-sign `generate` makes it: a random sk (here seeded), nk and rivk
    // from it by the legacy derivation, the group key as ak. Then sk is dropped: it is not
    // returned, printed or written. Only the seed label that made it is documented.
    let sk = draw_sk(&format!("{name}/sk"));
    let osk = orchard::keys::SpendingKey::from_bytes(sk).unwrap();
    let (nk, rivk) = nk_rivk_orchard(&osk);
    assert_eq!((nk, rivk), nk_rivk_manual(&sk), "nk/rivk: orchard and the manual PRF^expand disagree");
    drop(osk);
    let mut fvk = [0u8; 96];
    fvk[..32].copy_from_slice(&ak);
    fvk[32..64].copy_from_slice(&nk);
    fvk[64..].copy_from_slice(&rivk);

    Group { name, t, n, ak, nk, rivk, fvk, negated, commitments, members }
}

// ---------------------------------------------------------------------------------------------
// Checks (each returns Err with what failed; `--red-check` runs each on a one-byte change)
// ---------------------------------------------------------------------------------------------

type Check = Result<(), String>;

fn check_ak_valid(ak: &[u8; 32]) -> Check {
    orchard::keys::SpendValidatingKey::from_bytes(ak).map(|_| ()).ok_or_else(|| "orchard rejects ak as a SpendValidatingKey".into())
}

fn check_fvk_valid(fvk: &[u8; 96]) -> Check {
    let k = orchard::keys::FullViewingKey::from_bytes(fvk).ok_or("orchard FullViewingKey::from_bytes rejects ak||nk||rivk")?;
    if &k.to_bytes() != fvk {
        return Err("FullViewingKey does not round-trip".into());
    }
    Ok(())
}

fn check_pairs_reconstruct(g: &Group, shares: &[[u8; 32]]) -> Check {
    for i in 0..shares.len() {
        for j in i + 1..shares.len() {
            let kp = |k: usize| -> Result<KeyPackage, String> {
                let ss = SigningShare::deserialize(&shares[k]).map_err(|e| format!("{e:?}"))?;
                Ok(KeyPackage::new(
                    g.members[k].identifier,
                    ss,
                    VerifyingShare::from(ss),
                    VerifyingKey::deserialize(&g.ak).map_err(|e| format!("{e:?}"))?,
                    g.t as u16,
                ))
            };
            let secret: SigningKey = frost_rerandomized::frost_core::keys::reconstruct::<frost::PallasBlake2b512>(&[kp(i)?, kp(j)?]).map_err(|e| format!("{e:?}"))?;
            let pk = ser32(VerifyingKey::from(&secret).serialize().unwrap());
            if pk != g.ak {
                return Err(format!("members {} and {} reconstruct a secret whose public key is not ak", i + 1, j + 1));
            }
        }
    }
    Ok(())
}

fn check_verifying_shares(g: &Group, shares: &[[u8; 32]]) -> Check {
    let vss = VerifiableSecretSharingCommitment::deserialize(g.commitments.iter().map(|c| c.to_vec()).collect::<Vec<_>>()).unwrap();
    for (k, m) in g.members.iter().enumerate() {
        let ss = SigningShare::deserialize(&shares[k]).map_err(|e| format!("{e:?}"))?;
        let vs = ser32(VerifyingShare::from(ss).serialize().unwrap());
        if vs != m.verifying_share {
            return Err(format!("member {}: G*share != verifying share", k + 1));
        }
        let (vs2, vk) = SecretShare::new(m.identifier, ss, vss.clone()).verify().map_err(|e| format!("member {}: VSS: {e:?}", k + 1))?;
        if ser32(vs2.serialize().unwrap()) != m.verifying_share || ser32(vk.serialize().unwrap()) != g.ak {
            return Err(format!("member {}: VSS commitment disagrees", k + 1));
        }
    }
    Ok(())
}

/// Every t-subset signs with rerandomized FROST (RedPallas); the signature verifies under ak
/// randomized by alpha in frost, and under orchard's own SpendValidatingKey::randomize(alpha).
fn check_pairs_sign(g: &Group, shares: &[[u8; 32]]) -> Check {
    use frost_rerandomized::{Randomizer, RandomizedParams};
    let vk = VerifyingKey::deserialize(&g.ak).map_err(|e| format!("{e:?}"))?;
    let vshares: BTreeMap<_, _> = g.members.iter().map(|m| (m.identifier, VerifyingShare::deserialize(&m.verifying_share).unwrap())).collect();
    let pkp = PublicKeyPackage::new(vshares, vk, Some(g.t as u16));
    let msg = b"zips#1413 v2 vectors: synthetic sighash";
    let mut rng = seeded_rng(&format!("{}/signing", g.name));
    let alpha = scalar_from_stream(&mut rng);
    let params = RandomizedParams::from_randomizer(&vk, Randomizer::from_scalar(alpha));
    for i in 0..shares.len() {
        for j in i + 1..shares.len() {
            let mut nonces = BTreeMap::new();
            let mut commits = BTreeMap::new();
            for &k in &[i, j] {
                let ss = SigningShare::deserialize(&shares[k]).map_err(|e| format!("{e:?}"))?;
                let (nn, cc) = frost::round1::commit(&ss, &mut rng);
                nonces.insert(k, (ss, nn));
                commits.insert(g.members[k].identifier, cc);
            }
            let sp = frost::SigningPackage::new(commits, msg);
            let mut sig_shares = BTreeMap::new();
            for (&k, (ss, nn)) in &nonces {
                let kp = KeyPackage::new(g.members[k].identifier, *ss, VerifyingShare::from(*ss), vk, g.t as u16);
                #[allow(deprecated)]
                let s = frost_rerandomized::sign(&sp, nn, &kp, Randomizer::from_scalar(alpha)).map_err(|e| format!("{e:?}"))?;
                sig_shares.insert(g.members[k].identifier, s);
            }
            let sig = frost_rerandomized::aggregate(&sp, &sig_shares, &pkp, &params)
                .map_err(|e| format!("members {} and {}: aggregate: {e:?}", i + 1, j + 1))?;
            params.randomized_verifying_key().verify(msg, &sig).map_err(|e| format!("frost verify: {e:?}"))?;
            // Cross-crate: orchard (reddsa 0.6, pasta_curves 0.6) from the same bytes.
            let sig_bytes: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();
            let ovk = orchard::keys::SpendValidatingKey::from_bytes(&g.ak).ok_or("orchard rejects ak")?;
            let oalpha: pasta06::pallas::Scalar =
                Option::from(<pasta06::pallas::Scalar as ff14::PrimeField>::from_repr(alpha.to_repr())).unwrap();
            let rk = ovk.randomize(&oalpha);
            rk.verify(msg, &orchard::primitives::redpallas::Signature::from(sig_bytes))
                .map_err(|e| format!("orchard verify: {e:?}"))?;
        }
    }
    Ok(())
}

fn check_even_y_rule(g: &Group, shares: &[[u8; 32]]) -> Check {
    // Path 2 for the negation: hand reddsa the un-normalized key packages and let its `EvenY`
    // decide. Its output must equal our shares.
    for (k, m) in g.members.iter().enumerate() {
        let mine = pallas::Scalar::from_repr(shares[k]).into_option().ok_or("non-canonical share")?;
        let raw = if g.negated { -mine } else { mine };
        let raw_ss = SigningShare::deserialize(&raw.to_repr()).unwrap();
        let raw_group_key = {
            // The raw group key is -ak when negated: same x, sign bit set.
            let mut b = g.ak;
            if g.negated {
                b[31] |= 0x80;
            }
            VerifyingKey::deserialize(&b).map_err(|e| format!("{e:?}"))?
        };
        let kp = KeyPackage::new(m.identifier, raw_ss, VerifyingShare::from(raw_ss), raw_group_key, g.t as u16);
        let even = kp.into_even_y(None);
        if ser32(even.signing_share().serialize()) != m.share || ser32(even.verifying_key().serialize().unwrap()) != g.ak {
            return Err(format!("member {}: reddsa EvenY disagrees with our negation", k + 1));
        }
    }
    Ok(())
}

fn check_encoders_agree(payload: &[u8]) -> Check {
    let a = encode_crate(payload);
    let b = encode_own(HRP, payload);
    if a != b {
        return Err("bech32 crate and the BIP 350 code here give different strings".into());
    }
    Ok(())
}

fn check_roundtrip(s: &str, expected: &Payload) -> Check {
    let d = decode(s).map_err(|e| format!("decode: {e:?}"))?;
    if &d != expected {
        return Err("decoded fields differ from the inputs".into());
    }
    // The crate must agree that the checksum is Bech32m and give the same bytes.
    let c = bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(s).map_err(|e| format!("bech32 crate: {e}"))?;
    if c.byte_iter().collect::<Vec<u8>>() != expected.to_bytes() {
        return Err("bech32 crate decodes other bytes".into());
    }
    Ok(())
}

fn check_counts(payload: &[u8], s: &str, id_form: u8) -> Check {
    let (pl, sl) = if id_form == ID_SHORT { (139, 237) } else { (170, 286) };
    if payload.len() != pl || s.len() != sl {
        return Err(format!("payload {} bytes / string {} chars, the comment says {pl} / {sl}", payload.len(), s.len()));
    }
    Ok(())
}

fn check_nk_rivk_paths(sk: &[u8; 32]) -> Check {
    let o = orchard::keys::SpendingKey::from_bytes(*sk).into_option().ok_or("not an Orchard sk")?;
    if nk_rivk_orchard(&o) != nk_rivk_manual(sk) {
        return Err("orchard and manual PRF^expand disagree".into());
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------
// Output helpers (the row-per-line JSON layout of zcash-test-vectors)
// ---------------------------------------------------------------------------------------------

use serde_json::{json, Value};

fn h(b: &[u8]) -> Value {
    Value::String(hex::encode(b))
}

fn render(header: &str, fields: &[&str], rows: &[Vec<Value>]) -> String {
    let mut out = String::from("[\n");
    let mut lines = vec![
        serde_json::to_string(&json!([header])).unwrap(),
        serde_json::to_string(&json!([fields.join(", ")])).unwrap(),
    ];
    for r in rows {
        let cells: Vec<String> = r.iter().map(|v| serde_json::to_string(v).unwrap()).collect();
        lines.push(format!("[{}]", cells.join(", ")));
    }
    out.push_str(&lines.iter().map(|l| format!("    {l}")).collect::<Vec<_>>().join(",\n"));
    out.push_str("\n]\n");
    out
}

const SOURCE: &str = "PROVISIONAL. Generated by frost-member-backup-v2-vectors (Konclave) for key source 0x02 of the version 2 payload in zcash/zips#1413, as revised by its author on 2026-11-20. Not part of zcash/zips#1432. Regenerate if that payload changes.";

fn ufvk(fvk: &[u8; 96], net: u8) -> Value {
    use zcash_address::unified::{Encoding, Fvk, Revision, Ufvk, Uitem};
    use zcash_protocol::consensus::NetworkType;
    let nt = match net {
        NET_MAINNET => NetworkType::Main,
        NET_TESTNET => NetworkType::Test,
        _ => NetworkType::Regtest,
    };
    let u = Ufvk::try_from_items(Revision::R0, vec![Uitem::Data(Fvk::Orchard(*fvk))]).unwrap();
    Value::String(u.encode(&nt))
}

fn member_payload(g: &Group, m: &Member, net: u8, birthday: u32) -> Payload {
    Payload {
        key_source: KS_VIEWING_KEY_ONLY,
        network: net,
        t: g.t,
        n: g.n,
        id_form: m.id_form,
        id: m.id_payload.clone(),
        share: m.share,
        birthday,
        sk: None,
        key: g.fvk.to_vec(),
    }
}

fn leftover_bits(len: usize) -> usize {
    let chars = (len * 8 + 4) / 5;
    chars * 5 - len * 8
}

// ---------------------------------------------------------------------------------------------

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut log = String::new();
    let a = build_group("A", false, &mut log);
    let b = build_group("B", true, &mut log);

    if args.get(1).map(String::as_str) == Some("--red-check") {
        red_check(&a, &b);
        return;
    }
    let out_dir = args.get(1).cloned().unwrap_or_else(|| ".".into());

    // ---- group checks ----
    for g in [&a, &b] {
        let shares: Vec<[u8; 32]> = g.members.iter().map(|m| m.share).collect();
        let checks: [(&str, Check); 6] = [
            ("ak is a valid Orchard SpendValidatingKey (sign bit 0)", check_ak_valid(&g.ak)),
            ("orchard FullViewingKey::from_bytes accepts ak||nk||rivk", check_fvk_valid(&g.fvk)),
            ("any two shares reconstruct one secret whose public key is ak", check_pairs_reconstruct(g, &shares)),
            ("each verifying share matches its signing share (and the VSS commitment)", check_verifying_shares(g, &shares)),
            ("every pair signs (rerandomized FROST), verifies in frost and orchard", check_pairs_sign(g, &shares)),
            ("our sign-bit negation equals reddsa's EvenY", check_even_y_rule(g, &shares)),
        ];
        for (name, r) in checks {
            match r {
                Ok(()) => writeln!(log, "group {}: PASS {name}", g.name).unwrap(),
                Err(e) => panic!("group {}: FAIL {name}: {e}", g.name),
            }
        }
    }

    // ---- valid vectors ----
    let mut rows = Vec::new();
    let mut emit = |g: &Group, net: u8, birthday: u32, log: &mut String| {
        for (k, m) in g.members.iter().enumerate() {
            let p = member_payload(g, m, net, birthday);
            let bytes = p.to_bytes();
            let s = encode_crate(&bytes);
            for (name, r) in [
                ("encoders agree", check_encoders_agree(&bytes)),
                ("decode gives back every field", check_roundtrip(&s, &p)),
                ("byte and character counts", check_counts(&bytes, &s, m.id_form)),
            ] {
                if let Err(e) = r {
                    panic!("group {} member {} net {net}: FAIL {name}: {e}", g.name, k + 1);
                }
            }
            let (rp, rfvk) = restore(&s, net, Some(&m.verifying_share)).expect("restore");
            assert_eq!(rp, p);
            assert_eq!(rfvk.to_bytes(), g.fvk);
            writeln!(log, "group {} member {} {}: {} bytes, {} chars, {} leftover bits, restore ok", g.name, k + 1,
                ["Mainnet", "Testnet", "Regtest"][net as usize], bytes.len(), s.len(), leftover_bits(bytes.len())).unwrap();
            rows.push(vec![
                json!(format!("{:#04x}", KS_VIEWING_KEY_ONLY)),
                json!(["mainnet", "testnet", "regtest"][net as usize]),
                json!(g.t),
                json!(g.n),
                json!(m.id_form),
                h(&m.id_payload),
                h(&m.id_scalar),
                h(&m.share),
                h(&m.verifying_share),
                h(&g.ak),
                h(&g.nk),
                h(&g.rivk),
                json!(birthday),
                h(&bytes),
                json!(s),
                json!(bytes.len()),
                json!(s.len()),
                json!(leftover_bits(bytes.len())),
                ufvk(&g.fvk, net),
            ]);
        }
    };
    emit(&a, NET_TESTNET, BIRTHDAY_TESTNET, &mut log);
    emit(&a, NET_MAINNET, BIRTHDAY_MAINNET, &mut log);
    emit(&b, NET_TESTNET, BIRTHDAY_TESTNET, &mut log);
    let main_json = render(
        SOURCE,
        &["key_source", "network", "t", "n", "identifier_form", "identifier", "identifier_scalar", "signing_share",
          "verifying_share", "ak", "nk", "rivk", "birthday_height", "payload", "encoding", "payload_length",
          "encoding_length", "leftover_bits", "ufvk"],
        &rows,
    );

    // ---- decoding vectors ----
    let m1 = &a.members[0];
    let base = member_payload(&a, m1, NET_TESTNET, BIRTHDAY_TESTNET);
    let base_bytes = base.to_bytes();
    let base_s = encode_crate(&base_bytes);
    let b1 = member_payload(&b, &b.members[0], NET_TESTNET, BIRTHDAY_TESTNET);
    let b1_bytes = b1.to_bytes();
    let b1_s = encode_crate(&b1_bytes);
    let enc = |p: &[u8]| encode_crate(p);
    let with = |f: &dyn Fn(&mut Payload)| {
        let mut p = base.clone();
        f(&mut p);
        p.to_bytes()
    };
    let set_byte = |i: usize, v: u8| {
        let mut p = base_bytes.clone();
        p[i] = v;
        p
    };
    let full_id = |id: [u8; 32]| {
        let mut p = b1.clone();
        p.id = id.to_vec();
        p.to_bytes()
    };
    let int_id = |v: u8| {
        let mut x = [0u8; 32];
        x[0] = v;
        x
    };
    let flip_last = |s: &str| {
        let mut c: Vec<char> = s.chars().collect();
        let l = c.len() - 1;
        c[l] = if c[l] == 'q' { 'p' } else { 'q' };
        c.into_iter().collect::<String>()
    };
    let data5 = to_5bit(&base_bytes);
    let mut nonzero_pad = data5.clone();
    *nonzero_pad.last_mut().unwrap() |= 1; // short form leaves 3 bits; set the lowest
    let mut extra_char = to_5bit(&b1_bytes);
    extra_char.push(0); // full form leaves 0 bits; one more character leaves 5
    let mixed_data = {
        let i = HRP.len() + 1 + 10;
        let mut c: Vec<char> = base_s.chars().collect();
        c[i] = c[i].to_ascii_uppercase();
        if c[i] == base_s.chars().nth(i).unwrap() {
            c[i + 1] = c[i + 1].to_ascii_uppercase();
        }
        c.into_iter().collect::<String>()
    };
    let with_sk = with(&|p| p.sk = Some([0x5a; 32]));
    let ak_only = with(&|p| p.key = a.ak.to_vec());
    let ks1_no_sk = set_byte(1, KS_LEGACY);
    let id_gt_n = with(&|p| p.id = vec![4]);
    let birthday0 = with(&|p| p.birthday = 0);
    let regtest = with(&|p| p.network = NET_REGTEST);

    let neg_one_scalar = (-pallas::Scalar::ONE).to_repr(); // q - 1, the largest canonical scalar
    let mainnet_p = member_payload(&a, m1, NET_MAINNET, BIRTHDAY_MAINNET);
    let mainnet_s = encode_crate(&mainnet_p.to_bytes());
    let regtest_s = enc(&regtest);
    let short_hrp = |data: &[u8]| bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse("zkfros").unwrap(), data).unwrap();
    // 5-bit data with a non-zero padding bit, under a given hrp (a string rule 1 rejects)
    let bad_pad_with_hrp = |hrp: &str| encode_5bit(hrp, &nonzero_pad, BECH32M_CONST);
    let v1_shaped = {
        let mut v = vec![0x01u8];
        v.extend_from_slice(&base_bytes[1..68]);
        v
    };
    let ks3_short = set_byte(1, 0x03)[..138].to_vec();
    let ks3_140 = {
        let mut v = set_byte(1, 0x03);
        v.push(0);
        v
    };
    let net3_t1 = {
        let mut v = set_byte(2, 0x03);
        v[3] = 1;
        v
    };
    let form2_id0 = {
        let mut v = set_byte(5, 0x02);
        v[6] = 0;
        v
    };
    let all_unknown = {
        let mut v = set_byte(1, 0x03);
        v[2] = 0x03;
        v[5] = 0x02;
        v
    };
    let v3_ks3_short = {
        let mut v = set_byte(0, 0x03);
        v[1] = 0x03;
        v.truncate(138);
        v
    };
    let mut ver3_hrp_ok = base_bytes.clone();
    ver3_hrp_ok[0] = 0x03;
    let wrong_len_t1 = {
        let mut v = base_bytes[..138].to_vec();
        v[3] = 1;
        v
    };
    let wrong_len_id0 = {
        let mut v = base_bytes[..138].to_vec();
        v[6] = 0;
        v
    };
    let ks0_139 = set_byte(1, KS_ZIP2005);
    let t1_id0 = {
        let mut v = base_bytes.clone();
        v[3] = 1;
        v[6] = 0;
        v
    };
    let t4_noncanon = {
        let mut p = b1.clone();
        p.t = 4;
        p.id = Q_LE.to_vec();
        p.to_bytes()
    };
    let int256 = {
        let mut x = [0u8; 32];
        x[1] = 1;
        x
    };

    // (string, expected payload when it decodes, rule when it must be rejected, reason)
    type Dec = (String, Option<Vec<u8>>, Option<Rej>, String);
    let ok = |s: String, p: &Vec<u8>, why: &str| -> Dec { (s, Some(p.clone()), None, why.to_string()) };
    let rej = |s: String, rule: u8, name: &'static str, why: &str| -> Dec {
        (s, None, Some((rule, name)), format!("rule {rule}: {why}"))
    };
    let short255 = with(&|p| p.id = vec![255]);
    let decoding_cases: Vec<Dec> = vec![
        // ---- strings that decode ----
        ok(base_s.clone(), &base_bytes, "valid, lowercase (group A member 1, Testnet)"),
        ok(base_s.to_ascii_uppercase(), &base_bytes, "valid, uppercase"),
        ok(b1_s.clone(), &b1_bytes, "valid, full identifier (group B member 1, Testnet)"),
        ok(enc(&birthday0), &birthday0, "valid, birthday height 0 (unknown)"),
        ok(regtest_s.clone(), &regtest, "valid structure, network Regtest"),
        ok(enc(&id_gt_n), &id_gt_n, "decodes: identifier 4 greater than n = 3 is not checked in version 2"),
        ok(enc(&short255), &short255, "decodes: short identifier 255, the largest the short form holds"),
        ok(enc(&full_id(int256)), &full_id(int256), "decodes: full identifier 256, the smallest integer the short form cannot hold"),
        ok(enc(&full_id(neg_one_scalar)), &full_id(neg_one_scalar), "decodes: full identifier q - 1, the largest canonical scalar"),
        // ---- rule 1: Bech32m validity (case, checksum), leftover bits ----
        rej(flip_last(&base_s), 1, "not Bech32m", "invalid checksum"),
        rej(encode_5bit(HRP, &data5, BECH32_CONST), 1, "not Bech32m", "Bech32 checksum instead of Bech32m"),
        rej(format!("{}{}", HRP.to_ascii_uppercase(), &base_s[HRP.len()..]), 1, "not Bech32m", "mixed case (upper-case prefix, lower-case rest)"),
        rej(mixed_data, 1, "not Bech32m", "mixed case in the data part"),
        rej(encode_5bit(HRP, &nonzero_pad, BECH32M_CONST), 1, "invalid padding", "non-zero padding bit (short form, 3 leftover bits)"),
        rej(encode_5bit(HRP, &extra_char, BECH32M_CONST), 1, "invalid padding", "more than 4 padding bits (full form plus one character, 5 leftover bits)"),
        rej(bad_pad_with_hrp("zkfros"), 1, "invalid padding", "two rules: non-zero padding bit AND wrong prefix `zkfros`; the padding is first in order"),
        rej(flip_last(&short_hrp(&base_bytes)), 1, "not Bech32m", "two rules: invalid checksum AND wrong prefix `zkfros`; the checksum is first in order"),
        // ---- rule 2: human-readable part ----
        rej(short_hrp(&base_bytes), 2, "wrong human-readable part", "prefix `zkfros` instead of `zkfrost`"),
        rej(bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse("zkfrostx").unwrap(), &base_bytes).unwrap(), 2, "wrong human-readable part", "prefix `zkfrostx`"),
        rej(short_hrp(&ver3_hrp_ok), 2, "wrong human-readable part", "two rules: wrong prefix AND version 3; the prefix is first in order"),
        // ---- rule 3: format version ----
        rej(enc(&set_byte(0, 0x01)), 3, "unsupported version", "version byte 0x01 on a version 2 payload"),
        rej(enc(&v1_shaped), 3, "unsupported version", "a 68-byte payload starting 0x01: the version is checked before the length"),
        rej(enc(&ver3_hrp_ok), 3, "unsupported version", "version 3"),
        rej(enc(&v3_ks3_short), 3, "unsupported version", "three rules: version 3, key source 0x03 AND a 138-byte payload; the version is first in order"),
        // ---- rule 4: key source, network or identifier form unknown ----
        rej(enc(&set_byte(1, 0x03)), 4, "unknown key source", "key source 0x03"),
        rej(enc(&set_byte(2, 0x03)), 4, "unknown network", "network 0x03"),
        rej(enc(&set_byte(5, 0x02)), 4, "unknown identifier form", "identifier form 0x02"),
        rej(enc(&ks3_short), 4, "unknown key source", "two rules: key source 0x03 AND a 138-byte payload; the unknown value is first in order"),
        rej(enc(&ks3_140), 4, "unknown key source", "two rules: key source 0x03 AND a 140-byte payload (a length no layout has); the unknown value is first in order"),
        rej(enc(&net3_t1), 4, "unknown network", "two rules: network 0x03 AND threshold 1; the unknown value is first in order"),
        rej(enc(&form2_id0), 4, "unknown identifier form", "two rules: identifier form 0x02 AND identifier byte 0; the unknown value is first in order"),
        rej(enc(&all_unknown), 4, "unknown key source", "key source 0x03, network 0x03 and identifier form 0x02 together"),
        // ---- rule 5: exact length ----
        rej(enc(&with_sk), 5, "wrong payload length", "key source 0x02 with a 32-byte sk field before the viewing key (171 bytes)"),
        rej(enc(&ak_only), 5, "wrong payload length", "key source 0x02 with a 32-byte ak instead of the 96-byte viewing key (75 bytes)"),
        rej(enc(&ks1_no_sk), 5, "wrong payload length", "key source 0x01 on a 139-byte payload with no sk"),
        rej(enc(&ks0_139), 5, "wrong payload length", "key source 0x00 on a 139-byte payload with no sk"),
        rej(enc(&base_bytes[..138]), 5, "wrong payload length", "payload of 138 bytes for key source 0x02, short form"),
        rej(enc(&[base_bytes.as_slice(), &[0]].concat()), 5, "wrong payload length", "payload of 140 bytes for key source 0x02, short form"),
        rej(enc(&wrong_len_t1), 5, "wrong payload length", "two rules: 138 bytes AND threshold 1; the length is first in order"),
        rej(enc(&wrong_len_id0), 5, "wrong payload length", "two rules: 138 bytes AND identifier 0; the length is first in order"),
        // ---- rule 6: threshold and group size ----
        rej(enc(&with(&|p| p.t = 1)), 6, "invalid threshold or group size", "threshold 1"),
        rej(enc(&with(&|p| p.t = 0)), 6, "invalid threshold or group size", "threshold 0"),
        rej(enc(&with(&|p| p.t = 4)), 6, "invalid threshold or group size", "threshold 4 greater than n = 3"),
        rej(enc(&with(&|p| p.n = 0)), 6, "invalid threshold or group size", "group size 0"),
        rej(enc(&t1_id0), 6, "invalid threshold or group size", "two rules: threshold 1 AND short identifier 0; the threshold is first in order"),
        rej(enc(&t4_noncanon), 6, "invalid threshold or group size", "two rules: threshold 4 > n = 3 AND a non-canonical full identifier; the threshold is first in order"),
        // ---- rule 7: identifier ----
        rej(enc(&with(&|p| p.id = vec![0])), 7, "zero identifier", "short identifier 0"),
        rej(enc(&full_id(int_id(1))), 7, "full identifier that fits the short form", "full identifier 1, which the short form holds"),
        rej(enc(&full_id(int_id(255))), 7, "full identifier that fits the short form", "full identifier 255, which the short form holds"),
        rej(enc(&full_id([0; 32])), 7, "zero identifier", "full identifier 0"),
        rej(enc(&full_id(Q_LE)), 7, "non-canonical identifier", "full identifier equal to the Pallas scalar modulus (non-canonical)"),
        rej(enc(&full_id([0xff; 32])), 7, "non-canonical identifier", "full identifier of 32 bytes 0xff (non-canonical)"),
    ];
    let mut drows = Vec::new();
    for (s, expected, rule, reason) in &decoding_cases {
        // Own decoder and the bech32 crate must agree on whether the checksum layer accepts.
        let own_ok = bech32m_decode(s).is_ok();
        let crate_ok = bech32::primitives::decode::CheckedHrpstring::new::<bech32::Bech32m>(s).is_ok();
        assert_eq!(own_ok, crate_ok, "checksum layer disagreement on: {reason}");
        match (decode(s), expected, rule) {
            (Ok(p), Some(e), None) => assert_eq!(&p.to_bytes(), e, "{reason}"),
            (Err(got), None, Some(want)) => assert_eq!(got, *want, "{reason}"),
            (r, _, _) => panic!("{reason}: unexpected {r:?}"),
        }
        drows.push(vec![
            json!(s),
            expected.as_ref().map(|e| h(e)).unwrap_or(Value::Null),
            rule.map(|(r, _)| json!(r)).unwrap_or(Value::Null),
            json!(reason),
        ]);
    }
    let n_dec_ok = decoding_cases.iter().filter(|c| c.2.is_none()).count();
    writeln!(log, "decoding: {} cases ({} decode, {} rejected), all as expected; own Bech32m and the bech32 crate agree on every checksum",
        decoding_cases.len(), n_dec_ok, decoding_cases.len() - n_dec_ok).unwrap();
    let decoding_json = render(SOURCE, &["encoding", "payload", "rule", "reason"], &drows);

    // ---- restore vectors ----
    let fvk_with = |f: &dyn Fn(&mut [u8; 96])| {
        let mut k = a.fvk;
        f(&mut k);
        enc(&with(&|p| p.key = k.to_vec()))
    };
    let fvk_with_on = |f: &dyn Fn(&mut [u8; 96]), g: &dyn Fn(&mut Payload)| {
        let mut k = a.fvk;
        f(&mut k);
        enc(&with(&|p| {
            p.key = k.to_vec();
            g(p)
        }))
    };
    let not_on_curve_x = find_x_not_on_curve();
    let neg_share = (-pallas::Scalar::from_repr(m1.share).unwrap()).to_repr();
    let vs1 = m1.verifying_share;
    let vs2 = a.members[1].verifying_share;
    let main_net = NET_MAINNET;
    let test_net = NET_TESTNET;
    let reg_net = NET_REGTEST;
    // (string, wallet network, known verifying share, restore step that rejects, reason)
    type Res = (String, u8, Option<[u8; 32]>, Option<Rej>, String);
    let rok = |s: String, net: u8, vs: Option<[u8; 32]>, why: &str| -> Res { (s, net, vs, None, why.to_string()) };
    let rrej = |s: String, net: u8, vs: Option<[u8; 32]>, step: u8, name: &'static str, why: &str| -> Res {
        (s, net, vs, Some((step, name)), format!("step {step}: {why}"))
    };
    let restore_cases: Vec<Res> = vec![
        // ---- strings the restore accepts ----
        rok(base_s.clone(), test_net, Some(vs1), "valid, Testnet string on a Testnet wallet, the wallet knows the member's verifying share"),
        rok(base_s.clone(), test_net, None, "valid, verifying shares not known"),
        rok(b1_s.clone(), test_net, Some(b.members[0].verifying_share), "valid, full identifier"),
        rok(mainnet_s.clone(), main_net, Some(vs1), "valid, Mainnet string on a Mainnet wallet"),
        rok(regtest_s.clone(), reg_net, Some(vs1), "valid, Regtest string on a Regtest wallet"),
        rok(enc(&with(&|p| p.share = neg_share)), test_net, None, "signing share with the wrong sign, verifying share not known: passes the restore, fails at first signing"),
        // ---- step 1: decode ----
        rrej(enc(&base_bytes[..138]), test_net, None, 1, "wrong payload length", "the string does not decode (138-byte payload, decoding rule 5)"),
        // ---- step 2: network mismatch ----
        rrej(mainnet_s.clone(), test_net, None, 2, "network is not the wallet's", "Mainnet string, Testnet wallet"),
        rrej(mainnet_s.clone(), reg_net, None, 2, "network is not the wallet's", "Mainnet string, Regtest wallet"),
        rrej(base_s.clone(), main_net, None, 2, "network is not the wallet's", "Testnet string, Mainnet wallet"),
        rrej(base_s.clone(), reg_net, None, 2, "network is not the wallet's", "Testnet string, Regtest wallet"),
        rrej(regtest_s.clone(), main_net, None, 2, "network is not the wallet's", "Regtest string, Mainnet wallet: a test string is never restored on a real network"),
        rrej(regtest_s.clone(), test_net, None, 2, "network is not the wallet's", "Regtest string, Testnet wallet"),
        rrej(enc(&with(&|p| {
            p.network = NET_MAINNET;
            p.share = Q_LE;
        })), test_net, None, 2, "network is not the wallet's", "two steps: Mainnet string on a Testnet wallet AND a non-canonical signing share; the network is first"),
        rrej(fvk_with_on(&|k| k[..32].copy_from_slice(&[0; 32]), &|p| p.network = NET_MAINNET), test_net, None, 2, "network is not the wallet's", "two steps: Mainnet string on a Testnet wallet AND a viewing key whose ak is all zero; the network is first"),
        // ---- step 3: canonical signing share ----
        rrej(enc(&with(&|p| p.share = Q_LE)), test_net, None, 3, "non-canonical signing share", "non-canonical signing share (the Pallas scalar modulus)"),
        rrej(fvk_with_on(&|k| k[..32].copy_from_slice(&[0; 32]), &|p| p.share = Q_LE), test_net, None, 3, "non-canonical signing share", "two steps: a non-canonical signing share AND a viewing key whose ak is all zero; the share is first"),
        // ---- step 4: viewing key valid ----
        rrej(fvk_with(&|k| k[31] |= 0x80), test_net, None, 4, "invalid viewing key", "viewing key whose ak has the sign bit set (the raw odd-y group key)"),
        rrej(fvk_with(&|k| k[..32].copy_from_slice(&[0; 32])), test_net, None, 4, "invalid viewing key", "viewing key whose ak is all zero (the identity)"),
        rrej(fvk_with(&|k| k[..32].copy_from_slice(&not_on_curve_x)), test_net, None, 4, "invalid viewing key", "viewing key whose ak is not the x-coordinate of a Pallas point"),
        rrej(fvk_with(&|k| k[32..64].copy_from_slice(&P_LE)), test_net, None, 4, "invalid viewing key", "viewing key whose nk is the Pallas base field modulus (non-canonical)"),
        rrej(fvk_with(&|k| k[64..].copy_from_slice(&Q_LE)), test_net, None, 4, "invalid viewing key", "viewing key whose rivk is the Pallas scalar modulus (non-canonical)"),
        // ---- step 5: verifying share (a SHOULD, when the group's verifying shares are known) ----
        rrej(enc(&with(&|p| p.share = neg_share)), test_net, Some(vs1), 5, "verifying share mismatch", "signing share with the wrong sign, verifying share known"),
        rrej(base_s.clone(), test_net, Some(vs2), 5, "verifying share mismatch", "member 1's string checked against member 2's verifying share"),
    ];
    let mut rrows = Vec::new();
    for (s, net, vs, rule, reason) in &restore_cases {
        let r = restore(s, *net, vs.as_ref());
        match (&r, rule) {
            (Ok(_), None) => {}
            (Err(got), Some(want)) => assert_eq!(got, want, "{reason}"),
            _ => panic!("{reason}: unexpected {:?}", r.as_ref().map(|_| ())),
        }
        let fvk_out = r.ok().map(|(_, k)| h(&k.to_bytes())).unwrap_or(Value::Null);
        rrows.push(vec![
            json!(s),
            json!(["mainnet", "testnet", "regtest"][*net as usize]),
            vs.map(|v| h(&v)).unwrap_or(Value::Null),
            fvk_out,
            rule.map(|(r, _)| json!(r)).unwrap_or(Value::Null),
            json!(reason),
        ]);
    }
    let n_res_ok = restore_cases.iter().filter(|c| c.3.is_none()).count();
    writeln!(log, "restore: {} cases ({} accepted, {} rejected), all as expected", restore_cases.len(), n_res_ok, restore_cases.len() - n_res_ok).unwrap();
    let restore_json = render(SOURCE, &["encoding", "wallet_network", "verifying_share", "fvk", "step", "reason"], &rrows);

    std::fs::create_dir_all(&out_dir).unwrap();
    std::fs::write(format!("{out_dir}/frost_member_backup_v2_ks02.json"), main_json).unwrap();
    std::fs::write(format!("{out_dir}/frost_member_backup_v2_ks02_decoding.json"), decoding_json).unwrap();
    std::fs::write(format!("{out_dir}/frost_member_backup_v2_ks02_restore.json"), restore_json).unwrap();
    print!("{log}");
    println!("wrote 3 files to {out_dir}");
}

/// The first x (counting 2, 3, ...) with no point (x, y) on Pallas (y^2 = x^3 + 5), so ak = x
/// fails to decompress. Found here rather than hard-coded so the reason is visible.
fn find_x_not_on_curve() -> [u8; 32] {
    for x in 2u64.. {
        let xf = pallas::Base::from(x);
        let rhs = xf.square() * xf + pallas::Base::from(5u64);
        if bool::from(rhs.sqrt().is_none()) {
            return xf.to_repr();
        }
    }
    unreachable!()
}

// ---------------------------------------------------------------------------------------------
// Red-check: every check passes on the real input and fails when one input byte changes.
// ---------------------------------------------------------------------------------------------

fn red_check(a: &Group, b: &Group) {
    let rows = std::cell::RefCell::new(Vec::<(String, bool, bool)>::new());
    let mut notes = Vec::<String>::new();
    let run = |name: &str, good: Check, bad: Check| {
        rows.borrow_mut().push((name.to_string(), good.is_ok(), bad.is_err()));
    };
    for g in [a, b] {
        let shares: Vec<[u8; 32]> = g.members.iter().map(|m| m.share).collect();
        let mut bad_shares = shares.clone();
        bad_shares[1][0] ^= 0x01;

        let mut ak_bad = g.ak;
        ak_bad[31] |= 0x80; // one byte: the sign bit
        run(&format!("{}: ak valid  | byte 31 of ak |= 0x80", g.name), check_ak_valid(&g.ak), check_ak_valid(&ak_bad));

        let mut fvk_bad = g.fvk;
        fvk_bad[63] |= 0x80; // one byte: nk no longer canonical
        run(&format!("{}: fvk valid | byte 63 (top of nk) |= 0x80", g.name), check_fvk_valid(&g.fvk), check_fvk_valid(&fvk_bad));

        let mut fvk_bad2 = g.fvk;
        fvk_bad2[64] ^= 0x01; // one byte of rivk: still canonical, so validity alone cannot catch it
        let rivk_changed_ok = check_fvk_valid(&fvk_bad2).is_ok();
        notes.push(format!("{}: fvk with byte 64 of rivk ^ 0x01 is still accepted by orchard: {} (any canonical rivk with a non-zero ivk is a valid key; validity cannot pin rivk, only a comparison can)", g.name, rivk_changed_ok));

        run(&format!("{}: pairs reconstruct ak | byte 0 of share 2 ^ 0x01", g.name), check_pairs_reconstruct(g, &shares), check_pairs_reconstruct(g, &bad_shares));
        run(&format!("{}: verifying shares     | byte 0 of share 2 ^ 0x01", g.name), check_verifying_shares(g, &shares), check_verifying_shares(g, &bad_shares));
        run(&format!("{}: pairs sign           | byte 0 of share 2 ^ 0x01", g.name), check_pairs_sign(g, &shares), check_pairs_sign(g, &bad_shares));
        run(&format!("{}: EvenY rule           | byte 0 of share 2 ^ 0x01", g.name), check_even_y_rule(g, &shares), check_even_y_rule(g, &bad_shares));

        let m = &g.members[0];
        let p = member_payload(g, m, NET_TESTNET, BIRTHDAY_TESTNET);
        let bytes = p.to_bytes();
        let s = encode_crate(&bytes);

        let mut bytes_bad = bytes.clone();
        bytes_bad[10] ^= 0x01;
        // the crate encoding of the real payload against our encoding of the changed one
        let enc_bad = if encode_crate(&bytes) == encode_own(HRP, &bytes_bad) { Ok(()) } else { Err("differ".to_string()) };
        run(&format!("{}: encoders agree       | own encoder given byte 10 ^ 0x01", g.name), check_encoders_agree(&bytes), enc_bad);

        let mut s_bad: Vec<char> = s.chars().collect();
        let i = HRP.len() + 20;
        s_bad[i] = if s_bad[i] == 'q' { 'p' } else { 'q' };
        let s_bad: String = s_bad.into_iter().collect();
        run(&format!("{}: round trip           | one character of the string changed", g.name), check_roundtrip(&s, &p), check_roundtrip(&s_bad, &p));

        let mut p_bad = p.clone();
        p_bad.birthday ^= 0x0100; // one byte of the birthday
        run(&format!("{}: round trip           | one birthday byte changed in the encoded payload", g.name), check_roundtrip(&s, &p), check_roundtrip(&encode_crate(&p_bad.to_bytes()), &p));

        let longer = [bytes.as_slice(), &[0]].concat();
        run(&format!("{}: counts               | one byte appended", g.name), check_counts(&bytes, &s, m.id_form), check_counts(&longer, &encode_crate(&longer), m.id_form));

        let sk = draw_sk(&format!("{}/sk", g.name));
        let mut sk_bad = sk;
        sk_bad[0] ^= 0x01;
        let manual_bad = if nk_rivk_manual(&sk_bad) == nk_rivk_orchard(&orchard::keys::SpendingKey::from_bytes(sk).unwrap()) { Ok(()) } else { Err("differ".to_string()) };
        run(&format!("{}: nk/rivk two paths    | manual path given sk byte 0 ^ 0x01", g.name), check_nk_rivk_paths(&sk), manual_bad);
    }
    let rows = rows.into_inner();
    for n in &notes {
        println!("note  {n}");
    }
    for (name, pass, fail) in &rows {
        println!("{}  {}  {name}", if *pass { "pass" } else { "PASS-FAILED" }, if *fail { "red" } else { "NOT-RED" });
    }
    let all = rows.iter().all(|(_, p, f)| *p && *f);
    println!("{}", if all { "red-check: every check passes as built and fails with one byte changed" } else { "red-check: SOME CHECK DID NOT BEHAVE" });
    if !all {
        std::process::exit(1);
    }
}

// ---------------------------------------------------------------------------------------------
// Tests: each rejection is shown to fire for the stated reason by breaking one input of a valid
// string, and the order is shown by breaking two inputs at once.
// ---------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct Fx {
        a: Group,
        b: Group,
    }
    fn fx() -> Fx {
        let mut log = String::new();
        Fx { a: build_group("A", false, &mut log), b: build_group("B", true, &mut log) }
    }
    fn payload_a(f: &Fx, net: u8) -> Payload {
        member_payload(&f.a, &f.a.members[0], net, BIRTHDAY_TESTNET)
    }
    fn enc(b: &[u8]) -> String {
        encode_crate(b)
    }
    fn dec_err(b: &[u8]) -> Rej {
        decode(&enc(b)).expect_err("must be rejected")
    }
    fn bytes_with(f: &Fx, m: &dyn Fn(&mut Vec<u8>)) -> Vec<u8> {
        let mut v = payload_a(f, NET_TESTNET).to_bytes();
        m(&mut v);
        v
    }

    #[test]
    fn offsets_and_lengths_match_the_table() {
        let f = fx();
        // lengths per layout: sk short 107, sk full 138, no sk short 139, no sk full 170
        assert_eq!(expected_len(KS_ZIP2005, ID_SHORT), Some(107));
        assert_eq!(expected_len(KS_LEGACY, ID_SHORT), Some(107));
        assert_eq!(expected_len(KS_ZIP2005, ID_FULL), Some(138));
        assert_eq!(expected_len(KS_VIEWING_KEY_ONLY, ID_SHORT), Some(139));
        assert_eq!(expected_len(KS_VIEWING_KEY_ONLY, ID_FULL), Some(170));
        // no sk, short: birthday at 39, ak||nk||rivk at 43
        let short = payload_a(&f, NET_TESTNET).to_bytes();
        assert_eq!(short.len(), 139);
        assert_eq!(&short[7..39], &f.a.members[0].share);
        assert_eq!(&short[39..43], &BIRTHDAY_TESTNET.to_le_bytes());
        assert_eq!(&short[43..75], &f.a.ak);
        assert_eq!(&short[43..139], &f.a.fvk);
        // no sk, full: identifier 6..38, share 38, birthday at 70, ak||nk||rivk at 74
        let full = member_payload(&f.b, &f.b.members[0], NET_TESTNET, BIRTHDAY_TESTNET).to_bytes();
        assert_eq!(full.len(), 170);
        assert_eq!(&full[6..38], &f.b.members[0].id_payload[..]);
        assert_eq!(&full[38..70], &f.b.members[0].share);
        assert_eq!(&full[70..74], &BIRTHDAY_TESTNET.to_le_bytes());
        assert_eq!(&full[74..106], &f.b.ak);
        assert_eq!(&full[74..170], &f.b.fvk);
        // sk layouts: sk at 43 / 74, ak at 75 / 106 (a structural check of the layout the table gives)
        let mut with_sk = payload_a(&f, NET_TESTNET);
        with_sk.key_source = KS_ZIP2005;
        with_sk.sk = Some([7; 32]);
        with_sk.key = f.a.ak.to_vec();
        let b = with_sk.to_bytes();
        assert_eq!((b.len(), &b[43..75], &b[75..107]), (107, &[7u8; 32][..], &f.a.ak[..]));
    }

    #[test]
    fn rule1_bech32m_and_padding() {
        let f = fx();
        let s = enc(&payload_a(&f, NET_TESTNET).to_bytes());
        assert_eq!(decode(&s).map(|_| ()), Ok(()));
        let mut c: Vec<char> = s.chars().collect();
        let l = c.len() - 1;
        c[l] = if c[l] == 'q' { 'p' } else { 'q' };
        assert_eq!(decode(&c.into_iter().collect::<String>()), Err((1, "not Bech32m")));
        // mixed case
        let mixed = format!("{}{}", HRP.to_ascii_uppercase(), &s[HRP.len()..]);
        assert_eq!(decode(&mixed), Err((1, "not Bech32m")));
        // non-zero leftover bit, and more than 4 leftover bits
        let mut d5 = to_5bit(&payload_a(&f, NET_TESTNET).to_bytes());
        *d5.last_mut().unwrap() |= 1;
        assert_eq!(decode(&encode_5bit(HRP, &d5, BECH32M_CONST)), Err((1, "invalid padding")));
        let mut d5 = to_5bit(&member_payload(&f.b, &f.b.members[0], NET_TESTNET, BIRTHDAY_TESTNET).to_bytes());
        d5.push(0);
        assert_eq!(decode(&encode_5bit(HRP, &d5, BECH32M_CONST)), Err((1, "invalid padding")));
    }

    #[test]
    fn rule2_hrp() {
        let f = fx();
        let b = payload_a(&f, NET_TESTNET).to_bytes();
        for hrp in ["zkfros", "zkfrostx", "frost"] {
            let s = bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse(hrp).unwrap(), &b).unwrap();
            assert_eq!(decode(&s), Err((2, "wrong human-readable part")), "{hrp}");
        }
    }

    #[test]
    fn rule3_version() {
        let f = fx();
        for v in [0x00u8, 0x01, 0x03, 0xff] {
            assert_eq!(dec_err(&bytes_with(&f, &|b| b[0] = v)), (3, "unsupported version"), "{v}");
        }
        // a 68-byte payload that starts 0x01 is a version problem, not a length problem
        let mut v1 = vec![0x01u8];
        v1.extend(std::iter::repeat(0).take(67));
        assert_eq!(dec_err(&v1), (3, "unsupported version"));
    }

    #[test]
    fn rule4_unknown_values() {
        let f = fx();
        assert_eq!(dec_err(&bytes_with(&f, &|b| b[1] = 3)), (4, "unknown key source"));
        assert_eq!(dec_err(&bytes_with(&f, &|b| b[2] = 3)), (4, "unknown network"));
        assert_eq!(dec_err(&bytes_with(&f, &|b| b[5] = 2)), (4, "unknown identifier form"));
        assert_eq!(dec_err(&[0x02, 0x02]), (4, "unknown key source, network or identifier form"));
    }

    #[test]
    fn rule5_exact_length() {
        let f = fx();
        assert_eq!(dec_err(&bytes_with(&f, &|b| b.truncate(138))), (5, "wrong payload length"));
        assert_eq!(dec_err(&bytes_with(&f, &|b| b.push(0))), (5, "wrong payload length"));
        assert_eq!(dec_err(&bytes_with(&f, &|b| b[1] = KS_ZIP2005)), (5, "wrong payload length"));
        assert_eq!(dec_err(&bytes_with(&f, &|b| b[1] = KS_LEGACY)), (5, "wrong payload length"));
        assert_eq!(dec_err(&bytes_with(&f, &|b| b[5] = ID_FULL)), (5, "wrong payload length"));
    }

    #[test]
    fn rule6_threshold() {
        let f = fx();
        for (t, n) in [(1u8, 3u8), (0, 3), (4, 3), (3, 0), (2, 1)] {
            assert_eq!(dec_err(&bytes_with(&f, &|b| { b[3] = t; b[4] = n })), (6, "invalid threshold or group size"), "{t} of {n}");
        }
        assert!(decode(&enc(&bytes_with(&f, &|b| { b[3] = 2; b[4] = 2 }))).is_ok());
    }

    #[test]
    fn rule7_identifier() {
        let f = fx();
        assert_eq!(dec_err(&bytes_with(&f, &|b| b[6] = 0)), (7, "zero identifier"));
        let full = |id: [u8; 32]| {
            let mut p = member_payload(&f.b, &f.b.members[0], NET_TESTNET, BIRTHDAY_TESTNET);
            p.id = id.to_vec();
            p.to_bytes()
        };
        let int = |v: u8| { let mut x = [0u8; 32]; x[0] = v; x };
        assert_eq!(dec_err(&full([0; 32])), (7, "zero identifier"));
        assert_eq!(dec_err(&full(int(1))), (7, "full identifier that fits the short form"));
        assert_eq!(dec_err(&full(int(255))), (7, "full identifier that fits the short form"));
        assert_eq!(dec_err(&full(Q_LE)), (7, "non-canonical identifier"));
        assert_eq!(dec_err(&full([0xff; 32])), (7, "non-canonical identifier"));
        let mut x256 = [0u8; 32];
        x256[1] = 1;
        assert!(decode(&enc(&full(x256))).is_ok(), "256 is not held by the short form");
    }

    /// A vector that breaks two rules must trip the one that comes first.
    #[test]
    fn order_first_rule_wins() {
        let f = fx();
        let base = payload_a(&f, NET_TESTNET).to_bytes();
        // 1 before 2: bad padding under a wrong hrp
        let mut d5 = to_5bit(&base);
        *d5.last_mut().unwrap() |= 1;
        assert_eq!(decode(&encode_5bit("zkfros", &d5, BECH32M_CONST)), Err((1, "invalid padding")));
        // 2 before 3
        let mut v3 = base.clone();
        v3[0] = 3;
        let s = bech32::encode::<bech32::Bech32m>(bech32::Hrp::parse("zkfros").unwrap(), &v3).unwrap();
        assert_eq!(decode(&s), Err((2, "wrong human-readable part")));
        // 3 before 4 and 5
        let mut v = base.clone();
        v[0] = 3;
        v[1] = 3;
        v.truncate(138);
        assert_eq!(dec_err(&v), (3, "unsupported version"));
        // 4 before 5
        let mut v = base.clone();
        v[1] = 3;
        v.truncate(138);
        assert_eq!(dec_err(&v), (4, "unknown key source"));
        let mut v = base.clone();
        v[1] = 3;
        v.push(0);
        assert_eq!(dec_err(&v), (4, "unknown key source"));
        // 4 before 6 and 7
        let mut v = base.clone();
        v[2] = 3;
        v[3] = 1;
        assert_eq!(dec_err(&v), (4, "unknown network"));
        let mut v = base.clone();
        v[5] = 2;
        v[6] = 0;
        assert_eq!(dec_err(&v), (4, "unknown identifier form"));
        // 5 before 6 and 7
        let mut v = base.clone();
        v.truncate(138);
        v[3] = 1;
        v[6] = 0;
        assert_eq!(dec_err(&v), (5, "wrong payload length"));
        // 6 before 7
        let mut v = base.clone();
        v[3] = 1;
        v[6] = 0;
        assert_eq!(dec_err(&v), (6, "invalid threshold or group size"));
    }

    #[test]
    fn restore_network_mismatch_each_network() {
        let f = fx();
        let m1 = &f.a.members[0];
        for (s_net, w_net) in [
            (NET_MAINNET, NET_TESTNET), (NET_MAINNET, NET_REGTEST),
            (NET_TESTNET, NET_MAINNET), (NET_TESTNET, NET_REGTEST),
            (NET_REGTEST, NET_MAINNET), (NET_REGTEST, NET_TESTNET),
        ] {
            let s = enc(&payload_a(&f, s_net).to_bytes());
            assert_eq!(restore(&s, w_net, Some(&m1.verifying_share)).err(), Some((2, "network is not the wallet's")), "{s_net} on {w_net}");
            assert!(restore(&s, s_net, Some(&m1.verifying_share)).is_ok(), "{s_net} on its own network");
        }
    }

    #[test]
    fn restore_step_order() {
        let f = fx();
        let m1 = &f.a.members[0];
        let neg = (-pallas::Scalar::from_repr(m1.share).unwrap()).to_repr();
        // step 2 before 3 and 4
        let mut p = payload_a(&f, NET_MAINNET);
        p.share = Q_LE;
        p.key[..32].copy_from_slice(&[0; 32]);
        assert_eq!(restore(&enc(&p.to_bytes()), NET_TESTNET, None).err(), Some((2, "network is not the wallet's")));
        // step 3 before 4
        let mut p = payload_a(&f, NET_TESTNET);
        p.share = Q_LE;
        p.key[..32].copy_from_slice(&[0; 32]);
        assert_eq!(restore(&enc(&p.to_bytes()), NET_TESTNET, None).err(), Some((3, "non-canonical signing share")));
        // step 4 alone
        let mut p = payload_a(&f, NET_TESTNET);
        p.key[..32].copy_from_slice(&[0; 32]);
        assert_eq!(restore(&enc(&p.to_bytes()), NET_TESTNET, None).err(), Some((4, "invalid viewing key")));
        // step 4 with a known verifying share
        assert_eq!(restore(&enc(&p.to_bytes()), NET_TESTNET, Some(&m1.verifying_share)).err(), Some((4, "invalid viewing key")));
        // step 5 alone, and only when the verifying share is known
        let mut p = payload_a(&f, NET_TESTNET);
        p.share = neg;
        assert_eq!(restore(&enc(&p.to_bytes()), NET_TESTNET, Some(&m1.verifying_share)).err(), Some((5, "verifying share mismatch")));
        assert!(restore(&enc(&p.to_bytes()), NET_TESTNET, None).is_ok());
        // step 1: a decoding rejection is reported as step 1
        assert_eq!(restore(&enc(&bytes_with(&f, &|b| b.truncate(138))), NET_TESTNET, None).err(), Some((1, "wrong payload length")));
    }
}
