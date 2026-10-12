//! Ported from Shelter (github.com/sheltercash/shelter, MIT License, Copyright (c) 2026 Shelter).
//! Parameters, tweaks and test vectors are unchanged so the Rust and TS halves stay byte-identical;
//! only the hash call is the SDK's sha256 (the sol_sha256 syscall on chain).
//!
//! Winternitz one-time signatures (WOTS, w = 256) over SHA-256.
//!
//! The only thing that can make a bunker act. Security rests on SHA-256
//! preimage resistance alone — no elliptic curve, no discrete log, no
//! factoring — so neither Shor's algorithm nor a classical ECDLP shortcut
//! touches it. Each key signs exactly once; every signature also commits to
//! the hash of the NEXT key, so the bunker rotates its key on every action.
//!
//! This is NOT RFC 8554 LM-OTS: an LM-OTS signature at N32/W8 is ~1.1 KB and
//! does not fit a Solana transaction. Same family (hash chains + checksum),
//! different parameters:
//!   N  = 28-byte chain values (224-bit; 112-bit security against Grover)
//!   w  = 256 → one byte per digit, chains of 255 steps
//!   L1 = 28 message digits (the first 28 bytes of the message digest)
//!   L2 = 2 checksum digits (checksum = Σ(255 − dᵢ) ≤ 7140, big-endian)
//!   L  = 30 chains → 840-byte signature
//!
//! Every hash is tweaked with a per-key public seed, the chain index and the
//! step (WOTS+-style domain separation), so work against one chain or one key
//! never transfers to another. This file is mirrored byte-for-byte by
//! `client/src/wots.ts`; the cross-implementation vectors in the tests pin both.

pub const N: usize = 28;
pub const L1: usize = 28;
pub const L2: usize = 2;
pub const L: usize = L1 + L2;
pub const MAX_STEP: u8 = 255;
pub const SIG_LEN: usize = L * N;

pub const TAG_CHAIN: u8 = 0x00;
pub const TAG_KEY: u8 = 0x01;
pub const TAG_SEED: u8 = 0x02;
pub const TAG_MSG: u8 = 0x05;

pub type Chain = [u8; N];

pub(crate) fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    // The sol_sha256 syscall on-chain, the sha2 crate natively (tests, IDL build).
    anchor_lang::solana_program::hash::hashv(parts).to_bytes()
}

/// The public seed for key number `nonce` of a bunker. `anchor` is 32 zero
/// bytes here: a bunker's address already commits to its seed and first key.
pub fn pub_seed(anchor: &[u8; 32], seed: &[u8; 32], nonce: u64) -> [u8; 32] {
    sha256(&[&[TAG_SEED], anchor, seed, &nonce.to_le_bytes()])
}

/// One chain step: F(pub_seed, chain, step, x).
#[inline(always)]
fn step(ps: &[u8; 32], chain: u8, at: u8, x: &Chain) -> Chain {
    let h = sha256(&[&[TAG_CHAIN], ps, &[chain, at], x]);
    let mut out = [0u8; N];
    out.copy_from_slice(&h[..N]);
    out
}

/// Walks chain `chain` from position `from` up to 255.
pub fn chain_to_top(ps: &[u8; 32], chain: u8, from: u8, x: &Chain) -> Chain {
    let mut v = *x;
    let mut at = from;
    while at < MAX_STEP {
        v = step(ps, chain, at, &v);
        at += 1;
    }
    v
}

/// The 30 digits a 28-byte digest is signed as: its bytes, then the checksum.
pub fn digits(digest: &[u8; N]) -> [u8; L] {
    let mut d = [0u8; L];
    let mut csum: u32 = 0;
    for i in 0..L1 {
        d[i] = digest[i];
        csum += (MAX_STEP - digest[i]) as u32;
    }
    d[L1] = (csum >> 8) as u8;
    d[L1 + 1] = (csum & 0xff) as u8;
    d
}

/// Hashes the 30 chain tops into the 32-byte key hash a bunker stores.
pub fn key_hash(ps: &[u8; 32], tops: &[Chain; L]) -> [u8; 32] {
    let mut parts: [&[u8]; L + 2] = [&[]; L + 2];
    parts[0] = &[TAG_KEY];
    parts[1] = ps;
    for i in 0..L {
        parts[i + 2] = &tops[i];
    }
    sha256(&parts)
}

/// Recomputes the key hash a signature over `digest` implies. The caller
/// compares it with the stored key hash; any mismatch means a bad signature.
/// `sig` is the 840-byte signature (30 chain values of 28 bytes, in order).
pub fn recover_key_hash(ps: &[u8; 32], digest: &[u8; N], sig: &[u8]) -> Option<[u8; 32]> {
    if sig.len() != SIG_LEN {
        return None;
    }
    let d = digits(digest);
    let mut tops = [[0u8; N]; L];
    let mut x = [0u8; N];
    for i in 0..L {
        x.copy_from_slice(&sig[i * N..(i + 1) * N]);
        tops[i] = chain_to_top(ps, i as u8, d[i], &x);
    }
    Some(key_hash(ps, &tops))
}

/// Hash steps a verifier walks for this digest (clients grind `salt` to keep it low).
pub fn verify_cost(digest: &[u8; N]) -> u32 {
    digits(digest).iter().map(|x| (MAX_STEP - x) as u32).sum()
}

/// The 28-byte digest a bunker key signs: the program, the bunker, the key
/// number, the hash of the action it authorizes (see `action_hash` in lib.rs),
/// the next key's hash and a grinding salt.
pub fn message_digest(
    program: &[u8; 32],
    bunker: &[u8; 32],
    nonce: u64,
    action_hash: &[u8; 32],
    next_key_hash: &[u8; 32],
    salt: u32,
) -> [u8; N] {
    let h = sha256(&[
        &[TAG_MSG],
        program,
        bunker,
        &nonce.to_le_bytes(),
        action_hash,
        next_key_hash,
        &salt.to_le_bytes(),
    ]);
    let mut out = [0u8; N];
    out.copy_from_slice(&h[..N]);
    out
}

#[cfg(test)]
pub mod tests {
    use super::*;

    pub const TAG_SECRET: u8 = 0x03;

    /// Test-side key derivation (the client's, see wots.ts): sk = H(3‖master‖anchor‖seed‖nonce‖i)[..28].
    pub fn secret(master: &[u8; 32], anchor: &[u8; 32], seed: &[u8; 32], nonce: u64, i: u8) -> Chain {
        let h = sha256(&[&[TAG_SECRET], master, anchor, seed, &nonce.to_le_bytes(), &[i]]);
        let mut out = [0u8; N];
        out.copy_from_slice(&h[..N]);
        out
    }

    pub fn walk(ps: &[u8; 32], chain: u8, from: u8, to: u8, x: &Chain) -> Chain {
        let mut v = *x;
        for at in from..to {
            v = step(ps, chain, at, &v);
        }
        v
    }

    pub fn public_key_hash(master: &[u8; 32], anchor: &[u8; 32], seed: &[u8; 32], nonce: u64) -> [u8; 32] {
        let ps = pub_seed(anchor, seed, nonce);
        let mut tops = [[0u8; N]; L];
        for i in 0..L {
            tops[i] = chain_to_top(&ps, i as u8, 0, &secret(master, anchor, seed, nonce, i as u8));
        }
        key_hash(&ps, &tops)
    }

    pub fn sign(master: &[u8; 32], anchor: &[u8; 32], seed: &[u8; 32], nonce: u64, digest: &[u8; N]) -> Vec<u8> {
        let ps = pub_seed(anchor, seed, nonce);
        let d = digits(digest);
        let mut sig = Vec::with_capacity(SIG_LEN);
        for i in 0..L {
            sig.extend_from_slice(&walk(&ps, i as u8, 0, d[i], &secret(master, anchor, seed, nonce, i as u8)));
        }
        sig
    }

    pub fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    pub fn unhex<const K: usize>(s: &str) -> [u8; K] {
        let mut out = [0u8; K];
        for i in 0..K {
            out[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    pub const M: [u8; 32] = [7; 32];
    pub const S: [u8; 32] = [9; 32];
    pub const A: [u8; 32] = [6; 32];

    #[test]
    fn sign_then_verify() {
        let kh = public_key_hash(&M, &A, &S, 0);
        let dg = [0x5au8; N];
        let sig = sign(&M, &A, &S, 0, &dg);
        assert_eq!(recover_key_hash(&pub_seed(&A, &S, 0), &dg, &sig), Some(kh));
    }

    #[test]
    fn any_change_breaks_it() {
        let kh = public_key_hash(&M, &A, &S, 0);
        let dg = [0x5au8; N];
        let sig = sign(&M, &A, &S, 0, &dg);
        let ps = pub_seed(&A, &S, 0);
        // another digest
        let mut other = dg;
        other[27] ^= 1;
        assert_ne!(recover_key_hash(&ps, &other, &sig), Some(kh));
        // wrong seed / key number / anchor
        assert_ne!(recover_key_hash(&pub_seed(&A, &S, 1), &dg, &sig), Some(kh));
        assert_ne!(recover_key_hash(&pub_seed(&[5; 32], &S, 0), &dg, &sig), Some(kh));
        assert_ne!(recover_key_hash(&pub_seed(&A, &[5; 32], 0), &dg, &sig), Some(kh));
        // a tampered chain value
        let mut bad = sig.clone();
        bad[17 * N + 3] ^= 0x80;
        assert_ne!(recover_key_hash(&ps, &dg, &bad), Some(kh));
        assert_eq!(recover_key_hash(&ps, &dg, &sig[..SIG_LEN - 1]), None);
    }

    #[test]
    fn checksum_blocks_forward_forgery() {
        // Pushing a message digit up walks its chain forward (free for an
        // attacker) but lowers the checksum, which would need a chain walked
        // backward. Digits of any other digest can't all be ≥ these.
        let dg = [100u8; N];
        let d = digits(&dg);
        let mut up = dg;
        up[0] = 101;
        let u = digits(&up);
        assert!(u[0] > d[0]);
        let num = |x: &[u8; L]| ((x[L1] as u16) << 8) | x[L1 + 1] as u16;
        assert!(num(&u) < num(&d));
        assert!(u[L1] < d[L1] || u[L1 + 1] < d[L1 + 1]);
    }

    #[test]
    fn digit_layout() {
        let d = digits(&[255u8; N]);
        assert_eq!((d[L1], d[L1 + 1]), (0, 0));
        let d = digits(&[0u8; N]);
        let c = 28u32 * 255;
        assert_eq!((d[L1], d[L1 + 1]), ((c >> 8) as u8, (c & 0xff) as u8));
        assert_eq!(verify_cost(&[255u8; N]), 255 * 2);
        assert_eq!(SIG_LEN, 840);
    }

    /// Cross-implementation vectors, unchanged from Shelter (whose message digest produced
    /// VEC_DIGEST): client/test/wots.test.ts asserts the same strings.
    #[test]
    fn vectors() {
        let ps = pub_seed(&A, &S, 3);
        assert_eq!(hex(&ps), VEC_PUB_SEED);
        let kh = public_key_hash(&M, &A, &S, 3);
        assert_eq!(hex(&kh), VEC_KEY_HASH);
        let dg: [u8; N] = unhex(VEC_DIGEST);
        let sig = sign(&M, &A, &S, 3, &dg);
        assert_eq!(hex(&sig[..N]), VEC_SIG0);
        assert_eq!(hex(&sig[29 * N..]), VEC_SIG29);
        assert_eq!(recover_key_hash(&ps, &dg, &sig), Some(kh));
    }

    pub const VEC_PUB_SEED: &str = "c5719eed840528d62b474e1e1610395fad60ef1f2ae0702bee76f592bb20502a";
    pub const VEC_KEY_HASH: &str = "60c7d39670f4c52ddc53666c22de57cd5b1f26a6f3ca67b0f19b7b19fd90ca22";
    pub const VEC_DIGEST: &str = "7cfc963eb0c04282a272d64044f74da3d9894a7bf82f47ed32c8c44b";
    pub const VEC_SIG0: &str = "37f1d79a91ea323841ddb0b764b7592849bc72a457dc5be9aa72546e";
    pub const VEC_SIG29: &str = "81f245dd4b1032fc812b68e20daa2a79240614471d9c04b417f54ab4";
}
