# HashLiquid program

The on-chain program behind [hashliquid.tech](https://hashliquid.tech): a hash-locked wallet, the *bunker*,
for trading perpetual futures on Solana.

Program: `6PWQ13DKweZ66XQRMG7kZyau98jE6CJnc1ugxtgnRQn2` (mainnet).

## What it does

A bunker is an account of this program that owns a trading account on the venue it relays to. It has no
private key. The only way to make it act is a one-time hash-based signature over the exact instruction it
should send: place this order, cancel that one, withdraw this much to that token account. Every signature also
commits to the hash of the key that must sign next.

An 840-byte signature does not fit a transaction next to an instruction's accounts, so a move takes two:

1. `authorize` — verifies the signature over the hash of the instruction, retires the key, records that hash as
   the bunker's pending action.
2. `execute` — anyone may send it; it carries the instruction itself, which must hash to the pending action, and
   the bunker signs it by CPI. The bunker is the only signer ever lent to the venue.

Two things need no signature, because neither can take anything from a bunker: creating its trading account
(`init_trading`) and moving tokens the bunker already holds into that account (`deposit`).

## The signature scheme

Winternitz one-time signatures over SHA-256: w = 256, 28-byte chain values, 30 chains (28 for the message and
2 for the checksum), 840-byte signatures. A key is the hash of its 30 chain tops; the verifier walks the chains
forward and compares. Every hash is tweaked with the key's public seed, the chain index and the step, so work
against one chain never transfers to another. Security rests on SHA-256 preimage resistance alone. The scheme
is in [`programs/hashliquid/src/wots.rs`](programs/hashliquid/src/wots.rs) with its test vectors.

What a key signs is the SHA-256 of the instruction's program, data and accounts (with their flags), together
with the program, the bunker, the key number and the hash of the next key. A changed byte, a different
destination, another bunker or a replayed message all produce a different digest.

## Limits enforced on chain

- a bunker's address commits to its seed and its first key: nobody can open a bunker at your address with
  other keys
- a key signs once; the next key's hash is committed before the current one is spent
- `execute` relays only to the venue program, only the exact bytes that were signed, and lends no signer but
  the bunker
- `init_trading` and `deposit` only touch the bunker's own sub-account 0
- a signature that would cost more than 3600 hash steps to verify is refused (signers pick a salt to stay under)

## Build and test

```
cargo test -p hashliquid --lib
anchor build
```

Verifiable build (the deployed binary is built this way, see
[solana-verify](https://github.com/solana-foundation/solana-verifiable-build)):

```
solana-verify build --library-name hashliquid
solana-verify get-executable-hash target/deploy/hashliquid.so
solana-verify get-program-hash -u mainnet-beta 6PWQ13DKweZ66XQRMG7kZyau98jE6CJnc1ugxtgnRQn2
```

## Licence

MIT.
