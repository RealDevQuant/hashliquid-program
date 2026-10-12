//! HashLiquid: a hash-locked wallet for trading perps.
//!
//! A *bunker* is an account of this program that owns a trading account on
//! the venue (it is that account's `authority`). It has no private key. The one
//! way to make it act is a Winternitz one-time signature over the exact
//! venue instruction it should send: place this order, cancel that one,
//! withdraw this much to that token account. Each signature also names the
//! hash of the key that must sign next.
//!
//! An 840-byte signature doesn't fit a transaction next to an instruction's
//! accounts, so acting takes two:
//!   1. `authorize` — verifies the signature over the hash of the instruction,
//!      retires the key, records that hash as the bunker's pending action.
//!   2. `execute`   — anyone may send it; it carries the instruction itself,
//!      which must hash to the pending action, and the bunker signs it by CPI.
//!
//! Two things need no signature, because neither can take anything from a
//! bunker: creating its trading account (`init_trading`) and moving tokens the
//! bunker already holds into that account (`deposit`).

use anchor_lang::prelude::*;
use anchor_lang::solana_program::hash::hashv;
use anchor_lang::solana_program::instruction::{AccountMeta, Instruction};
use anchor_lang::solana_program::program::invoke_signed;

pub mod wots;

#[cfg(not(feature = "no-entrypoint"))]
use solana_security_txt::security_txt;
#[cfg(not(feature = "no-entrypoint"))]
security_txt! {
    name: "HashLiquid",
    project_url: "https://hashliquid.tech",
    contacts: "link:https://hashliquid.tech",
    policy: "https://hashliquid.tech/docs.html#security",
    preferred_languages: "en",
    source_code: "https://github.com/RealDevQuant/hashliquid-program"
}

declare_id!("6PWQ13DKweZ66XQRMG7kZyau98jE6CJnc1ugxtgnRQn2");

/// The venue: the only program a bunker ever calls.
pub mod venue {
    use anchor_lang::prelude::*;

    pub const ID: Pubkey = pubkey!("vELoC1audYbSYVRXn1vPaV8Axoa9oU6BYmNGZZBDZ1P");

    // Anchor discriminators of the venue's instructions, from its published IDL.
    pub const INITIALIZE_USER_STATS: [u8; 8] = [254, 243, 72, 98, 251, 130, 168, 213];
    pub const INITIALIZE_USER: [u8; 8] = [111, 17, 185, 250, 60, 122, 38, 254];
    pub const DEPOSIT: [u8; 8] = [242, 35, 198, 137, 82, 225, 242, 182];
}

/// Flags of one account of an action, as its owner signed them.
pub const FLAG_WRITABLE: u8 = 1;
pub const FLAG_SIGNER: u8 = 2;
/// Accounts an action may name (a venue instruction with its markets and oracles is far below this).
pub const MAX_ACTION_ACCOUNTS: usize = 40;
/// The most hash steps a signature may cost to verify. The signer grinds a salt to stay under it, so an
/// honest signature never hits this; it bounds the compute a stranger's bytes can make `authorize` burn.
pub const MAX_VERIFY_COST: u32 = 3600;
/// The only trading account a bunker uses: sub-account 0.
pub const SUB_ACCOUNT: u16 = 0;


/// A bunker's address commits to its seed and first key.
pub fn bunker_id(seed: &[u8; 32], key_hash: &[u8; 32]) -> [u8; 32] {
    hashv(&[seed, key_hash]).to_bytes()
}

/// What a bunker key signs: one instruction to the exchange, to the byte.
///
///   SHA-256("hashliquid:action" ‖ program ‖ len(data) ‖ data ‖ n ‖ (account ‖ flags) × n)
///
/// `accounts` are the instruction's accounts in order, each with the flags it
/// is passed with (FLAG_WRITABLE, FLAG_SIGNER). Thirty-two zero bytes stand
/// for "nothing": authorizing that cancels a pending action.
pub fn action_hash(program: &Pubkey, data: &[u8], accounts: &[(Pubkey, u8)]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(17 + 32 + 4 + data.len() + 1 + accounts.len() * 33);
    buf.extend_from_slice(b"hashliquid:action");
    buf.extend_from_slice(program.as_ref());
    buf.extend_from_slice(&(data.len() as u32).to_le_bytes());
    buf.extend_from_slice(data);
    buf.push(accounts.len() as u8);
    for (key, flags) in accounts {
        buf.extend_from_slice(key.as_ref());
        buf.push(*flags);
    }
    hashv(&[&buf]).to_bytes()
}

#[program]
pub mod hashliquid {
    use super::*;

    /// Opens a bunker at PDA(["bunker", id]) with id = H(seed ‖ key_hash).
    /// Permissionless: whoever pays, the keys are the ones the address commits
    /// to. Opening an open bunker changes nothing and succeeds.
    pub fn open(ctx: Context<Open>, id: [u8; 32], seed: [u8; 32], key_hash: [u8; 32]) -> Result<()> {
        require!(id == bunker_id(&seed, &key_hash), HlError::BadId);
        require!(key_hash != [0u8; 32], HlError::BadNextKey);
        let b = &mut ctx.accounts.bunker;
        if b.opened_at != 0 {
            return Ok(());
        }
        b.id = id;
        b.seed = seed;
        b.key_hash = key_hash;
        b.nonce = 0;
        b.pending = [0u8; 32];
        b.pending_nonce = 0;
        b.opened_at = Clock::get()?.unix_timestamp;
        b.bump = ctx.bumps.bunker;
        emit!(BunkerOpened { bunker: b.key(), key_hash });
        Ok(())
    }

    /// Creates the bunker's trading account on the venue (and, the first time,
    /// its stats account), with the bunker as authority. Anyone can pay for it:
    /// it only creates accounts the bunker owns, with no referrer. Only
    /// sub-account 0 exists: one bunker, one trading account.
    pub fn init_trading(ctx: Context<InitTrading>, sub_account_id: u16, name: [u8; 32]) -> Result<()> {
        require!(sub_account_id == SUB_ACCOUNT, HlError::WrongSubAccount);
        let a = &ctx.accounts;
        let seeds: &[&[u8]] = &[b"bunker", a.bunker.id.as_ref(), &[a.bunker.bump]];

        if a.user_stats.data_is_empty() {
            let ix = Instruction {
                program_id: venue::ID,
                accounts: vec![
                    AccountMeta::new(a.user_stats.key(), false),
                    AccountMeta::new(a.state.key(), false),
                    AccountMeta::new_readonly(a.bunker.key(), true),
                    AccountMeta::new(a.payer.key(), true),
                    AccountMeta::new_readonly(a.rent.key(), false),
                    AccountMeta::new_readonly(a.system_program.key(), false),
                ],
                data: venue::INITIALIZE_USER_STATS.to_vec(),
            };
            invoke_signed(
                &ix,
                &[
                    a.user_stats.to_account_info(),
                    a.state.to_account_info(),
                    a.bunker.to_account_info(),
                    a.payer.to_account_info(),
                    a.rent.to_account_info(),
                    a.system_program.to_account_info(),
                    a.venue_program.to_account_info(),
                ],
                &[seeds],
            )?;
        }

        let mut data = Vec::with_capacity(8 + 2 + 32);
        data.extend_from_slice(&venue::INITIALIZE_USER);
        data.extend_from_slice(&sub_account_id.to_le_bytes());
        data.extend_from_slice(&name);
        let ix = Instruction {
            program_id: venue::ID,
            accounts: vec![
                AccountMeta::new(a.user.key(), false),
                AccountMeta::new(a.user_stats.key(), false),
                AccountMeta::new(a.state.key(), false),
                AccountMeta::new_readonly(a.bunker.key(), true),
                AccountMeta::new(a.payer.key(), true),
                AccountMeta::new_readonly(a.rent.key(), false),
                AccountMeta::new_readonly(a.system_program.key(), false),
            ],
            data,
        };
        invoke_signed(
            &ix,
            &[
                a.user.to_account_info(),
                a.user_stats.to_account_info(),
                a.state.to_account_info(),
                a.bunker.to_account_info(),
                a.payer.to_account_info(),
                a.rent.to_account_info(),
                a.system_program.to_account_info(),
                a.venue_program.to_account_info(),
            ],
            &[seeds],
        )?;
        Ok(())
    }

    /// Moves tokens the bunker holds into its own trading account. Anyone can
    /// send it: the tokens can only come from a token account the bunker owns
    /// (the venue checks that) and only go to the bunker's own account (checked
    /// here). The venue's remaining accounts (oracle, spot market, …) follow.
    pub fn deposit<'info>(
        ctx: Context<'_, '_, 'info, 'info, Deposit<'info>>,
        sub_account_id: u16,
        market_index: u16,
        amount: u64,
    ) -> Result<()> {
        require!(sub_account_id == SUB_ACCOUNT, HlError::WrongSubAccount);
        let a = &ctx.accounts;
        let bunker_key = a.bunker.key();
        let (user, _) = Pubkey::find_program_address(
            &[b"user", bunker_key.as_ref(), &sub_account_id.to_le_bytes()],
            &venue::ID,
        );
        require_keys_eq!(a.user.key(), user, HlError::NotThisBunkersAccount);

        let mut data = Vec::with_capacity(8 + 2 + 8 + 1);
        data.extend_from_slice(&venue::DEPOSIT);
        data.extend_from_slice(&market_index.to_le_bytes());
        data.extend_from_slice(&amount.to_le_bytes());
        data.push(0); // reduce_only = false

        let mut accounts = vec![
            AccountMeta::new_readonly(a.state.key(), false),
            AccountMeta::new(a.user.key(), false),
            AccountMeta::new(a.user_stats.key(), false),
            AccountMeta::new_readonly(bunker_key, true),
            AccountMeta::new(a.spot_market_vault.key(), false),
            AccountMeta::new(a.bunker_token_account.key(), false),
            AccountMeta::new_readonly(a.token_program.key(), false),
        ];
        let mut infos = vec![
            a.state.to_account_info(),
            a.user.to_account_info(),
            a.user_stats.to_account_info(),
            a.bunker.to_account_info(),
            a.spot_market_vault.to_account_info(),
            a.bunker_token_account.to_account_info(),
            a.token_program.to_account_info(),
        ];
        for acc in ctx.remaining_accounts.iter() {
            accounts.push(AccountMeta { pubkey: acc.key(), is_signer: false, is_writable: acc.is_writable });
            infos.push(acc.clone());
        }
        infos.push(a.venue_program.to_account_info());

        let ix = Instruction { program_id: venue::ID, accounts, data };
        invoke_signed(&ix, &infos, &[&[b"bunker", a.bunker.id.as_ref(), &[a.bunker.bump]]])?;
        Ok(())
    }

    /// Verifies a Winternitz signature by the bunker's current key over
    /// (program, bunker, key number, action hash, next key hash, salt), retires
    /// that key and records the action as pending. Anyone may submit it: the
    /// signature is the authority, the fee payer is irrelevant. A second
    /// authorize replaces an unexecuted action (that is how one cancels).
    pub fn authorize(
        ctx: Context<Authorize>,
        sig: Vec<u8>,
        action_hash: [u8; 32],
        next_key_hash: [u8; 32],
        salt: u32,
    ) -> Result<()> {
        let b = &mut ctx.accounts.bunker;
        require!(next_key_hash != [0u8; 32] && next_key_hash != b.key_hash, HlError::BadNextKey);

        let digest = wots::message_digest(&crate::ID.to_bytes(), &b.key().to_bytes(), b.nonce, &action_hash, &next_key_hash, salt);
        require!(wots::verify_cost(&digest) <= MAX_VERIFY_COST, HlError::TooCostly);
        let ps = wots::pub_seed(&[0u8; 32], &b.seed, b.nonce);
        let recovered = wots::recover_key_hash(&ps, &digest, &sig).ok_or(HlError::BadSignature)?;
        require!(recovered == b.key_hash, HlError::BadSignature);

        let used = b.nonce;
        b.nonce = used.checked_add(1).ok_or(HlError::MathOverflow)?;
        b.key_hash = next_key_hash;
        b.pending = action_hash;
        b.pending_nonce = used;
        emit!(Authorized { bunker: b.key(), nonce: used, action_hash, next_key_hash });
        Ok(())
    }

    /// Sends the pending action: `data` and the remaining accounts, with
    /// `flags` (one byte per account, as signed), are the venue instruction
    /// the bunker's key authorized, and must hash to it. The bunker signs it,
    /// and only the bunker: no other signer is ever lent to the venue.
    /// Permissionless, and it runs once: the pending action is cleared first.
    pub fn execute<'info>(ctx: Context<'_, '_, 'info, 'info, Execute<'info>>, data: Vec<u8>, flags: Vec<u8>) -> Result<()> {
        let remaining = ctx.remaining_accounts;
        require!(flags.len() == remaining.len() && remaining.len() <= MAX_ACTION_ACCOUNTS, HlError::WrongAction);
        let bunker_key = ctx.accounts.bunker.key();

        let signed: Vec<(Pubkey, u8)> = remaining.iter().zip(flags.iter()).map(|(a, f)| (a.key(), *f)).collect();
        let hash = action_hash(&venue::ID, &data, &signed);

        let b = &mut ctx.accounts.bunker;
        require!(b.pending != [0u8; 32], HlError::NothingPending);
        require!(hash == b.pending, HlError::WrongAction);
        let nonce = b.pending_nonce;
        b.pending = [0u8; 32];
        let (id, bump) = (b.id, b.bump);
        // on chain before the call, so nothing the call does can find it still pending
        b.exit(&crate::ID)?;

        let mut accounts = Vec::with_capacity(remaining.len());
        for (acc, f) in remaining.iter().zip(flags.iter()) {
            let is_writable = f & FLAG_WRITABLE != 0;
            let is_signer = f & FLAG_SIGNER != 0;
            // what was signed can't ask for more than this transaction grants, and the only signer is the bunker
            require!(!is_writable || acc.is_writable, HlError::MissingPrivilege);
            require!(!is_signer || acc.key() == bunker_key, HlError::MissingPrivilege);
            accounts.push(AccountMeta { pubkey: acc.key(), is_signer, is_writable });
        }
        let mut infos = remaining.to_vec();
        infos.push(ctx.accounts.venue_program.to_account_info());

        let ix = Instruction { program_id: venue::ID, accounts, data };
        invoke_signed(&ix, &infos, &[&[b"bunker", id.as_ref(), &[bump]]])?;

        emit!(Executed { bunker: bunker_key, nonce, action_hash: hash });
        Ok(())
    }
}

#[account]
#[derive(InitSpace)]
pub struct Bunker {
    /// H(seed ‖ first key hash): what the address is derived from.
    pub id: [u8; 32],
    /// Public seed of every key of this bunker.
    pub seed: [u8; 32],
    /// Hash of the one-time public key that must sign next.
    pub key_hash: [u8; 32],
    /// Number of that key. Grows by one with every signature.
    pub nonce: u64,
    /// Hash of the action the last signature authorized. Zero when there is none.
    pub pending: [u8; 32],
    /// Number of the key that authorized it.
    pub pending_nonce: u64,
    pub opened_at: i64,
    pub bump: u8,
}

#[derive(Accounts)]
#[instruction(id: [u8; 32])]
pub struct Open<'info> {
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + Bunker::INIT_SPACE,
        seeds = [b"bunker", id.as_ref()],
        bump
    )]
    pub bunker: Account<'info, Bunker>,
    #[account(mut)]
    pub payer: Signer<'info>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct InitTrading<'info> {
    pub bunker: Account<'info, Bunker>,
    #[account(mut)]
    pub payer: Signer<'info>,
    /// CHECK: the venue's state; the venue checks it
    #[account(mut)]
    pub state: UncheckedAccount<'info>,
    /// CHECK: created by the venue at the address it derives from the bunker
    #[account(mut)]
    pub user: UncheckedAccount<'info>,
    /// CHECK: created by the venue at the address it derives from the bunker
    #[account(mut)]
    pub user_stats: UncheckedAccount<'info>,
    /// CHECK: the venue
    #[account(address = venue::ID @ HlError::WrongProgram)]
    pub venue_program: UncheckedAccount<'info>,
    pub rent: Sysvar<'info, Rent>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    pub bunker: Account<'info, Bunker>,
    /// CHECK: the venue's state; the venue checks it
    pub state: UncheckedAccount<'info>,
    /// CHECK: must be the bunker's own trading account (checked in the handler)
    #[account(mut)]
    pub user: UncheckedAccount<'info>,
    /// CHECK: the venue checks it belongs to `user`
    #[account(mut)]
    pub user_stats: UncheckedAccount<'info>,
    /// CHECK: the venue derives and checks it
    #[account(mut)]
    pub spot_market_vault: UncheckedAccount<'info>,
    /// CHECK: the venue requires its token authority to be the bunker
    #[account(mut)]
    pub bunker_token_account: UncheckedAccount<'info>,
    /// CHECK: the venue checks it
    pub token_program: UncheckedAccount<'info>,
    /// CHECK: the venue
    #[account(address = venue::ID @ HlError::WrongProgram)]
    pub venue_program: UncheckedAccount<'info>,
}

/// No signer: the one-time signature in the instruction is the authority.
#[derive(Accounts)]
pub struct Authorize<'info> {
    #[account(mut)]
    pub bunker: Account<'info, Bunker>,
}

#[derive(Accounts)]
pub struct Execute<'info> {
    #[account(mut)]
    pub bunker: Account<'info, Bunker>,
    /// CHECK: the venue
    #[account(address = venue::ID @ HlError::WrongProgram)]
    pub venue_program: UncheckedAccount<'info>,
}

#[event]
pub struct BunkerOpened {
    pub bunker: Pubkey,
    pub key_hash: [u8; 32],
}

#[event]
pub struct Authorized {
    pub bunker: Pubkey,
    /// Number of the key that signed.
    pub nonce: u64,
    pub action_hash: [u8; 32],
    /// Hash of the key that must sign next.
    pub next_key_hash: [u8; 32],
}

#[event]
pub struct Executed {
    pub bunker: Pubkey,
    pub nonce: u64,
    pub action_hash: [u8; 32],
}

#[error_code]
pub enum HlError {
    #[msg("The id is not the hash of the seed and key")]
    BadId,
    #[msg("The next key hash must be new and not zero")]
    BadNextKey,
    #[msg("The signature does not match the bunker's current key")]
    BadSignature,
    #[msg("Nothing is pending")]
    NothingPending,
    #[msg("This is not the action the bunker's key signed")]
    WrongAction,
    #[msg("An account is missing a privilege the signed action needs")]
    MissingPrivilege,
    #[msg("Not the venue program")]
    WrongProgram,
    #[msg("Only sub-account 0 exists")]
    WrongSubAccount,
    #[msg("The signature would cost too much to verify: use another salt")]
    TooCostly,
    #[msg("Not this bunker's trading account")]
    NotThisBunkersAccount,
    #[msg("Math overflow")]
    MathOverflow,
}

#[cfg(test)]
mod tests {
    use super::wots::tests::{hex, public_key_hash, sign, M, S};
    use super::*;

    const ZERO: [u8; 32] = [0u8; 32];

    fn sample_action() -> [u8; 32] {
        let accounts = [
            (Pubkey::new_from_array([1; 32]), 0),
            (Pubkey::new_from_array([2; 32]), FLAG_WRITABLE),
            (Pubkey::new_from_array([3; 32]), FLAG_SIGNER),
        ];
        action_hash(&venue::ID, &[9, 8, 7, 6, 5], &accounts)
    }

    #[test]
    fn the_id_commits_to_seed_and_key() {
        let kh = public_key_hash(&M, &ZERO, &S, 0);
        assert_eq!(bunker_id(&S, &kh), hashv(&[&S, &kh]).to_bytes());
        assert_ne!(bunker_id(&S, &kh), bunker_id(&[1; 32], &kh));
        assert_ne!(bunker_id(&S, &kh), bunker_id(&S, &[1; 32]));
    }

    #[test]
    fn an_action_is_its_data_and_its_accounts_to_the_byte() {
        let a = [(Pubkey::new_from_array([1; 32]), 0u8), (Pubkey::new_from_array([2; 32]), FLAG_WRITABLE)];
        let h = action_hash(&venue::ID, &[1, 2, 3], &a);
        // other data, another account, another flag, another order, another program, one account more
        assert_ne!(h, action_hash(&venue::ID, &[1, 2, 4], &a));
        assert_ne!(h, action_hash(&venue::ID, &[1, 2, 3], &[a[0], (Pubkey::new_from_array([9; 32]), FLAG_WRITABLE)]));
        assert_ne!(h, action_hash(&venue::ID, &[1, 2, 3], &[a[0], (a[1].0, 0)]));
        assert_ne!(h, action_hash(&venue::ID, &[1, 2, 3], &[a[1], a[0]]));
        assert_ne!(h, action_hash(&crate::ID, &[1, 2, 3], &a));
        assert_ne!(h, action_hash(&venue::ID, &[1, 2, 3], &[a[0], a[1], a[0]]));
        // moving a byte between the data and the account list doesn't collide: lengths are part of it
        assert_ne!(action_hash(&venue::ID, &[1, 2], &[]), action_hash(&venue::ID, &[1], &[]));
        assert_ne!(h, ZERO);
    }

    #[test]
    fn a_signature_authorizes_one_action_with_one_key() {
        let bunker = [4u8; 32];
        let program = crate::ID.to_bytes();
        let action = sample_action();
        let k0 = public_key_hash(&M, &ZERO, &S, 0);
        let k1 = public_key_hash(&M, &ZERO, &S, 1);
        let dg = wots::message_digest(&program, &bunker, 0, &action, &k1, 7);
        let sig = sign(&M, &ZERO, &S, 0, &dg);
        let ok = |program: &[u8; 32], bunker: &[u8; 32], nonce: u64, action: &[u8; 32], next: &[u8; 32], salt: u32| {
            let d = wots::message_digest(program, bunker, nonce, action, next, salt);
            wots::recover_key_hash(&wots::pub_seed(&ZERO, &S, 0), &d, &sig) == Some(k0)
        };
        assert!(ok(&program, &bunker, 0, &action, &k1, 7));
        assert!(!ok(&[8; 32], &bunker, 0, &action, &k1, 7), "another program");
        assert!(!ok(&program, &[8; 32], 0, &action, &k1, 7), "another bunker");
        assert!(!ok(&program, &bunker, 1, &action, &k1, 7), "another key number");
        assert!(!ok(&program, &bunker, 0, &[8; 32], &k1, 7), "another action");
        assert!(!ok(&program, &bunker, 0, &action, &[8; 32], 7), "another next key");
        assert!(!ok(&program, &bunker, 0, &action, &k1, 8), "another salt");
        // the next key doesn't verify it either
        assert_ne!(wots::recover_key_hash(&wots::pub_seed(&ZERO, &S, 1), &dg, &sig), Some(k0));
    }

    /// Cross-implementation vectors: client/test/wots.test.ts asserts the same strings.
    #[test]
    fn vectors() {
        assert_eq!(hex(&sample_action()), VEC_ACTION);
        let dg = wots::message_digest(&[1; 32], &[2; 32], 3, &sample_action(), &[5; 32], 42);
        assert_eq!(hex(&dg), VEC_DIGEST);
        assert_eq!(hex(&bunker_id(&[9; 32], &[5; 32])), VEC_ID);
    }

    const VEC_ACTION: &str = "324365531a3396ea16c0c518abd5094b3ff151c0f752066feaf12e2a2f541806";
    const VEC_DIGEST: &str = "4bd8d111fe6d40b700ed89b74e62bfebc32e76dac38ca6d8160f9a55";
    const VEC_ID: &str = "efc0019078245633355452f02df540bb30518b9a1531c1d72da4623b67b44a5e";
}
