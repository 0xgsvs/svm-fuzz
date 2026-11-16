use solana_program::{
    account_info::{next_account_info, AccountInfo},
    entrypoint,
    entrypoint::ProgramResult,
    program_error::ProgramError,
    pubkey::Pubkey,
};

const DEPOSIT: u8 = 0;
const WITHDRAW: u8 = 1;
const DEPOSIT_LAMPORTS: u64 = 100_000_000;
const WITHDRAW_LAMPORTS: u64 = 1_000_000;

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    data: &[u8],
) -> ProgramResult {
    match data.first().copied() {
        Some(DEPOSIT) => deposit(program_id, accounts),
        Some(WITHDRAW) => withdraw(program_id, accounts),
        _ => Err(ProgramError::InvalidInstructionData),
    }
}

fn deposit(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault = next_account_info(accounts_iter)?;
    let user = next_account_info(accounts_iter)?;

    if vault.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    if !user.is_signer {
        return Err(ProgramError::MissingRequiredSignature);
    }
    let amount = DEPOSIT_LAMPORTS.min(user.lamports());
    if amount == 0 {
        return Err(ProgramError::InsufficientFunds);
    }

    **user.try_borrow_mut_lamports()? -= amount;
    **vault.try_borrow_mut_lamports()? += amount;
    Ok(())
}

fn withdraw(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();
    let vault = next_account_info(accounts_iter)?;
    let authority = next_account_info(accounts_iter)?;
    let recipient = next_account_info(accounts_iter)?;

    if vault.owner != program_id {
        return Err(ProgramError::IncorrectProgramId);
    }
    let vault_data = vault.try_borrow_data()?;
    if vault_data.len() < 32 {
        return Err(ProgramError::InvalidAccountData);
    }
    if vault_data[..32] != authority.key.to_bytes() {
        return Err(ProgramError::IllegalOwner);
    }
    drop(vault_data);

    // Seeded vulnerability: authority identity is checked, its signature is not.
    let amount = WITHDRAW_LAMPORTS.min(vault.lamports());
    if amount == 0 {
        return Err(ProgramError::InsufficientFunds);
    }
    **vault.try_borrow_mut_lamports()? -= amount;
    **recipient.try_borrow_mut_lamports()? += amount;
    Ok(())
}
