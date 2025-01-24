use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    // borsh::{BorshDeserialize, BorshSerialize},
    entrypoint,
    entrypoint::ProgramResult,
    msg,
    program::invoke,
    program::invoke_signed,
    program_error::ProgramError,
    program_pack::Pack,
    pubkey::Pubkey,
    system_instruction::create_account,
    system_program,
    sysvar::{rent::Rent, Sysvar}, // Import Rent and Sysvar
};

use spl_associated_token_account::{
    get_associated_token_address_with_program_id, instruction::create_associated_token_account, ID,
};
use spl_token::{instruction::initialize_account, state::Account as TokenAccount};
use spl_token_2022::{
    amount_to_ui_amount, instruction::initialize_account2, instruction::transfer_checked,
    ID as TOKEN_2022_PROGRAM_ID,
};
use std::str::FromStr;

// A base58-encoded Pubkey string
const KNOWN_PUBKEY_STR: &str = "4Eej8VTCvaR1veafc2UfduTqdcjB52DB6YCBazyUkagD";

// State data structure to store necessary state information
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct State {
    pub admin_pubkey: Pubkey,
    // Add other state data here
}
// The structure that holds the claim record data
#[derive(BorshSerialize, BorshDeserialize, Debug)]
pub struct ClaimRecord {
    pub user_pubkey: Pubkey,
    pub amount: u64,
    pub claimed: bool,
}

pub struct EntireClaimData {
    claims: Vec<ClaimRecord>,
}

// State account structure:
// First 32 bytes will store the admin public key
// The rest will store claim records

// Entry point of the program
entrypoint!(process_instruction);
fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8], // The instruction data (can be to initialize, claim, or update admin)
) -> ProgramResult {
    // The first byte of `instruction_data` indicates which operation to perform
    let instruction_type = instruction_data[0];

    match instruction_type {
        0 => initialize_state_account(program_id, accounts, &instruction_data[1..]), // Initialize state account with admin key
        1 => initialize_claim(program_id, accounts, &instruction_data[1..]), // Add claim record
        2 => claim_airdrop(program_id, accounts, &instruction_data[1..]),    // Claim airdrop
        3 => update_admin_key(program_id, accounts, &instruction_data[1..]), // Update the admin public key
        4 => initialize_token_account(program_id, accounts), // Update the admin public key
        _ => Err(ProgramError::InvalidInstructionData),
    }
    // msg!("all good");
    // Ok(());
}

/// Initialize the state account with the admin public key (restricted to the authorized initializer)
fn initialize_state_account(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8], // The data contains the admin public key
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    // Get the state account and the payer account (initial deployer or authorized initializer)
    let state_account = next_account_info(accounts_iter)?;
    let payer_account = next_account_info(accounts_iter)?;
    let rent_sysvar_account = next_account_info(accounts_iter)?; // Rent sysvar account

    // Ensure the payer is a signer
    if !payer_account.is_signer {
        msg!("Payer must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    let rent = Rent::from_account_info(rent_sysvar_account)?;
    let required_lamports = rent.minimum_balance(4032); // Example: 64 bytes needed for the state

    let create_account_ix = create_account(
        payer_account.key,
        state_account.key,
        required_lamports,
        4032, // Space for the state account (adjust as needed)
        program_id,
    );
    let (expected_state_pda, bump_seed) = Pubkey::find_program_address(&[b"state"], program_id);
    // Check that the provided state account matches the derived PDA
    if *state_account.key != expected_state_pda {
        msg!("Invalid state account! The provided state account does not match the expected PDA.");
        return Err(ProgramError::InvalidAccountData);
    }

    // Invoke the instruction using the PDA (which requires `invoke_signed`)
    invoke_signed(
        &create_account_ix,
        &[payer_account.clone(), state_account.clone()],
        &[&[b"state", &[bump_seed]]], // PDA seeds and bump
    )?;

    msg!("State account (PDA) initialized successfully");
    // Only allow initialization if the state account is not already initialized
    let mut state_data = state_account.try_borrow_mut_data()?;
    // if state_data.len() > 0 {
    //     msg!("State account already initialized.");
    //     return Err(ProgramError::AccountAlreadyInitialized); // Prevent re-initialization
    // }
    // Initialize the state account (PDA) with the required lamports and space

    // Store the admin public key in the first 32 bytes of the state account
    let admin_pubkey = Pubkey::new(&instruction_data[..32]); // Admin public key (32 bytes)
    state_data[..32].copy_from_slice(admin_pubkey.as_ref());

    msg!(
        "State account initialized with admin public key: {}",
        admin_pubkey
    );

    Ok(())
}

/// Update the admin public key (only the current admin can do this)
fn update_admin_key(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8], // The data contains the new admin public key
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    // Get the state account and the payer account (current admin)
    let state_account = next_account_info(accounts_iter)?;
    let payer_account = next_account_info(accounts_iter)?;

    // Ensure the payer is a signer
    if !payer_account.is_signer {
        msg!("Payer must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Derive the expected PDA for the state account
    let expected_pda = Pubkey::find_program_address(&[b"state"], program_id).0;

    // Check that the provided state account matches the derived PDA
    if *state_account.key != expected_pda {
        msg!("Invalid state account! The provided state account does not match the expected PDA.");
        return Err(ProgramError::InvalidAccountData);
    }

    // Verify that the payer is the current admin by reading the admin public key from the state account
    let state_data = state_account.try_borrow_data()?;
    let current_admin_pubkey = Pubkey::new(&state_data[..32]); // First 32 bytes store the admin public key
    if payer_account.key != &current_admin_pubkey {
        msg!("Unauthorized: Only the current admin can update the admin public key.");
        return Err(ProgramError::Custom(1)); // Custom error for unauthorized access
    }

    // Update the admin public key with the new key from the instruction data
    let new_admin_pubkey = Pubkey::new(&instruction_data[..32]); // New admin public key (32 bytes)
    let mut state_data = state_account.try_borrow_mut_data()?;
    state_data[..32].copy_from_slice(new_admin_pubkey.as_ref());

    msg!("Admin public key updated to: {}", new_admin_pubkey);

    Ok(())
}

/// Initialize a claim record (Admin adds claim before user claims)
fn initialize_claim(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8], // The data contains the user's public key and allocation
) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    // Get the state account and the payer account (admin account)
    let state_account = next_account_info(accounts_iter)?;
    let payer_account = next_account_info(accounts_iter)?;

    // Ensure the payer is a signer (i.e., the admin adding the claim record)
    if !payer_account.is_signer {
        msg!("Payer must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    // Verify the state account PDA
    let (expected_state_pda, _bump_seed) = Pubkey::find_program_address(&[b"state"], program_id);
    if state_account.key != &expected_state_pda {
        msg!("Invalid state account! Expected PDA does not match.");
        return Err(ProgramError::InvalidAccountData);
    }

    // **Admin Check**: Verify that the payer is the admin by reading the admin public key from the state account
    let mut state_data = state_account.try_borrow_mut_data()?;
    let stored_admin_pubkey = Pubkey::new(&state_data[..32]); // First 32 bytes store the admin public key
    if payer_account.key != &stored_admin_pubkey {
        msg!("Unauthorized: Only the admin can add claim records.");
        return Err(ProgramError::Custom(0)); // Custom error for unauthorized access
    }
    state_data[32..].fill(0);
    state_data[32..32 + instruction_data.len()].copy_from_slice(&instruction_data);

    msg!("Claim record added");

    Ok(())
}

/// Claim the airdrop (user claims the allocated tokens)
fn claim_airdrop(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    instruction_data: &[u8], // Contains the user's public key
) -> ProgramResult {
    let user_pubkey = Pubkey::new(instruction_data); // Extract user public key from the instruction data
    let accounts_iter = &mut accounts.iter();

    // Get the necessary accounts
    let state_account = next_account_info(accounts_iter)?;
    let user_token_account = next_account_info(accounts_iter)?;
    let token_mint_account = next_account_info(accounts_iter)?;
    let program_token_account = next_account_info(accounts_iter)?;
    let program_pda_account = next_account_info(accounts_iter)?;
    let program_token2022_account = next_account_info(accounts_iter)?;
    let payer_account = next_account_info(accounts_iter)?;
    if !payer_account.is_signer {
        msg!("Payer must be a signer");
        return Err(ProgramError::MissingRequiredSignature);
    }

    if payer_account.key != &user_pubkey {
        msg!("Unauthorized: can not claim airdrops belonging to others");
        return Err(ProgramError::Custom(1)); // Custom error for unauthorized access
    }

    // Verify the state account PDA
    let (expected_state_pda, _bump_seed) = Pubkey::find_program_address(&[b"state"], program_id);
    if state_account.key != &expected_state_pda {
        msg!("Invalid state account! Expected PDA does not match.");
        return Err(ProgramError::InvalidAccountData);
    }

    // Find the user's claim record in the state data
    let mut state_data = state_account.try_borrow_mut_data()?;
    let claim_index = find_claim_record(&state_data, &user_pubkey)?;
    let claim_record = extract_claim_record(&state_data, claim_index)?;

    // Check if the user has already claimed their airdrop
    if claim_record.claimed == true {
        msg!("Airdrop already claimed for this user.");
        return Err(ProgramError::Custom(1)); // Custom error: already claimed
    }

    msg!("Process transfer..");
    let (expected_token_pda, bump_seed) = Pubkey::find_program_address(&[b"token"], program_id);
    if &expected_token_pda != program_pda_account.key {
        msg!("Invalid token account! Expected PDA does not match.");
        msg!("Expect pda: {}", expected_token_pda);
        return Err(ProgramError::InvalidAccountData);
    }

    // Transfer the allocated tokens from the program's token account to the user's token account
    let transfer_instruction = match spl_token_2022::instruction::transfer_checked(
        &TOKEN_2022_PROGRAM_ID,
        &program_token_account.key, // Program's token account ata
        &token_mint_account.key,    // Token mint account
        &user_token_account.key,    // User's token account ata
        &expected_token_pda,        // PDA as authority
        &[],
        claim_record.amount,
        8,
    ) {
        Ok(instruction) => instruction,
        Err(e) => return Err(e.into()), // Properly handle the error
    };

    msg!("invoke sign");

    let result = invoke_signed(
        &transfer_instruction,
        &[
            program_token_account.clone(),
            token_mint_account.clone(),
            user_token_account.clone(),
            program_pda_account.clone(),
        ],
        &[&[b"token", &[bump_seed]]], // Signer seeds if necessary
    );

    match result {
        Ok(_) => msg!("Success: Transfer completed."),
        Err(e) => msg!("Error is xxx: {:?}", e),
    }

    msg!(
        "Transferred {} tokens to user {}",
        amount_to_ui_amount(claim_record.amount, 8),
        user_pubkey
    );
    // update claim status
    // Mark the user's airdrop as claimed in the state data
    mark_as_claimed(&mut state_data, claim_index)?;

    Ok(())
}

/// Extract the claim record from the state data
fn extract_claim_record(state_data: &[u8], index: usize) -> Result<ClaimRecord, ProgramError> {
    let pubkey = Pubkey::new(&state_data[index..index + 32]);
    let amount = u64::from_le_bytes(state_data[index + 32..index + 40].try_into().unwrap());
    let claimed = (state_data[index + 40] != 0);
    Ok(ClaimRecord {
        user_pubkey: pubkey,
        amount,
        claimed,
    })
}

/// Mark the user's claim record as claimed in the state data
fn mark_as_claimed(state_data: &mut [u8], index: usize) -> ProgramResult {
    state_data[index + 40] = 1; // Set the claimed flag to true (1)
    Ok(())
}

/// Find the user's claim record in the state data
fn find_claim_record(state_data: &[u8], user_pubkey: &Pubkey) -> Result<usize, ProgramError> {
    let record_size = 41; // 32 bytes pubkey + 8 bytes amount + 1 byte claimed flag
    let mut index = 32; // Start after the admin public key (first 32 bytes)
    while index + record_size <= state_data.len() {
        let pubkey = Pubkey::new(&state_data[index..index + 32]);
        if pubkey == *user_pubkey {
            msg!("claim index is: {}", index);
            return Ok(index);
        }
        index += record_size;
    }
    Err(ProgramError::Custom(3)) // Return error if no matching record is found
}

/// Initialize the token account with the admin public key (restricted to the authorized initializer)
pub fn initialize_token_account(program_id: &Pubkey, accounts: &[AccountInfo]) -> ProgramResult {
    let accounts_iter = &mut accounts.iter();

    // Get the accounts
    let program_pda = next_account_info(accounts_iter)?; // PDA of the program
    let payer_account = next_account_info(accounts_iter)?; // Payer (admin)
    let mint_account = next_account_info(accounts_iter)?; // Token mint
    let token_account = next_account_info(accounts_iter)?; // Token account
    let rent_sysvar_account = next_account_info(accounts_iter)?; // Rent sysvar
    let token_program_account = next_account_info(accounts_iter)?; // SPL Token Program
    let system_program_account = next_account_info(accounts_iter)?; // System Program
    let ata_program_account: &AccountInfo = next_account_info(accounts_iter)?; //ATA program

    // Derive the correct PDA
    let (pda, bump_seed) = Pubkey::find_program_address(&[b"token"], program_id);

    if *program_pda.key != pda {
        msg!("Passed PDA does not match the derived PDA.");
        return Err(ProgramError::InvalidAccountData);
    }

    // Check the associated token account address
    let associated_token_address = get_associated_token_address_with_program_id(
        &pda,
        mint_account.key,
        &TOKEN_2022_PROGRAM_ID,
    );
    if *token_account.key != associated_token_address {
        msg!("Token account does not match the expected associated token account.");
        return Err(ProgramError::InvalidAccountData);
    }

    // Ensure the token account is not already created
    if token_account.lamports() > 0 {
        msg!("Token account already exists.");
        return Err(ProgramError::AccountAlreadyInitialized);
    }

    // Get the rent exemption
    let rent = Rent::from_account_info(rent_sysvar_account)?;
    let required_lamports = rent.minimum_balance(spl_token_2022::state::Account::LEN);

    msg!("Creating the token account using the System Program1");

    // Step 1: Create the account (for the token account)
    // Step 1: Creating the token account using the system instruction
    let create_account_ix = create_associated_token_account(
        payer_account.key,      // Payer signs the transaction
        program_pda.key,        // Token account being created (PDA is not a signer)
        mint_account.key,       // Rent-exempt lamports
        &TOKEN_2022_PROGRAM_ID, // Size of the token account
    );

    // Invoke the instruction, only the payer needs to sign
    invoke(
        &create_account_ix,
        &[
            payer_account.clone(), // Payer signs the transaction
            program_pda.clone(),   // The new token account (PDA, not a signer)
            token_account.clone(),
            mint_account.clone(),
            token_program_account.clone(),
            ata_program_account.clone(),
        ],
    )?;

    msg!("Token account created successfully using the System Program");

    msg!("State account (PDA) initialized successfully");

    msg!("Token account created and initialized for the PDA.");
    Ok(())
}
