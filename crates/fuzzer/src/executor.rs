use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use litesvm::LiteSVM;
use solana_account::Account;
use solana_address::Address;
use solana_instruction::{AccountMeta, Instruction};
use solana_keypair::Keypair;
use solana_message::Message;
use solana_signer::Signer;
use solana_transaction::Transaction;

use crate::error::{Error, Result};
use crate::generator::Step;
use crate::invariant::{Invariant, StepContext, selected_names};
use crate::spec::{ProgramSpec, ResolvedSpec};
use crate::world::{AccountState, StepTrace, Violation, World, diff_worlds};

pub struct Executor {
    spec: ProgramSpec,
    program: Vec<u8>,
    invariants: Vec<Box<dyn Invariant>>,
}

pub struct RunReport {
    pub seed: u64,
    pub requested_steps: usize,
    pub executed_steps: usize,
    pub traces: Vec<StepTrace>,
    pub violation: Option<Violation>,
}

impl Executor {
    pub fn new(spec: ProgramSpec, program: Vec<u8>) -> Result<Self> {
        let invariants = crate::invariant::builtin_invariants(&spec)?;
        Self::with_invariants(spec, program, invariants)
    }

    pub fn with_invariants(
        spec: ProgramSpec,
        program: Vec<u8>,
        invariants: Vec<Box<dyn Invariant>>,
    ) -> Result<Self> {
        spec.resolve()?;
        Ok(Self {
            spec,
            program,
            invariants,
        })
    }

    pub fn run(&self, seed: u64, steps: &[Step]) -> Result<RunReport> {
        self.run_inner(seed, steps, None)
    }

    pub fn run_with_invariant(
        &self,
        seed: u64,
        steps: &[Step],
        invariant: &str,
    ) -> Result<RunReport> {
        self.run_inner(seed, steps, Some(invariant))
    }

    pub fn spec(&self) -> &ProgramSpec {
        &self.spec
    }

    fn run_inner(&self, seed: u64, steps: &[Step], only: Option<&str>) -> Result<RunReport> {
        let resolved = self.spec.resolve()?;
        let selected = selected_names(&self.invariants, only)?;
        let keypairs = keypairs(&resolved)?;

        let mut svm = LiteSVM::new();
        svm.add_program(resolved.program_id, &self.program)?;
        for account in &resolved.accounts {
            svm.set_account(
                account.address,
                Account {
                    lamports: account.lamports,
                    data: account.data.clone(),
                    owner: account.owner,
                    executable: false,
                    rent_epoch: 0,
                },
            )?;
        }

        let payer = Keypair::new();
        if let Err(failed) = svm.airdrop(&payer.pubkey(), 1_000_000_000_000) {
            return Err(Error::Transaction(format!(
                "funding the fuzzer payer failed: {:?}",
                failed.err
            )));
        }

        let mut traces = Vec::with_capacity(steps.len());
        for (step_index, step) in steps.iter().enumerate() {
            let signers = validate_step(&resolved, step, step_index)?;
            let before = snapshot(&svm, &resolved, &signers);

            let instruction = Instruction {
                program_id: resolved.program_id,
                accounts: step
                    .accounts
                    .iter()
                    .map(|account| {
                        let address = parse_step_address(account.address.as_str(), step_index)?;
                        Ok(AccountMeta {
                            pubkey: address,
                            is_signer: account.is_signer,
                            is_writable: account.writable,
                        })
                    })
                    .collect::<Result<Vec<_>>>()?,
                data: step.data()?,
            };

            let blockhash = svm.latest_blockhash();
            let message =
                Message::new_with_blockhash(&[instruction], Some(&payer.pubkey()), &blockhash);
            let mut signing: Vec<&Keypair> = Vec::with_capacity(signers.len() + 1);
            signing.push(&payer);
            for address in &signers {
                let signer = keypairs.get(address).ok_or_else(|| Error::Step {
                    index: step_index,
                    message: format!("signer {address} has no keypair in the spec"),
                })?;
                signing.push(signer);
            }
            let transaction = Transaction::new(&signing, message, blockhash);

            let (ok, error, logs) = match svm.send_transaction(transaction) {
                Ok(metadata) => (true, None, metadata.logs),
                Err(failed) => (false, Some(format!("{:?}", failed.err)), failed.meta.logs),
            };
            let after = snapshot(&svm, &resolved, &signers);
            traces.push(StepTrace {
                step_index,
                instruction: step.instruction.clone(),
                ok,
                error,
                logs,
            });

            let context = StepContext {
                spec: &self.spec,
                program_id: resolved.program_id,
                seed,
                step_index,
                step,
                before: &before,
                after: &after,
                trace: &traces,
            };
            for invariant in &self.invariants {
                if !selected.contains(invariant.name()) {
                    continue;
                }
                if let Err(message) = invariant.check(&context) {
                    let violation = Violation {
                        invariant: invariant.name().to_string(),
                        step_index,
                        message,
                        seed,
                        sequence: steps[..=step_index].to_vec(),
                        diff: diff_worlds(&before, &after),
                    };
                    return Ok(RunReport {
                        seed,
                        requested_steps: steps.len(),
                        executed_steps: step_index + 1,
                        traces,
                        violation: Some(violation),
                    });
                }
            }
        }

        Ok(RunReport {
            seed,
            requested_steps: steps.len(),
            executed_steps: steps.len(),
            traces,
            violation: None,
        })
    }
}

fn keypairs(resolved: &ResolvedSpec) -> Result<BTreeMap<Address, Keypair>> {
    let mut keypairs = BTreeMap::new();
    for account in &resolved.accounts {
        if let Some(secret) = &account.secret_key {
            let keypair =
                Keypair::try_from(secret.as_slice()).map_err(|error| Error::SecretKey {
                    field: format!("accounts.{}", account.name),
                    message: error.to_string(),
                })?;
            keypairs.insert(account.address, keypair);
        }
    }
    Ok(keypairs)
}

fn validate_step(
    resolved: &ResolvedSpec,
    step: &Step,
    step_index: usize,
) -> Result<BTreeSet<Address>> {
    let template = resolved
        .instruction(&step.instruction)
        .ok_or_else(|| Error::Step {
            index: step_index,
            message: format!("unknown instruction template {:?}", step.instruction),
        })?;
    if template.index != step.index {
        return Err(Error::Step {
            index: step_index,
            message: format!(
                "template {:?} has index {}, step has {}",
                step.instruction, template.index, step.index
            ),
        });
    }
    if step.accounts.len() != template.accounts.len() {
        return Err(Error::Step {
            index: step_index,
            message: format!(
                "template {:?} expects {} accounts, step has {}",
                step.instruction,
                template.accounts.len(),
                step.accounts.len()
            ),
        });
    }
    for (actual, expected) in step.accounts.iter().zip(&template.accounts) {
        if actual.name != expected.name
            || actual.address != expected.address.to_string()
            || actual.writable != expected.writable
        {
            return Err(Error::Step {
                index: step_index,
                message: format!(
                    "account slot mismatch: step has {:?}, template expects {:?}",
                    actual.name, expected.name
                ),
            });
        }
    }

    let mut signers = BTreeSet::new();
    for signer in &step.signers {
        let address = parse_step_address(signer, step_index)?;
        if !signers.insert(address) {
            return Err(Error::Step {
                index: step_index,
                message: format!("duplicate signer {address}"),
            });
        }
        if !step
            .accounts
            .iter()
            .any(|account| account.is_signer && account.address == *signer)
        {
            return Err(Error::Step {
                index: step_index,
                message: format!("signer {address} is not a signer account in the step"),
            });
        }
    }
    for account in &step.accounts {
        if account.is_signer != signers.contains(&parse_step_address(&account.address, step_index)?)
        {
            return Err(Error::Step {
                index: step_index,
                message: format!(
                    "account {} signer flag disagrees with signer list",
                    account.name
                ),
            });
        }
    }
    Ok(signers)
}

fn parse_step_address(value: &str, step_index: usize) -> Result<Address> {
    Address::from_str(value).map_err(|_| Error::Step {
        index: step_index,
        message: format!("invalid address {value:?}"),
    })
}

fn snapshot(svm: &LiteSVM, resolved: &ResolvedSpec, signers: &BTreeSet<Address>) -> World {
    let mut addresses: BTreeSet<Address> = resolved
        .accounts
        .iter()
        .map(|account| account.address)
        .collect();
    for template in &resolved.instructions {
        for account in &template.accounts {
            addresses.insert(account.address);
        }
    }
    addresses.extend(
        svm.get_program_accounts(&resolved.program_id)
            .into_iter()
            .map(|(address, _)| address),
    );

    let mut accounts = BTreeMap::new();
    for address in addresses {
        if let Some(account) = svm.get_account(&address) {
            accounts.insert(
                address,
                AccountState {
                    lamports: account.lamports,
                    owner: account.owner,
                    data: account.data,
                },
            );
        }
    }
    World {
        accounts,
        signers: signers.clone(),
    }
}
