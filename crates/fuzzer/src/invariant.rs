use std::collections::BTreeSet;

use solana_address::Address;

use crate::error::{Error, Result};
use crate::generator::Step;
use crate::spec::{ProgramSpec, ResolvedProtected};
use crate::world::World;

/// Everything an invariant may inspect about one executed step.
pub struct StepContext<'a> {
    pub spec: &'a ProgramSpec,
    pub program_id: Address,
    pub seed: u64,
    pub step_index: usize,
    pub step: &'a Step,
    pub before: &'a World,
    pub after: &'a World,
    pub trace: &'a [crate::world::StepTrace],
}

/// A property that must hold after every instruction.
///
/// Returning `Err` produces a [`crate::Violation`] carrying the message.
pub trait Invariant {
    fn name(&self) -> &str;
    fn check(&self, context: &StepContext<'_>) -> std::result::Result<(), String>;
}

pub const LAMPORT_CONSERVATION: &str = "lamport-conservation";
pub const PROTECTED_ACCOUNTS: &str = "protected-accounts";
pub const NO_UNAUTHORIZED_DEBIT: &str = "no-unauthorized-debit";

pub struct LamportConservation;

impl Invariant for LamportConservation {
    fn name(&self) -> &str {
        LAMPORT_CONSERVATION
    }

    fn check(&self, context: &StepContext<'_>) -> std::result::Result<(), String> {
        let before: u128 = context
            .before
            .accounts
            .values()
            .map(|account| u128::from(account.lamports))
            .sum();
        let after: u128 = context
            .after
            .accounts
            .values()
            .map(|account| u128::from(account.lamports))
            .sum();
        if before == after {
            Ok(())
        } else {
            Err(format!(
                "tracked lamports changed from {before} to {after} (delta {})",
                after as i128 - before as i128
            ))
        }
    }
}

pub struct ProtectedAccounts {
    rules: Vec<ResolvedProtected>,
}

impl ProtectedAccounts {
    pub fn from_spec(spec: &ProgramSpec) -> Result<Self> {
        Ok(Self {
            rules: spec.resolve()?.protected,
        })
    }
}

impl Invariant for ProtectedAccounts {
    fn name(&self) -> &str {
        PROTECTED_ACCOUNTS
    }

    fn check(&self, context: &StepContext<'_>) -> std::result::Result<(), String> {
        for rule in &self.rules {
            let before = context.before.accounts.get(&rule.account);
            let after = context.after.accounts.get(&rule.account);
            if before.is_none() && after.is_none() {
                continue;
            }

            let before_owner = before.map(|account| account.owner);
            let after_owner = after.map(|account| account.owner);
            if before_owner != after_owner {
                return Err(format!(
                    "protected account {} ({}) owner changed from {} to {}",
                    rule.account,
                    rule.account_name,
                    before_owner.map_or_else(|| "<absent>".to_string(), |owner| owner.to_string()),
                    after_owner.map_or_else(|| "<absent>".to_string(), |owner| owner.to_string())
                ));
            }

            let before_lamports = before.map_or(0, |account| account.lamports);
            let after_lamports = after.map_or(0, |account| account.lamports);
            let lamports_decreased = after_lamports < before_lamports;
            let data_changed =
                before.map(|account| &account.data) != after.map(|account| &account.data);
            if (lamports_decreased || data_changed)
                && !context.after.signers.contains(&rule.authority)
            {
                return Err(format!(
                    "protected account {} ({}) changed without signature from authority {} ({}): \
                     lamports {before_lamports} -> {after_lamports}, data_changed={data_changed}",
                    rule.account, rule.account_name, rule.authority, rule.authority_name
                ));
            }
        }
        Ok(())
    }
}

pub struct NoUnauthorizedDebit {
    program_id: Address,
}

impl NoUnauthorizedDebit {
    pub fn new(program_id: Address) -> Self {
        Self { program_id }
    }
}

impl Invariant for NoUnauthorizedDebit {
    fn name(&self) -> &str {
        NO_UNAUTHORIZED_DEBIT
    }

    fn check(&self, context: &StepContext<'_>) -> std::result::Result<(), String> {
        for (address, before) in &context.before.accounts {
            let after_lamports = context
                .after
                .accounts
                .get(address)
                .map_or(0, |account| account.lamports);
            if after_lamports >= before.lamports {
                continue;
            }
            let signed = context.after.signers.contains(address);
            let owner = context
                .after
                .accounts
                .get(address)
                .map_or(before.owner, |account| account.owner);
            if !signed && owner != self.program_id {
                return Err(format!(
                    "account {} lost {} lamports without signing; owner {} is not the executing \
                     program {}",
                    address,
                    before.lamports - after_lamports,
                    owner,
                    self.program_id
                ));
            }
        }
        Ok(())
    }
}

pub fn builtin_invariants(spec: &ProgramSpec) -> Result<Vec<Box<dyn Invariant>>> {
    let resolved = spec.resolve()?;
    Ok(vec![
        Box::new(LamportConservation),
        Box::new(ProtectedAccounts::from_spec(spec)?),
        Box::new(NoUnauthorizedDebit::new(resolved.program_id)),
    ])
}

pub fn filter_invariants(
    invariants: Vec<Box<dyn Invariant>>,
    only: Option<&str>,
) -> Result<Vec<Box<dyn Invariant>>> {
    let Some(name) = only else {
        return Ok(invariants);
    };
    let available: Vec<String> = invariants
        .iter()
        .map(|invariant| invariant.name().to_string())
        .collect();
    if !available.iter().any(|candidate| candidate == name) {
        return Err(Error::UnknownInvariant {
            name: name.to_string(),
            available,
        });
    }
    Ok(invariants
        .into_iter()
        .filter(|invariant| invariant.name() == name)
        .collect())
}

pub(crate) fn selected_names(
    invariants: &[Box<dyn Invariant>],
    only: Option<&str>,
) -> Result<BTreeSet<String>> {
    let all: BTreeSet<String> = invariants
        .iter()
        .map(|invariant| invariant.name().to_string())
        .collect();
    match only {
        None => Ok(all),
        Some(name) if all.contains(name) => Ok(BTreeSet::from([name.to_string()])),
        Some(name) => Err(Error::UnknownInvariant {
            name: name.to_string(),
            available: all.into_iter().collect(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::{BTreeMap, BTreeSet};

    use solana_address::Address;

    use super::*;
    use crate::generator::Step;
    use crate::spec::ProgramSpec;
    use crate::world::AccountState;

    fn address(byte: u8) -> Address {
        Address::new_from_array([byte; 32])
    }

    fn program_spec() -> ProgramSpec {
        ProgramSpec::from_json_str(
            r#"{
                "name": "unit",
                "program_id": "BPFLoader1111111111111111111111111111111111",
                "accounts": [
                    { "name": "vault", "address": "SysvarRent111111111111111111111111111111111", "lamports": 100, "owner": "BPFLoader1111111111111111111111111111111111" },
                    { "name": "authority", "address": "11111111111111111111111111111111", "lamports": 1, "owner": "11111111111111111111111111111111" }
                ],
                "instructions": [{ "name": "touch", "index": 0, "accounts": [{ "name": "vault", "writable": true }] }],
                "protected": [{ "account": "vault", "authority": "authority" }]
            }"#,
        )
        .unwrap()
    }

    fn step() -> Step {
        Step {
            instruction: "touch".to_string(),
            index: 0,
            accounts: Vec::new(),
            signers: Vec::new(),
            data_hex: String::new(),
        }
    }

    fn world(accounts: &[(Address, u64, Address, Vec<u8>)], signers: &[Address]) -> World {
        World {
            accounts: accounts
                .iter()
                .map(|(address, lamports, owner, data)| {
                    (
                        *address,
                        AccountState {
                            lamports: *lamports,
                            owner: *owner,
                            data: data.clone(),
                        },
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            signers: signers.iter().copied().collect::<BTreeSet<_>>(),
        }
    }

    fn check(
        invariant: &dyn Invariant,
        spec: &ProgramSpec,
        step: &Step,
        before: &World,
        after: &World,
    ) -> std::result::Result<(), String> {
        invariant.check(&StepContext {
            spec,
            program_id: Address::new_from_array([9; 32]),
            seed: 1,
            step_index: 0,
            step,
            before,
            after,
            trace: &[],
        })
    }

    #[test]
    fn lamport_conservation_detects_a_leak() {
        let spec = program_spec();
        let step = step();
        let account = address(1);
        let owner = address(9);
        let before = world(&[(account, 100, owner, Vec::new())], &[]);
        let after = world(&[(account, 99, owner, Vec::new())], &[]);
        assert!(check(&LamportConservation, &spec, &step, &before, &before).is_ok());
        let error = check(&LamportConservation, &spec, &step, &before, &after).unwrap_err();
        assert!(error.contains("delta -1"));
    }

    #[test]
    fn protected_accounts_require_the_authority_signature() {
        let spec = program_spec();
        let step = step();
        let resolved = spec.resolve().unwrap();
        let rule = &resolved.protected[0];
        let before = world(&[(rule.account, 100, resolved.program_id, vec![7])], &[]);
        let unsigned = world(&[(rule.account, 90, resolved.program_id, vec![7])], &[]);
        let signed = world(
            &[(rule.account, 90, resolved.program_id, vec![7])],
            &[rule.authority],
        );
        let invariant = ProtectedAccounts::from_spec(&spec).unwrap();
        assert!(check(&invariant, &spec, &step, &before, &unsigned).is_err());
        assert!(check(&invariant, &spec, &step, &before, &signed).is_ok());

        let changed_data = world(&[(rule.account, 100, resolved.program_id, vec![8])], &[]);
        assert!(check(&invariant, &spec, &step, &before, &changed_data).is_err());
    }

    #[test]
    fn unauthorized_debit_rule_matches_the_documented_exemption() {
        let spec = program_spec();
        let step = step();
        let program_id = Address::new_from_array([9; 32]);
        let victim = address(2);
        let system_owner = Address::new_from_array([1; 32]);
        let invariant = NoUnauthorizedDebit::new(program_id);

        let before = world(&[(victim, 100, system_owner, Vec::new())], &[]);
        let after = world(&[(victim, 90, system_owner, Vec::new())], &[]);
        assert!(check(&invariant, &spec, &step, &before, &after).is_err());

        let signed = world(&[(victim, 90, system_owner, Vec::new())], &[victim]);
        assert!(check(&invariant, &spec, &step, &before, &signed).is_ok());

        let program_owned = world(&[(victim, 90, program_id, Vec::new())], &[]);
        assert!(check(&invariant, &spec, &step, &before, &program_owned).is_ok());
    }
}
