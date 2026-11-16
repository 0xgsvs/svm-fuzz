use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use serde::{Deserialize, Serialize};
use solana_address::Address;

use crate::generator::Step;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountState {
    pub lamports: u64,
    pub owner: Address,
    pub data: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct World {
    pub accounts: BTreeMap<Address, AccountState>,
    pub signers: BTreeSet<Address>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountView {
    pub lamports: u64,
    pub owner: String,
    pub data_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountDiff {
    pub address: String,
    pub before: Option<AccountView>,
    pub after: Option<AccountView>,
    pub lamports_delta: i128,
}

impl fmt::Display for AccountDiff {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(formatter, "{}", self.address)?;
        let (before_lamports, after_lamports) = match (&self.before, &self.after) {
            (Some(before), Some(after)) => (before.lamports, after.lamports),
            (Some(before), None) => (before.lamports, 0),
            (None, Some(after)) => (0, after.lamports),
            (None, None) => (0, 0),
        };
        writeln!(
            formatter,
            "  lamports: {before_lamports} -> {after_lamports} ({:+})",
            self.lamports_delta
        )?;
        writeln!(
            formatter,
            "  owner: {} -> {}",
            view_field(&self.before, |view| view.owner.as_str()),
            view_field(&self.after, |view| view.owner.as_str())
        )?;
        writeln!(
            formatter,
            "  data: {} -> {}",
            view_field(&self.before, |view| view.data_hex.as_str()),
            view_field(&self.after, |view| view.data_hex.as_str())
        )
    }
}

fn view_field<'a, T>(view: &'a Option<AccountView>, pick: impl Fn(&'a AccountView) -> T) -> String
where
    T: fmt::Display + 'a,
{
    match view {
        Some(view) => format!("{}", pick(view)),
        None => "<absent>".to_string(),
    }
}

/// First invariant failure found while executing a sequence.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Violation {
    pub invariant: String,
    pub step_index: usize,
    pub message: String,
    pub seed: u64,
    pub sequence: Vec<Step>,
    pub diff: Vec<AccountDiff>,
}

#[derive(Clone, Debug)]
pub struct StepTrace {
    pub step_index: usize,
    pub instruction: String,
    pub ok: bool,
    pub error: Option<String>,
    pub logs: Vec<String>,
}

pub fn account_view(state: Option<&AccountState>) -> Option<AccountView> {
    state.map(|state| AccountView {
        lamports: state.lamports,
        owner: state.owner.to_string(),
        data_hex: hex::encode(&state.data),
    })
}

pub fn diff_worlds(before: &World, after: &World) -> Vec<AccountDiff> {
    let addresses: BTreeSet<&Address> = before
        .accounts
        .keys()
        .chain(after.accounts.keys())
        .collect();
    let mut diffs = Vec::new();
    for address in addresses {
        let before_state = before.accounts.get(address);
        let after_state = after.accounts.get(address);
        if before_state == after_state {
            continue;
        }
        let before_lamports = before_state.map_or(0, |state| state.lamports) as i128;
        let after_lamports = after_state.map_or(0, |state| state.lamports) as i128;
        diffs.push(AccountDiff {
            address: address.to_string(),
            before: account_view(before_state),
            after: account_view(after_state),
            lamports_delta: after_lamports - before_lamports,
        });
    }
    diffs
}
