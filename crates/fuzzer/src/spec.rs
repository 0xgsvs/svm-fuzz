use std::collections::BTreeSet;
use std::fs;
use std::path::Path;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use solana_address::Address;
use solana_keypair::Keypair;
use solana_signer::Signer;

use crate::error::{Error, Result};

/// Largest instruction-argument payload a generated template may ask for.
pub const MAX_GENERATED_DATA_LEN: usize = 64;

/// A JSON program specification: the program id, the starting account set, and
/// the instruction templates the generator is allowed to emit.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProgramSpec {
    pub name: String,
    pub program_id: String,
    pub accounts: Vec<AccountSpec>,
    pub instructions: Vec<InstructionTemplate>,
    #[serde(default)]
    pub protected: Vec<ProtectedAccount>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountSpec {
    pub name: String,
    pub address: String,
    pub lamports: u64,
    pub owner: String,
    #[serde(default)]
    pub data_hex: String,
    /// Whether the generator may put this account in a transaction's signer set.
    #[serde(default)]
    pub can_sign: bool,
    /// Base58-encoded 64-byte keypair. Required when `can_sign` is true.
    #[serde(default)]
    pub secret_key: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionTemplate {
    pub name: String,
    /// Instruction discriminator prepended to the generated data.
    pub index: u8,
    pub accounts: Vec<InstructionAccount>,
    #[serde(default)]
    pub data: DataTemplate,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InstructionAccount {
    pub name: String,
    #[serde(default)]
    pub writable: bool,
    /// Sign this account on every generated step. It must be able to sign.
    #[serde(default)]
    pub required_signer: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DataTemplate {
    /// Fixed argument bytes, hex encoded.
    Fixed { hex: String },
    /// `len` random argument bytes drawn from the seeded RNG.
    Generated { len: usize },
}

impl Default for DataTemplate {
    fn default() -> Self {
        Self::Fixed { hex: String::new() }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProtectedAccount {
    pub account: String,
    pub authority: String,
}

impl ProgramSpec {
    pub fn load(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path).map_err(|source| Error::Io {
            path: path.to_path_buf(),
            source,
        })?;
        let spec: Self = serde_json::from_str(&text).map_err(|source| Error::Json {
            path: path.to_path_buf(),
            source,
        })?;
        spec.resolve()?;
        Ok(spec)
    }

    pub fn from_json_str(text: &str) -> Result<Self> {
        let spec: Self = serde_json::from_str(text)?;
        spec.resolve()?;
        Ok(spec)
    }

    pub(crate) fn resolve(&self) -> Result<ResolvedSpec> {
        let program_id = parse_address("program_id", &self.program_id)?;
        if self.name.trim().is_empty() {
            return Err(Error::InvalidSpec("name must not be empty".into()));
        }

        let mut account_names = BTreeSet::new();
        let mut account_addresses = BTreeSet::new();
        let mut accounts = Vec::with_capacity(self.accounts.len());
        for account in &self.accounts {
            if !account_names.insert(account.name.clone()) {
                return Err(Error::InvalidSpec(format!(
                    "duplicate account name {:?}",
                    account.name
                )));
            }
            let address = parse_address(&format!("accounts.{}", account.name), &account.address)?;
            if !account_addresses.insert(address) {
                return Err(Error::InvalidSpec(format!(
                    "duplicate account address {}",
                    account.address
                )));
            }
            let owner = parse_address(&format!("accounts.{}.owner", account.name), &account.owner)?;
            let data = decode_hex(
                &format!("accounts.{}.data_hex", account.name),
                &account.data_hex,
            )?;

            let secret_key = match &account.secret_key {
                Some(encoded) => {
                    let bytes =
                        decode_base58(&format!("accounts.{}.secret_key", account.name), encoded)?;
                    let keypair =
                        Keypair::try_from(bytes.as_slice()).map_err(|error| Error::SecretKey {
                            field: format!("accounts.{}", account.name),
                            message: error.to_string(),
                        })?;
                    if keypair.pubkey() != address {
                        return Err(Error::InvalidSpec(format!(
                            "account {:?}: secret_key does not match address {}",
                            account.name, account.address
                        )));
                    }
                    Some(bytes)
                }
                None => None,
            };

            if account.can_sign && secret_key.is_none() {
                return Err(Error::InvalidSpec(format!(
                    "account {:?}: can_sign requires secret_key",
                    account.name
                )));
            }
            if !account.can_sign && secret_key.is_some() {
                return Err(Error::InvalidSpec(format!(
                    "account {:?}: secret_key provided but can_sign is false",
                    account.name
                )));
            }

            accounts.push(ResolvedAccount {
                name: account.name.clone(),
                address,
                lamports: account.lamports,
                owner,
                data,
                secret_key,
                can_sign: account.can_sign,
            });
        }

        if self.instructions.is_empty() {
            return Err(Error::InvalidSpec(
                "at least one instruction template is required".into(),
            ));
        }

        let mut instruction_names = BTreeSet::new();
        let mut instruction_indices = BTreeSet::new();
        let mut instructions = Vec::with_capacity(self.instructions.len());
        for template in &self.instructions {
            if !instruction_names.insert(template.name.clone()) {
                return Err(Error::InvalidSpec(format!(
                    "duplicate instruction name {:?}",
                    template.name
                )));
            }
            if !instruction_indices.insert(template.index) {
                return Err(Error::InvalidSpec(format!(
                    "duplicate instruction index {}",
                    template.index
                )));
            }
            if template.accounts.is_empty() {
                return Err(Error::InvalidSpec(format!(
                    "instruction {:?}: accounts must not be empty",
                    template.name
                )));
            }

            let mut seen = BTreeSet::new();
            let mut template_accounts = Vec::with_capacity(template.accounts.len());
            for used in &template.accounts {
                let Some(account) = accounts.iter().find(|a| a.name == used.name) else {
                    return Err(Error::InvalidSpec(format!(
                        "instruction {:?} references unknown account {:?}",
                        template.name, used.name
                    )));
                };
                if !seen.insert(account.address) {
                    return Err(Error::InvalidSpec(format!(
                        "instruction {:?} lists account {:?} twice",
                        template.name, used.name
                    )));
                }
                if used.required_signer && !account.can_sign {
                    return Err(Error::InvalidSpec(format!(
                        "instruction {:?} requires signer {:?}, but that account cannot sign",
                        template.name, used.name
                    )));
                }
                template_accounts.push(ResolvedInstructionAccount {
                    name: account.name.clone(),
                    address: account.address,
                    writable: used.writable,
                    required_signer: used.required_signer,
                    can_sign: account.can_sign,
                });
            }

            let data = match &template.data {
                DataTemplate::Fixed { hex } => ResolvedData::Fixed(decode_hex(
                    &format!("instructions.{}.data.hex", template.name),
                    hex,
                )?),
                DataTemplate::Generated { len } => {
                    if *len > MAX_GENERATED_DATA_LEN {
                        return Err(Error::InvalidSpec(format!(
                            "instruction {:?}: generated data length {len} exceeds {MAX_GENERATED_DATA_LEN}",
                            template.name
                        )));
                    }
                    ResolvedData::Generated { len: *len }
                }
            };

            instructions.push(ResolvedInstruction {
                name: template.name.clone(),
                index: template.index,
                accounts: template_accounts,
                data,
            });
        }

        let mut protected = Vec::with_capacity(self.protected.len());
        for rule in &self.protected {
            let account = accounts
                .iter()
                .find(|a| a.name == rule.account)
                .ok_or_else(|| {
                    Error::InvalidSpec(format!(
                        "protected account {:?} is not declared",
                        rule.account
                    ))
                })?;
            let authority = accounts
                .iter()
                .find(|a| a.name == rule.authority)
                .ok_or_else(|| {
                    Error::InvalidSpec(format!(
                        "protected authority {:?} is not declared",
                        rule.authority
                    ))
                })?;
            protected.push(ResolvedProtected {
                account: account.address,
                account_name: account.name.clone(),
                authority: authority.address,
                authority_name: authority.name.clone(),
            });
        }

        Ok(ResolvedSpec {
            program_id,
            accounts,
            instructions,
            protected,
        })
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedSpec {
    pub program_id: Address,
    pub accounts: Vec<ResolvedAccount>,
    pub instructions: Vec<ResolvedInstruction>,
    pub protected: Vec<ResolvedProtected>,
}

impl ResolvedSpec {
    pub(crate) fn instruction(&self, name: &str) -> Option<&ResolvedInstruction> {
        self.instructions
            .iter()
            .find(|instruction| instruction.name == name)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedAccount {
    pub name: String,
    pub address: Address,
    pub lamports: u64,
    pub owner: Address,
    pub data: Vec<u8>,
    pub secret_key: Option<Vec<u8>>,
    pub can_sign: bool,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedInstruction {
    pub name: String,
    pub index: u8,
    pub accounts: Vec<ResolvedInstructionAccount>,
    pub data: ResolvedData,
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedInstructionAccount {
    pub name: String,
    pub address: Address,
    pub writable: bool,
    pub required_signer: bool,
    pub can_sign: bool,
}

#[derive(Clone, Debug)]
pub(crate) enum ResolvedData {
    Fixed(Vec<u8>),
    Generated { len: usize },
}

#[derive(Clone, Debug)]
pub(crate) struct ResolvedProtected {
    pub account: Address,
    pub account_name: String,
    pub authority: Address,
    pub authority_name: String,
}

pub(crate) fn parse_address(field: &str, value: &str) -> Result<Address> {
    Address::from_str(value).map_err(|_| Error::InvalidAddress {
        field: field.to_string(),
        value: value.to_string(),
    })
}

fn decode_base58(field: &str, value: &str) -> Result<Vec<u8>> {
    bs58::decode(value)
        .into_vec()
        .map_err(|error| Error::Base58 {
            field: field.to_string(),
            value: value.to_string(),
            message: error.to_string(),
        })
}

fn decode_hex(field: &str, value: &str) -> Result<Vec<u8>> {
    hex::decode(value).map_err(|source| Error::Hex {
        field: field.to_string(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = include_str!("../../../examples/vault.json");

    #[test]
    fn example_spec_resolves() {
        let spec = ProgramSpec::from_json_str(EXAMPLE).unwrap();
        assert_eq!(spec.accounts.len(), 4);
        assert_eq!(spec.instructions.len(), 2);
        assert_eq!(spec.protected.len(), 1);
        let resolved = spec.resolve().unwrap();
        assert_eq!(resolved.instructions[1].name, "withdraw");
        assert_eq!(resolved.protected[0].authority_name, "authority");
    }

    #[test]
    fn duplicate_account_name_is_rejected() {
        let text = r#"{
            "name": "broken",
            "program_id": "BPFLoader1111111111111111111111111111111111",
            "accounts": [
                { "name": "a", "address": "11111111111111111111111111111111", "lamports": 1, "owner": "11111111111111111111111111111111" },
                { "name": "a", "address": "BPFLoader1111111111111111111111111111111111", "lamports": 1, "owner": "11111111111111111111111111111111" }
            ],
            "instructions": [{ "name": "touch", "index": 0, "accounts": [{ "name": "a" }] }]
        }"#;
        let error = ProgramSpec::from_json_str(text).unwrap_err();
        assert!(error.to_string().contains("duplicate account name"));
    }

    #[test]
    fn can_sign_without_secret_key_is_rejected() {
        let text = r#"{
            "name": "broken",
            "program_id": "BPFLoader1111111111111111111111111111111111",
            "accounts": [
                { "name": "a", "address": "11111111111111111111111111111111", "lamports": 1, "owner": "11111111111111111111111111111111", "can_sign": true }
            ],
            "instructions": [{ "name": "touch", "index": 0, "accounts": [{ "name": "a" }] }]
        }"#;
        let error = ProgramSpec::from_json_str(text).unwrap_err();
        assert!(error.to_string().contains("requires secret_key"));
    }
}
