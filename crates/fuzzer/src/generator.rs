use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::error::Result;
use crate::spec::{ProgramSpec, ResolvedData, ResolvedSpec};

/// One concrete instruction emitted by the generator and later replayed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    pub instruction: String,
    pub index: u8,
    pub accounts: Vec<StepAccount>,
    pub signers: Vec<String>,
    pub data_hex: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepAccount {
    pub name: String,
    pub address: String,
    pub writable: bool,
    pub is_signer: bool,
}

impl Step {
    pub fn data(&self) -> std::result::Result<Vec<u8>, crate::error::Error> {
        hex::decode(&self.data_hex).map_err(|source| crate::error::Error::Hex {
            field: format!("step {} data_hex", self.instruction),
            source,
        })
    }
}

impl std::fmt::Display for Step {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} accounts=[", self.instruction)?;
        for (index, account) in self.accounts.iter().enumerate() {
            if index > 0 {
                write!(formatter, ", ")?;
            }
            write!(
                formatter,
                "{}:{}{}",
                account.name,
                if account.writable { "w" } else { "r" },
                if account.is_signer { ":signer" } else { "" }
            )?;
        }
        write!(
            formatter,
            "] signers=[{}] data=0x{}",
            self.signers.join(","),
            self.data_hex
        )
    }
}

/// Seeded instruction-sequence generator.
///
/// The same spec, seed, and step count always produce the same sequence. The
/// RNG drives template choice, optional signer selection, and generated
/// instruction argument bytes, in that order.
pub struct Generator {
    resolved: ResolvedSpec,
    rng: StdRng,
}

impl Generator {
    pub fn new(spec: &ProgramSpec, seed: u64) -> Result<Self> {
        Ok(Self {
            resolved: spec.resolve()?,
            rng: StdRng::seed_from_u64(seed),
        })
    }

    pub fn sequence(&mut self, steps: usize) -> Result<Vec<Step>> {
        let mut sequence = Vec::with_capacity(steps);
        for _ in 0..steps {
            sequence.push(self.next_step()?);
        }
        Ok(sequence)
    }

    pub fn next_step(&mut self) -> Result<Step> {
        let template_index = self.rng.random_range(0..self.resolved.instructions.len());
        let template = &self.resolved.instructions[template_index];

        let mut accounts = Vec::with_capacity(template.accounts.len());
        let mut signers = Vec::new();
        for used in &template.accounts {
            let is_signer = used.can_sign && (used.required_signer || self.rng.random_bool(0.5));
            if is_signer {
                signers.push(used.address.to_string());
            }
            accounts.push(StepAccount {
                name: used.name.clone(),
                address: used.address.to_string(),
                writable: used.writable,
                is_signer,
            });
        }

        let mut data = vec![template.index];
        match &template.data {
            ResolvedData::Fixed(bytes) => data.extend_from_slice(bytes),
            ResolvedData::Generated { len } => {
                for _ in 0..*len {
                    data.push(self.rng.random::<u8>());
                }
            }
        }

        Ok(Step {
            instruction: template.name.clone(),
            index: template.index,
            accounts,
            signers,
            data_hex: hex::encode(data),
        })
    }
}

pub fn generate_sequence(spec: &ProgramSpec, seed: u64, steps: usize) -> Result<Vec<Step>> {
    Generator::new(spec, seed)?.sequence(steps)
}
