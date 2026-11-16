use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::spec::ProgramSpec;
use crate::world::Violation;

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Case {
    pub schema_version: u32,
    pub id: String,
    pub program_path: String,
    pub program_sha256: String,
    pub spec: ProgramSpec,
    pub violation: Violation,
    pub original_steps: usize,
    pub minimized_steps: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CaseSummary {
    pub id: String,
    pub seed: u64,
    pub invariant: String,
    pub minimized_steps: usize,
    pub program_path: String,
}

impl Case {
    pub fn new(
        program_path: String,
        program: &[u8],
        spec: &ProgramSpec,
        violation: Violation,
        original_steps: usize,
    ) -> Result<Self> {
        let id = compute_case_id(program, spec, violation.seed)?;
        let minimized_steps = violation.sequence.len();
        Ok(Self {
            schema_version: SCHEMA_VERSION,
            id,
            program_path,
            program_sha256: sha256_hex(program),
            spec: spec.clone(),
            violation,
            original_steps,
            minimized_steps,
        })
    }

    pub fn summary(&self) -> CaseSummary {
        CaseSummary {
            id: self.id.clone(),
            seed: self.violation.seed,
            invariant: self.violation.invariant.clone(),
            minimized_steps: self.minimized_steps,
            program_path: self.program_path.clone(),
        }
    }
}

pub struct Corpus {
    dir: PathBuf,
}

impl Corpus {
    pub fn new(dir: impl Into<PathBuf>) -> Self {
        Self { dir: dir.into() }
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn case_path(&self, id: &str) -> Result<PathBuf> {
        let id = normalize_id(id)?;
        Ok(self.dir.join(format!("{id}.json")))
    }

    pub fn save(&self, case: &Case) -> Result<PathBuf> {
        fs::create_dir_all(&self.dir).map_err(|source| Error::Write {
            path: self.dir.clone(),
            source,
        })?;
        let path = self.case_path(&case.id)?;
        let temporary = path.with_extension("json.tmp");
        let mut bytes = serde_json::to_vec_pretty(case)?;
        bytes.push(b'\n');
        fs::write(&temporary, bytes).map_err(|source| Error::Write {
            path: temporary.clone(),
            source,
        })?;
        fs::rename(&temporary, &path).map_err(|source| Error::Write {
            path: path.clone(),
            source,
        })?;
        Ok(path)
    }

    pub fn load(&self, id: &str) -> Result<Case> {
        let path = self.case_path(id)?;
        let text = fs::read_to_string(&path).map_err(|source| Error::Io {
            path: path.clone(),
            source,
        })?;
        let case: Case =
            serde_json::from_str(&text).map_err(|source| Error::Json { path, source })?;
        if case.schema_version != SCHEMA_VERSION {
            return Err(Error::Corpus(format!(
                "unsupported case schema version {} (expected {SCHEMA_VERSION})",
                case.schema_version
            )));
        }
        Ok(case)
    }

    pub fn list(&self) -> Result<Vec<CaseSummary>> {
        let entries = fs::read_dir(&self.dir).map_err(|source| Error::Io {
            path: self.dir.clone(),
            source,
        })?;
        let mut summaries = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|source| Error::Io {
                path: self.dir.clone(),
                source,
            })?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let text = fs::read_to_string(&path).map_err(|source| Error::Io {
                path: path.clone(),
                source,
            })?;
            let case: Case = serde_json::from_str(&text).map_err(|source| Error::Json {
                path: path.clone(),
                source,
            })?;
            summaries.push(case.summary());
        }
        summaries.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(summaries)
    }
}

fn normalize_id(id: &str) -> Result<&str> {
    let id = id.strip_suffix(".json").unwrap_or(id);
    if id.is_empty() || id.len() > 64 || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::Corpus(format!(
            "invalid case id {id:?}: expected hex digits"
        )));
    }
    Ok(id)
}

pub fn compute_case_id(program: &[u8], spec: &ProgramSpec, seed: u64) -> Result<String> {
    let spec_json = serde_json::to_vec(spec)?;
    let mut hasher = Sha256::new();
    hasher.update((program.len() as u64).to_le_bytes());
    hasher.update(program);
    hasher.update((spec_json.len() as u64).to_le_bytes());
    hasher.update(&spec_json);
    hasher.update(seed.to_le_bytes());
    Ok(hex::encode(&hasher.finalize()[..16]))
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn case_id_depends_on_program_spec_and_seed() {
        let spec =
            ProgramSpec::from_json_str(include_str!("../../../examples/vault.json")).unwrap();
        let first = compute_case_id(b"program", &spec, 7).unwrap();
        let second = compute_case_id(b"program", &spec, 7).unwrap();
        let other_seed = compute_case_id(b"program", &spec, 8).unwrap();
        let other_program = compute_case_id(b"different", &spec, 7).unwrap();
        assert_eq!(first, second);
        assert_ne!(first, other_seed);
        assert_ne!(first, other_program);
        assert_eq!(first.len(), 32);
    }
}
