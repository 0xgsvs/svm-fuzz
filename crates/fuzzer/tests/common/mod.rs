use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

use svm_fuzz::ProgramSpec;

static FIXTURE: OnceLock<PathBuf> = OnceLock::new();

pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("crates/fuzzer has two parents")
        .to_path_buf()
}

pub fn fixture_program() -> &'static Path {
    FIXTURE.get_or_init(|| match find_or_build() {
        Ok(path) => path,
        Err(error) => panic!("{error}"),
    })
}

pub fn fixture_spec() -> ProgramSpec {
    ProgramSpec::load(&repo_root().join("examples/vault.json"))
        .expect("examples/vault.json must be a valid spec")
}

pub fn fixture_bytes() -> Vec<u8> {
    std::fs::read(fixture_program()).expect("fixture .so must be readable")
}

fn find_or_build() -> Result<PathBuf, String> {
    let root = repo_root();
    let candidates = [
        root.join("target/deploy/buggy_vault.so"),
        root.join("programs/buggy-vault/target/deploy/buggy_vault.so"),
        root.join("target/sbpfv3-solana-solana/release/buggy_vault.so"),
        root.join("programs/buggy-vault/target/sbpfv3-solana-solana/release/buggy_vault.so"),
    ];
    if let Some(path) = candidates.iter().find(|path| path.is_file()) {
        return Ok(path.clone());
    }

    let manifest = root.join("programs/buggy-vault/Cargo.toml");
    let command = format!("cargo build-sbf --manifest-path {}", manifest.display());
    let output = Command::new("cargo")
        .args(["build-sbf", "--manifest-path"])
        .arg(&manifest)
        .current_dir(&root)
        .env("CARGO_BUILD_JOBS", "3")
        .output()
        .map_err(|error| format!("failed to run `{command}`: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "`{command}` failed with {}\nstdout:\n{}\nstderr:\n{}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }

    candidates
        .iter()
        .find(|path| path.is_file())
        .cloned()
        .ok_or_else(|| {
            format!(
                "`{command}` succeeded but no .so was found; looked in: {}",
                candidates
                    .iter()
                    .map(|path| path.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        })
}
