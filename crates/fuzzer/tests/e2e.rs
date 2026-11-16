mod common;

use std::path::PathBuf;
use std::str::FromStr;

use svm_fuzz::{
    Case, Corpus, Executor, Invariant, PROTECTED_ACCOUNTS, ProgramSpec, StepContext,
    generate_sequence, shrink,
};

const SEED: u64 = 2;
const STEPS: usize = 64;

fn temp_corpus(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("svm-fuzz-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

#[test]
fn finds_shrinks_and_replays_the_seeded_bug() {
    let spec = common::fixture_spec();
    let program = common::fixture_bytes();
    let executor = Executor::new(spec.clone(), program.clone()).unwrap();

    let sequence = generate_sequence(&spec, SEED, STEPS).unwrap();
    let report = executor.run(SEED, &sequence).unwrap();
    let violation = report.violation.clone().expect("seed 2 must find the bug");
    assert_eq!(violation.invariant, PROTECTED_ACCOUNTS);
    assert_eq!(violation.seed, SEED);
    assert!(
        violation.sequence.len() > 1,
        "the original failure must need shrinking"
    );
    assert!(
        violation.diff.iter().any(|diff| diff.lamports_delta < 0),
        "the vault debit must appear in the account diff"
    );

    let outcome = shrink(&executor, SEED, &violation.sequence, &violation.invariant).unwrap();
    assert_eq!(outcome.original_steps, violation.sequence.len());
    assert_eq!(outcome.minimized_steps, 1);
    assert_eq!(outcome.sequence.len(), 1);
    assert_eq!(outcome.sequence[0].instruction, "withdraw");
    let authority = spec
        .accounts
        .iter()
        .find(|account| account.name == "authority")
        .expect("example spec declares authority");
    assert!(
        !outcome.sequence[0].signers.contains(&authority.address),
        "the shrunk withdraw must not be signed by the authority"
    );

    let replayed = executor
        .run_with_invariant(SEED, &outcome.sequence, &outcome.violation.invariant)
        .unwrap();
    assert_eq!(replayed.violation.as_ref(), Some(&outcome.violation));
}

#[test]
fn same_seed_produces_byte_identical_sequences_and_violations() {
    let spec = common::fixture_spec();
    let program = common::fixture_bytes();
    let executor = Executor::new(spec.clone(), program).unwrap();

    let first = generate_sequence(&spec, SEED, STEPS).unwrap();
    let second = generate_sequence(&spec, SEED, STEPS).unwrap();
    assert_eq!(first, second);
    assert_eq!(
        serde_json::to_vec(&first).unwrap(),
        serde_json::to_vec(&second).unwrap()
    );

    let different = generate_sequence(&spec, SEED + 1, STEPS).unwrap();
    assert_ne!(first, different);

    let first_report = executor.run(SEED, &first).unwrap();
    let second_report = executor.run(SEED, &second).unwrap();
    assert_eq!(first_report.violation, second_report.violation);
    assert_eq!(first_report.traces.len(), second_report.traces.len());
}

#[test]
fn corpus_roundtrip_preserves_the_case_and_replays_it() {
    let spec = common::fixture_spec();
    let program = common::fixture_bytes();
    let executor = Executor::new(spec.clone(), program.clone()).unwrap();
    let sequence = generate_sequence(&spec, SEED, STEPS).unwrap();
    let violation = executor
        .run(SEED, &sequence)
        .unwrap()
        .violation
        .expect("seed 2 must find the bug");
    let original_steps = violation.sequence.len();
    let outcome = shrink(&executor, SEED, &violation.sequence, &violation.invariant).unwrap();

    let dir = temp_corpus("roundtrip");
    let corpus = Corpus::new(&dir);
    let case = Case::new(
        common::fixture_program().display().to_string(),
        &program,
        &spec,
        outcome.violation.clone(),
        original_steps,
    )
    .unwrap();
    let saved = corpus.save(&case).unwrap();
    assert!(saved.is_file());

    let loaded = corpus.load(&case.id).unwrap();
    assert_eq!(loaded.id, case.id);
    assert_eq!(loaded.violation, case.violation);
    assert_eq!(loaded.program_sha256, case.program_sha256);
    assert_eq!(loaded.minimized_steps, 1);

    let listing = corpus.list().unwrap();
    assert_eq!(listing.len(), 1);
    assert_eq!(listing[0].id, case.id);

    let replay = executor
        .run_with_invariant(
            loaded.violation.seed,
            &loaded.violation.sequence,
            &loaded.violation.invariant,
        )
        .unwrap();
    assert_eq!(replay.violation.as_ref(), Some(&loaded.violation));

    let _ = std::fs::remove_dir_all(&dir);
}

struct RecipientGain {
    recipient: solana_address::Address,
}

impl Invariant for RecipientGain {
    fn name(&self) -> &str {
        "recipient-gain"
    }

    fn check(&self, context: &StepContext<'_>) -> std::result::Result<(), String> {
        let before = context
            .before
            .accounts
            .get(&self.recipient)
            .map_or(0, |account| account.lamports);
        let after = context
            .after
            .accounts
            .get(&self.recipient)
            .map_or(0, |account| account.lamports);
        if after > before {
            Err(format!("recipient gained {} lamports", after - before))
        } else {
            Ok(())
        }
    }
}

#[test]
fn custom_invariants_are_pluggable() {
    let spec = common::fixture_spec();
    let program = common::fixture_bytes();
    let recipient = spec
        .accounts
        .iter()
        .find(|account| account.name == "recipient")
        .expect("example spec declares recipient");
    let recipient = solana_address::Address::from_str(&recipient.address).unwrap();

    let executor = Executor::with_invariants(
        spec.clone(),
        program,
        vec![Box::new(RecipientGain { recipient })],
    )
    .unwrap();
    let sequence = generate_sequence(&spec, 0, 8).unwrap();
    let report = executor.run(0, &sequence).unwrap();
    let violation = report.violation.expect("custom invariant must fire");
    assert_eq!(violation.invariant, "recipient-gain");
    assert!(
        violation
            .diff
            .iter()
            .any(|diff| diff.address == recipient.to_string())
    );
}

#[test]
fn cli_exit_codes_and_replay() {
    let dir = temp_corpus("cli");
    let program = common::fixture_program();
    let spec = common::repo_root().join("examples/vault.json");
    let binary = env!("CARGO_BIN_EXE_svm-fuzz");

    let run = std::process::Command::new(binary)
        .args(["run", "--program"])
        .arg(program)
        .args(["--spec"])
        .arg(&spec)
        .args(["--seed", "2", "--steps", "64", "--corpus"])
        .arg(&dir)
        .output()
        .unwrap();
    assert_eq!(run.status.code(), Some(1));
    let stdout = String::from_utf8(run.stdout).unwrap();
    assert!(stdout.contains("invariant: protected-accounts"));
    let corpus_line = stdout
        .lines()
        .find(|line| line.starts_with("corpus: "))
        .expect("run prints the corpus path");
    let case_path = PathBuf::from(corpus_line.trim_start_matches("corpus: "));
    let id = case_path.file_stem().unwrap().to_str().unwrap().to_string();
    assert!(case_path.is_file());

    let replay = std::process::Command::new(binary)
        .args(["replay", "--corpus"])
        .arg(&dir)
        .args(["--id", &id])
        .output()
        .unwrap();
    assert_eq!(replay.status.code(), Some(0));
    assert!(
        String::from_utf8(replay.stdout)
            .unwrap()
            .contains("replayed case")
    );

    let corpus = Corpus::new(&dir);
    let mut case = corpus.load(&id).unwrap();
    case.violation.sequence.clear();
    corpus.save(&case).unwrap();
    let broken = std::process::Command::new(binary)
        .args(["replay", "--corpus"])
        .arg(&dir)
        .args(["--id", &id])
        .output()
        .unwrap();
    assert_ne!(broken.status.code(), Some(0));
    assert!(
        String::from_utf8(broken.stderr)
            .unwrap()
            .contains("no longer reproduces")
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shrink_is_idempotent() {
    let spec = common::fixture_spec();
    let executor = Executor::new(spec.clone(), common::fixture_bytes()).unwrap();
    let sequence = generate_sequence(&spec, SEED, STEPS).unwrap();
    let violation = executor
        .run(SEED, &sequence)
        .unwrap()
        .violation
        .expect("seed 2 must find the bug");
    let first = shrink(&executor, SEED, &violation.sequence, &violation.invariant).unwrap();
    let second = shrink(&executor, SEED, &first.sequence, &first.violation.invariant).unwrap();
    assert_eq!(second.sequence, first.sequence);
    assert_eq!(second.violation, first.violation);
}

#[test]
fn spec_rejects_unknown_account_references() {
    let text = r#"{
        "name": "broken",
        "program_id": "BPFLoader1111111111111111111111111111111111",
        "accounts": [],
        "instructions": [
            {
                "name": "touch",
                "index": 0,
                "accounts": [{ "name": "missing" }]
            }
        ]
    }"#;
    let error = ProgramSpec::from_json_str(text).unwrap_err();
    assert!(error.to_string().contains("unknown account"));
}
