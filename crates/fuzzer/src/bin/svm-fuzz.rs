use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use svm_fuzz::{
    Case, Corpus, Error, Executor, ProgramSpec, Violation, builtin_invariants, filter_invariants,
    generate_sequence, shrink,
};

#[derive(Parser)]
#[command(
    name = "svm-fuzz",
    version,
    about = "Invariant fuzzer for Solana programs on LiteSVM"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run(RunArgs),
    Replay(ReplayArgs),
    Shrink(ShrinkArgs),
    List(ListArgs),
}

#[derive(Args)]
struct RunArgs {
    #[arg(long)]
    program: PathBuf,
    #[arg(long)]
    spec: PathBuf,
    #[arg(long)]
    seed: u64,
    #[arg(long, default_value_t = 64)]
    steps: usize,
    #[arg(long, default_value = "corpus")]
    corpus: PathBuf,
    #[arg(long)]
    invariant: Option<String>,
}

#[derive(Args)]
struct ReplayArgs {
    #[arg(long, default_value = "corpus")]
    corpus: PathBuf,
    #[arg(long)]
    id: String,
}

#[derive(Args)]
struct ShrinkArgs {
    #[arg(long, default_value = "corpus")]
    corpus: PathBuf,
    #[arg(long)]
    id: String,
}

#[derive(Args)]
struct ListArgs {
    #[arg(long, default_value = "corpus")]
    corpus: PathBuf,
}

fn main() -> ExitCode {
    match dispatch() {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(2)
        }
    }
}

fn dispatch() -> Result<ExitCode> {
    match Cli::parse().command {
        Command::Run(args) => run(args),
        Command::Replay(args) => replay(args),
        Command::Shrink(args) => shrink_case(args),
        Command::List(args) => list(args),
    }
}

fn run(args: RunArgs) -> Result<ExitCode> {
    let spec = ProgramSpec::load(&args.spec)
        .with_context(|| format!("loading spec {}", args.spec.display()))?;
    let (program_path, program) = read_program(&args.program)?;
    let invariants = filter_invariants(builtin_invariants(&spec)?, args.invariant.as_deref())?;
    let executor = Executor::with_invariants(spec.clone(), program.clone(), invariants)?;

    let sequence = generate_sequence(&spec, args.seed, args.steps)?;
    let report = executor.run(args.seed, &sequence)?;
    let Some(violation) = report.violation else {
        println!(
            "no violation: seed={} steps={} executed={}",
            args.seed, args.steps, report.executed_steps
        );
        return Ok(ExitCode::SUCCESS);
    };

    let original_steps = violation.sequence.len();
    let outcome = shrink(
        &executor,
        args.seed,
        &violation.sequence,
        &violation.invariant,
    )?;
    let case = Case::new(
        program_path,
        &program,
        &spec,
        outcome.violation.clone(),
        original_steps,
    )?;
    let corpus = Corpus::new(&args.corpus);
    let case_path = corpus.save(&case)?;

    println!("violation found: seed={} steps={}", args.seed, args.steps);
    println!(
        "shrunk: {} -> {} steps",
        outcome.original_steps, outcome.minimized_steps
    );
    print_violation(&outcome.violation);
    println!("corpus: {}", case_path.display());
    Ok(ExitCode::from(1))
}

fn replay(args: ReplayArgs) -> Result<ExitCode> {
    let corpus = Corpus::new(&args.corpus);
    let case = corpus.load(&args.id)?;
    let program = read_case_program(&case)?;
    let executor = executor_for_case(&case, program)?;

    let report = executor.run_with_invariant(
        case.violation.seed,
        &case.violation.sequence,
        &case.violation.invariant,
    )?;
    let Some(violation) = report.violation else {
        eprintln!(
            "case {} no longer reproduces {} at seed {}",
            case.id, case.violation.invariant, case.violation.seed
        );
        return Ok(ExitCode::FAILURE);
    };
    if violation != case.violation {
        eprintln!("case {} reproduced a different violation", case.id);
        print_violation(&violation);
        return Ok(ExitCode::FAILURE);
    }

    println!(
        "replayed case {} from seed {}",
        case.id, case.violation.seed
    );
    print_violation(&violation);
    Ok(ExitCode::SUCCESS)
}

fn shrink_case(args: ShrinkArgs) -> Result<ExitCode> {
    let corpus = Corpus::new(&args.corpus);
    let mut case = corpus.load(&args.id)?;
    let program = read_case_program(&case)?;
    let executor = executor_for_case(&case, program)?;

    let report = executor.run_with_invariant(
        case.violation.seed,
        &case.violation.sequence,
        &case.violation.invariant,
    )?;
    let Some(current) = report.violation else {
        eprintln!(
            "case {} no longer reproduces {}; refusing to rewrite",
            case.id, case.violation.invariant
        );
        return Ok(ExitCode::FAILURE);
    };

    let outcome = shrink(
        &executor,
        case.violation.seed,
        &current.sequence,
        &current.invariant,
    )?;
    let before = outcome.original_steps;
    case.violation = outcome.violation;
    case.minimized_steps = outcome.minimized_steps;
    let case_path = corpus.save(&case)?;

    println!(
        "re-shrunk case {}: {} -> {} steps",
        case.id, before, case.minimized_steps
    );
    print_violation(&case.violation);
    println!("corpus: {}", case_path.display());
    Ok(ExitCode::SUCCESS)
}

fn list(args: ListArgs) -> Result<ExitCode> {
    let corpus = Corpus::new(&args.corpus);
    let cases = match corpus.list() {
        Ok(cases) => cases,
        Err(Error::Io { source, .. }) if source.kind() == std::io::ErrorKind::NotFound => {
            Vec::new()
        }
        Err(error) => return Err(error.into()),
    };
    if cases.is_empty() {
        println!("no cases in {}", corpus.dir().display());
        return Ok(ExitCode::SUCCESS);
    }
    println!(
        "{:<34} {:<20} {:>6} {:>6}  program",
        "id", "invariant", "seed", "steps"
    );
    for case in cases {
        println!(
            "{:<34} {:<20} {:>6} {:>6}  {}",
            case.id, case.invariant, case.seed, case.minimized_steps, case.program_path
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn executor_for_case(case: &Case, program: Vec<u8>) -> Result<Executor> {
    let invariants = filter_invariants(
        builtin_invariants(&case.spec)?,
        Some(case.violation.invariant.as_str()),
    )?;
    Executor::with_invariants(case.spec.clone(), program, invariants).map_err(Into::into)
}

fn read_program(path: &Path) -> Result<(String, Vec<u8>)> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("resolving program {}", path.display()))?;
    let bytes =
        fs::read(&canonical).with_context(|| format!("reading program {}", canonical.display()))?;
    Ok((canonical.to_string_lossy().into_owned(), bytes))
}

fn read_case_program(case: &Case) -> Result<Vec<u8>> {
    let (_, program) = read_program(Path::new(&case.program_path))?;
    let digest = svm_fuzz::sha256_hex(&program);
    if digest != case.program_sha256 {
        anyhow::bail!(
            "program bytes changed for case {}: stored {}, current {}",
            case.id,
            case.program_sha256,
            digest
        );
    }
    Ok(program)
}

fn print_violation(violation: &Violation) {
    println!("invariant: {}", violation.invariant);
    println!("seed: {}", violation.seed);
    println!("step: {}", violation.step_index);
    println!("message: {}", violation.message);
    println!("minimal sequence ({} steps):", violation.sequence.len());
    for (index, step) in violation.sequence.iter().enumerate() {
        println!("  {index}: {step}");
    }
    println!("account diff:");
    if violation.diff.is_empty() {
        println!("  (no account changes)");
    }
    for diff in &violation.diff {
        print!("{diff}");
    }
}
