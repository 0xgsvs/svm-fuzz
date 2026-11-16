pub mod corpus;
pub mod error;
pub mod executor;
pub mod generator;
pub mod invariant;
pub mod shrink;
pub mod spec;
pub mod world;

pub use corpus::{Case, CaseSummary, Corpus, compute_case_id, sha256_hex};
pub use error::{Error, Result};
pub use executor::{Executor, RunReport};
pub use generator::{Generator, Step, StepAccount, generate_sequence};
pub use invariant::{
    Invariant, LAMPORT_CONSERVATION, NO_UNAUTHORIZED_DEBIT, NoUnauthorizedDebit,
    PROTECTED_ACCOUNTS, ProtectedAccounts, StepContext, builtin_invariants, filter_invariants,
};
pub use shrink::{ShrinkOutcome, shrink};
pub use spec::{
    AccountSpec, DataTemplate, InstructionAccount, InstructionTemplate, ProgramSpec,
    ProtectedAccount,
};
pub use world::{AccountDiff, AccountState, StepTrace, Violation, World};
