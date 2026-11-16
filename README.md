# svm-fuzz

Property and invariant fuzzer for Solana programs running in-process on
[LiteSVM](https://github.com/LiteSVM/litesvm).

`svm-fuzz` takes a program `.so`, a JSON description of its accounts and
instruction interface, and a seed. It generates a deterministic instruction
sequence, executes it on LiteSVM, and checks invariants after every step. The
first violation is shrunk with delta debugging, written to a corpus, and can be
replayed from the printed seed.

This repository implements milestones M1 and M2: harness, invariants, seeded
generator, determinism, corpus, shrinking, and a deliberately vulnerable fixture
program. It does not yet include M3/M4 polish such as machine-readable reports,
a real third-party program target, or published release artifacts.

## Demo

Build the fixture:

```console
$ cargo build-sbf --manifest-path programs/buggy-vault/Cargo.toml
...
Finished `release` profile [optimized] target(s) in 2.28s
$ find target -name buggy_vault.so -print -quit
target/sbpfv3-solana-solana/release/buggy_vault.so
```

The `build-sbf` output location depends on the Agave/cargo-build-sbf version:
native toolchains write `target/deploy/`, SBPF v3 host toolchains such as 4.5.0
with platform-tools v1.57 write `target/sbpfv3-solana-solana/release/`. Use the
path `find` prints; the test helper searches both.

Run the fuzzer with the seed that finds the seeded missing-signer bug:

```console
$ cargo run -- run --program target/sbpfv3-solana-solana/release/buggy_vault.so \
    --spec examples/vault.json --seed 2 --steps 64 --corpus ./corpus
violation found: seed=2 steps=64
shrunk: 7 -> 1 steps
invariant: protected-accounts
seed: 2
step: 0
message: protected account pALTd3LLjma8cekBZLdQaBtX4a2VNbTDAkcNA5GoUhY (vault) changed without signature from authority 1jRRajKew9UTsfTaERXeye8fhz9zysrFx56aWBMepMd (authority): lamports 5000000000 -> 4999000000, data_changed=false
minimal sequence (1 steps):
  0: withdraw accounts=[vault:w, authority:r, recipient:w:signer] signers=[FSdmZbtxMpfByepBYWM8ea7SeRyH9aue9FEyFdeJqzXd] data=0x01
account diff:
pALTd3LLjma8cekBZLdQaBtX4a2VNbTDAkcNA5GoUhY
  lamports: 5000000000 -> 4999000000 (-1000000)
  owner: 3nrNgr7DBiPUxMCGBAZUbaA24heeS8yCN6Q2BYsqStbh -> 3nrNgr7DBiPUxMCGBAZUbaA24heeS8yCN6Q2BYsqStbh
  data: 002ff73787b603f5b15a195d026000bc34d32935be21aee2d16774d10e5fcc50 -> 002ff73787b603f5b15a195d026000bc34d32935be21aee2d16774d10e5fcc50
FSdmZbtxMpfByepBYWM8ea7SeRyH9aue9FEyFdeJqzXd
  lamports: 1000000 -> 2000000 (+1000000)
  owner: 11111111111111111111111111111111 -> 11111111111111111111111111111111
  data:  -> 
corpus: ./corpus/<id>.json
$ echo $?
1
```

`<id>` is the 32-hex-character case id printed on that line; it changes when the
fixture program bytes change, so copy it from your own run.

Replay the stored case:

```console
$ cargo run -- replay --corpus ./corpus --id <id>
replayed case <id> from seed 2
invariant: protected-accounts
seed: 2
step: 0
message: protected account pALTd3LLjma8cekBZLdQaBtX4a2VNbTDAkcNA5GoUhY (vault) changed without signature from authority 1jRRajKew9UTsfTaERXeye8fhz9zysrFx56aWBMepMd (authority): lamports 5000000000 -> 4999000000, data_changed=false
minimal sequence (1 steps):
  0: withdraw accounts=[vault:w, authority:r, recipient:w:signer] signers=[FSdmZbtxMpfByepBYWM8ea7SeRyH9aue9FEyFdeJqzXd] data=0x01
...
$ echo $?
0
```

The fixture's `withdraw` compares the supplied authority address with the
authority stored in the vault but never calls `authority.is_signer`. The
minimized sequence is a single unsigned `withdraw` that moves 1,000,000 lamports
out of the vault.

## Quickstart

Requirements:

- Rust stable (verified with 1.99.1) with `rustfmt` and `clippy`
- `cargo-build-sbf` from Agave (verified with 4.5.0 and platform-tools v1.57)

```console
cargo build-sbf --manifest-path programs/buggy-vault/Cargo.toml
cargo run -- run --program "$(find target -name buggy_vault.so -print -quit)" \
  --spec examples/vault.json --seed 2 --steps 64 --corpus ./corpus
cargo run -- replay --corpus ./corpus --id <id-from-the-run-output>
cargo test
```

`cargo test` builds the fixture once per test process through a `OnceLock` when
no built `.so` is found, then reuses it. The helper searches `target/deploy/`
and `target/sbpfv3-solana-solana/release/` plus the per-crate variants. If the
build fails, the helper prints the exact `cargo build-sbf` command and its
captured output.

CLI:

```text
svm-fuzz run    --program <so> --spec <json> --seed <u64> --steps <n>
                [--corpus <dir>] [--invariant <name>]
svm-fuzz replay --corpus <dir> --id <id>
svm-fuzz shrink --corpus <dir> --id <id>
svm-fuzz list   --corpus <dir>
```

`run` exits 1 when it finds a violation and 0 otherwise. `replay` exits nonzero
when the stored case no longer reproduces exactly. The default corpus is
`./corpus`.

## Architecture

```text
crates/fuzzer/src/spec.rs       JSON spec parsing, validation, address decoding
crates/fuzzer/src/generator.rs  seeded instruction-sequence generator
crates/fuzzer/src/executor.rs   LiteSVM setup, transaction execution, snapshots
crates/fuzzer/src/invariant.rs  Invariant trait and built-in invariants
crates/fuzzer/src/world.rs      world snapshots, violations, account diffs
crates/fuzzer/src/corpus.rs     case files, stable ids, listing
crates/fuzzer/src/shrink.rs     deterministic delta debugging
crates/fuzzer/src/bin/svm-fuzz.rs  CLI
programs/buggy-vault/           SBF fixture with a seeded missing-signer bug
```

Execution flow:

1. Resolve and validate the spec.
2. Generate `steps` instructions from `StdRng::seed_from_u64(seed)`.
3. Create LiteSVM, deploy the program, install the spec accounts, fund an
   internal fee payer.
4. For each step: snapshot tracked accounts, build and sign the transaction,
   send it, snapshot again, then evaluate each selected invariant with the
   before/after worlds, the step, and the trace.
5. On the first failure, stop, truncate the sequence at that step, and shrink
   the failing sequence before writing a case.

## Spec schema

A complete example is [`examples/vault.json`](examples/vault.json).

```json
{
  "name": "buggy-vault",
  "program_id": "<base58 program id>",
  "accounts": [
    {
      "name": "vault",
      "address": "<base58 address>",
      "lamports": 5000000000,
      "owner": "<base58 owner>",
      "data_hex": "002ff7...",
      "can_sign": false
    },
    {
      "name": "authority",
      "address": "<base58 address>",
      "lamports": 1000000000,
      "owner": "11111111111111111111111111111111",
      "can_sign": true,
      "secret_key": "<base58 64-byte keypair>"
    }
  ],
  "instructions": [
    {
      "name": "withdraw",
      "index": 1,
      "accounts": [
        { "name": "vault", "writable": true },
        { "name": "authority" },
        { "name": "recipient", "writable": true }
      ],
      "data": { "kind": "fixed", "hex": "" }
    }
  ],
  "protected": [
    { "account": "vault", "authority": "authority" }
  ]
}
```

| Field | Meaning |
| --- | --- |
| `name` | Human-readable spec name. |
| `program_id` | Base58 program id passed to `LiteSVM::add_program`. |
| `accounts[].address` | Base58 account address. |
| `accounts[].lamports` | Starting lamports. |
| `accounts[].owner` | Base58 owner program. |
| `accounts[].data_hex` | Starting account data, hex encoded. Default empty. |
| `accounts[].can_sign` | Generator may include this account as a transaction signer. |
| `accounts[].secret_key` | Base58 64-byte keypair. Required when `can_sign` is true and must match the address. |
| `instructions[].name` | Template name used in traces and corpus files. |
| `instructions[].index` | Discriminator byte prepended to instruction data. |
| `instructions[].accounts` | Account slots with `writable` and optional `required_signer`. |
| `instructions[].data` | `{"kind":"fixed","hex":"..."}` or `{"kind":"generated","len":N}` with `N <= 64`. Generated bytes come from the seeded RNG. |
| `protected[]` | Account/authority pairs for the protected-accounts invariant. |

Unknown fields are rejected. Duplicate account names/addresses, unknown account
references, duplicate instruction names/indices, signer requirements on
non-signable accounts, and missing keypairs fail validation with a typed error.

Secret keys are test keypairs. Corpus files embed the whole spec, so they embed
those keys too. Never put a real keypair in a spec or corpus.

## Invariants

Accounts are tracked when they appear in the spec, in any instruction template,
or in `get_program_accounts(program_id)`. A violation stores the invariant
name, step index, message, seed, the failing sequence, and the account diff for
the step that failed.

### `lamport-conservation`

The sum of lamports over all tracked accounts must be identical before and
after every step. The internal fee payer is not tracked, so transaction fees do
not count. A failed transaction is also checked; LiteSVM rolls it back, so the
sum should be unchanged.

### `protected-accounts`

For every `protected` rule:

- The owner of the account must never change.
- Lamports may increase without a signature.
- Any lamport decrease or any data change requires the configured authority
  address to be in the causing transaction's signer set.

### `no-unauthorized-debit`

Exact rule:

```text
For every tracked account A with before.lamports > after.lamports:
    A must be in the causing transaction's signer set
    OR after.owner == executing program id.
```

This is the rule requested for the MVP. Its program-owner exemption means it
cannot detect a program draining an account it already owns, which is exactly
what `buggy-vault` does to its vault. That case is caught by
`protected-accounts`. Use `protected-accounts` or a custom invariant when a
program-owned account must stay above some balance.

### Custom invariants

Implement `svm_fuzz::Invariant` and pass the list to
`Executor::with_invariants`. Each check receives `StepContext` with the spec,
program id, seed, step index, the raw `Step`, before/after `World` snapshots
(accounts plus signer set), and the step trace. The integration test
`custom_invariants_are_pluggable` defines a `recipient-gain` invariant without
touching the executor.

```rust
use svm_fuzz::{Executor, Invariant, StepContext};

struct NoRecipientGain;

impl Invariant for NoRecipientGain {
    fn name(&self) -> &str { "no-recipient-gain" }

    fn check(&self, context: &StepContext<'_>) -> Result<(), String> {
        // inspect context.before, context.after, context.step, context.trace
        Ok(())
    }
}

let executor = Executor::with_invariants(spec, program_bytes, vec![Box::new(NoRecipientGain)])?;
```

## Corpus

One JSON file per case in the corpus directory. `run` writes the case after
shrinking; `shrink` rewrites it after re-shrinking; `replay` loads it and runs
the stored sequence against the stored spec.

The corpus id is a stable hash:

```text
sha256(
  u64_le(program.len()) || program
  || u64_le(spec_json.len()) || spec_json
  || u64_le(seed)
)[0..16] as lowercase hex
```

The spec is serialized from the parsed struct, so formatting differences in the
input file do not change the id. Program path, program SHA-256, the full spec,
the violation, and the minimized sequence are stored in the case. Replay checks
the program SHA-256 before executing.

The id deliberately does not include the step count. Per the MVP contract it
hashes program bytes, spec, and seed; running the same seed with a different
step count overwrites the same case file.

## Shrinking

The shrinker starts from the failing prefix and repeatedly applies, in this
order:

1. Remove each single step (left to right, first success wins).
2. Try shorter prefixes, longest first.
3. Try suffixes with increasingly larger dropped prefixes.

A candidate is accepted when the same invariant fails. The loop stops when no
transformation reproduces the violation. The result is deterministic and
1-minimal under those transformations, not a global minimum. Shrinking reruns
the same seed and spec, so it needs no external state.

## What is NOT sound

- This is a dynamic fuzzer, not a proof. A run with no violation proves nothing
  about other seeds, other account states, or other programs.
- Account state is fixed at the starting spec. The generator randomizes template
  choice, optional signers, and generated argument bytes. It does not fuzz
  lamports, data, account creation, or realloc.
- Invariants run after each transaction, not after each CPI. An intermediate
  violation repaired before the transaction commits is invisible.
- Only accounts reachable from the spec, instruction templates, and
  `get_program_accounts(program_id)` are snapshotted. Lamport conservation and
  debit checks are relative to that tracked set. An account created and credited
  outside the tracked set would not be seen.
- The fee payer is not tracked, so conservation ignores transaction fees by
  construction.
- `no-unauthorized-debit` exempts program-owned accounts by design.
- Only accounts with keypairs in the spec can sign. An address without a secret
  key can never be a signer, even if the real system would let its owner sign.
- LiteSVM is not a validator. Compute budget, rent, epoch transitions, and
  sysvar time are not modeled beyond LiteSVM defaults.
- The corpus stores absolute program paths and plaintext test secret keys. It is
  not a portable archive and must not contain production keys.
- Shrinking is 1-minimal for single deletion/prefix/suffix deletion only.
- Determinism is guaranteed for the same crate version, spec, seed, steps, and
  fixture bytes. `StdRng` output is stable within the current `rand` dependency
  but is not a cross-version serialization format.

## Verification

```console
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test
```

Tests include:

- seeded bug discovery at seed 2, shrinking from 7 to 1 step, and replay;
- byte-identical sequence generation and identical violations for the same
  seed, plus a different sequence for a different seed;
- corpus save/load/listing and replay of the stored case;
- CLI run exits 1 on a violation and replay returns 0, then exits nonzero after
  the stored sequence is corrupted;
- a custom invariant firing without built-in invariants;
- unit tests for each built-in invariant's accept and reject paths;
- spec validation failures and stable corpus ids.

## License

MIT OR Apache-2.0. See `LICENSE-MIT` and `LICENSE-APACHE`.
