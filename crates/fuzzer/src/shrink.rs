use crate::error::{Error, Result};
use crate::executor::Executor;
use crate::generator::Step;
use crate::world::Violation;

pub struct ShrinkOutcome {
    pub sequence: Vec<Step>,
    pub violation: Violation,
    pub original_steps: usize,
    pub minimized_steps: usize,
}

/// Delta-debug a failing sequence by deleting steps, truncating the tail, and
/// dropping prefixes, in that order, until no single transformation reproduces
/// the same invariant.
pub fn shrink(
    executor: &Executor,
    seed: u64,
    sequence: &[Step],
    invariant: &str,
) -> Result<ShrinkOutcome> {
    let original_steps = sequence.len();
    let mut current = sequence.to_vec();
    let mut violation = reproduce(executor, seed, &current, invariant)?;

    loop {
        let mut next = None;

        if current.len() > 1 {
            for index in 0..current.len() {
                let mut candidate = current.clone();
                candidate.remove(index);
                if let Some(found) = maybe_reproduce(executor, seed, &candidate, invariant)? {
                    next = Some((candidate, found));
                    break;
                }
            }
        }

        if next.is_none() {
            for length in (1..current.len()).rev() {
                let candidate = current[..length].to_vec();
                if let Some(found) = maybe_reproduce(executor, seed, &candidate, invariant)? {
                    next = Some((candidate, found));
                    break;
                }
            }
        }

        if next.is_none() {
            for start in 1..current.len() {
                let candidate = current[start..].to_vec();
                if let Some(found) = maybe_reproduce(executor, seed, &candidate, invariant)? {
                    next = Some((candidate, found));
                    break;
                }
            }
        }

        match next {
            Some((candidate, found)) => {
                current = candidate;
                violation = found;
            }
            None => break,
        }
    }

    Ok(ShrinkOutcome {
        minimized_steps: current.len(),
        sequence: current,
        violation,
        original_steps,
    })
}

fn maybe_reproduce(
    executor: &Executor,
    seed: u64,
    sequence: &[Step],
    invariant: &str,
) -> Result<Option<Violation>> {
    if sequence.is_empty() {
        return Ok(None);
    }
    Ok(executor
        .run_with_invariant(seed, sequence, invariant)?
        .violation)
}

fn reproduce(
    executor: &Executor,
    seed: u64,
    sequence: &[Step],
    invariant: &str,
) -> Result<Violation> {
    maybe_reproduce(executor, seed, sequence, invariant)?.ok_or_else(|| {
        Error::Shrink(format!(
            "the {invariant} violation does not reproduce at seed {seed}"
        ))
    })
}
