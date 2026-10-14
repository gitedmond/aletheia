"""Suffix minimization specified by Phase 1A §10.4, step 7."""

from collections.abc import Callable, Iterable


def minimize_counterexample(inputs: Iterable[bytes], mismatches: Callable[[bytes], bool]) -> bytes:
    """Select shortest then lexical input; stop at the first non-failing suffix.

    The caller must return True only for a clean, repeatable output mismatch,
    never for a fault, state dependence, unsupported import, or exhausted budget.
    Fresh-emulator reproduction before CONTRADICTED is the T15 runner's duty.
    """
    values = list(inputs)
    if not values:
        raise ValueError("no failing inputs")
    candidate = min(values, key=lambda value: (len(value), value.hex()))
    if not mismatches(candidate):
        raise ValueError("selected failing input does not reproduce")
    while candidate and mismatches(candidate[:-1]):
        candidate = candidate[:-1]
    return candidate
