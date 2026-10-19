# Phase 1B X3 scope amendment v1

Status: frozen for evaluation of the existing Phase 1B v3 held-out receipts.

The all-claims development result is 115 of 256 scripted algorithm-identity claims decisive across both variants (44.92%), below the 50% threshold. The frozen v3 held-out gate also records X3 as failed; its detailed held-out counts remain private. DESIGN section 3.3 explicitly allows narrowing claim types when this gate is missed. This amendment defines one narrower claim type before any detailed held-out re-evaluation.

## Eligible claim type

A scripted algorithm-identity claim is in scope when all of these conditions hold:

- Its target is a scorable ground-truth function with a non-complex, non-variadic compiler ABI signature.
- The target has no annotated ctx parameter role. Context-stateful targets require a multi-call composite proof and are outside this direct-call scope.
- The pack for the family stated in the claim exists and declares at least one call shape whose parameter count equals the target function's compiler ABI parameter count.

The criterion uses only the claim family, frozen ground-truth ABI and parameter-role annotations, and frozen pack declarations. It does not inspect the verdict, probe result, claimed correctness, or whether a claim was decisive. Correct and mutated scripted claims are both included whenever they satisfy the same predicate.

Every eligible outcome remains in the denominator, including INCONCLUSIVE and UNVERIFIABLE. VERIFIED and CONTRADICTED form the numerator. The original all-claims result and exclusion counts must remain in the report beside the scoped result; the old result is not replaced or relabeled as passing.

## Development-only basis

The predicate was checked against the public development portion of the frozen v3 cohort before inspecting held-out claim outcomes:

| Population | Claims | Decisive | Rate |
|---|---:|---:|---:|
| Original all-claims, baseline | 128 | 56 | 43.75% |
| Original all-claims, hardened | 128 | 59 | 46.09% |
| Scoped direct-call, baseline | 77 | 44 | 57.14% |
| Scoped direct-call, hardened | 77 | 47 | 61.04% |
| Scoped direct-call, combined | 154 | 91 | 59.09% |

The development exclusions were 64 claims whose target ABI arity had no declared shape in the claimed-family pack, 2 with complex or variadic ABI signatures, and 36 with an annotated context parameter. This is a scope change, so the unscoped failure remains part of the final report and interpretation.

## Held-out evaluation

After this file and its evaluator are committed, evaluate the frozen v3 held-out receipts once with this predicate. The evaluator may emit only aggregate counts, rates, and exclusion counts. Keep the raw all-claims X3 gate result, held-out identifiers, and underlying records private. The amended gate may change X3 only; every other criterion, especially X14 author review, retains its original status.

This amendment addresses only the X3 measurement scope. It does not create author labels or author sign-off, and it does not authorize Phase 2 by itself.
