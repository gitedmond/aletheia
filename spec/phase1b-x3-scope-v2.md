# Phase 1B X3 scope amendment v2

Status: frozen before the v2 aggregate evaluation. This refines v1 using the public development cohort only because v1 matched pack shapes by arity but did not prove that their argument roles and ABI types were compatible.

The v1 receipt and amended gate remain intact. A v2 result on the same held-out cohort is a remediation reanalysis after the v1 aggregate was observed; it is not an independent first-use validation. Any report must identify both scope versions and preserve the original full-population gate.

## Eligible claim type

A scripted algorithm-identity claim is in scope when:

- Its target is a scorable ground-truth function with a non-complex, non-variadic compiler ABI signature.
- The target does not have an annotated ctx parameter. These targets need a multi-call composite proof.
- The pack for the family stated in the claim exists.
- At least one call shape in that pack has the same parameter count as the target ABI and is ABI-compatible in argument order.

When ground truth has parameter-role annotations, the shape roles must match that sequence exactly. When roles are unannotated, shape roles are checked against compiler ABI classes using this fixed map:

| Shape roles | Required ABI types |
|---|---|
| buf, cstr, cstr_b, out, inout, key, path, out_ptr, len_ptr | pointer, 64-bit |
| seed, byte, u32 | integer, 32-bit |
| len, key_len | integer, 64-bit |

Unknown shape roles and incompatible parameter types are out of scope. Eligibility uses only the claim family, frozen target ABI and parameter-role annotations, and frozen pack declarations. It never depends on a verdict, probe result, or whether a claim was decisive. Correct and mutated scripted claims are both included whenever they satisfy the same predicate.

All eligible verdicts remain in the denominator, including INCONCLUSIVE and UNVERIFIABLE. VERIFIED and CONTRADICTED form the numerator. The unscoped result and each exclusion count remain beside the scoped result.

## Development-only basis

The v2 predicate was checked on the public development portion of the frozen v3 cohort:

| Population | Claims | Decisive | Rate |
|---|---:|---:|---:|
| Original all-claims, baseline | 128 | 56 | 43.75% |
| Original all-claims, hardened | 128 | 59 | 46.09% |
| ABI-compatible direct-call, baseline | 54 | 44 | 81.48% |
| ABI-compatible direct-call, hardened | 54 | 46 | 85.19% |
| ABI-compatible direct-call, combined | 108 | 90 | 83.33% |

Development exclusions were 110 incompatible ABI shapes, 36 context-stateful targets, and 2 complex or variadic signatures. The evaluator records baseline and hardened rows separately and retains all eligible abstentions.

## Interpretation

This scope measures algorithm identity only for claims whose claimed-family pack shape can be applied to the target's annotated ABI. It does not measure composite/context-stateful claims, unsupported ABI shapes, or every algorithm identity claim in the corpus. Because v1 already read an aggregate from the same held-out cohort, v2 is useful for remediation but cannot establish independent generalization by itself.
