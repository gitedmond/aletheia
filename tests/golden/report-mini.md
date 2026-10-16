> Synthetic mini-run presentation fixture. All resource table values are test constants, not observed benchmark measurements.

# Aletheia Phase 1A report

Benchmark 0.1.0; schema 1.0; split dev.

## Runs

| Run | Program | Source | Scenario |
| --- | --- | --- | --- |
| r_4738be24d39c3ef0 | mini | scripted:v1 | mutated |
| r_961f339ca8a36cf8 | mini | tool:findcrypt@3.1.10 (shared backend) | tool |
| r_dbe6ffb983e4bd55 | mini | tool:capa@9.4.0 | tool |

## Versions and pins

Pin set `e5e5e2dded30a6bd0abdc68c6e8f85b47e7208b6d090aacedacbdefcac47be14`:

```json
{
  "algorithms_version": "1.0",
  "analysis_options_hash": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
  "grader_version": "0.1.0",
  "image_digests": {
    "analysis": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "mapping_hashes": {},
  "pack_hashes": {},
  "schema_version": "1.0",
  "seeds": {
    "bootstrap": 7
  },
  "verifier_version": "0.1.0",
  "versions": {
    "benchmark": "0.1.0",
    "ghidra": "11.4.3"
  }
}
```

## Per-source metrics

Intervals use a seeded program-cluster bootstrap. With only five Phase 1A programs, intervals are wide; a mini run has fewer clusters.
Undefined means the denominator is zero. ERROR is excluded from reliability metrics and retained in source accuracy and defect counts.

### scripted:v1

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 1 | [1, 1] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 0.81 | [0.81, 0.81] | 10 |
| catch_rate | 0.5 | [0.5, 0.5] | 10 |
| cwr_lenient@0.8 | 0.5 | [0.5, 0.5] | 10 |
| cwr_lenient@0.9 | 0.5 | [0.5, 0.5] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 0.5 | [0.5, 0.5] | 10 |
| false_alarm_rate | undefined | [undefined, undefined] | 0 |
| false_label_rate | 0.5 | [0.5, 0.5] | 10 |
| granularity | 0 | [0, 0] | 10 |
| lenient_accuracy | 0.5 | [0.5, 0.5] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | undefined | [undefined, undefined] | 0 |

Counts: `{"claims":2,"on_target":2,"reliability_claims":2,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| CONTRADICTED | 0 | 1 |
| UNVERIFIABLE | 0 | 1 |

### scripted:v1 / tierA/mini

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 1 | [1, 1] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 0.81 | [0.81, 0.81] | 10 |
| catch_rate | 0.5 | [0.5, 0.5] | 10 |
| cwr_lenient@0.8 | 0.5 | [0.5, 0.5] | 10 |
| cwr_lenient@0.9 | 0.5 | [0.5, 0.5] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 0.5 | [0.5, 0.5] | 10 |
| false_alarm_rate | undefined | [undefined, undefined] | 0 |
| false_label_rate | 0.5 | [0.5, 0.5] | 10 |
| granularity | 0 | [0, 0] | 10 |
| lenient_accuracy | 0.5 | [0.5, 0.5] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | undefined | [undefined, undefined] | 0 |

Counts: `{"claims":2,"on_target":2,"reliability_claims":2,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| CONTRADICTED | 0 | 1 |
| UNVERIFIABLE | 0 | 1 |

### scripted:v1 / probe.crc32@1

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 1 | [1, 1] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 0.81 | [0.81, 0.81] | 10 |
| catch_rate | 1 | [1, 1] | 10 |
| cwr_lenient@0.8 | 0 | [0, 0] | 10 |
| cwr_lenient@0.9 | 0 | [0, 0] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 1 | [1, 1] | 10 |
| false_alarm_rate | undefined | [undefined, undefined] | 0 |
| false_label_rate | 0 | [0, 0] | 10 |
| granularity | 0 | [0, 0] | 10 |
| lenient_accuracy | 1 | [1, 1] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | undefined | [undefined, undefined] | 0 |

Counts: `{"claims":1,"on_target":1,"reliability_claims":1,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| CONTRADICTED | 0 | 1 |

### scripted:v1 / probe.fnv@1

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 0 | [0, 0] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 0.81 | [0.81, 0.81] | 10 |
| catch_rate | 0 | [0, 0] | 10 |
| cwr_lenient@0.8 | 1 | [1, 1] | 10 |
| cwr_lenient@0.9 | 1 | [1, 1] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 0 | [0, 0] | 10 |
| false_alarm_rate | undefined | [undefined, undefined] | 0 |
| false_label_rate | 1 | [1, 1] | 10 |
| granularity | 0 | [0, 0] | 10 |
| lenient_accuracy | 0 | [0, 0] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | undefined | [undefined, undefined] | 0 |

Counts: `{"claims":1,"on_target":1,"reliability_claims":1,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| UNVERIFIABLE | 0 | 1 |

### tool:findcrypt@3.1.10 (shared backend)

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 1 | [1, 1] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 1 | [1, 1] | 10 |
| catch_rate | undefined | [undefined, undefined] | 0 |
| cwr_lenient@0.8 | 0 | [0, 0] | 10 |
| cwr_lenient@0.9 | 0 | [0, 0] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 1 | [1, 1] | 10 |
| false_alarm_rate | 0 | [0, 0] | 10 |
| false_label_rate | 0 | [0, 0] | 10 |
| granularity | 1 | [1, 1] | 10 |
| lenient_accuracy | 1 | [1, 1] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | 1 | [1, 1] | 10 |

Counts: `{"claims":1,"on_target":1,"reliability_claims":1,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| VERIFIED | 1 | 0 |

### tool:findcrypt@3.1.10 (shared backend) / tierA/mini

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 1 | [1, 1] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 1 | [1, 1] | 10 |
| catch_rate | undefined | [undefined, undefined] | 0 |
| cwr_lenient@0.8 | 0 | [0, 0] | 10 |
| cwr_lenient@0.9 | 0 | [0, 0] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 1 | [1, 1] | 10 |
| false_alarm_rate | 0 | [0, 0] | 10 |
| false_label_rate | 0 | [0, 0] | 10 |
| granularity | 1 | [1, 1] | 10 |
| lenient_accuracy | 1 | [1, 1] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | 1 | [1, 1] | 10 |

Counts: `{"claims":1,"on_target":1,"reliability_claims":1,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| VERIFIED | 1 | 0 |

### tool:findcrypt@3.1.10 (shared backend) / probe.crc32@1

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 1 | [1, 1] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 1 | [1, 1] | 10 |
| catch_rate | undefined | [undefined, undefined] | 0 |
| cwr_lenient@0.8 | 0 | [0, 0] | 10 |
| cwr_lenient@0.9 | 0 | [0, 0] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 1 | [1, 1] | 10 |
| false_alarm_rate | 0 | [0, 0] | 10 |
| false_label_rate | 0 | [0, 0] | 10 |
| granularity | 1 | [1, 1] | 10 |
| lenient_accuracy | 1 | [1, 1] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | 1 | [1, 1] | 10 |

Counts: `{"claims":1,"on_target":1,"reliability_claims":1,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| VERIFIED | 1 | 0 |

### tool:capa@9.4.0

0 claims; metrics undefined. Adapter counts are retained below.

## Independent scripted verifier reliability

Included: scripted claims with shares_backend=false. Excluded: capa, FindCrypt, human and agent claims, and every shared-backend source.
Family-only algorithm claims use lenient correctness; exact variants and call relations use strict correctness. Tool-conditioned results remain separate above.
Static constants are supporting evidence; their method rows are non-decision observations, never claim verdicts.

### Independent aggregate

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 1 | [1, 1] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 0.81 | [0.81, 0.81] | 10 |
| catch_rate | 0.5 | [0.5, 0.5] | 10 |
| cwr_lenient@0.8 | 0.5 | [0.5, 0.5] | 10 |
| cwr_lenient@0.9 | 0.5 | [0.5, 0.5] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 0.5 | [0.5, 0.5] | 10 |
| false_alarm_rate | undefined | [undefined, undefined] | 0 |
| false_label_rate | 0.5 | [0.5, 0.5] | 10 |
| granularity | 0 | [0, 0] | 10 |
| lenient_accuracy | 0.5 | [0.5, 0.5] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | undefined | [undefined, undefined] | 0 |

Counts: `{"claims":2,"on_target":2,"reliability_claims":2,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| CONTRADICTED | 0 | 1 |
| UNVERIFIABLE | 0 | 1 |

### Scenario: mutated

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 1 | [1, 1] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 0.81 | [0.81, 0.81] | 10 |
| catch_rate | 0.5 | [0.5, 0.5] | 10 |
| cwr_lenient@0.8 | 0.5 | [0.5, 0.5] | 10 |
| cwr_lenient@0.9 | 0.5 | [0.5, 0.5] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 0.5 | [0.5, 0.5] | 10 |
| false_alarm_rate | undefined | [undefined, undefined] | 0 |
| false_label_rate | 0.5 | [0.5, 0.5] | 10 |
| granularity | 0 | [0, 0] | 10 |
| lenient_accuracy | 0.5 | [0.5, 0.5] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | undefined | [undefined, undefined] | 0 |

Counts: `{"claims":2,"on_target":2,"reliability_claims":2,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| CONTRADICTED | 0 | 1 |
| UNVERIFIABLE | 0 | 1 |

### Claim type: algorithm_identity

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 1 | [1, 1] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 0.81 | [0.81, 0.81] | 10 |
| catch_rate | 0.5 | [0.5, 0.5] | 10 |
| cwr_lenient@0.8 | 0.5 | [0.5, 0.5] | 10 |
| cwr_lenient@0.9 | 0.5 | [0.5, 0.5] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 0.5 | [0.5, 0.5] | 10 |
| false_alarm_rate | undefined | [undefined, undefined] | 0 |
| false_label_rate | 0.5 | [0.5, 0.5] | 10 |
| granularity | 0 | [0, 0] | 10 |
| lenient_accuracy | 0.5 | [0.5, 0.5] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | undefined | [undefined, undefined] | 0 |

Counts: `{"claims":2,"on_target":2,"reliability_claims":2,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| CONTRADICTED | 0 | 1 |
| UNVERIFIABLE | 0 | 1 |

### Method: probe.crc32@1

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 1 | [1, 1] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 0.81 | [0.81, 0.81] | 10 |
| catch_rate | 1 | [1, 1] | 10 |
| cwr_lenient@0.8 | 0 | [0, 0] | 10 |
| cwr_lenient@0.9 | 0 | [0, 0] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 1 | [1, 1] | 10 |
| false_alarm_rate | undefined | [undefined, undefined] | 0 |
| false_label_rate | 0 | [0, 0] | 10 |
| granularity | 0 | [0, 0] | 10 |
| lenient_accuracy | 1 | [1, 1] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | undefined | [undefined, undefined] | 0 |

Counts: `{"claims":1,"on_target":1,"reliability_claims":1,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| CONTRADICTED | 0 | 1 |

### Method: probe.fnv@1

| Metric | Estimate | 95% CI | Defined resamples |
| --- | ---: | --- | ---: |
| algorithm_coverage_lenient | 0 | [0, 0] | 10 |
| algorithm_coverage_strict | 0 | [0, 0] | 10 |
| brier | 0.81 | [0.81, 0.81] | 10 |
| catch_rate | 0 | [0, 0] | 10 |
| cwr_lenient@0.8 | 1 | [1, 1] | 10 |
| cwr_lenient@0.9 | 1 | [1, 1] | 10 |
| cwr_strict@0.8 | 1 | [1, 1] | 10 |
| cwr_strict@0.9 | 1 | [1, 1] | 10 |
| decisiveness | 0 | [0, 0] | 10 |
| false_alarm_rate | undefined | [undefined, undefined] | 0 |
| false_label_rate | 1 | [1, 1] | 10 |
| granularity | 0 | [0, 0] | 10 |
| lenient_accuracy | 0 | [0, 0] | 10 |
| strict_accuracy | 0 | [0, 0] | 10 |
| verification_precision | undefined | [undefined, undefined] | 0 |

Counts: `{"claims":1,"on_target":1,"reliability_claims":1,"scorable_algorithm_functions":1}`.

| Verdict | Correct at claimed granularity | Wrong |
| --- | ---: | ---: |
| UNVERIFIABLE | 0 | 1 |

## Contradicted claims

- `c_ed5fd7cd96272a6627b1ad07`: scripted:v1; tierA/mini; subject `0x00001000`; tool label none.
  Claim: `{"family":"crc32","variant":"jamcrc"}`; wrong at claimed granularity; on_target=true, phantom=false.
  Verdict: CONTRADICTED; reason none.
  Harness: Function-level emulation; seed_buf_len; stubs S1; fixed published CRC vector.
  Counterexample: `{"actual_hex":"00000000","call_shape":"seed_buf_len","expected_hex":"ffffffff","input_hex":"","matches_variant":"ieee","variant":"jamcrc"}`.

## Wrong claims the verifier did not catch

- `c_cf03147d3219afd8c923e0f8`: scripted:v1; tierA/mini; subject `0x00002000`; tool label none.
  Claim: `{"family":"fnv","variant":"fnv1a-64"}`; wrong at claimed granularity; on_target=true, phantom=false.
  Verdict: UNVERIFIABLE; reason no_pack.

## Off-target and phantom claims

None.

## Adapter counts and generator exclusions

| Source | Counted label or scope | Count |
| --- | --- | ---: |
| tool:capa@9.4.0 | unmapped_label:example | 2 |

## Excluded functions

| Program | Function | Reason |
| --- | --- | --- |
| tierA/mini | tiny | trivial |

## Compute and memory

CPU is measured container CPU time. Peak memory is the maximum per-container cgroup memory.peak for that run, not concurrent aggregate memory. Cache hits do not claim new execution cost.

| Run | Executed jobs | CPU seconds | Peak job memory bytes | Measurement errors |
| --- | ---: | ---: | ---: | --- |
| r_4738be24d39c3ef0 | 2 | 1 | 1024 | [] |
| r_961f339ca8a36cf8 | 2 | 1 | 1024 | [] |
| r_dbe6ffb983e4bd55 | 2 | 1 | 1024 | [] |

Defects (ERROR outcomes): `{}`.

95% percentile intervals resample whole programs with replacement using paired draws; undefined draws are omitted and counted.

Coverage denominators include all supplied scorable algorithm functions, including functions with no claim.

ERROR verdicts are excluded from reliability denominators and counted as defects; source accuracy and calibration retain all claims.

Independent verifier reliability includes controlled scripted claims only; other source populations remain separate.

Only five programs are planned for Phase 1A; cluster intervals can be wide and are not held-out generalization evidence.
