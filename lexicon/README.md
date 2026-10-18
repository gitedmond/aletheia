# Name quality lexicon v1

F20 author-delegated proposal. This deterministic, secondary metric expands
abbreviations and the specification's synonym groups. It does not infer function
purpose or enter primary metrics, calibration, headline results or exit gates.

The threshold stays unfitted until 200 actual dev-agent name pairs are labeled.
Threshold decisions use score >= threshold; agreement ties choose the highest
threshold. Label method and provenance are reported, and model-assisted labels
must never be described as independent human validation.

Human review sets `human_validated`; it preserves an existing `ai-assisted` or
`synthetic` method in both labels and fitted output. Only an unlabeled export
becomes `human` after labeling.
