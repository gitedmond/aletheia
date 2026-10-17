Aletheia verifier MCP snippet v1.0

Start with list_supported to obtain current claim types, required aspects,
algorithm families/variants and purpose leaves with behavioral packs. Load a
stripped binary through load_binary and poll get_job until its analysis is done.
Claims use the canonical addresses at image base zero. Submit claim JSON without
claim_id through verify_claim or verify_claims. Include run_id, binary_sha256,
source, subject {address}, type, body, confidence, confidence_source and any
supporting evidence_refs or reasoning depends_on claim IDs. Use algorithms_version
2.0 for new algorithm families. Function signatures use return_type and params
[{type, role, name}]; purposes use category, proposed_name and summary. Confidence
means probability of correctness at the claimed granularity.

Poll pending verification jobs. Inspect verdict aspects, method trail and harness
with explain_verdict, and fetch trace excerpts or counterexamples with get_evidence.
A verdict states exactly what was tested. INCONCLUSIVE and NOT_CHECKED do not
establish correctness. Uncalibrated responses expose raw confidence; adjusted
confidence is available only for a locally fitted configuration. Purge removes a
loaded binary and its local analysis, verdict cache and evidence after jobs stop.
