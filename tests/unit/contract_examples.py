"""Fixed wire examples retained verbatim from the approved contract.

Illustrative IDs/hashes are substituted by the existing acceptance test.
"""

CLAIM_EXAMPLES = [
    {
        "schema_version": "1.0",
        "run_id": "r_correct_example",
        "source": {"origin": "scripted", "source_id": "scripted:v1", "shares_backend": False},
        "binary_sha256": "<sha>",
        "subject": {"kind": "function", "address": "0x00001230"},
        "type": "algorithm_identity",
        "body": {"family": "crc32", "variant": "ieee"},
        "confidence": 0.9,
        "confidence_source": "scripted",
        "rationale": None,
        "evidence_refs": [],
        "depends_on": [],
        "supersedes": None,
        "derived_from": "scripted_correct",
        "tool_label": None,
        "algorithms_version": "1.0",
        "client_ref": None,
    },
    {
        "schema_version": "1.0",
        "run_id": "r_mutated_example",
        "source": {"origin": "scripted", "source_id": "scripted:v1", "shares_backend": False},
        "binary_sha256": "<sha>",
        "subject": {"kind": "function", "address": "0x00001230"},
        "type": "call_relation",
        "body": {"callee": "0x00002000", "kind": "direct"},
        "confidence": 0.9,
        "confidence_source": "scripted",
        "rationale": None,
        "evidence_refs": [],
        "depends_on": [],
        "supersedes": None,
        "derived_from": "scripted_mutated",
        "tool_label": None,
        "algorithms_version": "1.0",
        "client_ref": None,
    },
    {
        "schema_version": "1.0",
        "claim_id": "c_3f9a0c1e2b7d4a6e8f10c2d4",
        "run_id": "r_8d2e4f6a0b1c3d5e",
        "source": {
            "origin": "tool",
            "source_id": "tool:capa@<ver>+rules@<tag>",
            "shares_backend": False,
        },
        "binary_sha256": "<sha>",
        "subject": {"kind": "function", "address": "0x00001410"},
        "type": "algorithm_identity",
        "body": {"family": "crc32", "variant": None},
        "confidence": 1.0,
        "confidence_source": "tool_default",
        "rationale": None,
        "evidence_refs": [],
        "depends_on": [],
        "supersedes": None,
        "derived_from": "capa_rule",
        "tool_label": "hash data with CRC32",
        "algorithms_version": "1.0",
        "client_ref": None,
    },
]

VERDICT_EXAMPLE = {
    "claim_id": "c_3f9a0c1e2b7d4a6e8f10c2d4",
    "intrinsic_verdict": "INCONCLUSIVE",
    "strength": None,
    "aspects": {
        "output_match": {"verdict": "INCONCLUSIVE", "strength": None, "method": "probe.crc32@1"}
    },
    "graph_status": "OK",
    "methods_run": ["probe.crc32@1", "static.constants@1"],
    "reason": "no_matching_call_shape",
    "harness": None,
    "evidence": [
        {"kind": "constant_match", "artifact": "sha256:...", "summary": "0xEDB88320 present"}
    ],
    "counterexample": None,
    "budget_used": {"instructions": 0},
    "verifier_version": "0.1.0",
    "env_digest": "sha256:...",
}
