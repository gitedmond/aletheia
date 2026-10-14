# AGENTS.md (Aletheia)

You are working on Aletheia Phase 1a. Read SPEC-PHASE-1A.md before anything else.

## Non-negotiable rules
1. No LLM, classifier, or embedding model in verification or grading code.
2. Code under aletheia/verify/ never imports aletheia/corpus/ and never reads ground truth,
   unstripped binaries, sources, annotations, or corpus tests.
3. Ground truth uses symbols plus capstone; the verifier uses Ghidra. Do not share code.
4. Determinism: no wall-clock decisions, no unseeded randomness, sorted outputs, canonical JSON.
5. Never edit tests/golden/, tests/fixtures/, mappings/, or configs/ghidra-analysis.json.
   Propose changes in a PR labeled fixture-proposal.
6. Pin every version. Never add a dependency without the author's approval.
7. No silent fallbacks: every failure becomes a reason code, error code, or counted exclusion.
8. Untrusted binaries are parsed only inside the sandbox.
9. Never weaken or edit a test to make it pass.

## Workflow per task
1. Pick a task from Section 17 whose dependencies are done.
2. Write or confirm the acceptance test first; it must fail.
3. Implement until it passes.
4. Run: uv run ruff check, uv run pyright, uv run pytest -m "not slow".
5. Open a PR titled "T<id>: <task>", listing the acceptance test and any HR gate.
6. If the spec is ambiguous or contradicts DESIGN.md, stop and ask. Do not guess.

## Implementation decisions
Work only in the Linux checkout as edmond. Read STATUS.md before choosing a task.
The IP prerequisite is not applicable per author confirmation. Public gitedmond/aletheia and
MIT were selected by the author. uv_build and required locked upstream dependencies are approved.
The author approved the design conversion and foundation direction. Fix T04 CI, complete T05,
and prepare T06 for author review. Keep the Ghidra security review open. Lane G is deferred; never initiate provider calls.
Never mark a task done without its acceptance evidence and any required author sign-off.
Original Windows staging documents are immutable. Protected fixture proposals are separate
reviews; no golden, fixture, mapping, or analyzer configuration has been approved.
All task evidence and next eligible work go in STATUS.md.
