# Prompt for the Aletheia planning agent

Work in Plan mode. Prepare a decision-ready initial implementation plan for Aletheia.
Do not implement, provision the environment, move files, install dependencies, create repositories,
start containers, publish anything, or send messages to other agents. Your deliverable is the plan
and the essential questions needed to finalize it.

## Read first

The current document staging folder is `C:\Users\edmnd\OneDrive\Desktop\aletheia`.
Read `SPEC-PHASE-1A.md` v0.2 in full, then `Aletheia-Design.docx` (design v0.4.1), including
its tables and appendices. The spec is authoritative for Phase 1A; intentional design deviations
are in Section 21. Report remaining conflicts explicitly rather than guessing. Do not expand
into Phase 1B or use its spec to override Phase 1A.

The folder currently contains the design document, both phase specs, and this prompt, with no
project scaffold or Git repository. Ubuntu-24.04 was observed installed as WSL2 and stopped;
verify current environment state with read-only checks rather than assuming Docker or tools work.

## Agreed decisions

Treat C1-C7 in spec Section 0.2 as settled implementation choices, not unresolved alternatives:

1. Inputs move to `0x78000000`; all emulator regions and guard gaps are validated.
2. Scripted claims use deterministic correct, family-only, and mutated scenario/case runs that
   preserve the one-active-claim rule and genuinely false mutations.
3. Registered unprobed variants return `UNVERIFIABLE no_pack`; incomplete family coverage cannot
   justify a family-level contradiction. A supported clean match can still verify a family claim.
4. T15 waits for T11 and its human review; self-tests establish binding through production arity
   analysis and real fixture callers.
5. Verdict cache payloads omit claim identity, reattach the requesting ID, and use semantic keys
   containing all verdict-affecting configuration.
6. FindCrypt records its shared backend. The independent reliability aggregate uses scripted
   claims; tool-conditioned results remain separate, with FindCrypt explicitly labeled.
7. Track unwritten `.bss` and initially zero-filled mutable `.data`, using
   `uninitialized_state_reads` consistently and restoring initialization state per invocation.

## Planning scope

Detail T00-T04: repository scaffold, pinned toolchain/images and doctor, data contracts and
canonical hashing/schema export, SQLite/artifact storage, and sandbox runner/worker protocol.
Keep the rest of Phase 1A as a dependency roadmap with integration milestones and review gates.
Use existing task IDs and the smallest complete implementation. Keep optional LLM lane G deferred;
LLM runs remain disabled with cost cap zero. Do not design a general orchestration framework.

The implementation repository must live inside the Ubuntu WSL filesystem, proposed
`~/src/aletheia`, rather than OneDrive or `/mnt/c`. Plan how to establish that location and retain
the original staging documents. Propose a reviewed conversion of the DOCX to `DESIGN.md` that
preserves meaning, tables, examples, and section references, with one maintained design source
after conversion. Do not perform the conversion or relocation during this planning pass.

Keep durable context lean: `AGENTS.md` follows Appendix A, the design/spec define requirements,
and one `STATUS.md` records task states, accepted decisions, commits, exact validation evidence,
pending human reviews, blockers, and the next eligible task. Distinguish implemented, validated,
awaiting human review, and done. Fresh chats must be able to resume from these repository files.

## Boundaries and prerequisites

- The design still lists the employment/IP review as open and requires its recorded completion
  before code. Ask for its status without requesting private agreement contents. Do not infer
  completion from the existence of the documents or the authorization of C1-C7.
- Identify other applicable Phase 0 gates, including any tension with Phase 1A deferrals, and
  separate prerequisites that block T00 from inputs needed only by later tasks. Confirm the
  intended WSL repository location and repository ownership/visibility before provisioning or
  publishing. Do not assume the repository should be public immediately.
- No LLM, classifier, or embeddings in verification or grading. Verifier code cannot read ground
  truth, source, annotations, unstripped binaries, or corpus tests. Ground truth uses symbols and
  Capstone; verifier analysis uses clean Ghidra. No shared analysis helpers.
- Untrusted binaries are parsed only inside sandbox jobs. Deterministic instruction budgets,
  canonical outputs, pinned inputs, and explicit failures are mandatory.
- Protected goldens, fixtures, mappings, and analyzer configuration remain human-owned.
  Acceptance of C1-C7 does not approve future fixture contents or satisfy any HR gate.
- Use only allowed dependencies. Research exact compatible pins from primary sources when
  needed for T01, retaining the spec's Python/Ghidra/Capstone/Unicorn constraints. Report
  incompatibilities instead of silently changing required versions. Do not install anything.

## Required output

1. A short recommendation and a bounded first implementation milestone.
2. A prerequisite table: confirmed facts, unknowns, when each is needed, and essential author
   decisions. Ask focused questions for required inputs; propose defaults for routine choices.
3. A T00-T04 plan giving dependencies, concrete files/interfaces, acceptance tests, validation
   commands, and completion evidence. Specify tests derived independently from the contracts.
4. A remaining Phase 1A dependency roadmap that incorporates the corrected T15 and T17
   dependencies, protected fixture proposals, human gates, replay, reports, and X1-X10.
5. A practical iteration/handoff process: task-sized branches and PRs once a remote is configured,
   status updates, and review packages. Do not create branches, PRs, or extra chats now.
6. Remaining ambiguities and risks, with the earliest task each affects. Do not reopen C1-C7
   without demonstrating a concrete contradiction or impossible requirement.

Normal task validation is `uv run ruff check`, `uv run pyright`, and
`uv run pytest -m "not slow"`; slow checks run before HR gates. Report what was actually
verified during planning separately from proposed future checks. Do not treat a plan as evidence
that a test, toolchain, sandbox, or human gate has passed.
