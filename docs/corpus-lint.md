# Corpus source linting

Run `uv run alth corpus lint` for corpus/tierA, or pass a program directory positionally.
Global `--json` precedes `corpus lint`. Empty corpora and any finding return exit 1.
Each finding records a path, source line when available, stable rule code, and explanation.
Use `uv run alth corpus lint --program crc32tool` to select one named program under
the corpus root; an absent named program is an explicit `program_missing` failure.

Source annotation completeness now applies to every definition, including main and trivial
helpers, per the author's 2026-10-14 clarification. Exact non-triviality still uses more than
10 instructions from the O0 build at T08. Source lint does not estimate machine instructions.

The linter checks the controlled corpus's conventional named C definitions, adjacent annotations,
registry values, unique names, known Section 4.2 target markers and noinline macro, indirect
member/pointer call declarations, C17 source/header extensions, standard/project includes,
assembly/C++ exclusions, constructors, program/family strings, main input/target/hex behavior,
native test files, and explicit third-party linker libraries. Comments, character literals,
C escape sequences, and adjacent strings are handled separately from executable source.

It is a source policy checker, not a complete C preprocessor, syntax checker, ELF parser, or
proof of indirect-call completeness. Macro-generated function definitions are outside the
controlled authoring style. Native compilation/tests at T06 establish C17 syntax and behavior;
T07/T08 validate emitted symbols, initializers, leakage, and exact instruction counts. Include
conditions and indirect callbacks still require the T06 human semantic review.

Native tests are found under each program's tests/ and are not scoring source. No goldens,
near-miss fixtures, mapping tables, or analyzer options are introduced by T05.
