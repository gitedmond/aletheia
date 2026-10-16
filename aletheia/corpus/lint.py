"""Source-only checks for the controlled C17 corpus; binary facts are established later."""

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from aletheia.schema.models import REGISTRY
from aletheia.schema.taxonomy import Taxonomy

STANDARD_HEADERS = {
    "assert.h",
    "complex.h",
    "ctype.h",
    "errno.h",
    "fenv.h",
    "float.h",
    "inttypes.h",
    "iso646.h",
    "limits.h",
    "locale.h",
    "math.h",
    "setjmp.h",
    "signal.h",
    "stdalign.h",
    "stdarg.h",
    "stdatomic.h",
    "stdbool.h",
    "stddef.h",
    "stdint.h",
    "stdio.h",
    "stdlib.h",
    "stdnoreturn.h",
    "string.h",
    "tgmath.h",
    "threads.h",
    "time.h",
    "uchar.h",
    "wchar.h",
    "wctype.h",
}
TARGET_NAMES = {
    "crc32_update",
    "crc32_bitwise",
    "jamcrc",
    "crc32_table_init",
    "crc32_update_rt",
    "crc32_selftest",
    "hex_print32",
    "adler32_update",
    "adler32",
    "fletcher16",
    "sum_file",
    "fnv1a_32",
    "fnv1_32",
    "djb2",
    "djb2_buf",
    "djb2a_buf",
    "ht_create",
    "ht_insert",
    "ht_lookup",
    "ht_destroy",
    "b64_encode",
    "b64_encode_url",
    "b64_decode",
    "b64_encoded_len",
    "lookup_cmd",
    "dispatch",
    "run_command",
    "cmd_hash",
    "cmd_sum",
    "cmd_help",
    "fnv1a_32_local",
    "sum8",
    "log_msg",
}
TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|\x27(?:\\.|[^\x27\\])*\x27', re.S)
FUNCTION = re.compile(
    r"(?m)^(?P<head>[ \t]*(?:(?:[A-Za-z_]\w*)(?:[ \t\n]+|(?=\*))|\*[ \t]*)+)"
    r"(?P<name>[A-Za-z_]\w*)\s*\((?P<args>[^;{}]*)\)\s*\{"
)
CALL = re.compile(r"\b([A-Za-z_]\w*)\s*\(")


@dataclass(frozen=True)
class LintError:
    path: str
    line: int
    rule: str
    message: str


@dataclass(frozen=True)
class Function:
    name: str
    path: Path
    line: int
    head: str
    body: str
    parameters: str = ""


def _decode_literal(value: str) -> str:
    escapes = {
        "a": "\a",
        "b": "\b",
        "f": "\f",
        "n": "\n",
        "r": "\r",
        "t": "\t",
        "v": "\v",
        "\n": "",
        "?": "?",
    }

    def replace(match: re.Match[str]) -> str:
        token = match[0][1:]
        if token.startswith("x"):
            return chr(int(token[1:], 16))
        if token[0] in "01234567":
            return chr(int(token, 8))
        return escapes.get(token, token)

    return re.sub(r"\\(?:x[0-9a-fA-F]+|[0-7]{1,3}|.|\n)", replace, value)


def _mask(text: str) -> tuple[str, list[tuple[int, int, str]]]:
    literals: list[tuple[int, int, str]] = []

    def replace(match: re.Match[str]) -> str:
        token = match[0]
        if token.startswith('"'):
            literals.append((match.start(), match.end(), _decode_literal(token[1:-1])))
        return "".join("\n" if char == "\n" else " " for char in token)

    return TOKEN.sub(replace, text), literals


def _functions(code: str, path: Path) -> list[Function]:
    result: list[Function] = []
    last_end = 0
    for match in FUNCTION.finditer(code):
        if match.start() < last_end:
            continue
        depth, end = 1, match.end()
        while end < len(code) and depth:
            depth += (code[end] == "{") - (code[end] == "}")
            end += 1
        if depth:
            raise ValueError("unbalanced function body")
        line = code.count("\n", 0, match.start()) + 1
        result.append(
            Function(
                match["name"], path, line, match["head"], code[match.end() : end - 1], match["args"]
            )
        )
        last_end = end
    return result


def lint_program(program_dir: Path, *, phase: Literal["1a", "1b"] = "1a") -> list[LintError]:
    errors: list[LintError] = []
    functions: dict[str, Function] = {}
    indirect: list[tuple[Function, list[str]]] = []
    texts: dict[Path, str] = {}
    sources = sorted((program_dir / "src").rglob("*"))
    taxonomy = Taxonomy.bundled() if phase == "1b" else None

    def error(path: Path, line: int, rule: str, message: str) -> None:
        errors.append(LintError(path.as_posix(), line, rule, message))

    c_sources = [p for p in sources if p.suffix == ".c"]
    if not c_sources:
        error(program_dir, 0, "program_missing", "program requires src/*.c")
        return errors
    headers: set[Path] = set()
    for path in sources:
        if path.is_dir():
            continue
        if path.suffix not in (".c", ".h"):
            error(path, 0, "c17_only", "source directory accepts C17 .c/.h files only")
            continue
        if path.is_symlink() or not path.resolve().is_relative_to(program_dir.resolve()):
            error(path, 0, "source_escape", "source must be inside the program")
            continue
        try:
            text = path.read_text(encoding="utf-8")
            code, literals = _mask(text)
        except (OSError, ValueError) as exc:
            error(path, 0, "source_invalid", str(exc))
            continue
        texts[path] = text
        if re.search(r"\b(?:__asm__|asm)\s*\(", code) or "::" in code:
            error(path, 0, "c17_only", "inline assembly and C++ constructs are excluded")
        for match in re.finditer(r'(?m)^\s*#\s*include\s*[<"]([^>"]+)[>"]', text):
            include = match[1]
            line = text.count("\n", 0, match.start()) + 1
            if "<" in match[0]:
                if include not in STANDARD_HEADERS:
                    error(path, line, "libc_only", f"non-standard header: {include}")
            else:
                candidates = [
                    path.parent / include,
                    program_dir / "src" / include,
                    program_dir.parent.parent / "include" / include,
                ]
                found = next((p for p in candidates if p.is_file() and not p.is_symlink()), None)
                if found is None:
                    error(path, line, "libc_only", f"unresolved project header: {include}")
                else:
                    allowed = (
                        program_dir.resolve(),
                        (program_dir.parent.parent / "include").resolve(),
                    )
                    if not any(found.resolve().is_relative_to(root) for root in allowed):
                        error(path, line, "libc_only", "project header escapes corpus source")
                    else:
                        headers.add(found.resolve())
        if (
            re.search(r"\bconstructor\b", code)
            or ".init_array" in text
            and any(".init_array" in literal for _, _, literal in literals)
        ):
            error(path, 0, "constructor", "constructors and .init_array are excluded")
        # Adjacent literals concatenate in C; includes do not become binary strings.
        combined: list[tuple[int, int, str]] = []
        for start, end, literal in literals:
            line_start = text.rfind("\n", 0, start) + 1
            if re.match(r"#\s*include\b", text[line_start:start].lstrip()):
                continue
            if combined and not code[combined[-1][1] : start].strip():
                old_start, _, previous = combined.pop()
                combined.append((old_start, end, previous + literal))
            else:
                combined.append((start, end, literal))
        labels = set(REGISTRY) | {program_dir.name.lower()}
        for start, _, literal in combined:
            if any(label in literal.lower() for label in labels):
                error(
                    path,
                    text.count("\n", 0, start) + 1,
                    "label_string",
                    "string contains a program or algorithm label",
                )
        try:
            found_functions = _functions(code, path)
        except ValueError as exc:
            error(path, 0, "source_invalid", str(exc))
            continue
        lines = text.splitlines()
        for fn in found_functions:
            if fn.name in functions:
                error(path, fn.line, "duplicate_function", f"duplicate definition: {fn.name}")
            else:
                functions[fn.name] = fn
            previous = fn.line - 2
            annotation: list[str] = []
            while previous >= 0 and lines[previous].strip().startswith("// @"):
                annotation.insert(0, lines[previous].strip())
                previous -= 1
            algorithms = [
                a.removeprefix("// @algorithm ")
                for a in annotation
                if a.startswith("// @algorithm ")
            ]
            if len(algorithms) != 1:
                gap = previous
                while gap >= 0 and not lines[gap].strip():
                    gap -= 1
                rule = (
                    "annotation_adjacent"
                    if gap < previous
                    and gap >= 0
                    and (lines[gap].strip().startswith("// @algorithm"))
                    else "annotation_required"
                )
                error(path, fn.line, rule, "one adjacent @algorithm annotation is required")
            else:
                algorithm = algorithms[0]
                family, slash, variant = algorithm.partition("/")
                if algorithm != "none" and (not slash or variant not in REGISTRY.get(family, ())):
                    error(path, fn.line, "annotation_invalid", f"unknown algorithm: {algorithm}")
            if phase == "1b":
                assert taxonomy is not None
                categories = [
                    a.removeprefix("// @category ")
                    for a in annotation
                    if a.startswith("// @category ")
                ]
                if not categories:
                    error(path, fn.line, "category_required", "one adjacent @category is required")
                elif len(categories) != 1 or categories[0] not in taxonomy.leaves:
                    error(path, fn.line, "category_invalid", "category must name one taxonomy leaf")
                alternatives = [
                    a.removeprefix("// @acceptable ")
                    for a in annotation
                    if a.startswith("// @acceptable ")
                ]
                if len(alternatives) > 1 or any(
                    not item.strip() or item.strip() not in taxonomy.leaves
                    for row in alternatives
                    for item in row.split(",")
                ):
                    error(
                        path,
                        fn.line,
                        "acceptable_invalid",
                        "alternatives must name taxonomy leaves",
                    )
                roles = [
                    a.removeprefix("// @roles ") for a in annotation if a.startswith("// @roles ")
                ]
                allowed = {"seed", "buf", "len", "cstr", "out", "out_len", "ctx", "key", "other"}
                if len(roles) > 1 or any(
                    item.strip() not in allowed for row in roles for item in row.split(",")
                ):
                    error(path, fn.line, "roles_invalid", "unknown or duplicate role annotation")
                elif roles and len(roles[0].split(",")) != parameter_count(fn.parameters):
                    error(path, fn.line, "roles_arity", "one role is required for each parameter")
            known = (
                "// @algorithm ",
                "// @indirect-targets ",
                "// @category ",
                "// @acceptable ",
                "// @roles ",
            )
            if any(not a.startswith(known) for a in annotation):
                error(path, fn.line, "annotation_invalid", "unknown annotation")
            targets = [
                a.removeprefix("// @indirect-targets ").split(",")
                for a in annotation
                if a.startswith("// @indirect-targets ")
            ]
            if len(targets) > 1:
                error(path, fn.line, "annotation_invalid", "duplicate indirect target annotation")
            elif targets:
                indirect.append((fn, [name.strip() for name in targets[0]]))
            elif re.search(r"(?:->|\.)\s*\w+\s*\(|\(\s*\*\s*\w+\s*\)\s*\(", fn.body):
                error(
                    path,
                    fn.line,
                    "indirect_targets_required",
                    "indirect call requires @indirect-targets",
                )
            if fn.name in TARGET_NAMES and "ALETHEIA_TARGET" not in fn.head:
                error(
                    path, fn.line, "target_noinline", f"target {fn.name} requires ALETHEIA_TARGET"
                )
    for fn, targets in indirect:
        if len(targets) != len(set(targets)) or any(name not in functions for name in targets):
            error(
                fn.path,
                fn.line,
                "indirect_target_missing",
                "indirect targets must name distinct definitions in this program",
            )
    has_target = any("ALETHEIA_TARGET" in fn.head for fn in functions.values())
    if has_target:
        header_text = (
            "\n".join(p.read_text() for p in sorted(headers)) + "\n" + "\n".join(texts.values())
        )
        header_text = _mask(header_text)[0]
        if not re.search(
            r"#\s*define\s+ALETHEIA_TARGET\s+__attribute__\s*\(\(\s*noinline\s*\)\)", header_text
        ):
            error(program_dir, 0, "target_noinline", "shared macro must expand to noinline")
    main = functions.get("main")
    if main is None:
        error(program_dir, 0, "main_required", "program requires main")
    else:
        reachable, pending = set[str](), ["main"]
        while pending:
            name = pending.pop()
            if name in reachable:
                continue
            reachable.add(name)
            pending.extend(
                n
                for n in CALL.findall(functions[name].body)
                if n in functions and n not in reachable
            )
        bodies = "\n".join(functions[name].body for name in sorted(reachable))
        if not re.search(r"\b(fread|fgetc|fgets|getchar|scanf|fscanf)\s*\(", bodies):
            error(
                main.path, main.line, "main_input", "main must read input directly or via a helper"
            )
        if not any("ALETHEIA_TARGET" in functions[name].head for name in reachable - {"main"}):
            error(main.path, main.line, "main_target", "main must call a target")
        if not any(
            re.search(r"%(?:[-+ #0]*\d*(?:\.\d+)?(?:hh|h|ll|l|j|z|t)?)[xX]", text)
            or "PRIx" in text
            or "PRIX" in text
            for text in texts.values()
        ):
            error(main.path, main.line, "main_hex", "program must print results as hexadecimal")
    if not list((program_dir / "tests").glob("*.c")) or not (program_dir / "Makefile").is_file():
        error(program_dir, 0, "native_tests", "program requires native tests and a Makefile")
    makefile = program_dir / "Makefile"
    if makefile.is_file():
        make_text = "\n".join(line.split("#", 1)[0] for line in makefile.read_text().splitlines())
        for library in re.findall(r"(?<!\w)-l\s*([\w+-]+)", make_text):
            if library != "c":
                error(makefile, 0, "libc_only", f"third-party link library: {library}")
    return sorted(errors, key=lambda e: (e.path, e.line, e.rule, e.message))


def source_functions(text: str, path: Path) -> list[Function]:
    """Locate controlled definitions with the same lexical rules as source lint."""
    return _functions(_mask(text)[0], path)


def parameter_count(parameters: str) -> int:
    """Count the controlled C parameter list, keeping nested declarators together."""
    if parameters.strip() in ("", "void", "..."):
        return 0
    depth, count = 0, 1
    for char in parameters:
        depth += char in "(["
        depth -= char in ")]"
        if char == "," and depth == 0:
            count += 1
    if re.search(r",\s*\.\.\.\s*$", parameters):
        count -= 1
    return count


def annotation_lines(text: str, function_line: int) -> list[str]:
    """Read the validated contiguous annotation block immediately before a definition."""
    lines = text.splitlines()
    i = function_line - 2
    result: list[str] = []
    while i >= 0 and lines[i].strip().startswith("// @"):
        result.append(lines[i].strip())
        i -= 1
    return result
