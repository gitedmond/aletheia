"""Compiler IR signatures, independent of verifier register/type inference."""

import re
from typing import cast

from pydantic import JsonValue


def _parts(text: str, separator: str) -> list[str]:
    depth = 0
    quoted = escaped = False
    start = 0
    result: list[str] = []
    for i, char in enumerate(text):
        if char == '"' and not escaped:
            quoted = not quoted
        if not quoted:
            depth += char in "([{<"
            depth -= char in ")]}>"
            if depth < 0:
                raise ValueError("unbalanced IR definition")
            if depth == 0 and (char == separator or separator == " " and char.isspace()):
                if text[start:i].strip():
                    result.append(text[start:i].strip())
                start = i + 1
        escaped = char == "\\" and not escaped
    if depth or quoted:
        raise ValueError("unbalanced IR definition")
    if text[start:].strip():
        result.append(text[start:].strip())
    return result


def _type(declared: str) -> dict[str, JsonValue]:
    if declared == "void":
        return {"class": "void", "width": 0}
    if declared == "ptr":
        return {"class": "ptr", "width": 64}
    if declared in {"float", "double"}:
        return {"class": "float", "width": 32 if declared == "float" else 64}
    integer = re.fullmatch(r"i([0-9]+)", declared)
    if integer:
        width = int(integer[1])
        if width in (1, 8, 16, 32, 64):
            return {"class": "int", "width": max(8, width)}
        return {"class": "other", "width": width, "declared": declared}
    vector = re.fullmatch(r"<([0-9]+) x (.+)>", declared)
    width = _type(vector[2])["width"] if vector else None
    return {
        "class": "other",
        "width": int(vector[1]) * width if vector and isinstance(width, int) else None,
        "declared": declared,
    }


def parse_abi(ir: str) -> dict[str, dict[str, JsonValue]]:
    result: dict[str, dict[str, JsonValue]] = {}
    for line in ir.splitlines():
        if not line.startswith("define "):
            continue
        match = re.match(r"define\s+(.+?)\s+@([A-Za-z_.$][\w.$]*)\(", line)
        if match is None:
            raise ValueError("unsupported IR definition")
        name = match[2]
        if name in result:
            raise ValueError("duplicate IR function: " + name)
        start = match.end()
        depth, end = 1, start
        while depth and end < len(line):
            depth += (line[end] == "(") - (line[end] == ")")
            end += 1
        if depth:
            raise ValueError("unterminated IR definition")
        params = _parts(line[start : end - 1], ",")
        return_type = _type(_parts(match[1], " ")[-1])
        types = [_type(_parts(param, " ")[0]) for param in params if param != "..."]
        result[name] = {
            "return": return_type,
            "params": cast(list[JsonValue], types),
            "variadic": "..." in params,
            "abi_complex": return_type["class"] == "other"
            or any(t["class"] == "other" for t in types)
            or bool(re.search(r"\b(?:byval|sret|inalloca)\b", line[start : end - 1])),
        }
    return result
