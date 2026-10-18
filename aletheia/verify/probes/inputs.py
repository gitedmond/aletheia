"""Local seeded generation; fixed inputs retain pack order."""

import base64
import random
import re
from collections.abc import Sequence

from aletheia.verify.probes.pack import CallShape, Inputs, Role, VariantProbe


def generate_inputs(spec: Inputs) -> list[bytes]:
    rng = random.Random(spec.random.seed)
    if spec.string_pairs or spec.byte_pairs:
        pairs = [(bytes.fromhex(a), bytes.fromhex(b)) for a, b in spec.fixed_pairs]
        for index in range(spec.random.count):
            left = rng.randbytes(rng.randrange(spec.random.max_len + 1))
            if spec.string_pairs:
                left = left.replace(b"\0", b"\1")
            right = (
                left
                if index % 4 == 0
                else left + b"x"
                if index % 4 == 1
                else b"\x80" + left
                if index % 4 == 2
                else b"\1" + left
            )
            pairs.append((left, right))
        if any(
            len(a) > 65535 or (spec.string_pairs and (b"\0" in a or b"\0" in b))
            for a, b in pairs
        ):
            raise ValueError(
                "invalid C-string pair" if spec.string_pairs else "invalid byte pair"
            )
        return [len(a).to_bytes(2, "little") + a + b for a, b in pairs]
    values = [value.encode("utf-8") for value in spec.fixed]
    values.extend(bytes.fromhex(value) for value in spec.fixed_hex)
    fixed_count = len(values)
    if spec.boundary_lengths:
        values.extend(
            rng.randbytes(n) for n in (0, 1, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 1000)
        )
    for _ in range(spec.random.count):
        length = (
            spec.random.exact_len
            if spec.random.exact_len is not None
            else rng.randrange(spec.random.max_len + 1)
        )
        values.append(rng.randbytes(length))
    return (
        values[:fixed_count] + [value.replace(b"\0", b"\1") for value in values[fixed_count:]]
        if spec.string_data
        else values
    )


def inputs_for_shape(values: Sequence[bytes], roles: Sequence[Role]) -> list[bytes]:
    """Skip embedded-NUL inputs only for the declared C-string shape.

    The later probe runner records input/skip counts and provides the trailing
    NUL in its own mapped buffer; these inputs remain the oracle's original bytes.
    """
    if "cstr_b" in roles:
        from aletheia.verify.probes.oracles import string_pair

        for value in values:
            string_pair(value)
        return list(values)
    return [value for value in values if "cstr" not in roles or b"\0" not in value]


def inputs_for_variant(values: Sequence[bytes], probe: VariantProbe) -> list[bytes]:
    if probe.input_encoding in {"decimal_signed", "decimal_unsigned"}:
        result: list[bytes] = []
        signed = probe.input_encoding == "decimal_signed"
        for value in values:
            if re.fullmatch(rb"(?:0|-[1-9][0-9]*|[1-9][0-9]*)", value):
                number = int(value)
                if not signed and number < 0:
                    continue
            else:
                number = int.from_bytes(value, "little") % (1 << 64)
                if signed and number >= 1 << 63:
                    number -= 1 << 64
            result.append(str(number).encode("ascii"))
        return result
    return (
        [base64.b64encode(value) for value in values]
        if probe.input_encoding == "base64"
        else list(values)
    )


def inputs_for_call(values: Sequence[bytes], probe: VariantProbe, shape: CallShape) -> list[bytes]:
    inputs = inputs_for_shape(inputs_for_variant(values, probe), shape.roles)
    if shape.id in {"parse_int32", "parse_int64"}:
        signed = probe.input_encoding == "decimal_signed"
        low = -(1 << (shape.return_width - 1)) if signed else 0
        high = (1 << (shape.return_width - int(signed))) - 1
        inputs = [value for value in inputs if low <= int(value) <= high]
    return inputs
