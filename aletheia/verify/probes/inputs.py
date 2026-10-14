"""Local seeded generation; fixed inputs retain pack order."""

import random
from collections.abc import Sequence

from aletheia.verify.probes.pack import Inputs, Role


def generate_inputs(spec: Inputs) -> list[bytes]:
    rng = random.Random(spec.random.seed)
    values = [value.encode("utf-8") for value in spec.fixed]
    values.extend(bytes.fromhex(value) for value in spec.fixed_hex)
    for _ in range(spec.random.count):
        values.append(rng.randbytes(rng.randrange(spec.random.max_len + 1)))
    return values


def inputs_for_shape(values: Sequence[bytes], roles: Sequence[Role]) -> list[bytes]:
    """Skip embedded-NUL inputs only for the declared C-string shape.

    The later probe runner records input/skip counts and provides the trailing
    NUL in its own mapped buffer; these inputs remain the oracle's original bytes.
    """
    return [value for value in values if "cstr" not in roles or b"\0" not in value]
