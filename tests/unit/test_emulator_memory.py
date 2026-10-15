"""T12 memory regions must preserve the specified gaps before mapping anything."""

from pathlib import Path

import pytest

from aletheia.config import Budgets
from aletheia.verify.emulate.core import Emulator, memory_regions


def test_default_regions_and_image_adjacency_are_disjoint_with_guard_pages():
    regions = memory_regions([(0, 4096), (4096, 8192)], Budgets())
    assert [(r.name, r.start, r.end) for r in regions if r.name.startswith("image")] == [
        ("image", 0x10000000, 0x10002000)
    ]
    heap = next(r for r in regions if r.name == "heap")
    assert (heap.start, heap.end) == (0x73000000, 0x77000000)
    assert all(
        right.start - left.end >= 4096 for left, right in zip(regions, regions[1:], strict=False)
    )
    for ranges, cfg in [
        ([], Budgets(heap_mb=80)),
        ([(0x60000000, 0x60001000)], Budgets()),
        ([(0x5FFFF000, 0x60000000)], Budgets()),
    ]:
        with pytest.raises(ValueError, match="guard|overlap"):
            memory_regions(ranges, cfg)


def test_native_emulator_rejects_host_execution_before_binary_parsing():
    with pytest.raises(ValueError, match="sandbox"):
        Emulator(Path("/job/in/" + "a" * 64 + ".bin"), Budgets())
