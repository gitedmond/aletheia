from hashlib import sha256
from types import SimpleNamespace

import pytest

from aletheia.verify.engine import DEFAULT_PACK_DIRECTORY
from tools.phase1b_x3_scope import (
    CRITERIA,
    SCOPE_DOCUMENT,
    SCOPE_ID,
    amend_gate,
    scope_exclusion,
)


def abi(count, *, complex=False, variadic=False):
    return SimpleNamespace(
        params=[object() for _ in range(count)],
        abi_complex=complex,
        variadic=variadic,
    )


def function(count, *, roles=(), complex=False, variadic=False):
    return SimpleNamespace(
        scorable=True,
        roles=list(roles),
        abi_signature=abi(count, complex=complex, variadic=variadic),
    )


def test_x3_scope_includes_supported_direct_shape_and_excludes_context_or_bad_abi():
    direct = function(3, roles=("seed", "buf", "len"))
    assert scope_exclusion(direct, "crc32", DEFAULT_PACK_DIRECTORY) is None
    assert scope_exclusion(
        function(3, roles=("ctx", "buf", "len")), "sha256", DEFAULT_PACK_DIRECTORY
    ) == "context_stateful"
    assert (
        scope_exclusion(function(2), "sha256", DEFAULT_PACK_DIRECTORY)
        == "unsupported_abi_shape"
    )
    assert scope_exclusion(
        function(3, complex=True), "crc32", DEFAULT_PACK_DIRECTORY
    ) == "unsupported_abi"
    assert scope_exclusion(
        function(3, variadic=True), "crc32", DEFAULT_PACK_DIRECTORY
    ) == "unsupported_abi"


def test_x3_gate_amendment_changes_only_x3_and_keeps_author_gate():
    original = {
        "status": "failed",
        "criteria": {
            name: {"passed": name not in {"X3", "X14"}, "details": {"prior": name}}
            for name in CRITERIA
        },
    }
    scope = {
        "scope_id": SCOPE_ID,
        "scope_sha256": sha256(SCOPE_DOCUMENT.read_bytes()).hexdigest(),
        "experiment_source_commit": "f800009d43ee42fb1b7c25ec29e1f25871c2317e",
        "split": "heldout",
        "scoped_claims": {"claims": 10, "decisive": 6},
        "excluded": {"unsupported_abi_shape": 2},
    }
    result = amend_gate(
        original,
        scope,
        original_gate_sha256="a" * 64,
        scope_receipt_sha256="b" * 64,
    )
    assert result["criteria"]["X3"]["passed"]
    assert not result["criteria"]["X14"]["passed"]
    assert result["status"] == "failed"
    assert all(
        result["criteria"][name] == original["criteria"][name]
        for name in CRITERIA
        if name != "X3"
    )
    assert not original["criteria"]["X3"]["passed"]


def test_x3_gate_amendment_rejects_dev_or_stale_scope():
    scope = {
        "scope_id": SCOPE_ID,
        "scope_sha256": sha256(SCOPE_DOCUMENT.read_bytes()).hexdigest(),
        "experiment_source_commit": "f800009d43ee42fb1b7c25ec29e1f25871c2317e",
        "split": "dev",
        "scoped_claims": {"claims": 10, "decisive": 6},
        "excluded": {},
    }
    original = {"criteria": {name: {"passed": name != "X3"} for name in CRITERIA}}
    with pytest.raises(ValueError):
        amend_gate(
            original,
            scope,
            original_gate_sha256="a" * 64,
            scope_receipt_sha256="b" * 64,
        )
