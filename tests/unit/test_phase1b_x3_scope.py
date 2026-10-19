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


def function(params, *, roles=(), complex=False, variadic=False):
    abi = SimpleNamespace(
        params=[SimpleNamespace(kind=kind, width=width) for kind, width in params],
        abi_complex=complex,
        variadic=variadic,
    )
    return SimpleNamespace(scorable=True, roles=list(roles), abi_signature=abi)


def test_x3_scope_requires_compatible_roles_and_compiler_abi():
    direct = function(
        [("int", 32), ("ptr", 64), ("int", 64)],
        roles=("seed", "buf", "len"),
    )
    assert scope_exclusion(direct, "crc32", DEFAULT_PACK_DIRECTORY) is None
    unannotated = function([("ptr", 64), ("int", 64)])
    assert scope_exclusion(unannotated, "djb2", DEFAULT_PACK_DIRECTORY) is None
    assert scope_exclusion(
        function(
            [("ptr", 64), ("int", 64), ("ptr", 64)],
            roles=("ctx", "buf", "len"),
        ),
        "sha256",
        DEFAULT_PACK_DIRECTORY,
    ) == "context_stateful"
    assert scope_exclusion(
        function([("int", 32), ("int", 32)]), "sha256", DEFAULT_PACK_DIRECTORY
    ) == "incompatible_abi_shape"
    assert scope_exclusion(
        function(
            [("int", 32), ("ptr", 64), ("int", 64)],
            roles=("seed", "buf", "len"),
        ),
        "sha256",
        DEFAULT_PACK_DIRECTORY,
    ) == "incompatible_abi_shape"
    assert scope_exclusion(
        function([("int", 32), ("ptr", 64), ("int", 64)], complex=True),
        "crc32",
        DEFAULT_PACK_DIRECTORY,
    ) == "unsupported_abi"
    assert scope_exclusion(
        function([("int", 32), ("ptr", 64), ("int", 64)], variadic=True),
        "crc32",
        DEFAULT_PACK_DIRECTORY,
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
        "excluded": {"incompatible_abi_shape": 2},
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
