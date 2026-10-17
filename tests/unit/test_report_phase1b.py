"""Independently computed ECE/cluster examples and potential E2 scope exclusions."""

from pathlib import Path

import pytest

from aletheia.confidence import Adjustment, Sample
from aletheia.confidence.headline import Scored
from aletheia.corpus.verifiability import table_v2
from aletheia.report.phase1b import equal_mass_ece, population
from aletheia.schema.models import GroundTruth
from aletheia.verify.probes.pack import load_pack


def test_ece_equal_mass_bins_and_bootstrap_zero_claim_cluster():
    assert equal_mass_ece([]) is None
    assert equal_mass_ece(
        [(0.9, True), (0.8, False), (0.3, False), (0.2, True)], 2
    ) == pytest.approx(0.3)
    assert equal_mass_ece([(0.9, True), (0.8, False)], 10) == pytest.approx(0.45)
    with pytest.raises(ValueError):
        equal_mass_ece([(float("nan"), True)])
    row = Scored(
        sample=Sample(
            claim_id="c_" + "a" * 24,
            run_id="r_" + "b" * 16,
            program="private_marker",
            split="heldout",
            source={"origin": "agent", "source_id": "agent:test"},
            claim_type="function_signature",
            confidence=0.9,
            correct_claimed=False,
            on_target=True,
            verdict="CONTRADICTED",
            strength="E1",
            method="static.arity",
        ),
        confidence=Adjustment(
            raw=0.9,
            prior=0.8,
            adjusted=0.2,
            calibration="calibrated",
            likelihood="fitted",
            likelihood_ratio=1,
            dependency_cap=None,
        ),
    )
    result = population([row], ["private_marker", "zero_claim_marker"], resamples=100, seed=4)
    assert result["metrics"]["raw_overconfidence_gap"] == 0.9
    assert result["metrics"]["raw_cwr"] == 1
    assert result["metrics"]["adjusted_cwr"] is None
    assert result["intervals"]["raw_ece"]["defined_resamples"] < 100
    assert "marker" not in str(result)
    assert result == population(
        [row], ["private_marker", "zero_claim_marker"], resamples=100, seed=4
    )


def test_v2_potential_does_not_count_static_signatures_or_incomplete_composites():
    categories = ["string.length", "crypto.hash.md5.init", "util.other"]
    # util.other may not be a taxonomy leaf; take an intentionally unsupported real leaf.
    from aletheia.schema.taxonomy import Taxonomy

    categories[-1] = next(
        leaf for leaf in Taxonomy.bundled().leaves if leaf.startswith("compression.")
    )
    functions = [
        {
            "address": f"0x{i:08x}",
            "size": 32,
            "name": f"f{i}",
            "scorable": True,
            "algorithm": {"family": "none"},
            "category": category,
            "acceptable_categories": [category],
            "abi_signature": {
                "return": {"class": "int", "width": 32},
                "params": [],
                "variadic": False,
                "abi_complex": False,
            },
            "source_types": None,
            "roles": [],
        }
        for i, category in enumerate(categories, 4096)
    ]
    gt = GroundTruth.model_validate(
        {
            "schema_version": "2.0",
            "algorithms_version": "2.0",
            "binary_sha256": "a" * 64,
            "program_id": "tierA/test",
            "variant_id": "baseline",
            "build_flags": "test",
            "functions": functions,
        }
    )
    packs = [load_pack(Path("packs") / (name + ".yaml")) for name in ("strlen", "md5")]
    result = table_v2([gt], packs)
    assert result["scorable_functions"] == 3 and result["decidable_functions"] == 1
    assert result["decidable_share"] == 1 / 3
    assert "static E1 signatures excluded" in result["population"]
