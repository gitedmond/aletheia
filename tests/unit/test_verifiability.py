"""T26: declared pack coverage, unsupported variants and deterministic CLI tables."""

import json
from pathlib import Path

import yaml
from typer.testing import CliRunner

from aletheia.cli import app
from aletheia.corpus.verifiability import markdown, table
from aletheia.schema.models import GroundTruth
from aletheia.verify.probes.pack import Pack


def truth(program="first"):
    return GroundTruth.model_validate(
        {
            "binary_sha256": "a" * 64,
            "program_id": "tierA/" + program,
            "variant_id": "clang23-O2-x64-pie-hardoff",
            "build_flags": "test",
            "functions": [
                {
                    "address": "0x00001000",
                    "size": 32,
                    "name": "reference",
                    "scorable": True,
                    "algorithm": {"family": "crc32", "variant": "ieee"},
                },
                {
                    "address": "0x00002000",
                    "size": 32,
                    "name": "unprobed",
                    "scorable": True,
                    "algorithm": {"family": "fnv", "variant": "fnv1a-64"},
                },
                {
                    "address": "0x00003000",
                    "size": 32,
                    "name": "helper",
                    "scorable": True,
                    "algorithm": {"family": "none"},
                },
                {
                    "address": "0x00004000",
                    "size": 8,
                    "name": "excluded",
                    "scorable": False,
                    "algorithm": {"family": "crc32", "variant": "ieee"},
                },
            ],
        }
    )


def pack():
    return Pack.model_validate(
        {
            "family": "crc32",
            "version": 1,
            "call_shapes": [{"id": "buf_len", "roles": ["buf", "len"], "return_width": 32}],
            "variants": {"ieee": {"oracle": "crc32_ieee"}},
            "inputs": {"fixed": ["123456789"], "random": {"count": 0, "max_len": 0, "seed": 1}},
            "near_miss": [],
        }
    )


def test_counts_only_scorable_supported_variants_and_records_limits():
    first = truth()
    second = truth("second")
    result = table([first, second], [pack()])
    assert result["scorable_functions"] == 6
    assert result["decidable_functions"] == 2
    assert result["decidable_share"] == 2 / 6
    rows = {row["leaf"]: row for row in result["rows"]}
    assert rows["crc32/ieee"]["scorable_functions"] == 2
    assert rows["crc32/ieee"]["e2_method"] == "probe.crc32@1"
    assert "binding/state preconditions" in rows["crc32/ieee"]["known_blockers"]
    assert rows["fnv/fnv1a-64"]["scorable_functions"] == 2
    assert rows["fnv/fnv1a-64"]["e2_method"] is None
    assert rows["none"]["scorable_functions"] == 2
    assert "| tierA/first | 1/3 | 33.33% |" in markdown(result)
    assert "| tierA/second | 1/3 | 33.33% |" in markdown(result)
    assert result == table([second, first], [pack()])
    assert table([first], [])["decidable_functions"] == 0
    assert table([], [])["decidable_share"] is None
    empty_program = table([first.model_copy(update={"functions": []})], [])
    assert "| tierA/first | 0/0 | n/a |" in markdown(empty_program)


def test_cli_table_for_all_five_programs_does_not_invent_missing_packs(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    Path("aletheia.toml").write_text("")
    for program in ("adlerfletch", "b64", "cmd-dispatch", "crc32tool", "hashtable"):
        gt = truth(program)
        path = Path("build") / program / gt.variant_id / "private" / "ground_truth.json"
        path.parent.mkdir(parents=True)
        path.write_text(gt.model_dump_json())
    runner = CliRunner()
    response = runner.invoke(app, ["--json", "verifiability"])
    assert response.exit_code == 0, response.output
    result = json.loads(response.output)
    assert len(result["programs"]) == 5
    assert result["scorable_functions"] == 15
    assert result["decidable_share"] == 0
    assert "potential" in result["population"]
    text = runner.invoke(app, ["verifiability", "--program", "crc32tool"])
    assert text.exit_code == 0 and "crc32/ieee" in text.output and "0/3" in text.output

    Path("packs").mkdir()
    Path("packs/crc32.yaml").write_text(yaml.safe_dump(pack().model_dump(mode="json")))
    response = runner.invoke(app, ["--json", "verifiability"])
    assert response.exit_code == 0, response.output
    result = json.loads(response.output)
    assert result["decidable_functions"] == 5
    assert result["decidable_share"] == 0.333333
    text = runner.invoke(app, ["verifiability", "--program", "crc32tool"])
    assert text.exit_code == 0 and "1/3" in text.output

    path = Path("build/crc32tool") / gt.variant_id / "private/ground_truth.json"
    changed = json.loads(path.read_text())
    changed["program_id"] = "tierA/elsewhere"
    path.write_text(json.dumps(changed))
    response = runner.invoke(app, ["--json", "verifiability"])
    assert response.exit_code == 1 and "identity" in response.output
