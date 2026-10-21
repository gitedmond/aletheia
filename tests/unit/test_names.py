"""Independent secondary metric examples and exact threshold serialization."""

import pytest

from aletheia.names import Lexicon, NameFit, NameLabels, NamePair, fit_threshold, score, tokens


def test_tokenization_synonym_expansion_and_missing_names():
    from pathlib import Path

    lexicon = Lexicon.read(Path("lexicon/name-quality.yaml"))
    assert tokens("HTTPServer2_readBuf") == ["http", "server", "2", "read", "buf"]
    assert tokens("crc32C") == ["crc", "32", "c"]
    assert score("get_buf", "read_buffer", lexicon) == 1
    assert score("calc_len", "compute_length", lexicon) == 1
    assert score("alpha_beta", "alpha_gamma", lexicon) == pytest.approx(1 / 3)
    assert score("", "", lexicon) == 0


def test_threshold_uses_200_actual_labels_and_ties_choose_highest():
    lexicon = Lexicon(version="1.0", abbreviations={}, synonyms=[])
    pairs = [
        NamePair(
            pair_id=str(i),
            proposed_name="same" if i % 2 else "wrong",
            true_name="same",
            match=bool(i % 2),
        )
        for i in range(200)
    ]
    labels = NameLabels(method="synthetic", annotator_id="contract", available=200, pairs=pairs)
    fit = fit_threshold(labels, lexicon)
    assert fit.threshold == 1 and fit.agreement == 1 and fit.kappa == 1
    assert fit.secondary_only and not fit.human_validated
    with pytest.raises(ValueError, match="labeling method"):
        fit_threshold(labels.model_copy(update={"method": "unlabeled"}), lexicon)
    assert NameFit.model_validate_json(fit.model_dump_json()) == fit
    with pytest.raises(ValueError, match="200 labeled"):
        fit_threshold(labels.model_copy(update={"pairs": pairs[:199]}), lexicon)


def test_label_tool_requires_actual_review_of_assisted_labels(tmp_path):
    from typer.testing import CliRunner

    from aletheia.cli import app

    labels = NameLabels(
        method="ai-assisted",
        annotator_id="model",
        available=2,
        pairs=[
            NamePair(pair_id="1", proposed_name="guess", true_name="actual", match=True),
            NamePair(pair_id="2", proposed_name="read_buf", true_name="get_buffer"),
        ],
    )
    source = tmp_path / "pairs.json"
    source.write_text(labels.model_dump_json())
    config = tmp_path / "config.toml"
    config.write_text(
        f'[paths]\nruns="{tmp_path}/runs"\nartifacts="{tmp_path}/artifacts"\nbuild="{tmp_path}/build"\n'
    )
    target = tmp_path / "labels.json"
    result = CliRunner().invoke(
        app,
        [
            "--config",
            str(config),
            "names",
            "label",
            "--pairs",
            str(source),
            "--out",
            str(target),
            "--annotator",
            "contract-reviewer",
        ],
        input="n\ny\n",
    )
    assert result.exit_code == 0, result.output
    reviewed = NameLabels.model_validate_json(target.read_bytes())
    assert reviewed.human_validated and reviewed.method == "ai-assisted"
    assert [p.match for p in reviewed.pairs] == [False, True]


@pytest.mark.parametrize(
    "text",
    [
        'version: "1.0"\nabbreviations: {buf: buffer, buf: byte}\nsynonyms: []\n',
        'version: "1.0"\nabbreviations: {}\nsynonyms: []\nsynonyms: [[read, get]]\n',
    ],
)
def test_lexicon_rejects_duplicate_keys(tmp_path, text):
    path = tmp_path / "lexicon.yaml"
    path.write_text(text)
    with pytest.raises(ValueError, match="duplicate YAML key"):
        Lexicon.read(path)
