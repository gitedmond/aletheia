"""Blinded secondary annotation with explicit human or AI-assisted provenance."""

import fcntl
import hashlib
import json
import math
import random
import re
import shutil
import tempfile
from collections import Counter
from datetime import date
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, JsonValue, model_validator

from aletheia.config import StrictModel
from aletheia.corpus.build import snapshot_program
from aletheia.corpus.ground_truth import run_private_worker
from aletheia.corpus.lint import source_functions
from aletheia.heldout.guard import PrivateGuard
from aletheia.schema.taxonomy import Taxonomy


class Label(StrictModel):
    item_id: str
    category: str
    acceptable: list[str] = Field(default_factory=list)
    rationale: str | None = None


class SecondaryLabels(StrictModel):
    annotator_id: str = Field(min_length=1)
    method: Literal["independent", "intra-rater", "ai-assisted"]
    completed_at: date
    human_attestation: bool
    model_provenance: dict[str, JsonValue] | None = None
    labels: list[Label]

    @model_validator(mode="after")
    def truthful_provenance(self) -> Self:
        if self.method == "ai-assisted":
            if self.human_attestation or not self.model_provenance:
                raise ValueError(
                    "AI-assisted labels require model provenance and no human attestation"
                )
        elif not self.human_attestation or self.model_provenance is not None:
            raise ValueError("human annotation requires human attestation without model provenance")
        return self


def strip_annotations(source: str) -> str:
    return re.sub(r"(?m)^[ \t]*//\s*@[^\n]*(?:\n|$)", "", source)


def _kappa(first: list[str], second: list[str]) -> dict[str, float | int | str | None]:
    n = len(first)
    if not n:
        return {"n": 0, "kappa": None, "reason": "no_labels"}
    a, b = Counter(first), Counter(second)
    observed = sum(x == y for x, y in zip(first, second, strict=True)) / n
    expected = sum(count * b[key] for key, count in a.items()) / n**2
    return {
        "n": n,
        "observed": observed,
        "expected": expected,
        "kappa": (observed - expected) / (1 - expected) if expected < 1 else None,
        "reason": "ok" if expected < 1 else "undefined_expected_agreement",
    }


def agreement(first: list[str], second: list[str]) -> dict[str, object]:
    if len(first) != len(second):
        raise ValueError("annotation cohorts differ")
    a, b = [x.split(".")[0] for x in first], [x.split(".")[0] for x in second]
    nodes: dict[str, object] = {}
    for node in sorted(set(a) | set(b)):
        top = _kappa([str(x == node) for x in a], [str(x == node) for x in b])
        selected = [i for i in range(len(a)) if node in (a[i], b[i])]
        kappa = top["kappa"]
        nodes[node] = {
            "top_level": top,
            "exact_leaf": _kappa([first[i] for i in selected], [second[i] for i in selected]),
            "strict_scoring": isinstance(kappa, float) and kappa >= 0.7,
        }
    return {"top_level": _kappa(a, b), "exact_leaf": _kappa(first, second), "nodes": nodes}


def _write_new(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")
    path.chmod(0o600)


def export_sample(
    programs: list[tuple[Path, Path]],
    guard: PrivateGuard,
    *,
    sample: float,
    seed: int,
    taxonomy_path: Path,
) -> Path:
    if not 0 < sample <= 1:
        raise ValueError("sample must be in (0, 1]")
    if guard.root is None:
        raise ValueError("private_root is required for annotation records")
    output = guard.private_output(guard.root / "annotations")
    if (output / "primary.json").exists() or (output / "second/export.json").exists():
        raise ValueError("annotation export already exists; refusing replacement")
    taxonomy = Taxonomy.read(taxonomy_path)
    items: dict[str, dict[str, str]] = {}
    for source, build in sorted(programs):
        guard.access(source)
        guard.access(build)
        with tempfile.TemporaryDirectory(prefix=".annotation-", dir=build.parent) as temp:
            work = Path(temp)
            inputs, corpus, results = work / "in", work / "corpus", work / "out"
            for path in (inputs, corpus, results):
                path.mkdir()
            with (build.parent.parent / ".build.lock").open("a") as lock:
                fcntl.flock(lock, fcntl.LOCK_SH)
                shutil.copytree(build, inputs / "build")
            snapshot_program(source, corpus)
            metadata = json.loads((inputs / "build/build.json").read_bytes())
            (inputs / "request.json").write_text(
                json.dumps({"action": "review", "program": source.name, "source_root": str(source)})
            )
            run_private_worker(metadata["image"], inputs, corpus, results)
            counts = json.loads((results / "review.json").read_bytes())["o0_instruction_counts"]
        for path in sorted((source / "src").glob("*.c")):
            text = path.read_text()
            for fn in source_functions(text, path):
                if counts.get(fn.name, 0) <= 10:
                    continue
                lines = text.splitlines()
                annotations: list[str] = []
                i = fn.line - 2
                while i >= 0 and lines[i].strip().startswith("// @"):
                    annotations.append(lines[i].strip())
                    i -= 1
                categories = [
                    s.removeprefix("// @category ")
                    for s in annotations
                    if s.startswith("// @category ")
                ]
                if len(categories) != 1 or categories[0] not in taxonomy.leaves:
                    raise ValueError("missing or invalid primary annotation")
                identity = source.name + "/" + path.name + "/" + fn.name
                item_id = hashlib.sha256(identity.encode()).hexdigest()[:24]
                items[item_id] = {
                    "category": categories[0],
                    "identity": identity,
                    "source": strip_annotations(text[fn.start : fn.end]),
                    "source_sha256": hashlib.sha256(text.encode()).hexdigest(),
                }
    groups: dict[str, list[str]] = {}
    for item_id, value in sorted(items.items()):
        groups.setdefault(value["category"].split(".")[0], []).append(item_id)
    size = math.ceil(len(items) * sample)
    quotas = {node: len(ids) * sample for node, ids in groups.items()}
    counts = {node: math.floor(quota) for node, quota in quotas.items()}
    order = sorted(groups, key=lambda node: (-(quotas[node] - counts[node]), node))
    for node in order[: size - sum(counts.values())]:
        counts[node] += 1
    rng = random.Random(seed)
    chosen = sorted(
        i for node, ids in sorted(groups.items()) for i in rng.sample(ids, counts[node])
    )
    _write_new(
        output / "primary.json",
        {
            "seed": seed,
            "sample": sample,
            "exported_at": date.today().isoformat(),
            "population": len(items),
            "items": {i: items[i] for i in chosen},
        },
    )
    _write_new(
        output / "second/export.json",
        {
            "schema_version": "1.0",
            "taxonomy": taxonomy.model_dump(),
            "items": [{"item_id": i, "source": items[i]["source"]} for i in chosen],
            "instructions": "Human RE-literate annotator: assign one taxonomy leaf and optional "
            "acceptable leaves per item. Do not consult primary labels. Submit annotator_id, "
            "method (independent or intra-rater), completed_at (YYYY-MM-DD), "
            "human_attestation=true, and labels [{item_id, category, acceptable}]. "
            "Intra-rater requires at least 14 days after export. No AI-generated labels.",
        },
    )
    return output / "second/export.json"


def import_labels(path: Path, guard: PrivateGuard, taxonomy_path: Path) -> Path:
    if guard.root is None:
        raise ValueError("private_root is required")
    root = guard.private_output(guard.root / "annotations")
    guard.access(path)
    labels = SecondaryLabels.model_validate_json(path.read_bytes())
    primary = json.loads((root / "primary.json").read_bytes())
    if (
        labels.method == "intra-rater"
        and (labels.completed_at - date.fromisoformat(primary["exported_at"])).days < 14
    ):
        raise ValueError("blind intra-rater annotation requires at least 14 days")
    ids = [label.item_id for label in labels.labels]
    if len(set(ids)) != len(ids) or set(ids) != set(primary["items"]):
        raise ValueError("labels must cover exactly the exported sample without duplicates")
    leaves = set(Taxonomy.read(taxonomy_path).leaves)
    if any(
        label.category not in leaves or not set(label.acceptable) <= leaves
        for label in labels.labels
    ):
        raise ValueError("labels must use taxonomy leaves")
    destination = root / "second/labels.json"
    _write_new(destination, labels.model_dump(mode="json"))
    return destination


def compute_agreement(guard: PrivateGuard) -> Path:
    if guard.root is None:
        raise ValueError("private_root is required")
    root = guard.private_output(guard.root / "annotations")
    primary = json.loads((root / "primary.json").read_bytes())
    labels = SecondaryLabels.model_validate_json((root / "second/labels.json").read_bytes())
    secondary = {label.item_id: label.category for label in labels.labels}
    ids = sorted(primary["items"])
    result = agreement([primary["items"][i]["category"] for i in ids], [secondary[i] for i in ids])
    result.update(
        {
            "schema_version": "1.0",
            "method": labels.method,
            "annotator_id": labels.annotator_id,
            "primary_corrected": False,
            "human_validated": labels.human_attestation,
            "model_provenance": labels.model_provenance,
            "limitation": (
                "AI-assisted agreement is not independent human validation"
                if labels.method == "ai-assisted"
                else None
            ),
        }
    )
    destination = root / "annotation_agreement.json"
    _write_new(destination, result)
    return destination
