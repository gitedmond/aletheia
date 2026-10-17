"""Ground-truth counts against declared probe support, without binary analysis."""

from typing import TypedDict

from aletheia.schema.models import REGISTRY, GroundTruth
from aletheia.verify.probes.pack import Pack


class Row(TypedDict):
    leaf: str
    scorable_functions: int
    e2_method: str | None
    decisive_for: list[str]
    known_blockers: list[str]


class ProgramCoverage(TypedDict):
    program_id: str
    scorable_functions: int
    decidable_functions: int
    decidable_share: float | None


class Table(TypedDict):
    population: str
    programs: list[ProgramCoverage]
    rows: list[Row]
    scorable_functions: int
    decidable_functions: int
    decidable_share: float | None


def table(truths: list[GroundTruth], packs: list[Pack]) -> Table:
    """Count potential E2 coverage; actual decisiveness also requires binding and clean state."""
    if len({gt.program_id for gt in truths}) != len(truths):
        raise ValueError("expected exactly one ground-truth variant per program")
    if len({pack.family for pack in packs}) != len(packs):
        raise ValueError("duplicate family pack")
    supported = {
        f"{pack.family}/{variant}": f"probe.{pack.family}@{pack.version}"
        for pack in packs
        for variant in pack.variants
    }
    counts = {
        f"{family}/{variant}": 0 for family, variants in REGISTRY.items() for variant in variants
    } | {"none": 0}
    programs: list[ProgramCoverage] = []
    for gt in sorted(truths, key=lambda gt: gt.program_id):
        if len({function.address for function in gt.functions}) != len(gt.functions):
            raise ValueError("duplicate ground-truth function address")
        functions = [function for function in gt.functions if function.scorable]
        covered = 0
        for function in functions:
            algorithm = function.algorithm
            leaf = (
                "none" if algorithm.family == "none" else f"{algorithm.family}/{algorithm.variant}"
            )
            if leaf not in counts:
                raise ValueError(f"ground truth requires a concrete registered variant: {leaf}")
            counts[leaf] += 1
            covered += leaf in supported
        programs.append(
            {
                "program_id": gt.program_id,
                "scorable_functions": len(functions),
                "decidable_functions": covered,
                "decidable_share": covered / len(functions) if functions else None,
            }
        )
    rows: list[Row] = [
        {
            "leaf": leaf,
            "scorable_functions": count,
            "e2_method": supported.get(leaf),
            "decisive_for": ["VERIFIED", "CONTRADICTED"] if leaf in supported else [],
            "known_blockers": ["binding/state preconditions"] if leaf in supported else ["no_pack"],
        }
        for leaf, count in sorted(counts.items())
    ]
    total = sum(program["scorable_functions"] for program in programs)
    decidable = sum(program["decidable_functions"] for program in programs)
    return {
        "population": "dev; potential E2 coverage from installed packs; "
        "binding/state preconditions apply; actual decisiveness is measured separately",
        "programs": programs,
        "rows": rows,
        "scorable_functions": total,
        "decidable_functions": decidable,
        "decidable_share": decidable / total if total else None,
    }


def markdown(report: Table) -> str:
    lines = [
        report["population"],
        "",
        "| Program | Decidable/scorable | Share |",
        "|---|---:|---:|",
    ]
    for program in report["programs"]:
        share = program["decidable_share"]
        percentage = f"{100 * share:.2f}%" if share is not None else "n/a"
        lines.append(
            f"| {program['program_id']} | {program['decidable_functions']}/"
            f"{program['scorable_functions']} | {percentage} |"
        )
    lines += [
        "",
        "| Leaf | Scorable | E2 method | Decisive for | Known blockers |",
        "|---|---:|---|---|---|",
    ]
    for row in report["rows"]:
        lines.append(
            f"| {row['leaf']} | {row['scorable_functions']} | "
            f"{row['e2_method'] or 'none'} | {', '.join(row['decisive_for']) or 'neither'} | "
            f"{', '.join(row['known_blockers'])} |"
        )
    share = report["decidable_share"]
    percentage = f"{100 * share:.2f}%" if share is not None else "n/a"
    lines += [
        "",
        f"Decidable (potential E2): {report['decidable_functions']}/"
        f"{report['scorable_functions']} ({percentage}).",
    ]
    return "\n".join(lines)


def table_v2(truths: list[GroundTruth], packs: list[Pack]) -> Table:
    """Potential E2 union of algorithm and purpose scopes, never static signature evidence."""
    from pathlib import Path

    from aletheia.schema.models import GroundFunctionV2
    from aletheia.verify.probes.purpose import PurposeMapping

    if any(gt.schema_version != "2.0" for gt in truths):
        raise ValueError("v2 coverage requires compiler ABI/category ground truth")
    output = table(truths, packs)
    mapping = PurposeMapping.read(Path(__file__).parents[2] / "mappings/purpose_packs.yaml")
    installed = {pack.family for pack in packs}
    by_leaf: dict[str, Row] = {}
    programs: list[ProgramCoverage] = []
    for gt in sorted(truths, key=lambda item: item.program_id):
        functions = [fn for fn in gt.functions if isinstance(fn, GroundFunctionV2) and fn.scorable]
        categories = {fn.category for fn in functions}
        covered = 0
        for fn in functions:
            scope = mapping.map.get(fn.category or "")
            composite_ready = scope is not None and (
                not scope.composite
                or all(
                    f"crypto.hash.{scope.pack}.{role}" in categories
                    for role in ("init", "update", "final")
                )
            )
            algorithm_ready = any(
                p.family == fn.algorithm.family and fn.algorithm.variant in p.variants
                for p in packs
            )
            purpose_ready = scope is not None and scope.pack in installed and composite_ready
            ready = algorithm_ready or purpose_ready
            covered += ready
            key = fn.category or "none"
            row = by_leaf.setdefault(
                key,
                {
                    "leaf": key,
                    "scorable_functions": 0,
                    "e2_method": None,
                    "decisive_for": [],
                    "known_blockers": [],
                },
            )
            row["scorable_functions"] += 1
            if ready:
                row["e2_method"] = "probe." + (
                    scope.pack if purpose_ready and scope else fn.algorithm.family
                )
                row["decisive_for"] = ["VERIFIED", "CONTRADICTED"]
                row["known_blockers"] = sorted(
                    set(row["known_blockers"]) | {"binding/state preconditions"}
                )
            else:
                row["known_blockers"] = sorted(
                    set(row["known_blockers"]) | {"no_complete_e2_scope"}
                )
        programs.append(
            {
                "program_id": gt.program_id,
                "scorable_functions": len(functions),
                "decidable_functions": covered,
                "decidable_share": covered / len(functions) if functions else None,
            }
        )
    total = sum(p["scorable_functions"] for p in programs)
    covered = sum(p["decidable_functions"] for p in programs)
    output.update(
        population=(
            "v2; potential E2 algorithm/purpose union; binding/state "
            "preconditions apply; static E1 signatures excluded"
        ),
        programs=programs,
        rows=[by_leaf[k] for k in sorted(by_leaf)],
        scorable_functions=total,
        decidable_functions=covered,
        decidable_share=covered / total if total else None,
    )
    return output
