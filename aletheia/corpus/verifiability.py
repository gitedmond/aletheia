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
