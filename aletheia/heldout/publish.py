"""An explicit public projection; never copy per-program reports or free text."""

from typing import Any

from aletheia.metrics import MetricsReport


def aggregate_payload(metrics: MetricsReport, manifest_digests: list[str]) -> dict[str, Any]:
    return {
        "schema_version": metrics.schema_version,
        "split": "heldout",
        "manifest_digests": sorted(set(manifest_digests)),
        "independent": metrics.independent.model_dump(mode="json"),
        "independent_by_type": {
            name: population.model_dump(mode="json")
            for name, population in sorted(metrics.independent_by_type.items())
        },
        "sources": [
            {
                "source": item.source.model_dump(mode="json"),
                "label": item.label,
                "aggregate": item.aggregate.model_dump(mode="json"),
            }
            for item in metrics.sources
        ],
        "bootstrap_seed": metrics.bootstrap_seed,
        "bootstrap_resamples": metrics.bootstrap_resamples,
    }
