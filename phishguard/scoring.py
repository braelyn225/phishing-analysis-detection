from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Finding:
    name: str
    weight: int
    detail: str


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    score = sum(f.weight for f in findings)

    # Simple bands (tweakable)
    if score >= 70:
        label = "HIGH"
    elif score >= 35:
        label = "MEDIUM"
    else:
        label = "LOW"
    return score, label
