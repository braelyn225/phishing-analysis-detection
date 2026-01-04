from __future__ import annotations

import json
from dataclasses import asdict
from pathlib import Path
from typing import Any

from .scoring import Finding


def write_json(path: str | Path, data: dict[str, Any]) -> None:
    Path(path).write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


def write_markdown(path: str | Path, data: dict[str, Any]) -> None:
    lines = []
    lines.append("# PhishGuard Report\n")
    lines.append(f"**Risk:** {data['risk_label']}  \n**Score:** {data['risk_score']}\n")

    lines.append("## Summary\n")
    lines.append(f"- Subject: {data['email']['subject']}")
    lines.append(f"- From: {data['email']['from']}")
    lines.append(f"- Reply-To: {data['email']['reply_to']}")
    lines.append(f"- Date: {data['email']['date']}\n")

    lines.append("## Findings\n")
    if data["findings"]:
        for f in data["findings"]:
            lines.append(f"- **{f['name']}** (+{f['weight']}): {f['detail']}")
    else:
        lines.append("- None\n")

    lines.append("\n## IOCs\n")
    iocs = data["iocs"]
    for k in ["urls", "domains", "ips", "hashes"]:
        lines.append(f"### {k.upper()}\n")
        if iocs.get(k):
            for v in iocs[k]:
                lines.append(f"- `{v}`")
        else:
            lines.append("- (none)")
        lines.append("")

    Path(path).write_text("\n".join(lines).strip() + "\n", encoding="utf-8")


def findings_to_dict(findings: list[Finding]) -> list[dict]:
    return [asdict(f) for f in findings]
