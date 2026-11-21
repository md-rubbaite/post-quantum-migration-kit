"""Output formats: console text, JSON inventory, SARIF 2.1.0 (GitHub code scanning) and Markdown."""

from __future__ import annotations

import json

from . import __version__
from .rules import RULES
from .scanner import DEPRECATED_AFTER, DISALLOWED_AFTER, Finding, Settings, as_dicts, summarise

SARIF_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}


def to_text(findings: list[Finding]) -> str:
    rows = [f"{f.priority:<9}{f.rule:<8}{f.algorithm:<24}{f.file}:{f.line}" for f in findings]
    s = summarise(findings)
    rows.append("")
    rows.append(
        f"{s['total']} findings, {s['quantum_vulnerable']} quantum-vulnerable in {s['files_affected']} files, "
        f"{s['post_quantum_in_use']} post-quantum usages"
    )
    return "\n".join(rows)


def to_json(findings: list[Finding], settings: Settings) -> str:
    doc = {
        "tool": {"name": "pqcscan", "version": __version__},
        "policy": {
            "reference": "NIST IR 8547 (final, October 2026)",
            "quantum_vulnerable_deprecated_after": DEPRECATED_AFTER,
            "quantum_vulnerable_disallowed_after": DISALLOWED_AFTER,
            "data_shelf_life_years": settings.data_shelf_life_years,
            "migration_years": settings.migration_years,
        },
        "summary": summarise(findings),
        "findings": as_dicts(findings),
    }
    return json.dumps(doc, indent=2)


def to_sarif(findings: list[Finding]) -> str:
    used = sorted({f.rule for f in findings})
    rules = [
        {
            "id": r.id,
            "name": f"{r.algorithm} ({r.category})",
            "shortDescription": {"text": f"{r.algorithm} used for {r.category}"},
            "help": {"text": f"Migration target: {r.replacement}"},
            "properties": {"tags": ["cryptography", "post-quantum", r.category]},
        }
        for r in RULES
        if r.id in used
    ]
    results = [
        {
            "ruleId": f.rule,
            "level": SARIF_LEVEL[f.priority],
            "message": {"text": f"{f.algorithm} ({f.category}, priority {f.priority}). Move to: {f.replacement}"},
            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": {"startLine": f.line}}}],
        }
        for f in findings
    ]
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{"tool": {"driver": {"name": "pqcscan", "version": __version__, "rules": rules}}, "results": results}],
    }
    return json.dumps(doc, indent=2)


def to_markdown(findings: list[Finding], settings: Settings) -> str:
    s = summarise(findings)
    lines = [
        "# Cryptographic inventory and post-quantum migration report",
        "",
        f"Reference: NIST IR 8547 (final) — quantum-vulnerable public-key algorithms are deprecated after "
        f"{DEPRECATED_AFTER} and disallowed after {DISALLOWED_AFTER}.",
        f"Assumptions: data must stay confidential for {settings.data_shelf_life_years} years; "
        f"migration takes {settings.migration_years} years.",
        "",
        "| Metric | Value |",
        "|---|---|",
        f"| Findings | {s['total']} |",
        f"| Quantum-vulnerable usages | {s['quantum_vulnerable']} |",
        f"| Files affected | {s['files_affected']} |",
        f"| Post-quantum usages already present | {s['post_quantum_in_use']} |",
        "",
        "| Priority | Algorithm | Category | Location | Move to |",
        "|---|---|---|---|---|",
    ]
    for f in findings:
        lines.append(f"| {f.priority} | {f.algorithm} | {f.category} | `{f.file}:{f.line}` | {f.replacement} |")
    return "\n".join(lines) + "\n"
