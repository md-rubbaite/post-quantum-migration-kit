"""pqcscan command line."""

from __future__ import annotations

import argparse
import sys
import tomllib
from pathlib import Path

from . import __version__
from .report import to_json, to_markdown, to_sarif, to_text
from .scanner import Settings, scan_path

LEVELS = ["info", "low", "medium", "high", "critical"]


def load_settings(path: str | None) -> Settings:
    s = Settings()
    if path:
        with open(path, "rb") as f:
            data = tomllib.load(f).get("pqcscan", {})
        unknown = set(data) - {"data_shelf_life_years", "migration_years", "exclude"}
        if unknown:
            raise ValueError(f"unknown settings: {sorted(unknown)}")
        s.data_shelf_life_years = int(data.get("data_shelf_life_years", s.data_shelf_life_years))
        s.migration_years = int(data.get("migration_years", s.migration_years))
        s.exclude = list(data.get("exclude", []))
    return s


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="pqcscan", description="Find quantum-vulnerable cryptography and plan migration")
    p.add_argument("path")
    p.add_argument("--config", help="TOML file with a [pqcscan] table")
    p.add_argument("--format", choices=["text", "json", "sarif", "markdown"], default="text")
    p.add_argument("--out", help="write the report to a file instead of stdout")
    p.add_argument("--fail-on", choices=LEVELS + ["never"], default="never", help="exit 1 at or above this priority")
    p.add_argument("--version", action="version", version=f"pqcscan {__version__}")
    a = p.parse_args(argv)

    try:
        settings = load_settings(a.config)
    except (OSError, ValueError, tomllib.TOMLDecodeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    if not Path(a.path).exists():
        print(f"error: {a.path} does not exist", file=sys.stderr)
        return 2

    findings = scan_path(a.path, settings)
    out = {
        "text": lambda: to_text(findings),
        "json": lambda: to_json(findings, settings),
        "sarif": lambda: to_sarif(findings),
        "markdown": lambda: to_markdown(findings, settings),
    }[a.format]()
    if a.out:
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(out + "\n", encoding="utf-8")
    else:
        print(out)

    if a.fail_on != "never":
        threshold = LEVELS.index(a.fail_on)
        if any(LEVELS.index(f.priority) >= threshold for f in findings):
            return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
