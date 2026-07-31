"""Enforce English and Traditional Chinese pairs for maintained Markdown documents."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

TRANSLATION_SUFFIX = ".zh-TW.md"
SCANNED_LOCATIONS = (
    Path("*.md"),
    Path("docs/**/*.md"),
    Path(".github/**/*.md"),
)
IGNORED_PARTS = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "build",
    "dist",
    "htmlcov",
    "node_modules",
    "venv",
}
ENGLISH_NAME_OVERRIDES = {
    "LICENSE.zh-TW.md": "LICENSE",
}


def is_translation(path: Path) -> bool:
    """Return whether a Markdown path is a Traditional Chinese translation."""
    return path.name.endswith(TRANSLATION_SUFFIX)


def translation_for(path: Path) -> Path:
    """Return the expected Traditional Chinese peer for an English Markdown file."""
    return path.with_name(f"{path.stem}.zh-TW.md")


def english_for(path: Path) -> Path:
    """Return the expected English peer for a Traditional Chinese Markdown file."""
    if override := ENGLISH_NAME_OVERRIDES.get(path.name):
        return path.with_name(override)
    return path.with_name(f"{path.name.removesuffix(TRANSLATION_SUFFIX)}.md")


def discover_markdown(root: Path) -> list[Path]:
    """Discover maintained Markdown documents under the configured locations."""
    found: set[Path] = set()
    for pattern in SCANNED_LOCATIONS:
        for path in root.glob(pattern.as_posix()):
            relative = path.relative_to(root)
            if path.is_file() and not IGNORED_PARTS.intersection(relative.parts):
                found.add(path)
    return sorted(found, key=lambda path: path.relative_to(root).as_posix())


def find_pairing_errors(root: Path) -> list[str]:
    """Return deterministic errors for missing English or Traditional Chinese peers."""
    errors: list[str] = []
    for path in discover_markdown(root):
        relative = path.relative_to(root).as_posix()
        if is_translation(path):
            if not english_for(path).is_file():
                errors.append(f"orphan Traditional Chinese document: {relative}")
        elif not translation_for(path).is_file():
            expected = translation_for(path).relative_to(root).as_posix()
            errors.append(f"missing Traditional Chinese document: {relative} -> {expected}")
    return errors


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line parser."""
    parser = argparse.ArgumentParser(
        description="Check maintained Markdown files for English and zh-TW pairs."
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
        help="repository root (defaults to the script's parent repository)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the bilingual documentation check."""
    args = build_parser().parse_args(argv)
    root = args.root.resolve()
    errors = find_pairing_errors(root)
    if errors:
        lines = ["Bilingual documentation check failed:"]
        lines.extend(f"- {error}" for error in errors)
        sys.stdout.write("\n".join(lines) + "\n")
        return 1
    sys.stdout.write("Bilingual documentation check passed.\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
