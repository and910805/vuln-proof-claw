from pathlib import Path

import pytest
from scripts.check_bilingual_docs import (
    discover_markdown,
    english_for,
    find_pairing_errors,
    main,
    translation_for,
)


def write_document(root: Path, relative: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# Document\n", encoding="utf-8")
    return path


def test_peer_path_helpers() -> None:
    assert translation_for(Path("docs/guide.md")) == Path("docs/guide.zh-TW.md")
    assert english_for(Path("docs/guide.zh-TW.md")) == Path("docs/guide.md")
    assert english_for(Path("LICENSE.zh-TW.md")) == Path("LICENSE")


def test_complete_pairs_pass(tmp_path: Path) -> None:
    write_document(tmp_path, "README.md")
    write_document(tmp_path, "README.zh-TW.md")
    write_document(tmp_path, "docs/guide.md")
    write_document(tmp_path, "docs/guide.zh-TW.md")
    write_document(tmp_path, ".github/pull_request_template.md")
    write_document(tmp_path, ".github/pull_request_template.zh-TW.md")

    assert find_pairing_errors(tmp_path) == []
    assert main(["--root", str(tmp_path)]) == 0


def test_missing_translation_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    write_document(tmp_path, "docs/guide.md")

    assert find_pairing_errors(tmp_path) == [
        "missing Traditional Chinese document: docs/guide.md -> docs/guide.zh-TW.md"
    ]
    assert main(["--root", str(tmp_path)]) == 1
    assert "docs/guide.zh-TW.md" in capsys.readouterr().out


def test_orphan_translation_fails(tmp_path: Path) -> None:
    write_document(tmp_path, "README.zh-TW.md")

    assert find_pairing_errors(tmp_path) == [
        "orphan Traditional Chinese document: README.zh-TW.md"
    ]


def test_unmaintained_and_ignored_markdown_is_not_scanned(tmp_path: Path) -> None:
    write_document(tmp_path, "examples/example.md")
    write_document(tmp_path, "docs/.venv/generated.md")

    assert discover_markdown(tmp_path) == []
