import re
from pathlib import Path
from typing import Any

import yaml

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
ACTION_REFERENCE = re.compile(r"^\s*uses:\s*[^@\s]+@([0-9a-f]{40})(?:\s+#.*)?$", re.MULTILINE)
ANY_ACTION_REFERENCE = re.compile(r"^\s*uses:\s*[^@\s]+@([^\s#]+)", re.MULTILINE)


def load_yaml(relative: str) -> dict[str, Any]:
    with (REPOSITORY_ROOT / relative).open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream)
    assert isinstance(document, dict)
    return document


def test_all_external_actions_use_full_commit_sha() -> None:
    workflows = sorted((REPOSITORY_ROOT / ".github" / "workflows").glob("*.yml"))
    assert workflows

    for workflow in workflows:
        content = workflow.read_text(encoding="utf-8")
        references = ANY_ACTION_REFERENCE.findall(content)
        pinned_references = ACTION_REFERENCE.findall(content)
        assert references
        assert len(pinned_references) == len(references), workflow


def test_quality_workflow_contains_required_gates() -> None:
    content = (REPOSITORY_ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")

    for command in (
        "scripts/check_bilingual_docs.py",
        "python -m ruff check .",
        "python -m mypy",
        "python -m pytest --cov=",
        "python -m pip_audit",
        "python -m bandit -r src",
    ):
        assert command in content

    assert "npm test" in content


def test_container_workflow_builds_and_scans_both_images() -> None:
    content = (REPOSITORY_ROOT / ".github/workflows/container.yml").read_text(encoding="utf-8")

    assert "docker/worker/Dockerfile" in content
    assert "docker build" in content
    assert "severity: HIGH,CRITICAL" in content
    assert "format: cyclonedx" in content
    assert "sbom-${{ matrix.component }}.cdx.json" in content
    assert "scripts/write_image_identity.py" in content
    assert "--build-arg \"VCS_REF=${{ github.sha }}\"" in content
    assert "image-identity-${{ matrix.component }}.json" in content


def test_dependabot_targets_the_project_default_branch() -> None:
    document = load_yaml(".github/dependabot.yml")
    updates = document["updates"]

    assert isinstance(updates, list)
    assert updates
    assert all(update["target-branch"] == "mainer" for update in updates)
    assert {update["package-ecosystem"] for update in updates} >= {
        "docker",
        "github-actions",
        "pip",
    }


def test_issue_forms_are_valid_yaml_mappings() -> None:
    forms = sorted((REPOSITORY_ROOT / ".github/ISSUE_TEMPLATE").glob("*.yml"))
    assert forms

    for form in forms:
        assert load_yaml(str(form.relative_to(REPOSITORY_ROOT)))
