"""Tests for source-bound container image identity records."""

from __future__ import annotations

from pathlib import Path

import pytest
from scripts.write_image_identity import build_identity

REVISION = "a" * 40
REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
DOCKERFILE = REPOSITORY_ROOT / "docker" / "worker" / "Dockerfile"


def inspect_document(*, revision: str = REVISION) -> list[object]:
    return [
        {
            "Id": f"sha256:{'b' * 64}",
            "RepoDigests": [f"example.test/worker@sha256:{'c' * 64}"],
            "Os": "linux",
            "Architecture": "amd64",
            "Config": {"Labels": {"org.opencontainers.image.revision": revision}},
        }
    ]


def test_identity_binds_image_source_platform_and_dockerfile() -> None:
    identity = build_identity(
        component="worker",
        source_revision=REVISION,
        image_reference=f"worker:{REVISION}",
        dockerfile=DOCKERFILE,
        inspect_document=inspect_document(),
    )

    assert identity["schema_version"] == "v1"
    assert identity["source_revision"] == REVISION
    assert identity["image_id"] == f"sha256:{'b' * 64}"
    assert identity["publication_digest_available"] is True
    assert len(identity["dockerfile"]["sha256"]) == 64


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ([], "exactly one"),
        ([{"Id": "latest"}], "image ID"),
        (inspect_document(revision="d" * 40), "revision label"),
    ],
)
def test_identity_rejects_ambiguous_or_unbound_inspection(
    document: object,
    message: str,
) -> None:
    with pytest.raises(ValueError, match=message):
        build_identity(
            component="worker",
            source_revision=REVISION,
            image_reference="worker:test",
            dockerfile=DOCKERFILE,
            inspect_document=document,
        )
