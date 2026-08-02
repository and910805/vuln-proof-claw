"""Write a strict, source-bound identity record for one locally built image."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any

SHA256 = re.compile(r"^sha256:[a-f0-9]{64}$")
REVISION = re.compile(r"^[a-f0-9]{40,64}$")
COMPONENT = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
SOURCE_REVISION_LABEL = "org.opencontainers.image.revision"
MAXIMUM_IMAGE_REFERENCE_LENGTH = 255


def build_identity(
    *,
    component: str,
    source_revision: str,
    image_reference: str,
    dockerfile: Path,
    inspect_document: object,
) -> dict[str, Any]:
    """Validate Docker inspect output and construct a stable identity record."""
    if not COMPONENT.fullmatch(component):
        raise ValueError("component is invalid")
    if not REVISION.fullmatch(source_revision):
        raise ValueError("source revision is invalid")
    if not image_reference.strip() or len(image_reference) > MAXIMUM_IMAGE_REFERENCE_LENGTH:
        raise ValueError("image reference is invalid")
    if not isinstance(inspect_document, list) or len(inspect_document) != 1:
        raise ValueError("inspect document must contain exactly one image")
    image = inspect_document[0]
    if not isinstance(image, dict):
        raise ValueError("inspect image is invalid")

    image_id = image.get("Id")
    if not isinstance(image_id, str) or not SHA256.fullmatch(image_id):
        raise ValueError("image ID is invalid")
    config = image.get("Config")
    labels = config.get("Labels") if isinstance(config, dict) else None
    if not isinstance(labels, dict) or labels.get(SOURCE_REVISION_LABEL) != source_revision:
        raise ValueError("image source revision label does not match")
    repository_digests = image.get("RepoDigests") or []
    if not isinstance(repository_digests, list) or any(
        not isinstance(value, str)
        or "@" not in value
        or not SHA256.fullmatch(value.rsplit("@", maxsplit=1)[1])
        for value in repository_digests
    ):
        raise ValueError("repository digest is invalid")
    operating_system = image.get("Os")
    architecture = image.get("Architecture")
    if not isinstance(operating_system, str) or not operating_system:
        raise ValueError("image operating system is invalid")
    if not isinstance(architecture, str) or not architecture:
        raise ValueError("image architecture is invalid")

    dockerfile_bytes = dockerfile.read_bytes()
    return {
        "schema_version": "v1",
        "component": component,
        "source_revision": source_revision,
        "image_reference": image_reference,
        "image_id": image_id,
        "repository_digests": sorted(repository_digests),
        "publication_digest_available": bool(repository_digests),
        "platform": {"os": operating_system, "architecture": architecture},
        "dockerfile": {
            "path": dockerfile.as_posix(),
            "sha256": hashlib.sha256(dockerfile_bytes).hexdigest(),
        },
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--component", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--image-reference", required=True)
    parser.add_argument("--dockerfile", type=Path, required=True)
    parser.add_argument("--inspect-file", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    inspect_document = json.loads(args.inspect_file.read_text(encoding="utf-8"))
    identity = build_identity(
        component=args.component,
        source_revision=args.source_revision,
        image_reference=args.image_reference,
        dockerfile=args.dockerfile,
        inspect_document=inspect_document,
    )
    args.output.write_text(
        json.dumps(identity, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
