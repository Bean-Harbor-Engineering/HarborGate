#!/usr/bin/env python3
"""Generate the canonical HarborOS release descriptor and full material manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path
from typing import Any


PACKAGE_NAME = "harboros-im-gate"
SOURCE_REPOSITORY = "https://github.com/Bean-Harbor-Engineering/HarborGate"
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
COPYRIGHT_TEXT = "Copyright (c) 2026 Harborinno Ltd."


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def canonical_bytes(value: Any) -> bytes:
    return (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )


def load_canonical_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    if payload != canonical_bytes(value):
        raise ValueError(f"{label} must be canonical JSON")
    return value


def write_json(path: Path, value: dict[str, Any]) -> None:
    path.write_bytes(canonical_bytes(value))


def identity(kind: str, path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        raise ValueError(f"missing or unsafe release material: {path}")
    return {"filename": path.name, "kind": kind, "sha256": sha256(path)}


def generate_materials(args: argparse.Namespace) -> dict[str, Path]:
    if not args.artifact.is_file() or args.artifact.suffix != ".deb":
        raise ValueError("artifact must be an existing .deb")
    if args.artifact.parent.resolve() != args.output_dir.resolve():
        raise ValueError("artifact and release materials must share one directory")
    if not COMMIT_RE.fullmatch(args.source_commit):
        raise ValueError("source commit must be a full lowercase Git commit")

    runtime_evidence = "nexus-runtime-evidence-required" if getattr(args, "product_profile", "legacy-k3") == "nexus-amd64" else ("n2-runtime-evidence-required" if getattr(args, "product_profile", "legacy-k3") == "n2-riscv64" else "k3-runtime-evidence-required")
    prefix = args.artifact.name.removesuffix(".deb")
    paths = {
        "artifact-set": args.output_dir / f"{prefix}.artifact-set.json",
        "component-contract": args.output_dir / f"{prefix}.component-contract.json",
        "deb": args.artifact,
        "deb-sha256": args.output_dir / f"{args.artifact.name}.sha256",
        "first-party-rights": (
            args.output_dir / f"{prefix}.first-party-rights-approval.json"
        ),
        runtime_evidence.removesuffix("-required"): (
            args.output_dir / f"{prefix}.{runtime_evidence}.json"
        ),
        "license-review": args.output_dir / f"{prefix}.license-review.json",
        "provenance": args.output_dir / f"{prefix}.provenance.json",
        "root-license": args.output_dir / f"{prefix}.LICENSE",
        "sbom-cyclonedx": args.output_dir / f"{prefix}.sbom.cdx.json",
        "sbom-spdx": args.output_dir / f"{prefix}.sbom.spdx.json",
        "third-party-licenses": (
            args.output_dir / f"{prefix}.third-party-licenses.json"
        ),
    }
    identities = {kind: identity(kind, path) for kind, path in paths.items()}

    checksum = paths["deb-sha256"].read_text(encoding="ascii")
    if checksum != f"{sha256(args.artifact)}  {args.artifact.name}\n":
        raise ValueError("deb checksum sidecar is non-canonical or does not match")

    contract = load_canonical_json(paths["component-contract"], "component contract")
    if (
        contract.get("schema_version") != 1
        or contract.get("package") != PACKAGE_NAME
        or contract.get("source_commit") != args.source_commit
        or not isinstance(contract.get("contracts"), list)
        or not contract["contracts"]
    ):
        raise ValueError("component contract does not bind the package source")

    rights = load_canonical_json(paths["first-party-rights"], "first-party rights")
    approval = rights.get("approval")
    third_party = rights.get("third_party")
    if (
        rights.get("schema_version") != 1
        or rights.get("package") != PACKAGE_NAME
        or rights.get("source")
        != {"commit": args.source_commit, "repo": SOURCE_REPOSITORY}
        or not isinstance(approval, dict)
        or approval.get("decision") != "approved-for-distribution"
        or approval.get("organization") != "Harbor Innovations"
        or not isinstance(third_party, dict)
        or third_party.get("decision") != "separate-review-required"
    ):
        raise ValueError("first-party rights evidence does not bind the package source")

    review = load_canonical_json(paths["license-review"], "license review")
    blockers = review.get("blocking_reasons")
    root = review.get("root_component")
    if (
        review.get("package") != PACKAGE_NAME
        or review.get("version") != args.version
        or review.get("architecture") != args.architecture
        or review.get("policy") != "fail-closed"
        or review.get("review_status") not in {"approved", "blocked"}
        or not isinstance(review.get("release_eligible"), bool)
        or not isinstance(blockers, list)
        or any(not isinstance(item, str) or not item for item in blockers)
        or not isinstance(root, dict)
        or root.get("declared_license") != "MIT"
        or root.get("concluded_license") != "MIT"
        or root.get("copyright") != COPYRIGHT_TEXT
    ):
        raise ValueError("license review does not contain a valid package decision")
    eligible = review["review_status"] == "approved"
    if review["release_eligible"] is not eligible or (not blockers) is not eligible:
        raise ValueError("license review status, eligibility, and blockers disagree")

    decision = {
        "blocking_reasons": blockers,
        "concluded_license": root["concluded_license"],
        "copyright": root["copyright"],
        "declared_license": root["declared_license"],
        "policy": review["policy"],
        "release_eligible": review["release_eligible"],
        "status": review["review_status"],
    }
    descriptor = {
        "architecture": args.architecture,
        "artifact": {
            **identities["deb"],
            "size": args.artifact.stat().st_size,
        },
        "bindings": [
            identities[kind]
            for kind in (
                "component-contract",
                "license-review",
                "provenance",
                "sbom-spdx",
                "sbom-cyclonedx",
                "third-party-licenses",
            )
        ],
        "decision": decision,
        "installed_evidence": [
            {
                **identities["component-contract"],
                "installed_path": (
                    "/usr/share/harboros/component-contracts/harboros-im-gate.json"
                ),
            },
            {
                **identities["first-party-rights"],
                "installed_path": (
                    "/usr/share/doc/harboros-im-gate/first-party-rights-approval.json"
                ),
            },
            {
                **identities["root-license"],
                "installed_path": "/usr/share/doc/harboros-im-gate/copyright",
            },
            {
                **identities["third-party-licenses"],
                "installed_path": (
                    "/usr/share/doc/harboros-im-gate/third-party-licenses.json"
                ),
            },
        ],
        "materials": [identities[kind] for kind in sorted(identities)],
        "package": PACKAGE_NAME,
        "schema_version": 1,
        "source": {"commit": args.source_commit, "repo": SOURCE_REPOSITORY},
        "version": args.version,
    }
    descriptor_path = args.output_dir / f"{args.artifact.name}.release-materials.json"
    manifest_path = args.output_dir / f"{args.artifact.name}.materials.sha256"
    write_json(descriptor_path, descriptor)
    entries = {
        descriptor_path.name: sha256(descriptor_path),
        **{item["filename"]: item["sha256"] for item in descriptor["materials"]},
    }
    if len(entries) != len(descriptor["materials"]) + 1:
        raise ValueError("release material filenames must be unique")
    manifest_path.write_bytes(
        "".join(
            f"{digest}  {name}\n" for name, digest in sorted(entries.items())
        ).encode("ascii")
    )
    return {"descriptor": descriptor_path, "manifest": manifest_path}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--product-profile", choices=["nexus-amd64", "n2-riscv64", "legacy-k3"], default="legacy-k3")
    parser.add_argument("--architecture", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    return parser.parse_args()


def main() -> int:
    try:
        generate_materials(parse_args())
    except (OSError, UnicodeError, ValueError) as exc:
        raise SystemExit(f"release material generation failed: {exc}") from exc
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
