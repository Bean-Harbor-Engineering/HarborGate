#!/usr/bin/env python3
"""Generate deterministic SBOM and fail-closed license review documents."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import tomllib
import uuid
from pathlib import Path
from urllib.parse import quote


PACKAGE_NAME = "harboros-im-gate"
SOURCE_REPOSITORY = "https://github.com/Bean-Harbor-Engineering/HarborGate"
COPYRIGHT_TEXT = "Copyright (c) 2026 Harborinno Ltd."


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def spdx_id(name: str, version: str) -> str:
    value = re.sub(r"[^A-Za-z0-9.-]", "-", f"Package-{name}-{version}")
    return f"SPDXRef-{value}"


def load_json(path: Path, label: str) -> dict[str, object]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    canonical = (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    if payload != canonical:
        raise ValueError(f"{label} must be canonical JSON")
    return value


def validate_first_party_rights(path: Path, source_commit: str) -> dict[str, object]:
    value = load_json(path, "first-party rights approval")
    if (
        value.get("schema_version") != 1
        or value.get("package") != PACKAGE_NAME
        or value.get("source")
        != {"commit": source_commit, "repo": SOURCE_REPOSITORY}
        or value.get("approval")
        != {
            "basis": "rights-holder-confirmation",
            "confirmed_on": "2026-08-16",
            "decision": "approved-for-distribution",
            "organization": "Harbor Innovations",
            "scope": ["first-party-brand-materials", "first-party-source-code"],
            "use": ["HarborNavi qualification", "HarborOS Nexus amd64 distribution"],
        }
        or value.get("third_party")
        != {
            "decision": "separate-review-required",
            "scope": (
                "Locked dependencies and third-party materials remain governed "
                "by their original licenses."
            ),
        }
    ):
        raise ValueError("first-party rights approval does not match the qualification decision")
    return value


def cargo_components(
    evidence_path: Path,
    cargo_lock_path: Path,
    package_version: str,
    target: str,
    arch: str,
) -> tuple[dict[str, object], list[dict[str, object]]]:
    evidence = load_json(evidence_path, "third-party license evidence")
    summary = evidence.get("dependency_summary")
    scope = evidence.get("scope")
    dependencies = evidence.get("dependencies")
    blockers = evidence.get("blocking_reasons")
    if (
        evidence.get("schema_version") != 1
        or evidence.get("package") != PACKAGE_NAME
        or evidence.get("version") != package_version
        or evidence.get("architecture") != arch
        or evidence.get("policy") != "cargo-locked-target-closure-license-evidence-v1"
        or evidence.get("cargo_lock")
        != {"filename": cargo_lock_path.name, "sha256": sha256(cargo_lock_path)}
        or not isinstance(scope, dict)
        or scope.get("target") != target
        or scope.get("dependency_kinds") != ["build", "normal"]
        or scope.get("dev_dependencies_included") is not False
        or not isinstance(summary, dict)
        or not isinstance(dependencies, list)
        or not dependencies
        or not isinstance(blockers, list)
        or any(not isinstance(item, str) or not item for item in blockers)
    ):
        raise ValueError("third-party license evidence identity or scope is invalid")

    components = []
    identities = set()
    resolved = 0
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("third-party license dependency record is invalid")
        name = dependency.get("name")
        version = dependency.get("version")
        source = dependency.get("source")
        checksum = dependency.get("checksum")
        declared = dependency.get("declared_license")
        concluded = dependency.get("concluded_license")
        status = dependency.get("resolution_status")
        materials = dependency.get("license_materials")
        archive = dependency.get("archive")
        if (
            not isinstance(name, str)
            or not name
            or not isinstance(version, str)
            or not version
            or not isinstance(source, str)
            or not source.startswith("registry+")
            or not isinstance(checksum, str)
            or not re.fullmatch(r"[0-9a-f]{64}", checksum)
            or not isinstance(declared, str)
            or not declared
            or status not in {"resolved", "blocked"}
            or not isinstance(materials, list)
            or not isinstance(archive, dict)
        ):
            raise ValueError("third-party license dependency identity is invalid")
        identity = (name, version, source)
        if identity in identities:
            raise ValueError("third-party license evidence repeats a dependency")
        identities.add(identity)
        expected_archive_filename = f"{name}-{version}.crate"
        if status == "resolved":
            if (
                not isinstance(concluded, str)
                or not concluded
                or concluded == "NOASSERTION"
                or not materials
                or dependency.get("blocking_reasons")
                or archive.get("sha256") != checksum
                or archive.get("filename") != expected_archive_filename
                or archive.get("verification_status")
                != "verified-against-cargo-lock"
            ):
                raise ValueError("resolved third-party dependency lacks license evidence")
            for material in materials:
                if (
                    not isinstance(material, dict)
                    or not isinstance(material.get("path"), str)
                    or not material["path"]
                    or not isinstance(material.get("sha256"), str)
                    or not re.fullmatch(r"[0-9a-f]{64}", material["sha256"])
                    or material.get("encoding") not in {"utf-8", "base64"}
                    or not isinstance(material.get("content"), str)
                ):
                    raise ValueError("third-party license material is invalid")
            resolved += 1
        else:
            archive_verified = (
                archive.get("sha256") == checksum
                and archive.get("filename") == expected_archive_filename
                and archive.get("verification_status")
                == "verified-against-cargo-lock"
            )
            archive_unavailable = (
                archive.get("expected_sha256") == checksum
                and archive.get("expected_filename") == expected_archive_filename
                and archive.get("verification_status")
                == "unavailable-or-checksum-mismatch"
            )
            if (
                not (archive_verified or archive_unavailable)
                or concluded != "NOASSERTION"
                or not dependency.get("blocking_reasons")
            ):
                raise ValueError("blocked third-party dependency lacks an explicit blocker")
        components.append(
            {
                "checksum": checksum,
                "concluded_license": concluded,
                "declared_license": declared,
                "license_material_sha256": [item["sha256"] for item in materials],
                "name": name,
                "purl": f"pkg:cargo/{quote(name, safe='.-~')}@{quote(version, safe='.-~')}",
                "source": source,
                "status": status,
                "version": version,
            }
        )

    expected_summary = {
        "resolved": resolved,
        "total": len(components),
        "unresolved": len(components) - resolved,
    }
    eligible = resolved == len(components)
    if (
        summary != expected_summary
        or evidence.get("release_eligible") is not eligible
        or (not blockers) is not eligible
    ):
        raise ValueError("third-party license evidence decision is inconsistent")
    return evidence, components


def license_review(
    cargo_toml_path: Path,
    cargo_lock_path: Path,
    license_path: Path,
    rights_approval_path: Path,
    third_party_evidence_path: Path,
    third_party_evidence: dict[str, object],
    components: list[dict[str, object]],
    package_name: str,
    package_version: str,
    arch: str,
    created: str,
    source_commit: str,
) -> dict[str, object]:
    cargo_toml = tomllib.loads(cargo_toml_path.read_text(encoding="utf-8"))
    declared_license = cargo_toml.get("package", {}).get("license")
    if not isinstance(declared_license, str) or not declared_license.strip():
        raise ValueError("Cargo.toml package.license is required")
    if package_name != PACKAGE_NAME or declared_license != "MIT":
        raise ValueError("root package identity or declared license differs from review")

    license_text = license_path.read_text(encoding="utf-8")
    copyright_notices = [
        line.strip()
        for line in license_text.splitlines()
        if line.strip().lower().startswith("copyright ")
    ]
    if not copyright_notices:
        raise ValueError("LICENSE must contain an explicit copyright notice")
    if COPYRIGHT_TEXT not in copyright_notices:
        raise ValueError("LICENSE copyright differs from the reviewed root component")
    rights_approval = validate_first_party_rights(rights_approval_path, source_commit)

    dependencies = [
        {
            "checksum": component["checksum"],
            "concluded_license": component["concluded_license"],
            "copyright": f"See {third_party_evidence_path.name} package-local materials.",
            "declared_license": component["declared_license"],
            "license_material_sha256": component["license_material_sha256"],
            "name": component["name"],
            "review_basis": (
                "checksum-verified-crate-archive-and-package-local-license-materials"
            ),
            "source": component["source"],
            "status": component["status"],
            "version": component["version"],
        }
        for component in components
    ]
    summary = third_party_evidence["dependency_summary"]
    blockers = third_party_evidence["blocking_reasons"]
    release_eligible = third_party_evidence["release_eligible"]
    return {
        "schema_version": 1,
        "package": package_name,
        "version": package_version,
        "architecture": arch,
        "reviewed_at": created,
        "review_status": "approved" if release_eligible else "blocked",
        "policy": "fail-closed",
        "release_eligible": release_eligible,
        "root_component": {
            "declared_license": declared_license,
            "concluded_license": declared_license,
            "copyright": COPYRIGHT_TEXT,
            "copyright_notices": copyright_notices,
        },
        "first_party_rights": {
            "status": "approved",
            "evidence": {
                "path": rights_approval_path.name,
                "sha256": sha256(rights_approval_path),
            },
            "resolution": rights_approval["approval"],
        },
        "reviewed_sources": [
            {"path": "Cargo.toml", "sha256": sha256(cargo_toml_path)},
            {"path": "Cargo.lock", "sha256": sha256(cargo_lock_path)},
            {"path": "LICENSE", "sha256": sha256(license_path)},
            {
                "path": rights_approval_path.name,
                "sha256": sha256(rights_approval_path),
            },
            {
                "path": third_party_evidence_path.name,
                "sha256": sha256(third_party_evidence_path),
            },
        ],
        "dependency_summary": summary,
        "dependencies": dependencies,
        "blocking_reasons": blockers,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cargo-lock", type=Path, required=True)
    parser.add_argument("--cargo-toml", type=Path, required=True)
    parser.add_argument("--license", type=Path, required=True)
    parser.add_argument("--artifact", type=Path, required=True)
    parser.add_argument("--rights-approval", type=Path, required=True)
    parser.add_argument("--third-party-licenses", type=Path, required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-date-epoch", type=int, required=True)
    parser.add_argument("--container-digest", required=True)
    parser.add_argument("--debian-snapshot", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--prefix", required=True)
    args = parser.parse_args()

    created = dt.datetime.fromtimestamp(args.source_date_epoch, dt.UTC).isoformat().replace(
        "+00:00", "Z"
    )
    root = {
        "name": PACKAGE_NAME,
        "version": args.version,
        "purl": f"pkg:deb/{PACKAGE_NAME}@{quote(args.version, safe='.-~')}?arch={args.arch}",
        "checksum": sha256(args.artifact),
    }
    cargo_toml = tomllib.loads(args.cargo_toml.read_text(encoding="utf-8"))
    if not isinstance(cargo_toml.get("package", {}).get("name"), str):
        raise ValueError("Cargo.toml package.name is required")
    third_party_evidence, components = cargo_components(
        args.third_party_licenses,
        args.cargo_lock,
        args.version,
        args.target,
        args.arch,
    )
    root_id = spdx_id(root["name"], root["version"])
    packages = [
        {
            "name": root["name"],
            "SPDXID": root_id,
            "versionInfo": root["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "MIT",
            "licenseDeclared": "MIT",
            "copyrightText": COPYRIGHT_TEXT,
            "checksums": [{"algorithm": "SHA256", "checksumValue": root["checksum"]}],
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": root["purl"],
                }
            ],
        }
    ]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    for component in components:
        package_id = spdx_id(component["name"], component["version"])
        package = {
            "name": component["name"],
            "SPDXID": package_id,
            "versionInfo": component["version"],
            "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": component["concluded_license"],
            "licenseDeclared": (
                component["concluded_license"]
                if component["concluded_license"] != "NOASSERTION"
                else "NOASSERTION"
            ),
            "copyrightText": (
                f"See {args.third_party_licenses.name} package-local materials."
            ),
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": component["purl"],
                }
            ],
        }
        if component["checksum"]:
            package["checksums"] = [
                {"algorithm": "SHA256", "checksumValue": component["checksum"]}
            ]
        packages.append(package)
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )

    spdx = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"harboros-im-gate-{args.version}-{args.arch}",
        "documentNamespace": (
            f"https://harboros.ai/sbom/harboros-im-gate/{args.version}/{args.arch}"
        ),
        "creationInfo": {
            "created": created,
            "creators": ["Organization: Harbor Innovations"],
        },
        "packages": packages,
        "relationships": relationships,
    }
    cyclonedx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, root['purl'])}",
        "version": 1,
        "metadata": {
            "timestamp": created,
            "component": {
                "type": "application",
                "name": root["name"],
                "version": root["version"],
                "purl": root["purl"],
                "hashes": [{"alg": "SHA-256", "content": root["checksum"]}],
                "licenses": [{"expression": "MIT"}],
                "properties": [
                    {"name": "harboros:copyright", "value": COPYRIGHT_TEXT},
                    {"name": "harboros:license-concluded", "value": "MIT"},
                    {"name": "harboros:license-declared", "value": "MIT"},
                ],
            },
        },
        "components": [
            {
                "type": "library",
                "name": component["name"],
                "version": component["version"],
                "purl": component["purl"],
                "hashes": [{"alg": "SHA-256", "content": component["checksum"]}],
                **(
                    {"licenses": [{"expression": component["concluded_license"]}]}
                    if component["concluded_license"] != "NOASSERTION"
                    else {}
                ),
                "properties": [
                    {
                        "name": "harboros:license-evidence-sha256",
                        "value": ",".join(component["license_material_sha256"]),
                    }
                ],
            }
            for component in components
        ],
    }
    review = license_review(
        args.cargo_toml,
        args.cargo_lock,
        args.license,
        args.rights_approval,
        args.third_party_licenses,
        third_party_evidence,
        components,
        root["name"],
        root["version"],
        args.arch,
        created,
        args.source_commit,
    )

    args.output_dir.mkdir(parents=True, exist_ok=True)
    for name, payload in (
        (f"{args.prefix}.sbom.spdx.json", spdx),
        (f"{args.prefix}.sbom.cdx.json", cyclonedx),
        (f"{args.prefix}.license-review.json", review),
    ):
        (args.output_dir / name).write_bytes(
            (
                json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
            ).encode("utf-8")
        )


if __name__ == "__main__":
    main()
