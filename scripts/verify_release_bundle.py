#!/usr/bin/env python3
"""Verify the exact HarborGate qualification bundle and canonical materials."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import quote


PACKAGE_NAME = "harboros-im-gate"
SOURCE_REPOSITORY = "https://github.com/Bean-Harbor-Engineering/HarborGate"
COPYRIGHT_TEXT = "Copyright (c) 2026 Harborinno Ltd."
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


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


def canonical_json_sha256(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def cargo_dependency_records(
    dependencies: list[dict[str, Any]],
) -> list[dict[str, str]]:
    records = []
    identities = set()
    purls = set()
    for dependency in dependencies:
        identity = (
            dependency.get("name"),
            dependency.get("version"),
            dependency.get("source"),
        )
        checksum = dependency.get("checksum")
        if (
            not all(isinstance(item, str) and item for item in identity)
            or identity in identities
            or not isinstance(checksum, str)
            or not SHA256_RE.fullmatch(checksum)
        ):
            raise ValueError("target Cargo dependency identity is invalid")
        name, version, source = identity
        purl = f"pkg:cargo/{quote(name, safe='.-~')}@{quote(version, safe='.-~')}"
        if purl in purls:
            raise ValueError(f"target Cargo dependency repeats a purl: {purl}")
        identities.add(identity)
        purls.add(purl)
        records.append(
            {
                "checksum": checksum,
                "name": name,
                "purl": purl,
                "source": source,
                "version": version,
            }
        )
    return sorted(records, key=lambda item: (item["name"], item["version"], item["source"]))


def require_resolved_dependency(
    dependencies: Any, *, uri: str, digest: dict[str, str], label: str
) -> None:
    expected = {"digest": digest, "uri": uri}
    matches = [
        item
        for item in dependencies
        if isinstance(item, dict) and item.get("uri") == uri
    ] if isinstance(dependencies, list) else []
    if matches != [expected]:
        raise ValueError(f"{label} is absent, repeated, or malformed")


def load_canonical_json(path: Path, label: str) -> dict[str, Any]:
    try:
        payload = path.read_bytes()
        value = json.loads(payload.decode("utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"invalid {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"{label} must be a JSON object")
    if payload != canonical_bytes(value):
        raise ValueError(f"{label} is not canonical JSON")
    return value


def verify_checksum_manifest(path: Path, expected: dict[str, str]) -> None:
    entries: dict[str, str] = {}
    try:
        payload = path.read_bytes()
        lines = payload.decode("ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise ValueError(f"invalid checksum manifest: {path.name}") from exc
    for line in lines:
        parts = line.split("  ", 1)
        if len(parts) != 2:
            raise ValueError(f"invalid checksum manifest line: {path.name}")
        digest, name = parts
        if not SHA256_RE.fullmatch(digest):
            raise ValueError(f"invalid SHA256 digest: {path.name}")
        if "\\" in name or Path(name).name != name or name in {".", ".."}:
            raise ValueError(f"unsafe checksum manifest member: {name}")
        if name in entries:
            raise ValueError(f"duplicate checksum manifest member: {name}")
        entries[name] = digest
    expected_payload = "".join(
        f"{digest}  {name}\n" for name, digest in sorted(expected.items())
    ).encode("ascii")
    if entries != expected or payload != expected_payload:
        raise ValueError(f"checksum manifest membership mismatch: {path.name}")


def identities(value: Any, label: str) -> list[dict[str, str]]:
    if not isinstance(value, list) or not value:
        raise ValueError(f"{label} must be a non-empty list")
    result: list[dict[str, str]] = []
    for item in value:
        if (
            not isinstance(item, dict)
            or set(item) != {"filename", "kind", "sha256"}
            or not isinstance(item["filename"], str)
            or "\\" in item["filename"]
            or Path(item["filename"]).name != item["filename"]
            or not isinstance(item["kind"], str)
            or not re.fullmatch(r"[a-z0-9][a-z0-9-]*", item["kind"])
            or not isinstance(item["sha256"], str)
            or not SHA256_RE.fullmatch(item["sha256"])
        ):
            raise ValueError(f"{label} contains an invalid identity")
        result.append(item)
    if len({item["kind"] for item in result}) != len(result):
        raise ValueError(f"{label} repeats a kind")
    if len({item["filename"] for item in result}) != len(result):
        raise ValueError(f"{label} repeats a filename")
    return result


def verify_sboms(
    bundle: Path,
    prefix: str,
    version: str,
    artifact_digest: str,
    decision: dict[str, Any],
    third_party_dependencies: list[dict[str, Any]],
) -> None:
    spdx = load_canonical_json(bundle / f"{prefix}.sbom.spdx.json", "SPDX SBOM")
    packages = spdx.get("packages")
    root_packages = [
        item
        for item in packages
        if isinstance(item, dict)
        and item.get("name") == PACKAGE_NAME
        and item.get("versionInfo") == version
        and {"algorithm": "SHA256", "checksumValue": artifact_digest}
        in item.get("checksums", [])
    ] if isinstance(packages, list) else []
    if len(root_packages) != 1:
        raise ValueError("SPDX SBOM does not bind the final deb")
    root = root_packages[0]
    if (
        root.get("licenseDeclared") != decision["declared_license"]
        or root.get("licenseConcluded") != decision["concluded_license"]
        or root.get("copyrightText") != decision["copyright"]
    ):
        raise ValueError("SPDX root license decision differs from release materials")
    package_ids = [item.get("SPDXID") for item in packages if isinstance(item, dict)]
    expected_relationship = {
        "relatedSpdxElement": root.get("SPDXID"),
        "relationshipType": "DESCRIBES",
        "spdxElementId": spdx.get("SPDXID"),
    }
    describes = [
        item
        for item in spdx.get("relationships", [])
        if isinstance(item, dict)
        and item.get("spdxElementId") == spdx.get("SPDXID")
        and item.get("relationshipType") == "DESCRIBES"
    ]
    if (
        len(package_ids) != len(set(package_ids))
        or spdx.get("SPDXID") in package_ids
        or describes != [expected_relationship]
    ):
        raise ValueError("SPDX package identities or DESCRIBES relationship are invalid")
    expected_dependencies = {
        (item["name"], item["version"]): item for item in third_party_dependencies
    }
    actual_dependencies = {
        (item.get("name"), item.get("versionInfo")): item
        for item in packages
        if isinstance(item, dict) and item is not root
    }
    if len(expected_dependencies) != len(third_party_dependencies) or (
        set(actual_dependencies) != set(expected_dependencies)
    ):
        raise ValueError("SPDX target dependency closure differs from license evidence")
    for identity, expected in expected_dependencies.items():
        actual = actual_dependencies[identity]
        concluded = expected["concluded_license"]
        if (
            {"algorithm": "SHA256", "checksumValue": expected["checksum"]}
            not in actual.get("checksums", [])
            or actual.get("licenseConcluded") != concluded
            or actual.get("licenseDeclared") != concluded
        ):
            raise ValueError(f"SPDX dependency decision differs: {identity}")

    cdx = load_canonical_json(bundle / f"{prefix}.sbom.cdx.json", "CycloneDX SBOM")
    component = cdx.get("metadata", {}).get("component", {})
    properties = component.get("properties", []) if isinstance(component, dict) else []
    properties_by_name = {
        item.get("name"): item.get("value") for item in properties if isinstance(item, dict)
    }
    if (
        not isinstance(component, dict)
        or component.get("name") != PACKAGE_NAME
        or component.get("version") != version
        or {"alg": "SHA-256", "content": artifact_digest}
        not in component.get("hashes", [])
        or component.get("licenses") != [{"expression": decision["concluded_license"]}]
        or len(properties_by_name) != len(properties)
        or properties_by_name.items()
        < {
            "harboros:copyright": decision["copyright"],
            "harboros:license-concluded": decision["concluded_license"],
            "harboros:license-declared": decision["declared_license"],
        }.items()
    ):
        raise ValueError("CycloneDX SBOM does not bind the final deb decision")
    cdx_dependencies = cdx.get("components")
    if not isinstance(cdx_dependencies, list):
        raise ValueError("CycloneDX target dependency closure is absent")
    actual_cdx = {
        (item.get("name"), item.get("version")): item
        for item in cdx_dependencies
        if isinstance(item, dict)
    }
    if len(actual_cdx) != len(cdx_dependencies) or set(actual_cdx) != set(
        expected_dependencies
    ):
        raise ValueError("CycloneDX target dependency closure differs from license evidence")
    for identity, expected in expected_dependencies.items():
        actual = actual_cdx[identity]
        concluded = expected["concluded_license"]
        expected_licenses = [] if concluded == "NOASSERTION" else [{"expression": concluded}]
        if (
            {"alg": "SHA-256", "content": expected["checksum"]}
            not in actual.get("hashes", [])
            or actual.get("licenses", []) != expected_licenses
        ):
            raise ValueError(f"CycloneDX dependency decision differs: {identity}")


def verify_third_party_licenses(
    path: Path, version: str, arch: str
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    evidence = load_canonical_json(path, "third-party license evidence")
    expected_targets = {
        "amd64": "x86_64-unknown-linux-gnu",
        "riscv64": "riscv64gc-unknown-linux-gnu",
    }
    summary = evidence.get("dependency_summary")
    scope = evidence.get("scope")
    cargo_lock = evidence.get("cargo_lock")
    dependencies = evidence.get("dependencies")
    blockers = evidence.get("blocking_reasons")
    if (
        evidence.get("schema_version") != 1
        or evidence.get("package") != PACKAGE_NAME
        or evidence.get("version") != version
        or evidence.get("architecture") != arch
        or evidence.get("policy") != "cargo-locked-target-closure-license-evidence-v1"
        or evidence.get("cargo_license_reference")
        != (
            "https://doc.rust-lang.org/cargo/reference/manifest.html#the-license-and-"
            "license-file-fields"
        )
        or not isinstance(cargo_lock, dict)
        or cargo_lock.get("filename") != "Cargo.lock"
        or not isinstance(cargo_lock.get("sha256"), str)
        or not SHA256_RE.fullmatch(cargo_lock["sha256"])
        or not isinstance(scope, dict)
        or scope.get("target") != expected_targets.get(arch)
        or scope.get("dependency_kinds") != ["build", "normal"]
        or scope.get("dev_dependencies_included") is not False
        or not isinstance(summary, dict)
        or not isinstance(dependencies, list)
        or not dependencies
        or not isinstance(blockers, list)
        or any(not isinstance(item, str) or not item for item in blockers)
    ):
        raise ValueError("third-party license evidence identity or scope is invalid")

    seen = set()
    resolved = 0
    for dependency in dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("third-party dependency evidence is invalid")
        identity = (
            dependency.get("name"),
            dependency.get("version"),
            dependency.get("source"),
        )
        checksum = dependency.get("checksum")
        archive = dependency.get("archive")
        materials = dependency.get("license_materials")
        status = dependency.get("resolution_status")
        if (
            any(not isinstance(item, str) or not item for item in identity)
            or identity in seen
            or not isinstance(checksum, str)
            or not SHA256_RE.fullmatch(checksum)
            or not isinstance(archive, dict)
            or not isinstance(materials, list)
            or status not in {"resolved", "blocked"}
        ):
            raise ValueError("third-party dependency identity/checksum is invalid")
        seen.add(identity)
        expected_archive_filename = f"{identity[0]}-{identity[1]}.crate"
        if status == "resolved":
            if (
                archive.get("sha256") != checksum
                or archive.get("verification_status")
                != "verified-against-cargo-lock"
                or archive.get("filename") != expected_archive_filename
                or dependency.get("concluded_license") in {None, "", "NOASSERTION"}
                or not isinstance(dependency.get("declared_license"), str)
                or not dependency["declared_license"]
                or not materials
                or dependency.get("blocking_reasons")
            ):
                raise ValueError("resolved dependency lacks a license decision")
            resolved += 1
        else:
            archive_is_verified = (
                archive.get("sha256") == checksum
                and archive.get("verification_status")
                == "verified-against-cargo-lock"
                and archive.get("filename") == expected_archive_filename
            )
            archive_is_unavailable = (
                archive.get("expected_sha256") == checksum
                and archive.get("verification_status")
                == "unavailable-or-checksum-mismatch"
                and archive.get("expected_filename") == expected_archive_filename
            )
            if (
                not (archive_is_verified or archive_is_unavailable)
                or dependency.get("concluded_license") != "NOASSERTION"
                or not dependency.get("blocking_reasons")
            ):
                raise ValueError("blocked dependency lacks an explicit blocker")
        material_paths = set()
        for material in materials:
            if not isinstance(material, dict):
                raise ValueError("third-party license material is invalid")
            material_path = material.get("path")
            encoding = material.get("encoding")
            content = material.get("content")
            digest = material.get("sha256")
            if (
                not isinstance(material_path, str)
                or not material_path
                or "\\" in material_path
                or material_path.startswith("/")
                or ".." in Path(material_path).parts
                or material_path in material_paths
                or encoding not in {"utf-8", "base64"}
                or not isinstance(content, str)
                or not isinstance(digest, str)
                or not SHA256_RE.fullmatch(digest)
            ):
                raise ValueError("third-party license material identity is invalid")
            material_paths.add(material_path)
            try:
                payload = (
                    content.encode("utf-8")
                    if encoding == "utf-8"
                    else base64.b64decode(content, validate=True)
                )
            except (UnicodeError, ValueError) as exc:
                raise ValueError("third-party license material encoding is invalid") from exc
            if hashlib.sha256(payload).hexdigest() != digest:
                raise ValueError("third-party license material content digest differs")

    expected_summary = {
        "resolved": resolved,
        "total": len(dependencies),
        "unresolved": len(dependencies) - resolved,
    }
    eligible = resolved == len(dependencies)
    if (
        summary != expected_summary
        or evidence.get("release_eligible") is not eligible
        or (not blockers) is not eligible
    ):
        raise ValueError("third-party license evidence decision is inconsistent")
    return evidence, dependencies


def verify_bundle(args: argparse.Namespace) -> None:
    product_profile = getattr(args, "product_profile", "n2-riscv64")
    runtime_evidence = "nexus-runtime-evidence-required" if product_profile == "nexus-amd64" else "k3-runtime-evidence-required"
    bundle = args.bundle
    prefix = f"{PACKAGE_NAME}_{args.version}_{args.arch}"
    deb_name = f"{prefix}.deb"
    descriptor_name = f"{deb_name}.release-materials.json"
    manifest_name = f"{deb_name}.materials.sha256"
    material_names = {
        deb_name,
        f"{deb_name}.sha256",
        f"{prefix}.LICENSE",
        f"{prefix}.artifact-set.json",
        f"{prefix}.component-contract.json",
        f"{prefix}.first-party-rights-approval.json",
        f"{prefix}.{runtime_evidence}.json",
        f"{prefix}.license-review.json",
        f"{prefix}.provenance.json",
        f"{prefix}.sbom.cdx.json",
        f"{prefix}.sbom.spdx.json",
        f"{prefix}.third-party-licenses.json",
    }
    expected_names = material_names | {descriptor_name, manifest_name}
    actual_names = {path.name for path in bundle.iterdir() if path.is_file()}
    if actual_names != expected_names:
        raise ValueError(
            f"release bundle file set mismatch; missing={sorted(expected_names - actual_names)} "
            f"unexpected={sorted(actual_names - expected_names)}"
        )

    deb = bundle / deb_name
    artifact_digest = sha256(deb)
    if (bundle / f"{deb_name}.sha256").read_text(encoding="ascii") != (
        f"{artifact_digest}  {deb_name}\n"
    ):
        raise ValueError("deb checksum sidecar does not bind the final deb")

    descriptor = load_canonical_json(bundle / descriptor_name, "release descriptor")
    required_fields = {
        "architecture", "artifact", "bindings", "decision", "installed_evidence",
        "materials", "package", "schema_version", "source", "version",
    }
    if set(descriptor) != required_fields:
        raise ValueError("release descriptor has an invalid field set")
    source = descriptor.get("source")
    source_commit = source.get("commit") if isinstance(source, dict) else None
    if (
        descriptor.get("schema_version") != 1
        or descriptor.get("package") != PACKAGE_NAME
        or descriptor.get("version") != args.version
        or descriptor.get("architecture") != args.arch
        or source != {"commit": source_commit, "repo": SOURCE_REPOSITORY}
        or not isinstance(source_commit, str)
        or not COMMIT_RE.fullmatch(source_commit)
        or descriptor.get("artifact")
        != {
            "filename": deb_name,
            "kind": "deb",
            "sha256": artifact_digest,
            "size": deb.stat().st_size,
        }
    ):
        raise ValueError("release descriptor package identity changed")

    material_entries = identities(descriptor.get("materials"), "release materials")
    by_kind = {item["kind"]: item for item in material_entries}
    if set(item["filename"] for item in material_entries) != material_names:
        raise ValueError("release descriptor does not cover the exact material set")
    for item in material_entries:
        if item["sha256"] != sha256(bundle / item["filename"]):
            raise ValueError(f"release material digest mismatch: {item['filename']}")
    binding_entries = identities(descriptor.get("bindings"), "release bindings")
    required_bindings = {
        "component-contract", "license-review", "provenance", "sbom-cyclonedx",
        "sbom-spdx", "third-party-licenses",
    }
    if {item["kind"] for item in binding_entries} != required_bindings:
        raise ValueError("release bindings are incomplete")
    if any(by_kind[item["kind"]] != item for item in binding_entries):
        raise ValueError("release binding differs from its material identity")

    installed = descriptor.get("installed_evidence")
    if not isinstance(installed, list) or not installed:
        raise ValueError("release descriptor lacks installed evidence")
    installed_kinds = set()
    for item in installed:
        if not isinstance(item, dict) or set(item) != {
            "filename", "installed_path", "kind", "sha256",
        }:
            raise ValueError("installed evidence contains an invalid identity")
        material_identity = {key: item[key] for key in ("filename", "kind", "sha256")}
        if by_kind.get(item["kind"]) != material_identity:
            raise ValueError("installed evidence differs from its material identity")
        installed_path = item["installed_path"]
        if (
            not isinstance(installed_path, str)
            or not installed_path.startswith("/")
            or "\\" in installed_path
            or "//" in installed_path
            or any(part in {"", ".", ".."} for part in installed_path.split("/")[1:])
        ):
            raise ValueError("installed evidence path is unsafe")
        installed_kinds.add(item["kind"])
    if not {
        "component-contract", "first-party-rights", "root-license",
        "third-party-licenses",
    }.issubset(installed_kinds):
        raise ValueError("installed evidence omits package rights or license identity")

    expected_manifest = {
        descriptor_name: sha256(bundle / descriptor_name),
        **{item["filename"]: item["sha256"] for item in material_entries},
    }
    verify_checksum_manifest(bundle / manifest_name, expected_manifest)

    decision = descriptor.get("decision")
    if not isinstance(decision, dict) or set(decision) != {
        "blocking_reasons", "concluded_license", "copyright", "declared_license",
        "policy", "release_eligible", "status",
    }:
        raise ValueError("release decision has an invalid field set")
    blockers = decision.get("blocking_reasons")
    eligible = decision.get("status") == "approved"
    if (
        decision.get("status") not in {"approved", "blocked"}
        or decision.get("policy") != "fail-closed"
        or decision.get("release_eligible") is not eligible
        or not isinstance(blockers, list)
        or (not blockers) is not eligible
        or decision.get("declared_license") != "MIT"
        or decision.get("concluded_license") != "MIT"
        or decision.get("copyright") != COPYRIGHT_TEXT
    ):
        raise ValueError("release decision is contradictory")

    review = load_canonical_json(bundle / f"{prefix}.license-review.json", "license review")
    first_party_rights = review.get("first_party_rights")
    for field, expected in (
        ("package", PACKAGE_NAME), ("version", args.version),
        ("architecture", args.arch), ("policy", decision["policy"]),
        ("review_status", decision["status"]),
        ("release_eligible", decision["release_eligible"]),
        ("blocking_reasons", blockers),
    ):
        if review.get(field) != expected:
            raise ValueError(f"license review differs from release decision: {field}")
    root = review.get("root_component", {})
    if (
        root.get("declared_license") != decision["declared_license"]
        or root.get("concluded_license") != decision["concluded_license"]
        or root.get("copyright") != decision["copyright"]
        or not isinstance(first_party_rights, dict)
        or first_party_rights.get("status") != "approved"
    ):
        raise ValueError("license review does not preserve the approved first-party decision")
    summary = review.get("dependency_summary", {})
    unresolved = summary.get("unresolved")
    if not isinstance(unresolved, int) or unresolved < 0:
        raise ValueError("license review must report an unresolved dependency count")
    if eligible is not (unresolved == 0):
        raise ValueError("license review eligibility contradicts unresolved dependencies")
    third_party_path = bundle / f"{prefix}.third-party-licenses.json"
    third_party_evidence, third_party_dependencies = verify_third_party_licenses(
        third_party_path, args.version, args.arch
    )
    if (
        third_party_evidence.get("dependency_summary") != summary
        or third_party_evidence.get("blocking_reasons") != blockers
        or third_party_evidence.get("release_eligible") is not eligible
    ):
        raise ValueError("license review differs from third-party license evidence")
    evidence_by_identity = {
        (item["name"], item["version"], item["source"]): item
        for item in third_party_dependencies
    }
    review_dependencies = review.get("dependencies")
    if not isinstance(review_dependencies, list) or len(review_dependencies) != len(
        evidence_by_identity
    ):
        raise ValueError("license review dependency closure is incomplete")
    for dependency in review_dependencies:
        if not isinstance(dependency, dict):
            raise ValueError("license review dependency record is invalid")
        identity = (
            dependency.get("name"), dependency.get("version"), dependency.get("source")
        )
        evidence_dependency = evidence_by_identity.get(identity)
        if evidence_dependency is None or (
            dependency.get("checksum") != evidence_dependency.get("checksum")
            or dependency.get("declared_license")
            != evidence_dependency.get("declared_license")
            or dependency.get("concluded_license")
            != evidence_dependency.get("concluded_license")
            or dependency.get("status")
            != evidence_dependency.get("resolution_status")
            or dependency.get("license_material_sha256")
            != [
                item["sha256"]
                for item in evidence_dependency.get("license_materials", [])
            ]
        ):
            raise ValueError("license review dependency differs from package evidence")
    if args.require_release_eligible and not eligible:
        raise ValueError("license review blocks formal release")

    rights = load_canonical_json(
        bundle / f"{prefix}.first-party-rights-approval.json", "first-party rights"
    )
    approval = rights.get("approval")
    third_party = rights.get("third_party")
    if (
        rights.get("package") != PACKAGE_NAME
        or rights.get("source") != source
        or not isinstance(approval, dict)
        or approval.get("decision") != "approved-for-distribution"
        or not isinstance(third_party, dict)
        or third_party.get("decision") != "separate-review-required"
    ):
        raise ValueError("first-party rights approval does not bind the package source")

    contract = load_canonical_json(
        bundle / f"{prefix}.component-contract.json", "component contract"
    )
    if contract.get("package") != PACKAGE_NAME or contract.get("source_commit") != source_commit:
        raise ValueError("component contract does not bind the package source")

    if product_profile == "nexus-amd64":
        if args.arch != "amd64" or contract.get("product_profile") != product_profile:
            raise ValueError("Nexus bundle uses the wrong architecture or contract lane")
        if any(item.get("id", "").startswith("harboros.k3.") for item in contract.get("contracts", [])):
            raise ValueError("Nexus bundle must not claim the N2 contract")
        runtime = load_canonical_json(bundle / f"{prefix}.{runtime_evidence}.json", "Nexus runtime evidence")
        if runtime.get("source_commit") != source_commit or runtime.get("product_profile") != product_profile:
            raise ValueError("Nexus runtime evidence does not bind the product source")

    provenance = load_canonical_json(
        bundle / f"{prefix}.provenance.json", "package provenance"
    )
    if provenance.get("subject") != [
        {"digest": {"sha256": artifact_digest}, "name": deb_name}
    ]:
        raise ValueError("provenance subject does not bind the final deb name and digest")
    dependencies = provenance.get("predicate", {}).get("buildDefinition", {}).get(
        "resolvedDependencies", []
    )
    if not any(
        isinstance(item, dict)
        and item.get("uri") == f"git+{SOURCE_REPOSITORY}@{source_commit}"
        and item.get("digest") == {"gitCommit": source_commit}
        for item in dependencies
    ):
        raise ValueError("provenance does not bind the descriptor source")
    require_resolved_dependency(
        dependencies,
        uri="Cargo.lock",
        digest={"sha256": third_party_evidence["cargo_lock"]["sha256"]},
        label="provenance Cargo.lock dependency",
    )
    require_resolved_dependency(
        dependencies,
        uri="cargo-metadata:resolved-packages",
        digest={
            "sha256": canonical_json_sha256(
                cargo_dependency_records(third_party_dependencies)
            )
        },
        label="provenance target Cargo metadata dependency",
    )

    verify_sboms(
        bundle,
        prefix,
        args.version,
        artifact_digest,
        decision,
        third_party_dependencies,
    )

    artifact_set = load_canonical_json(
        bundle / f"{prefix}.artifact-set.json", "artifact set"
    )
    members = artifact_set.get("artifacts")
    expected_artifact_members = material_names - {f"{prefix}.artifact-set.json"}
    if (
        artifact_set.get("package") != PACKAGE_NAME
        or artifact_set.get("version") != args.version
        or artifact_set.get("architecture") != args.arch
        or not isinstance(members, list)
        or {item.get("name") for item in members if isinstance(item, dict)}
        != expected_artifact_members
        or len(members) != len(expected_artifact_members)
    ):
        raise ValueError("artifact set membership is incomplete")
    for member in members:
        path = bundle / member["name"]
        if member.get("sha256") != sha256(path):
            raise ValueError(f"artifact-set digest mismatch: {path.name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--arch", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--product-profile", choices=["nexus-amd64", "n2-riscv64"], default="n2-riscv64")
    parser.add_argument("--require-release-eligible", action="store_true")
    verify_bundle(parser.parse_args())


if __name__ == "__main__":
    main()
