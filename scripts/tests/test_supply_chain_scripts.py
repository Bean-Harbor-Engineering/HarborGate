from __future__ import annotations

import hashlib
import importlib.util
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path
from urllib.parse import quote

import pytest


ROOT = Path(__file__).resolve().parents[2]
PACKAGE = "harboros-im-gate"
VERSION = "0.1.0-test"
ARCH = "riscv64"
COMMIT = "a" * 40
SOURCE_REPO = "https://github.com/Bean-Harbor-Engineering/HarborGate"
COPYRIGHT = "Copyright (c) 2026 Harborinno Ltd."
DEPENDENCY_BLOCKER = "dependency 1.0.0: package-local license text is absent"


def test_component_contract_records_existing_delivery_semantics() -> None:
    contract = json.loads(
        (ROOT / "debian" / "component-contract.json.in").read_text(encoding="utf-8")
    )

    assert contract == {
        "contracts": [
            {
                "capabilities": [
                    "beacon-gate-contract-2.0",
                    "harboros-auth-token-validation",
                    "external-riscv64-runtime-evidence-required",
                    "loopback-only",
                    "per-artifact-video-delivery",
                    "persistent-delivery-retry",
                    "platform-credential-ownership",
                    "service-bearer-redaction",
                ],
                "id": "harboros.k3.gate-v2-transport",
                "version": 1,
            }
        ],
        "package": "harboros-im-gate",
        "schema_version": 1,
        "source_commit": "SOURCE_COMMIT_PLACEHOLDER",
    }


def test_k3_service_keeps_device_sessions_in_the_persistent_writable_data_root() -> None:
    service = (ROOT / "debian" / "harbornavi-k3" / "harboros-im-gate.service").read_text(
        encoding="utf-8"
    )
    layout = (ROOT / "scripts" / "ensure-data-layout").read_text(encoding="utf-8")

    assert (
        "Environment=HARBORGATE_DEVICE_SESSION_STATE_DIR="
        "/data/harborgate/device-sessions"
    ) in service
    assert "Environment=HARBORGATE_RUNTIME_PROFILE=k3" in service
    assert "Requires=harboros-bootstrap.service" in service
    assert "After=network-online.target harboros-bootstrap.service" in service
    assert "ConditionPathExists=/run/harboros/home.env" in service.split("[Service]", 1)[0]
    assert "EnvironmentFile=/run/harboros/home.env" in service
    assert "EnvironmentFile=-/run/harboros/home.env" not in service
    assert "Requires=harboros-service-auth-recovery.service" in service
    for credential in ["gate-to-beacon-send", "beacon-to-gate-accept-current", "beacon-to-gate-accept-previous"]:
        assert f"LoadCredential={credential}:" in service
    assert "EnvironmentFile=/data/harboros/secrets/beacon-gate.env" not in service
    assert "ProtectSystem=strict" in service
    assert "ReadWritePaths=/data/harborgate" in service
    assert "/var/lib/harboros-im-gate/device-sessions" not in service
    assert "/etc/default/harboros-beacon-gate" not in service
    assert "/etc/default/harboros-im-gate" not in service
    assert '"$root/device-sessions"' in layout
    assert 'install -d -m 0700' in layout


@pytest.mark.skipif(sys.platform == "win32", reason="requires a POSIX shell")
@pytest.mark.parametrize("canonical", [False, True])
def test_legacy_k3_entrypoint_preserves_build_options(tmp_path: Path, canonical: bool) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    wrapper = scripts / "build_harbornavi_k3_deb.sh"
    shutil.copyfile(ROOT / "scripts" / wrapper.name, wrapper)
    (scripts / "build_harborgate_k3_deb.sh").write_text(
        "printf '%s\\n' \"$RUST_TARGET\" \"$DEBIAN_VERSION\" \"$DEB_ARCH\" \"$OUT_DIR\"\n",
        encoding="utf-8",
    )
    environment = dict(os.environ)
    environment.pop("RUST_TARGET", None)
    environment.pop("DEBIAN_VERSION", None)
    environment.update(TARGET="x86_64-unknown-linux-gnu", VERSION="0.1.0+compat",
                       DEB_ARCH="amd64", OUT_DIR=str(tmp_path / "output with spaces"))
    if canonical:
        environment.update(RUST_TARGET="riscv64gc-unknown-linux-gnu",
                           DEBIAN_VERSION="0.1.0+canonical", DEB_ARCH="riscv64")
    result = subprocess.run(["bash", str(wrapper)], env=environment, check=True,
                            capture_output=True, text=True)
    assert result.stdout.splitlines() == [
        "riscv64gc-unknown-linux-gnu" if canonical else "x86_64-unknown-linux-gnu",
        "0.1.0+canonical" if canonical else "0.1.0+compat",
        "riscv64" if canonical else "amd64",
        str(tmp_path / "output with spaces"),
    ]


def load_script(name: str):
    path = ROOT / "scripts" / name
    spec = importlib.util.spec_from_file_location(path.stem, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cargo_dependency_records(dependencies: list[dict]) -> list[dict[str, str]]:
    records = [
        {
            "checksum": item["checksum"],
            "name": item["name"],
            "purl": (
                f"pkg:cargo/{quote(item['name'], safe='.-~')}@"
                f"{quote(item['version'], safe='.-~')}"
            ),
            "source": item["source"],
            "version": item["version"],
        }
        for item in dependencies
    ]
    return sorted(records, key=lambda item: (item["name"], item["version"], item["source"]))


def canonical_json_sha256(value: object) -> str:
    payload = json.dumps(
        value, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii")
    return hashlib.sha256(payload).hexdigest()


def write_json(path: Path, value: dict) -> None:
    path.write_bytes(
        (
            json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    )


def rights_payload(commit: str = COMMIT) -> dict:
    return {
        "approval": {
            "basis": "rights-holder-confirmation",
            "confirmed_on": "2026-08-16",
            "decision": "approved-for-distribution",
            "organization": "Harbor Innovations",
            "scope": ["first-party-brand-materials", "first-party-source-code"],
            "use": "HarborNavi qualification",
        },
        "package": PACKAGE,
        "schema_version": 1,
        "source": {"commit": commit, "repo": SOURCE_REPO},
        "third_party": {
            "decision": "separate-review-required",
            "scope": (
                "Locked dependencies and third-party materials remain governed "
                "by their original licenses."
            ),
        },
    }


def test_packaging_rights_template_binds_current_repository(tmp_path: Path) -> None:
    template = json.loads(
        (ROOT / "debian" / "first-party-rights-approval.json.in").read_text(
            encoding="utf-8"
        )
    )
    assert template["source"]["commit"] == "SOURCE_COMMIT_PLACEHOLDER"
    template["source"]["commit"] = COMMIT
    approval = tmp_path / "first-party-rights-approval.json"
    write_json(approval, template)

    supply_chain = load_script("generate_supply_chain.py")
    assert supply_chain.validate_first_party_rights(approval, COMMIT) == rights_payload()


def third_party_payload(
    *,
    version: str = VERSION,
    arch: str = ARCH,
    resolved: bool = True,
    cargo_lock_sha256: str = "d" * 64,
    dependency_count: int = 1,
) -> dict:
    license_content = "MIT License fixture\nCopyright (c) Dependency Authors\n"
    material = {
        "basis": "package-root-license-material",
        "content": license_content,
        "encoding": "utf-8",
        "path": "LICENSE",
        "sha256": hashlib.sha256(license_content.encode("utf-8")).hexdigest(),
    }
    if dependency_count < 1 or dependency_count > 2:
        raise ValueError("fixture dependency_count must be one or two")
    dependencies = []
    for index in range(dependency_count):
        name = "dependency" if index == 0 else "dependency-two"
        package_version = "1.0.0" if index == 0 else "2.0.0"
        checksum = ("c" if index == 0 else "e") * 64
        dependency = {
            "archive": {
                "filename": f"{name}-{package_version}.crate",
                "sha256": checksum,
                "verification_status": "verified-against-cargo-lock",
            },
            "cargo_package_id": (
                "registry+https://github.com/rust-lang/crates.io-index"
                f"#{name}@{package_version}"
            ),
            "checksum": checksum,
            "concluded_license": "MIT" if resolved else "NOASSERTION",
            "declared_license": "MIT",
            "dependency_kinds": ["normal"],
            "features": [],
            "license_materials": [material] if resolved else [],
            "name": name,
            "resolution_status": "resolved" if resolved else "blocked",
            "review_basis": (
                "Cargo.lock checksum-verified crate archive, crate manifest declaration, "
                "and embedded package-local license materials"
                if resolved
                else "fail-closed-unresolved-package-license-evidence"
            ),
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "version": package_version,
        }
        if not resolved:
            dependency["blocking_reasons"] = ["package-local license text is absent"]
        dependencies.append(dependency)
    return {
        "architecture": arch,
        "blocking_reasons": [] if resolved else [DEPENDENCY_BLOCKER],
        "cargo_license_reference": (
            "https://doc.rust-lang.org/cargo/reference/manifest.html#the-license-and-"
            "license-file-fields"
        ),
        "cargo_lock": {"filename": "Cargo.lock", "sha256": cargo_lock_sha256},
        "dependencies": dependencies,
        "dependency_summary": {
            "resolved": dependency_count if resolved else 0,
            "total": dependency_count,
            "unresolved": 0 if resolved else dependency_count,
        },
        "generated_at": "2026-08-13T00:00:00Z",
        "package": PACKAGE,
        "policy": "cargo-locked-target-closure-license-evidence-v1",
        "release_eligible": resolved,
        "schema_version": 1,
        "scope": {
            "dependency_kinds": ["build", "normal"],
            "dev_dependencies_included": False,
            "target": "riscv64gc-unknown-linux-gnu",
        },
        "version": version,
    }


def test_license_review_approves_checksum_bound_target_dependencies(
    tmp_path: Path,
) -> None:
    supply_chain = load_script("generate_supply_chain.py")
    rights = tmp_path / "first-party-rights-approval.json"
    write_json(rights, rights_payload())
    third_party_path = tmp_path / "third-party-licenses.json"
    write_json(
        third_party_path,
        third_party_payload(cargo_lock_sha256=sha256(ROOT / "Cargo.lock")),
    )
    third_party, components = supply_chain.cargo_components(
        third_party_path,
        ROOT / "Cargo.lock",
        VERSION,
        "riscv64gc-unknown-linux-gnu",
        ARCH,
    )
    review = supply_chain.license_review(
        ROOT / "Cargo.toml",
        ROOT / "Cargo.lock",
        ROOT / "LICENSE",
        rights,
        third_party_path,
        third_party,
        components,
        PACKAGE,
        VERSION,
        ARCH,
        "2026-08-13T00:00:00Z",
        COMMIT,
    )

    assert review["root_component"] == {
        "declared_license": "MIT",
        "concluded_license": "MIT",
        "copyright": COPYRIGHT,
        "copyright_notices": [COPYRIGHT],
    }
    assert review["first_party_rights"]["status"] == "approved"
    assert review["dependency_summary"] == {"resolved": 1, "total": 1, "unresolved": 0}
    assert review["review_status"] == "approved"
    assert review["release_eligible"] is True
    assert review["blocking_reasons"] == []
    assert review["dependencies"][0]["declared_license"] == "MIT"
    assert review["dependencies"][0]["concluded_license"] == "MIT"


def test_legacy_cargo_license_slash_is_normalized_to_spdx_or() -> None:
    generator = load_script("generate_third_party_licenses.py")
    assert generator.normalize_license_expression("MIT/Apache-2.0") == (
        "MIT OR Apache-2.0",
        "cargo-legacy-slash-normalized-to-spdx-or",
    )
    with pytest.raises(ValueError, match="unsupported legacy"):
        generator.normalize_license_expression("MIT/(Apache-2.0 OR BSD-2-Clause)")


@pytest.mark.parametrize("value", ["Apache-2.0 / MIT", "Apache-2.0/ MIT", "Apache-2.0\t/\tMIT"])
def test_legacy_slash_accepts_whitespace_between_reviewed_identifiers(value: str) -> None:
    generator = load_script("generate_third_party_licenses.py")
    assert generator.normalize_license_expression(value) == (
        "Apache-2.0 OR MIT", "cargo-legacy-slash-normalized-to-spdx-or"
    )


@pytest.mark.parametrize("value", [
    "MIT//Apache-2.0", "/MIT", "MIT/", "MIT/Unknown-License", "MIT/AND",
    "MIT/(Apache-2.0)", "MIT/Apache-2.0 OR MIT", "MIT AND Apache-2.0/MIT",
    "MIT\n/Apache-2.0", "MIT /\u00a0Apache-2.0",
])
def test_legacy_slash_refuses_unknown_or_ambiguous_expressions(value: str) -> None:
    generator = load_script("generate_third_party_licenses.py")
    with pytest.raises(ValueError, match="legacy Cargo license"):
        generator.normalize_license_expression(value)


def supplemental_fixture(tmp_path: Path) -> tuple[Path, dict, Path, dict]:
    generator = load_script("generate_third_party_licenses.py")
    manifest = json.loads(generator.DEFAULT_SUPPLEMENTS.read_bytes())
    manifest["entries"] = manifest["entries"][:1]
    entry = manifest["entries"][0]
    archive_path = tmp_path / "base64-simd-0.8.0.crate"
    files = {
        "Cargo.toml": ('[package]\nname="base64-simd"\nversion="0.8.0"\n'
                       'license="MIT"\nrepository="https://github.com/Nugine/simd"\n').encode(),
        ".cargo_vcs_info.json": json.dumps({"git": {"sha1": entry["commit"]},
                                           "path_in_vcs": entry["crate_path"]}).encode(),
        "src/lib.rs": b"// Test archive has no embedded license text.\n",
    }
    with tarfile.open(archive_path, mode="w:gz") as archive:
        for relative, payload in files.items():
            info = tarfile.TarInfo("base64-simd-0.8.0/" + relative)
            info.size = len(payload)
            archive.addfile(info, io.BytesIO(payload))
    entry["archive_sha256"] = sha256(archive_path)
    supplements_path = tmp_path / "licenses/supplemental-materials.json"
    material_path = supplements_path.parent / entry["material"]["path"]
    material_path.parent.mkdir(parents=True)
    material_path.write_bytes((generator.DEFAULT_SUPPLEMENTS.parent / entry["material"]["path"]).read_bytes())
    write_json(supplements_path, manifest)
    package = {"name": entry["name"], "version": entry["version"], "source": entry["source"]}
    return archive_path, package, supplements_path, manifest


def test_supplement_uses_exact_upstream_bytes_and_preserves_crate(tmp_path: Path) -> None:
    generator = load_script("generate_third_party_licenses.py")
    archive, package, supplements, manifest = supplemental_fixture(tmp_path)
    before = archive.read_bytes()
    materials, identity = generator.crate_license_evidence(archive, package, "MIT", supplements)
    entry = manifest["entries"][0]
    material = materials[0]
    assert material["content"].encode() == (supplements.parent / entry["material"]["path"]).read_bytes()
    assert material["sha256"] == entry["material"]["sha256"]
    assert material["basis"] == "checksum-bound-upstream-license-supplement"
    assert material["supplement"]["commit"] == entry["commit"]
    assert material["supplement"]["declared_license"] == "MIT"
    assert material["supplement"]["archive_sha256"] == sha256(archive)
    assert identity["repository"] == entry["repository"]
    assert archive.read_bytes() == before


@pytest.mark.parametrize("fault", [
    "missing_material", "tampered_material", "missing_manifest", "duplicate",
    "archive_sha256", "commit", "crate_path", "source", "repository", "declared_license",
    "unbound_url", "unsafe_path",
])
def test_supplement_fails_closed_for_missing_tampered_or_unbound_material(tmp_path: Path, fault: str) -> None:
    generator = load_script("generate_third_party_licenses.py")
    archive, package, supplements, manifest = supplemental_fixture(tmp_path)
    entry = manifest["entries"][0]
    material_path = supplements.parent / entry["material"]["path"]
    if fault == "missing_material":
        material_path.unlink()
    elif fault == "tampered_material":
        material_path.write_bytes(material_path.read_bytes().replace(b"Nugine", b"Changed"))
    elif fault == "duplicate":
        manifest["entries"].append(entry.copy())
    elif fault == "unbound_url":
        entry["material"]["url"] = entry["material"]["url"].replace(entry["commit"], "main")
    elif fault == "unsafe_path":
        entry["material"]["path"] = "../LICENSE"
    elif fault != "missing_manifest":
        entry[fault] = "mismatch"
    write_json(supplements, manifest)
    if fault == "missing_manifest":
        supplements.unlink()
    with pytest.raises((ValueError, OSError)):
        generator.crate_license_evidence(archive, package, "MIT", supplements)


def test_complete_embedded_mit_header_is_package_local_license_evidence(
    tmp_path: Path,
) -> None:
    generator = load_script("generate_third_party_licenses.py")
    archive_path = tmp_path / "qrcodegen-1.8.0.crate"
    files = {
        "Cargo.toml": (
            b'[package]\nname = "qrcodegen"\nversion = "1.8.0"\nlicense = "MIT"\n'
        ),
        "src/lib.rs": (
            b"/* Copyright (c) Project Nayuki.\n"
            b"Permission is hereby granted, free of charge, to any person.\n"
            b"The above copyright notice and this permission notice shall be included.\n"
            b'The Software is provided "as is". */\n'
        ),
    }
    with tarfile.open(archive_path, mode="w:gz") as archive:
        for relative, payload in files.items():
            info = tarfile.TarInfo(f"qrcodegen-1.8.0/{relative}")
            info.size = len(payload)
            info.mtime = 0
            archive.addfile(info, io.BytesIO(payload))

    materials, _ = generator.crate_license_evidence(
        archive_path,
        {"name": "qrcodegen", "version": "1.8.0"},
        "MIT",
    )
    assert [item["path"] for item in materials] == ["src/lib.rs"]
    assert materials[0]["basis"] == "complete-mit-license-header-in-package-source"
    assert materials[0]["sha256"] == hashlib.sha256(files["src/lib.rs"]).hexdigest()


def test_target_closure_excludes_dev_only_edges(tmp_path: Path) -> None:
    generator = load_script("generate_third_party_licenses.py")
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text('[package]\nname="root"\nversion="1.0.0"\n', encoding="utf-8")
    root_id = "path+file:///root#root@1.0.0"
    normal_id = "registry+https://example.invalid#index#normal@1.0.0"
    dev_id = "registry+https://example.invalid#index#dev@1.0.0"
    metadata = {
        "packages": [
            {"id": root_id, "manifest_path": str(manifest), "source": None},
            {
                "id": normal_id,
                "manifest_path": str(tmp_path / "normal" / "Cargo.toml"),
                "name": "normal",
                "source": "registry+https://example.invalid/index",
                "version": "1.0.0",
            },
            {
                "id": dev_id,
                "manifest_path": str(tmp_path / "dev" / "Cargo.toml"),
                "name": "dev",
                "source": "registry+https://example.invalid/index",
                "version": "1.0.0",
            },
        ],
        "resolve": {
            "root": root_id,
            "nodes": [
                {
                    "id": root_id,
                    "deps": [
                        {"pkg": normal_id, "dep_kinds": [{"kind": None}]},
                        {"pkg": dev_id, "dep_kinds": [{"kind": "dev"}]},
                    ],
                    "features": [],
                },
                {"id": normal_id, "deps": [], "features": ["std"]},
                {"id": dev_id, "deps": [], "features": []},
            ],
        },
    }
    closure = generator.target_closure(metadata, manifest)
    assert [(item[0]["name"], item[1], item[2]) for item in closure] == [
        ("normal", ["normal"], ["std"])
    ]


def test_package_provenance_digest_uses_exact_target_non_dev_lock_records(
    tmp_path: Path,
) -> None:
    generator = load_script("generate_package_provenance.py")
    manifest = tmp_path / "Cargo.toml"
    manifest.write_text('[package]\nname="root"\nversion="1.0.0"\n', encoding="utf-8")
    source = "registry+https://github.com/rust-lang/crates.io-index"
    normal_id = f"{source}#normal@1.0.0"
    dev_id = f"{source}#dev@2.0.0"
    root_id = "path+file:///root#root@1.0.0"
    metadata = {
        "packages": [
            {"id": root_id, "manifest_path": str(manifest), "source": None},
            {"id": normal_id, "name": "normal", "source": source, "version": "1.0.0"},
            {"id": dev_id, "name": "dev", "source": source, "version": "2.0.0"},
        ],
        "resolve": {
            "root": root_id,
            "nodes": [
                {
                    "id": root_id,
                    "deps": [
                        {"pkg": normal_id, "dep_kinds": [{"kind": None}]},
                        {"pkg": dev_id, "dep_kinds": [{"kind": "dev"}]},
                    ],
                },
                {"id": normal_id, "deps": [], "features": []},
                {"id": dev_id, "deps": [], "features": []},
            ],
        },
    }
    cargo_lock = tmp_path / "Cargo.lock"
    cargo_lock.write_text(
        'version = 4\n\n'
        '[[package]]\nname = "normal"\nversion = "1.0.0"\n'
        f'source = "{source}"\nchecksum = "{"1" * 64}"\n\n'
        '[[package]]\nname = "dev"\nversion = "2.0.0"\n'
        f'source = "{source}"\nchecksum = "{"2" * 64}"\n',
        encoding="utf-8",
    )
    records = generator.target_dependency_records(metadata, manifest, cargo_lock)
    assert records == [
        {
            "checksum": "1" * 64,
            "name": "normal",
            "purl": "pkg:cargo/normal@1.0.0",
            "source": source,
            "version": "1.0.0",
        }
    ]
    assert generator.canonical_json_sha256(records) == canonical_json_sha256(records)


def test_supply_chain_sboms_bind_the_final_deb_and_have_unique_spdx_ids(
    tmp_path: Path,
) -> None:
    supply_chain = load_script("generate_supply_chain.py")
    artifact = tmp_path / f"{PACKAGE}_{VERSION}_{ARCH}.deb"
    artifact.write_bytes(b"final deb bytes")
    prefix = artifact.stem
    rights = tmp_path / f"{prefix}.first-party-rights-approval.json"
    write_json(rights, rights_payload())
    third_party = tmp_path / f"{prefix}.third-party-licenses.json"
    write_json(
        third_party,
        third_party_payload(cargo_lock_sha256=sha256(ROOT / "Cargo.lock")),
    )
    old_argv = sys.argv
    try:
        sys.argv = [
            "generate_supply_chain.py",
            "--cargo-lock",
            str(ROOT / "Cargo.lock"),
            "--cargo-toml",
            str(ROOT / "Cargo.toml"),
            "--license",
            str(ROOT / "LICENSE"),
            "--artifact",
            str(artifact),
            "--rights-approval",
            str(rights),
            "--third-party-licenses",
            str(third_party),
            "--version",
            VERSION,
            "--target",
            "riscv64gc-unknown-linux-gnu",
            "--arch",
            ARCH,
            "--source-commit",
            COMMIT,
            "--source-date-epoch",
            "1786579200",
            "--container-digest",
            f"sha256:{'b' * 64}",
            "--debian-snapshot",
            "20260801T000000Z",
            "--output-dir",
            str(tmp_path),
            "--prefix",
            prefix,
        ]
        supply_chain.main()
    finally:
        sys.argv = old_argv

    spdx_path = tmp_path / f"{prefix}.sbom.spdx.json"
    spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
    package_ids = [item["SPDXID"] for item in spdx["packages"]]
    assert len(package_ids) == len(set(package_ids))
    root = next(item for item in spdx["packages"] if item["name"] == PACKAGE)
    assert root["checksums"] == [
        {"algorithm": "SHA256", "checksumValue": sha256(artifact)}
    ]
    assert spdx_path.read_bytes() == (
        json.dumps(spdx, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    dependency = next(item for item in spdx["packages"] if item["name"] == "dependency")
    assert dependency["licenseConcluded"] == "MIT"
    review = json.loads(
        (tmp_path / f"{prefix}.license-review.json").read_text(encoding="utf-8")
    )
    assert review["review_status"] == "approved"


def make_bundle(
    path: Path,
    version: str = VERSION,
    arch: str = ARCH,
    commit: str = COMMIT,
    resolved: bool = True,
    dependency_count: int = 1,
) -> str:
    prefix = f"{PACKAGE}_{version}_{arch}"
    deb = path / f"{prefix}.deb"
    deb.write_bytes(b"deb payload")
    (path / f"{deb.name}.sha256").write_bytes(
        f"{sha256(deb)}  {deb.name}\n".encode("ascii")
    )
    (path / f"{prefix}.LICENSE").write_text(
        f"MIT License\n\n{COPYRIGHT}\n", encoding="utf-8"
    )
    write_json(
        path / f"{prefix}.component-contract.json",
        {
            "contracts": [{"id": "harboros.k3.gate-v2-transport", "version": 1}],
            "package": PACKAGE,
            "schema_version": 1,
            "source_commit": commit,
        },
    )
    write_json(path / f"{prefix}.first-party-rights-approval.json", rights_payload(commit))
    write_json(
        path / f"{prefix}.k3-runtime-evidence-required.json",
        {"package": PACKAGE, "schema_version": 1, "source_commit": commit},
    )
    third_party = third_party_payload(
        version=version,
        arch=arch,
        resolved=resolved,
        dependency_count=dependency_count,
    )
    third_party_name = f"{prefix}.third-party-licenses.json"
    write_json(path / third_party_name, third_party)
    evidence_dependencies = third_party["dependencies"]
    blockers = third_party["blocking_reasons"]
    review = {
        "architecture": arch,
        "blocking_reasons": blockers,
        "dependencies": [
            {
                "checksum": evidence_dependency["checksum"],
                "concluded_license": evidence_dependency["concluded_license"],
                "copyright": f"See {third_party_name} package-local materials.",
                "declared_license": "MIT",
                "license_material_sha256": [
                    item["sha256"] for item in evidence_dependency["license_materials"]
                ],
                "name": evidence_dependency["name"],
                "review_basis": (
                    "checksum-verified-crate-archive-and-package-local-license-materials"
                ),
                "source": evidence_dependency["source"],
                "status": evidence_dependency["resolution_status"],
                "version": evidence_dependency["version"],
            }
            for evidence_dependency in evidence_dependencies
        ],
        "dependency_summary": third_party["dependency_summary"],
        "first_party_rights": {"status": "approved"},
        "package": PACKAGE,
        "policy": "fail-closed",
        "release_eligible": resolved,
        "review_status": "approved" if resolved else "blocked",
        "root_component": {
            "concluded_license": "MIT",
            "copyright": COPYRIGHT,
            "declared_license": "MIT",
        },
        "schema_version": 1,
        "version": version,
    }
    write_json(path / f"{prefix}.license-review.json", review)
    write_json(
        path / f"{prefix}.provenance.json",
        {
            "_type": "https://in-toto.io/Statement/v1",
            "predicate": {
                "buildDefinition": {
                    "resolvedDependencies": [
                        {
                            "digest": {"gitCommit": commit},
                            "uri": f"git+{SOURCE_REPO}@{commit}",
                        },
                        {
                            "digest": {"sha256": third_party["cargo_lock"]["sha256"]},
                            "uri": "Cargo.lock",
                        },
                        {
                            "digest": {
                                "sha256": canonical_json_sha256(
                                    cargo_dependency_records(evidence_dependencies)
                                )
                            },
                            "uri": "cargo-metadata:resolved-packages",
                        },
                    ]
                }
            },
            "predicateType": "https://slsa.dev/provenance/v1",
            "subject": [{"digest": {"sha256": sha256(deb)}, "name": deb.name}],
        },
    )
    root_id = "SPDXRef-Package-harboros-im-gate"
    write_json(
        path / f"{prefix}.sbom.spdx.json",
        {
            "SPDXID": "SPDXRef-DOCUMENT",
            "packages": [
                {
                    "SPDXID": root_id,
                    "checksums": [
                        {"algorithm": "SHA256", "checksumValue": sha256(deb)}
                    ],
                    "copyrightText": COPYRIGHT,
                    "licenseConcluded": "MIT",
                    "licenseDeclared": "MIT",
                    "name": PACKAGE,
                    "versionInfo": version,
                }
            ]
            + [
                {
                    "SPDXID": f"SPDXRef-{evidence_dependency['name']}",
                    "checksums": [
                        {
                            "algorithm": "SHA256",
                            "checksumValue": evidence_dependency["checksum"],
                        }
                    ],
                    "licenseConcluded": evidence_dependency["concluded_license"],
                    "licenseDeclared": evidence_dependency["concluded_license"],
                    "name": evidence_dependency["name"],
                    "versionInfo": evidence_dependency["version"],
                }
                for evidence_dependency in evidence_dependencies
            ],
            "relationships": [
                {
                    "relatedSpdxElement": root_id,
                    "relationshipType": "DESCRIBES",
                    "spdxElementId": "SPDXRef-DOCUMENT",
                }
            ],
            "spdxVersion": "SPDX-2.3",
        },
    )
    write_json(
        path / f"{prefix}.sbom.cdx.json",
        {
            "bomFormat": "CycloneDX",
            "metadata": {
                "component": {
                    "hashes": [{"alg": "SHA-256", "content": sha256(deb)}],
                    "licenses": [{"expression": "MIT"}],
                    "name": PACKAGE,
                    "properties": [
                        {"name": "harboros:copyright", "value": COPYRIGHT},
                        {"name": "harboros:license-concluded", "value": "MIT"},
                        {"name": "harboros:license-declared", "value": "MIT"},
                    ],
                    "type": "application",
                    "version": version,
                }
            },
            "components": [
                {
                    "hashes": [
                        {
                            "alg": "SHA-256",
                            "content": evidence_dependency["checksum"],
                        }
                    ],
                    **(
                        {
                            "licenses": [
                                {
                                    "expression": evidence_dependency[
                                        "concluded_license"
                                    ]
                                }
                            ]
                        }
                        if evidence_dependency["concluded_license"] != "NOASSERTION"
                        else {}
                    ),
                    "name": evidence_dependency["name"],
                    "type": "library",
                    "version": evidence_dependency["version"],
                }
                for evidence_dependency in evidence_dependencies
            ],
            "specVersion": "1.6",
            "version": 1,
        },
    )

    artifact_members = [
        deb.name,
        f"{deb.name}.sha256",
        f"{prefix}.LICENSE",
        f"{prefix}.component-contract.json",
        f"{prefix}.first-party-rights-approval.json",
        f"{prefix}.k3-runtime-evidence-required.json",
        f"{prefix}.license-review.json",
        f"{prefix}.provenance.json",
        f"{prefix}.sbom.cdx.json",
        f"{prefix}.sbom.spdx.json",
        third_party_name,
    ]
    write_json(
        path / f"{prefix}.artifact-set.json",
        {
            "architecture": arch,
            "artifacts": [
                {"name": name, "sha256": sha256(path / name)}
                for name in artifact_members
            ],
            "package": PACKAGE,
            "schema_version": 1,
            "version": version,
        },
    )
    material_paths = {
        "artifact-set": path / f"{prefix}.artifact-set.json",
        "component-contract": path / f"{prefix}.component-contract.json",
        "deb": deb,
        "deb-sha256": path / f"{deb.name}.sha256",
        "first-party-rights": path / f"{prefix}.first-party-rights-approval.json",
        "k3-runtime-evidence": path / f"{prefix}.k3-runtime-evidence-required.json",
        "license-review": path / f"{prefix}.license-review.json",
        "provenance": path / f"{prefix}.provenance.json",
        "root-license": path / f"{prefix}.LICENSE",
        "sbom-cyclonedx": path / f"{prefix}.sbom.cdx.json",
        "sbom-spdx": path / f"{prefix}.sbom.spdx.json",
        "third-party-licenses": path / third_party_name,
    }
    material_identities = {
        kind: {"filename": item.name, "kind": kind, "sha256": sha256(item)}
        for kind, item in material_paths.items()
    }
    decision = {
        "blocking_reasons": blockers,
        "concluded_license": "MIT",
        "copyright": COPYRIGHT,
        "declared_license": "MIT",
        "policy": "fail-closed",
        "release_eligible": resolved,
        "status": "approved" if resolved else "blocked",
    }
    descriptor = {
        "architecture": arch,
        "artifact": {
            **material_identities["deb"],
            "size": deb.stat().st_size,
        },
        "bindings": [
            material_identities[kind]
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
                **material_identities["component-contract"],
                "installed_path": (
                    "/usr/share/harboros/component-contracts/harboros-im-gate.json"
                ),
            },
            {
                **material_identities["first-party-rights"],
                "installed_path": (
                    "/usr/share/doc/harboros-im-gate/first-party-rights-approval.json"
                ),
            },
            {
                **material_identities["root-license"],
                "installed_path": "/usr/share/doc/harboros-im-gate/copyright",
            },
            {
                **material_identities["third-party-licenses"],
                "installed_path": (
                    "/usr/share/doc/harboros-im-gate/third-party-licenses.json"
                ),
            },
        ],
        "materials": [material_identities[kind] for kind in sorted(material_identities)],
        "package": PACKAGE,
        "schema_version": 1,
        "source": {"commit": commit, "repo": SOURCE_REPO},
        "version": version,
    }
    descriptor_path = path / f"{deb.name}.release-materials.json"
    write_json(descriptor_path, descriptor)
    manifest_entries = {
        descriptor_path.name: sha256(descriptor_path),
        **{item["filename"]: item["sha256"] for item in descriptor["materials"]},
    }
    (path / f"{deb.name}.materials.sha256").write_bytes(
        "".join(
            f"{digest}  {name}\n" for name, digest in sorted(manifest_entries.items())
        ).encode("ascii")
    )
    return prefix


def run_verifier(
    verifier,
    bundle: Path,
    version: str = VERSION,
    require_release_eligible: bool = False,
) -> None:
    old_argv = sys.argv
    try:
        sys.argv = [
            "verify_release_bundle.py",
            str(bundle),
            "--arch",
            ARCH,
            "--version",
            version,
        ]
        if require_release_eligible:
            sys.argv.append("--require-release-eligible")
        verifier.main()
    finally:
        sys.argv = old_argv


def refresh_bundle_indexes(path: Path, prefix: str) -> None:
    artifact_set_path = path / f"{prefix}.artifact-set.json"
    artifact_set = json.loads(artifact_set_path.read_text(encoding="utf-8"))
    for item in artifact_set["artifacts"]:
        item["sha256"] = sha256(path / item["name"])
    write_json(artifact_set_path, artifact_set)

    deb = path / f"{prefix}.deb"
    descriptor_path = path / f"{deb.name}.release-materials.json"
    descriptor = json.loads(descriptor_path.read_text(encoding="utf-8"))
    identities = {}
    for item in descriptor["materials"]:
        item["sha256"] = sha256(path / item["filename"])
        identities[item["kind"]] = item
    descriptor["bindings"] = [
        dict(identities[item["kind"]]) for item in descriptor["bindings"]
    ]
    descriptor["installed_evidence"] = [
        {
            **identities[item["kind"]],
            "installed_path": item["installed_path"],
        }
        for item in descriptor["installed_evidence"]
    ]
    write_json(descriptor_path, descriptor)
    manifest_entries = {
        descriptor_path.name: sha256(descriptor_path),
        **{item["filename"]: item["sha256"] for item in descriptor["materials"]},
    }
    (path / f"{deb.name}.materials.sha256").write_bytes(
        "".join(
            f"{digest}  {name}\n" for name, digest in sorted(manifest_entries.items())
        ).encode("ascii")
    )


def test_bundle_verifier_accepts_exact_canonical_bundle(tmp_path: Path) -> None:
    verifier = load_script("verify_release_bundle.py")
    make_bundle(tmp_path)
    run_verifier(verifier, tmp_path)


def test_bundle_verifier_rejects_synchronized_dependency_deletion_with_fixed_provenance(
    tmp_path: Path,
) -> None:
    verifier = load_script("verify_release_bundle.py")
    prefix = make_bundle(tmp_path, dependency_count=2)

    third_party_path = tmp_path / f"{prefix}.third-party-licenses.json"
    third_party = json.loads(third_party_path.read_text(encoding="utf-8"))
    removed = third_party["dependencies"].pop()
    third_party["dependency_summary"] = {"resolved": 1, "total": 1, "unresolved": 0}
    write_json(third_party_path, third_party)

    review_path = tmp_path / f"{prefix}.license-review.json"
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["dependencies"] = [
        item
        for item in review["dependencies"]
        if (item["name"], item["version"])
        != (removed["name"], removed["version"])
    ]
    review["dependency_summary"] = third_party["dependency_summary"]
    write_json(review_path, review)

    spdx_path = tmp_path / f"{prefix}.sbom.spdx.json"
    spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
    spdx["packages"] = [
        item
        for item in spdx["packages"]
        if (item["name"], item["versionInfo"])
        != (removed["name"], removed["version"])
    ]
    write_json(spdx_path, spdx)

    cdx_path = tmp_path / f"{prefix}.sbom.cdx.json"
    cdx = json.loads(cdx_path.read_text(encoding="utf-8"))
    cdx["components"] = [
        item
        for item in cdx["components"]
        if (item["name"], item["version"])
        != (removed["name"], removed["version"])
    ]
    write_json(cdx_path, cdx)
    refresh_bundle_indexes(tmp_path, prefix)

    with pytest.raises(ValueError, match="target Cargo metadata dependency"):
        run_verifier(verifier, tmp_path)


def test_bundle_verifier_rejects_coordinated_dependency_relabel_with_fixed_provenance(
    tmp_path: Path,
) -> None:
    verifier = load_script("verify_release_bundle.py")
    prefix = make_bundle(tmp_path)
    old_name = "dependency"
    old_version = "1.0.0"
    new_name = "renamed-dependency"
    new_version = "9.9.9"

    third_party_path = tmp_path / f"{prefix}.third-party-licenses.json"
    third_party = json.loads(third_party_path.read_text(encoding="utf-8"))
    dependency = third_party["dependencies"][0]
    dependency["name"] = new_name
    dependency["version"] = new_version
    dependency["cargo_package_id"] = f"{dependency['source']}#{new_name}@{new_version}"
    dependency["archive"]["filename"] = f"{new_name}-{new_version}.crate"
    write_json(third_party_path, third_party)

    review_path = tmp_path / f"{prefix}.license-review.json"
    review = json.loads(review_path.read_text(encoding="utf-8"))
    review["dependencies"][0]["name"] = new_name
    review["dependencies"][0]["version"] = new_version
    write_json(review_path, review)

    spdx_path = tmp_path / f"{prefix}.sbom.spdx.json"
    spdx = json.loads(spdx_path.read_text(encoding="utf-8"))
    spdx_dependency = next(
        item
        for item in spdx["packages"]
        if (item["name"], item["versionInfo"]) == (old_name, old_version)
    )
    spdx_dependency["name"] = new_name
    spdx_dependency["versionInfo"] = new_version
    spdx_dependency["SPDXID"] = f"SPDXRef-{new_name}"
    write_json(spdx_path, spdx)

    cdx_path = tmp_path / f"{prefix}.sbom.cdx.json"
    cdx = json.loads(cdx_path.read_text(encoding="utf-8"))
    cdx["components"][0]["name"] = new_name
    cdx["components"][0]["version"] = new_version
    write_json(cdx_path, cdx)
    refresh_bundle_indexes(tmp_path, prefix)

    with pytest.raises(ValueError, match="target Cargo metadata dependency"):
        run_verifier(verifier, tmp_path)


def test_bundle_verifier_rejects_crate_filename_not_bound_to_dependency_identity(
    tmp_path: Path,
) -> None:
    verifier = load_script("verify_release_bundle.py")
    prefix = make_bundle(tmp_path)
    third_party_path = tmp_path / f"{prefix}.third-party-licenses.json"
    third_party = json.loads(third_party_path.read_text(encoding="utf-8"))
    third_party["dependencies"][0]["archive"]["filename"] = "other-1.0.0.crate"
    write_json(third_party_path, third_party)
    refresh_bundle_indexes(tmp_path, prefix)

    with pytest.raises(ValueError, match="resolved dependency lacks a license decision"):
        run_verifier(verifier, tmp_path)


def test_bundle_verifier_rejects_tampered_deb(tmp_path: Path) -> None:
    verifier = load_script("verify_release_bundle.py")
    prefix = make_bundle(tmp_path)
    (tmp_path / f"{prefix}.deb").write_bytes(b"tampered")
    with pytest.raises(ValueError, match="checksum sidecar"):
        run_verifier(verifier, tmp_path)


def test_bundle_verifier_rejects_unexpected_artifact(tmp_path: Path) -> None:
    verifier = load_script("verify_release_bundle.py")
    make_bundle(tmp_path)
    (tmp_path / "unreviewed.txt").write_text("unexpected", encoding="utf-8")
    with pytest.raises(ValueError, match="file set mismatch"):
        run_verifier(verifier, tmp_path)


def test_bundle_verifier_rejects_tampered_material(tmp_path: Path) -> None:
    verifier = load_script("verify_release_bundle.py")
    prefix = make_bundle(tmp_path)
    (tmp_path / f"{prefix}.first-party-rights-approval.json").write_text(
        "{}\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="release material digest mismatch"):
        run_verifier(verifier, tmp_path)


def test_bundle_verifier_rejects_unsafe_checksum_member(tmp_path: Path) -> None:
    verifier = load_script("verify_release_bundle.py")
    prefix = make_bundle(tmp_path)
    manifest = tmp_path / f"{prefix}.deb.materials.sha256"
    manifest.write_bytes(f"{'0' * 64}  ../{prefix}.deb\n".encode("ascii"))
    with pytest.raises(ValueError, match="unsafe checksum manifest member"):
        run_verifier(verifier, tmp_path)


def test_formal_release_rejects_unresolved_dependency_review(tmp_path: Path) -> None:
    verifier = load_script("verify_release_bundle.py")
    make_bundle(tmp_path, resolved=False)
    with pytest.raises(ValueError, match="license review blocks formal release"):
        run_verifier(verifier, tmp_path, require_release_eligible=True)
