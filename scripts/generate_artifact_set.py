#!/usr/bin/env python3
"""Generate the non-recursive artifact-set index for a Gate release bundle."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--prefix", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--product-profile", choices=["nexus-amd64", "n2-riscv64"], default="n2-riscv64")
    parser.add_argument("--arch", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    runtime_evidence = "nexus-runtime-evidence-required" if args.product_profile == "nexus-amd64" else "k3-runtime-evidence-required"
    names = [
        f"{args.prefix}.deb",
        f"{args.prefix}.deb.sha256",
        f"{args.prefix}.LICENSE",
        f"{args.prefix}.component-contract.json",
        f"{args.prefix}.first-party-rights-approval.json",
        f"{args.prefix}.{runtime_evidence}.json",
        f"{args.prefix}.license-review.json",
        f"{args.prefix}.provenance.json",
        f"{args.prefix}.sbom.cdx.json",
        f"{args.prefix}.sbom.spdx.json",
        f"{args.prefix}.third-party-licenses.json",
    ]
    payload = {
        "schema_version": 1,
        "package": "harboros-im-gate",
        "version": args.version,
        "architecture": args.arch,
        "artifacts": [
            {"name": name, "sha256": sha256(args.bundle / name)} for name in names
        ],
    }
    args.output.write_bytes(
        (
            json.dumps(payload, ensure_ascii=True, indent=2, sort_keys=True) + "\n"
        ).encode("utf-8")
    )


if __name__ == "__main__":
    main()
