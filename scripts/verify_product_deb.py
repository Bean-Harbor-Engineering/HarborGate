#!/usr/bin/env python3
"""Verify the package lane and real ELF before a product artifact is promoted."""
from __future__ import annotations
import argparse
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile


def verify(artifact: Path, product_profile: str, version: str) -> None:
    arch = "amd64" if product_profile == "nexus-amd64" else "riscv64"
    artifact_arch = "linux_amd64" if product_profile == "nexus-amd64" else arch
    if artifact.name != f"harboros-im-gate_{version}_{artifact_arch}.deb":
        raise ValueError("artifact filename differs from the requested product")
    for field, expected in [("Package", "harboros-im-gate"), ("Architecture", arch), ("Version", version), ("Provides", "harboros-service-auth-abi (= 1)")]:
        actual = subprocess.check_output(["dpkg-deb", "--field", str(artifact), field], text=True).strip()
        if actual != expected:
            raise ValueError(f"{field} differs from the requested product")
    with tempfile.TemporaryDirectory(prefix="gate-profile-") as directory:
        root = Path(directory)
        subprocess.run(["dpkg-deb", "--extract", str(artifact), directory], check=True)
        binary = root / "usr/bin/harboros-im-gate"
        header = binary.read_bytes()[:64]
        machine = 62 if arch == "amd64" else 243
        if len(header) != 64 or header[:6] != b"\x7fELF\x02\x01" or struct.unpack_from("<H", header, 18)[0] != machine:
            raise ValueError("package does not contain the expected Linux ELF64 binary")
        version_info = subprocess.check_output(["readelf", "--version-info", str(binary)], text=True)
        glibc = [tuple(map(int, item.split("."))) for item in re.findall(r"GLIBC_([0-9]+\.[0-9]+)", version_info)]
        if glibc and max(glibc) > (2, 36):
            raise ValueError("binary requires GLIBC newer than the pinned Bookworm build image")
        forbidden = [root / "etc/harboros/service-auth", root / "etc/default/harboros-beacon-gate"]
        if any(path.exists() or path.is_symlink() for path in forbidden):
            raise ValueError("release package contains per-device service credentials")
        service = (root / "usr/lib/systemd/system/harboros-im-gate.service").read_text()
        contract = json.loads((root / "usr/share/harboros/component-contracts/harboros-im-gate.json").read_text())
        if "LoadCredential=gate-to-beacon-send:" not in service or "Environment=IM_AGENT_HOST=127.0.0.1" not in service:
            raise ValueError("package lost service credentials or loopback binding")
        depends = subprocess.check_output(["dpkg-deb", "--field", str(artifact), "Depends"], text=True)
        if product_profile == "nexus-amd64":
            if contract.get("product_profile") != product_profile or "Environment=HARBORGATE_RUNTIME_PROFILE=nexus" not in service:
                raise ValueError("Nexus package uses the wrong product contract or unit")
            if any(value in service for value in ["/data/harborgate", "harboros-bootstrap", "/run/harboros/home.env", "4176"]):
                raise ValueError("Nexus unit contains an N2 bootstrap or demo edge dependency")
            if "harboros-system" in depends or "harboros-ffmpeg (>= 1.0.0)" not in depends:
                raise ValueError("Nexus package dependency lane is incorrect")
            if "StateDirectory=harboros-im-gate" not in service:
                raise ValueError("Nexus unit does not own its writable state")
        elif "Environment=HARBORGATE_RUNTIME_PROFILE=k3" not in service or "harboros-system" not in depends:
            raise ValueError("N2 package lost its Home bootstrap contract")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("artifact", type=Path)
    parser.add_argument("--product-profile", choices=["nexus-amd64", "n2-riscv64"], required=True)
    parser.add_argument("--version", required=True)
    args = parser.parse_args()
    verify(args.artifact, args.product_profile, args.version)
    print(f"Verified {args.product_profile}: {args.artifact.name}")


if __name__ == "__main__":
    main()
