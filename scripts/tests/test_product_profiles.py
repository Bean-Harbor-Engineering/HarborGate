"""Product lane regressions, complemented by verify_product_deb on real release ELF."""
from pathlib import Path
import importlib.util
import json
import re
import shutil
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[2]


def test_nexus_unit_and_dependency_lane_do_not_inherit_n2_bootstrap():
    unit=(ROOT/"debian/nexus/harboros-im-gate.service").read_text()
    control=(ROOT/"debian/nexus/control").read_text()
    assert "HARBORGATE_RUNTIME_PROFILE=nexus" in unit
    assert "StateDirectory=harboros-im-gate" in unit
    assert "ExecStartPre=/usr/lib/harboros-im-gate/verify-feishu-audio-runtime" in unit
    assert "LoadCredential=gate-to-beacon-send:" in unit
    assert "IM_AGENT_STATE_DIR=/var/lib/harboros-im-gate" in unit
    assert not any(value in unit for value in ["/data/harborgate", "harboros-bootstrap", "/run/harboros/home.env", "4176"])
    assert "harboros-system" not in control
    assert "harboros-ffmpeg (>= 1.0.0)" in control
    contract=json.loads((ROOT/"debian/nexus/component-contract.json.in").read_text())
    assert contract["product_profile"]=="nexus-amd64"
    assert contract["contracts"][0]["id"]=="harboros.nexus.gate-v2-transport"
    assert not any("riscv64" in c for c in contract["contracts"][0]["capabilities"])


def test_n2_unit_and_contract_keep_their_existing_home_authority():
    unit=(ROOT/"debian/harbornavi-k3/harboros-im-gate.service").read_text()
    assert "HARBORGATE_RUNTIME_PROFILE=k3" in unit
    assert "Requires=harboros-bootstrap.service" in unit
    assert "EnvironmentFile=/run/harboros/home.env" in unit
    contract=json.loads((ROOT/"debian/component-contract.json.in").read_text())
    assert contract["contracts"][0]["id"]=="harboros.k3.gate-v2-transport"


def test_release_is_manual_source_pinned_and_draft():
    workflow=(ROOT/".github/workflows/release.yml").read_text()
    assert "workflow_dispatch:" in workflow
    assert "source_commit:" in workflow
    assert "draft: true" in workflow
    assert "target_commitish: ${{ inputs.source_commit }}" in workflow
    assert "--require-release-eligible" in workflow
    assert "--product-profile" in workflow
    assert "refs/tags/v$DEBIAN_VERSION" in workflow
    assert "1.1.0+nexus.amd64" in workflow


@pytest.mark.skipif(not shutil.which("bash"), reason="requires bash")
def test_product_builder_refuses_an_unknown_profile_before_build(tmp_path):
    env=dict(__import__("os").environ,HARBOR_GATE_PRODUCT_PROFILE="wrong-lane")
    result=subprocess.run(["bash",str(ROOT/"scripts/build_harborgate_product_deb.sh")],env=env,capture_output=True,text=True)
    assert result.returncode != 0
    assert "unsupported Gate product profile" in result.stderr


@pytest.mark.skipif(not shutil.which("bash"), reason="requires bash")
def test_nexus_voice_preflight_fails_when_ffmpeg_is_missing():
    env=dict(__import__("os").environ,HARBORGATE_FFMPEG_BIN="/not-installed/ffmpeg")
    result=subprocess.run(["bash",str(ROOT/"debian/nexus/verify-feishu-audio-runtime")],env=env,capture_output=True,text=True)
    assert result.returncode != 0
    assert "libopus encoder" in result.stderr
