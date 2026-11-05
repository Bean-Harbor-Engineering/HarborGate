# Nexus HarborGate formal release

Nexus uses the real formal HarborGate mainline plus the Feishu voice/media,
message replay, processing acknowledgement and neutral model-card extensions.
The service retains v3 northbound gateway turns, v2 Beacon service calls,
directional service credentials and the formal persistent delivery ledger.
Demo edge proxies and temporary actor grants are excluded.

Select `HARBOR_GATE_PRODUCT_PROFILE=nexus-amd64` and an immutable
`1.1.0+nexus.amd64.<build>` version. Run
`scripts/build_harborgate_product_deb.sh` with a clean full source commit,
`SOURCE_DATE_EPOCH`, the pinned container digest and Debian snapshot.
The output is `harboros-im-gate_<version>_linux_amd64.deb` with checksum,
component contract, SBOM, license evidence and provenance bound to that commit.
The release workflow accepts the exact source SHA and produces a draft.
N2 retains its existing riscv64 unit, Home bootstrap and data layout.

The Nexus unit persists state under `/var/lib/harboros-im-gate`, binds loopback,
and loads the directional service credentials. It depends on the existing
`harboros-ffmpeg (>= 1.0.0)` package; a bounded libopus preflight blocks service
startup when voice conversion cannot work. The package contains no credentials.
Offline image assembly uses `SYSTEMD_OFFLINE=1` to defer credential generation;
the image assembler must reject any staged live service credential files. At
first boot the Nexus recovery unit runs the unchanged transactional `prepare`
then `recover` helper, preserving keys on later restarts and upgrades.

All Nexus browser proxy requests except public health require a real HarborOS
one-time token and verified administrator. Caller principal/workspace headers
are discarded and replaced by authenticated identity and configured workspace.
Native Connections settings call protected Gate setup APIs; standalone Nexus
setup pages direct users back to Harbor Assistant. Standard/N2 LAN behavior is
preserved.

Validation: Rust all-target tests and Clippy, audited supply-chain/profile tests,
real ffmpeg voice conversion against a local provider fixture, real ELF/GLIBC
inspection, checksum/license verification and a disposable-container package
lifecycle including offline install, first-boot generation, reinstall and removal.
Device acceptance still requires the actual Nexus/Feishu client; package tests
do not send messages or mutate a production NAS.
