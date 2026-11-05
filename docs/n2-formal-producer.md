# N2 formal producer and credential migration

The explicit `n2-riscv64` product package uses the existing strict `k3` runtime ABI (Home identity, `/data/harborgate`, bootstrap ordering), with a separate N2 unit, source-bound component contract and activation receipt. The historical K3 producer defaults to `legacy-k3` and retains its old unit and material filenames. It does not activate N2 migration.

Build a clean, fully pinned source with the existing pinned Rust 1.96.1 Bookworm toolchain and RISC-V cross linker:

```sh
export HARBOR_GATE_PRODUCT_PROFILE=n2-riscv64
export DEBIAN_VERSION=0.2.0+n2.riscv64.<unique-build>
export SOURCE_COMMIT=<full-40-character-commit>
export SOURCE_DATE_EPOCH=$(git show -s --format=%ct HEAD)
export HARBORGATE_BUILD_CONTAINER_DIGEST=sha256:a339861ae23e9abb272cea45dfafde21760d2ce6577a70f8a926153677902663
export HARBORGATE_DEBIAN_SNAPSHOT=20260801T000000Z
bash scripts/build_harborgate_product_deb.sh
```

The filename remains `harboros-im-gate_${DEBIAN_VERSION}_riscv64.deb`. The producer refuses an existing version's materials, cross-product versions/architectures, dirty source and mismatched source commits. Manual release dispatch checks the paginated release inventory including tagless drafts. The N2 component contract remains `internal_candidate`, `release_eligible=false`: actual RISC-V execution, dependency/runtime ABI closure and physical install/upgrade/rollback acceptance are still pending.

Gate is the single writer for the six-file service-auth ABI. New N2 packages depend on `harboros-n2-service-auth-abi (= 1)` from System Domain. Its first-boot adapter invokes `ensure-harborbeacon-token-env migrate-n2`, then projects the canonical senders into the legacy compatibility env while holding the same writer lock. Both Gate and Beacon consume canonical `LoadCredential` paths.

The migration parses `/data/harboros/secrets/beacon-gate.env` strictly as data. It imports a validated legacy pair unchanged, preserves matching four-file credentials, adds only missing empty previous slots, and resumes safely after interruption. A blank generic image carrying just two empty previous slots is supported transactionally. Canonical/legacy disagreement, unsafe metadata, unknown partial active state or malformed aliases fail closed without generating replacement tokens. No token values are printed. Ordinary prepare/switch/finalize/rollback behavior remains unchanged.

`SYSTEMD_OFFLINE=1` package configuration skips all credential creation. N2 first boot runs System Domain bootstrap and the N2 adapter before canonical recovery, then starts consumers. Existing private state is retained on upgrade and removal. Packages contain no per-device secrets, models or customer state. Tests use disposable filesystem roots and containers; they establish migration/source plumbing, not board qualification.
