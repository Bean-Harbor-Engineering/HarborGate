#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

target="${RUST_TARGET:-riscv64gc-unknown-linux-gnu}"
deb_arch="${DEB_ARCH:-riscv64}"
case "${target}:${deb_arch}" in
  x86_64-unknown-linux-gnu:amd64)
    ;;
  riscv64gc-unknown-linux-gnu:riscv64)
    command -v riscv64-linux-gnu-gcc >/dev/null || {
      echo "error: riscv64-linux-gnu-gcc is required" >&2
      exit 2
    }
    export CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER="${CARGO_TARGET_RISCV64GC_UNKNOWN_LINUX_GNU_LINKER:-riscv64-linux-gnu-gcc}"
    ;;
  *)
    echo "error: unsupported target/deb arch pair: ${target}/${deb_arch}" >&2
    exit 2
    ;;
esac

: "${DEBIAN_VERSION:?DEBIAN_VERSION is required}"
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"
: "${HARBORGATE_BUILD_CONTAINER_DIGEST:?HARBORGATE_BUILD_CONTAINER_DIGEST is required}"
: "${HARBORGATE_DEBIAN_SNAPSHOT:?HARBORGATE_DEBIAN_SNAPSHOT is required}"
[[ "$SOURCE_DATE_EPOCH" =~ ^[0-9]+$ ]] || {
  echo "error: SOURCE_DATE_EPOCH must be a Unix timestamp" >&2
  exit 2
}
dpkg --validate-version "$DEBIAN_VERSION"
[[ "$HARBORGATE_BUILD_CONTAINER_DIGEST" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "error: HARBORGATE_BUILD_CONTAINER_DIGEST must be a sha256 digest" >&2
  exit 2
}
[[ "$HARBORGATE_DEBIAN_SNAPSHOT" =~ ^[0-9]{8}T[0-9]{6}Z$ ]] || {
  echo "error: HARBORGATE_DEBIAN_SNAPSHOT must be an immutable snapshot timestamp" >&2
  exit 2
}

product_profile="${HARBOR_GATE_PRODUCT_PROFILE:-legacy-k3}"
case "$product_profile" in
  legacy-k3)
    package_profile_dir=debian/harbornavi-k3
    component_template=debian/component-contract.json.in
    runtime_template=debian/k3-runtime-evidence-required.json.in
    runtime_evidence=k3-runtime-evidence-required
    data_layout=scripts/ensure-data-layout
    recovery_service=debian/harboros-service-auth-recovery.service
    ;;
  n2-riscv64)
    [[ "${target}:${deb_arch}" == riscv64gc-unknown-linux-gnu:riscv64 ]] || { echo "error: N2 requires riscv64" >&2; exit 2; }
    [[ "$DEBIAN_VERSION" =~ ^0\.2\.0\+n2\.riscv64\.[0-9A-Za-z][0-9A-Za-z.-]*$ ]] || { echo "error: immutable N2 0.2.0 version required" >&2; exit 2; }
    package_profile_dir=debian/n2
    component_template=debian/n2/component-contract.json.in
    runtime_template=debian/n2/runtime-evidence-required.json.in
    runtime_evidence=n2-runtime-evidence-required
    data_layout=scripts/ensure-data-layout
    recovery_service=debian/n2/harboros-service-auth-recovery.service
    ;;
  nexus-amd64)
    [[ "${target}:${deb_arch}" == x86_64-unknown-linux-gnu:amd64 ]] || { echo "error: Nexus requires amd64" >&2; exit 2; }
    [[ "$DEBIAN_VERSION" =~ ^1\.1\.0\+nexus\.amd64\.[0-9A-Za-z][0-9A-Za-z.-]*$ ]] || { echo "error: immutable Nexus version required" >&2; exit 2; }
    package_profile_dir=debian/nexus
    component_template=debian/nexus/component-contract.json.in
    runtime_template=debian/nexus/runtime-evidence-required.json.in
    runtime_evidence=nexus-runtime-evidence-required
    data_layout=debian/nexus/ensure-data-layout
    recovery_service=debian/nexus/harboros-service-auth-recovery.service
    ;;
  *) echo "error: unsupported Gate product profile: $product_profile" >&2; exit 2 ;;
esac

source_commit="${SOURCE_COMMIT:-$(git rev-parse HEAD)}"
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]] || {
  echo "error: SOURCE_COMMIT must be a full lowercase Git commit" >&2
  exit 2
}
[[ "$source_commit" == "$(git rev-parse HEAD)" ]] || {
  echo "error: SOURCE_COMMIT does not match the checked out commit" >&2
  exit 2
}
[[ -z "$(git status --porcelain --untracked-files=normal)" ]] || {
  echo "error: refusing a release package from a dirty worktree" >&2
  exit 2
}

for command_name in cargo dpkg-deb python3 sha256sum touch; do
  command -v "$command_name" >/dev/null || {
    echo "error: ${command_name} is required" >&2
    exit 2
  }
done

out_dir="${OUT_DIR:-${repo_root}/dist/harborgate-debs}"
work_parent="${PACKAGE_WORK_ROOT:-${TMPDIR:-/tmp}}"
mkdir -p "$work_parent" "$out_dir"
build_root="$(mktemp -d "${work_parent%/}/harborgate-deb.XXXXXX")"
trap 'rm -rf -- "$build_root"' EXIT
pkg_dir="${build_root}/root"
cargo_target_dir="${CARGO_TARGET_DIR:-${repo_root}/target}"
artifact_arch="$deb_arch"
if [[ "$product_profile" == nexus-amd64 ]]; then artifact_arch="linux_amd64"; fi
material_prefix="harboros-im-gate_${DEBIAN_VERSION}_${artifact_arch}"
artifact="${out_dir}/${material_prefix}.deb"
if [[ "$product_profile" != legacy-k3 ]] && compgen -G "$out_dir/${material_prefix}*" >/dev/null; then
  echo "error: refusing to replace immutable product release materials" >&2
  exit 73
fi
third_party_material="${out_dir}/${material_prefix}.third-party-licenses.json"

export CARGO_INCREMENTAL=0
export RUSTFLAGS="${RUSTFLAGS:+${RUSTFLAGS} }--remap-path-prefix=${repo_root}=."
cargo build --locked --release --target "$target" --bin harboros-im-gate

install -d \
  "$pkg_dir/DEBIAN" \
  "$pkg_dir/usr/bin" \
  "$pkg_dir/usr/lib/harborgate" \
  "$pkg_dir/usr/lib/harboros-im-gate" \
  "$pkg_dir/usr/lib/systemd/system" \
  "$pkg_dir/usr/share/doc/harboros-im-gate" \
  "$pkg_dir/usr/share/harboros/component-contracts"
install -m 0755 \
  "$cargo_target_dir/$target/release/harboros-im-gate" \
  "$pkg_dir/usr/bin/harboros-im-gate"
install -m 0755 "$data_layout" \
  "$pkg_dir/usr/lib/harborgate/ensure-data-layout"
install -m 0755 debian/ensure-harborbeacon-token-env \
  "$pkg_dir/usr/lib/harboros-im-gate/ensure-harborbeacon-token-env"
if [[ "$product_profile" == nexus-amd64 ]]; then
  install -m 0755 debian/nexus/verify-feishu-audio-runtime "$pkg_dir/usr/lib/harboros-im-gate/verify-feishu-audio-runtime"
fi
install -m 0644 "$recovery_service" \
  "$pkg_dir/usr/lib/systemd/system/harboros-service-auth-recovery.service"
install -m 0644 "$package_profile_dir/harboros-im-gate.service" \
  "$pkg_dir/usr/lib/systemd/system/harboros-im-gate.service"
install -m 0644 LICENSE "$pkg_dir/usr/share/doc/harboros-im-gate/copyright"
if [[ "$product_profile" == n2-riscv64 ]]; then
  install -d "$pkg_dir/usr/share/harboros-im-gate"
  printf '%s\n' "$product_profile" > "$pkg_dir/usr/share/harboros-im-gate/product-profile"
  printf '%s\n' "$source_commit" > "$pkg_dir/usr/share/harboros-im-gate/source-commit"
fi
sed \
  -e "s/VERSION_PLACEHOLDER/${DEBIAN_VERSION}/g" \
  -e "s/ARCH_PLACEHOLDER/${deb_arch}/g" \
  "$package_profile_dir/control" > "$pkg_dir/DEBIAN/control"
sed 's/\r$//' "$package_profile_dir/postinst" > "$pkg_dir/DEBIAN/postinst"
sed 's/\r$//' "$package_profile_dir/prerm" > "$pkg_dir/DEBIAN/prerm"
chmod 0755 "$pkg_dir/DEBIAN/postinst" "$pkg_dir/DEBIAN/prerm"
sed -e "s/SOURCE_COMMIT_PLACEHOLDER/${source_commit}/g" \
  "$component_template" \
  > "$pkg_dir/usr/share/harboros/component-contracts/harboros-im-gate.json"
sed -e "s/SOURCE_COMMIT_PLACEHOLDER/${source_commit}/g" \
  "$runtime_template" \
  > "$pkg_dir/usr/share/doc/harboros-im-gate/${runtime_evidence}.json"
sed -e "s/SOURCE_COMMIT_PLACEHOLDER/${source_commit}/g" \
  debian/first-party-rights-approval.json.in \
  > "$pkg_dir/usr/share/doc/harboros-im-gate/first-party-rights-approval.json"
python3 scripts/generate_third_party_licenses.py \
  --cargo-lock "$repo_root/Cargo.lock" \
  --cargo-toml "$repo_root/Cargo.toml" \
  --target "$target" \
  --arch "$deb_arch" \
  --version "$DEBIAN_VERSION" \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  --output "$third_party_material"
install -m 0644 "$third_party_material" \
  "$pkg_dir/usr/share/doc/harboros-im-gate/third-party-licenses.json"

find "$pkg_dir" -print0 | xargs -0 touch --no-dereference --date="@${SOURCE_DATE_EPOCH}"
SOURCE_DATE_EPOCH="$SOURCE_DATE_EPOCH" dpkg-deb \
  --root-owner-group --build --uniform-compression -Zxz -z9 \
  "$pkg_dir" "$artifact"
if [[ "$product_profile" != legacy-k3 ]]; then
  python3 scripts/verify_product_deb.py "$artifact" --product-profile "$product_profile" --version "$DEBIAN_VERSION"
fi
install -m 0644 \
  "$pkg_dir/usr/share/doc/harboros-im-gate/copyright" \
  "$out_dir/${material_prefix}.LICENSE"
install -m 0644 \
  "$pkg_dir/usr/share/harboros/component-contracts/harboros-im-gate.json" \
  "$out_dir/${material_prefix}.component-contract.json"
install -m 0644 \
  "$pkg_dir/usr/share/doc/harboros-im-gate/first-party-rights-approval.json" \
  "$out_dir/${material_prefix}.first-party-rights-approval.json"
install -m 0644 \
  "$pkg_dir/usr/share/doc/harboros-im-gate/${runtime_evidence}.json" \
  "$out_dir/${material_prefix}.${runtime_evidence}.json"
(
  cd "$out_dir"
  sha256sum "$(basename "$artifact")" > "$(basename "$artifact").sha256"
)
python3 scripts/generate_supply_chain.py \
  --cargo-lock "$repo_root/Cargo.lock" \
  --cargo-toml "$repo_root/Cargo.toml" \
  --license "$repo_root/LICENSE" \
  --artifact "$artifact" \
  --rights-approval "$out_dir/${material_prefix}.first-party-rights-approval.json" \
  --third-party-licenses "$third_party_material" \
  --version "$DEBIAN_VERSION" \
  --target "$target" \
  --arch "$deb_arch" \
  --source-commit "$source_commit" \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  --container-digest "$HARBORGATE_BUILD_CONTAINER_DIGEST" \
  --debian-snapshot "$HARBORGATE_DEBIAN_SNAPSHOT" \
  --output-dir "$out_dir" \
  --prefix "$material_prefix"
python3 scripts/generate_package_provenance.py \
  --artifact "$artifact" \
  --cargo-lock "$repo_root/Cargo.lock" \
  --cargo-toml "$repo_root/Cargo.toml" \
  --third-party-licenses "$third_party_material" \
  --license "$repo_root/LICENSE" \
  --rights-approval "$out_dir/${material_prefix}.first-party-rights-approval.json" \
  --version "$DEBIAN_VERSION" \
  --target "$target" \
  --arch "$deb_arch" \
  --source-commit "$source_commit" \
  --source-date-epoch "$SOURCE_DATE_EPOCH" \
  --container-digest "$HARBORGATE_BUILD_CONTAINER_DIGEST" \
  --debian-snapshot "$HARBORGATE_DEBIAN_SNAPSHOT" \
  --output "$out_dir/${material_prefix}.provenance.json"
python3 scripts/generate_artifact_set.py \
  --bundle "$out_dir" \
  --prefix "$material_prefix" \
  --version "$DEBIAN_VERSION" \
  --arch "$deb_arch" \
  --product-profile "$product_profile" \
  --output "$out_dir/${material_prefix}.artifact-set.json"
python3 scripts/generate_release_materials.py \
  --artifact "$artifact" \
  --version "$DEBIAN_VERSION" \
  --architecture "$deb_arch" \
  --product-profile "$product_profile" \
  --source-commit "$source_commit" \
  --output-dir "$out_dir"
touch --date="@${SOURCE_DATE_EPOCH}" "$out_dir/${material_prefix}."*
(
  cd "$out_dir"
  python3 "$repo_root/scripts/verify_release_bundle.py" \
    . --arch "$deb_arch" --version "$DEBIAN_VERSION" --product-profile "$product_profile"
)

printf '%s\n' "$artifact"
