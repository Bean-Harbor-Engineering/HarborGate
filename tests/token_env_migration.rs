#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use tempfile::TempDir;

// The production writer is root-only. CI runs ignored tests in this target via sudo.
const LEGACY_TOKEN: &str = "legacy_shared_token_0123456789abcdef0123456789abcdef";
const G2B_LEGACY_TOKEN: &str = "legacy_gate_to_beacon_0123456789abcdef0123456789";
const B2G_LEGACY_TOKEN: &str = "legacy_beacon_to_gate_0123456789abcdef0123456789";
const UNRELATED_TOKEN: &str = "unrelated_previous_0123456789abcdef0123456789ab";
const CREDENTIALS: [&str; 6] = [
    "gate-to-beacon.send",
    "gate-to-beacon.accept-current",
    "gate-to-beacon.accept-previous",
    "beacon-to-gate.send",
    "beacon-to-gate.accept-current",
    "beacon-to-gate.accept-previous",
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .canonicalize()
        .expect("repo root should resolve")
}

fn writer_command(
    mode: &str,
    auth_dir: &Path,
    legacy_env: &Path,
    failpoint: Option<&str>,
) -> Command {
    let mut command = Command::new("bash");
    command
        .arg(repo_root().join("debian/ensure-harborbeacon-token-env"))
        .arg(mode)
        .env("HARBOR_SERVICE_AUTH_DIR", auth_dir)
        .env("HARBOR_LEGACY_SHARED_ENV_FILE", legacy_env);
    if let Some(failpoint) = failpoint {
        command.env("HARBOR_SERVICE_AUTH_FAILPOINT", failpoint);
    }
    command
}

fn run_writer(mode: &str, auth_dir: &Path, legacy_env: &Path, failpoint: Option<&str>) -> Output {
    writer_command(mode, auth_dir, legacy_env, failpoint)
        .output()
        .expect("service-auth writer should execute")
}

fn credential(auth_dir: &Path, name: &str) -> String {
    fs::read_to_string(auth_dir.join(name))
        .expect("credential should exist")
        .trim()
        .to_string()
}

fn snapshot(auth_dir: &Path) -> BTreeMap<String, Vec<u8>> {
    CREDENTIALS
        .into_iter()
        .map(|name| {
            (
                name.to_string(),
                fs::read(auth_dir.join(name)).expect("credential should exist"),
            )
        })
        .collect()
}

fn assert_success_without_secret_output(output: &Output, secrets: &[&str]) {
    assert!(
        output.status.success(),
        "writer failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_no_secret_output(output, secrets);
}

fn assert_no_secret_output(output: &Output, secrets: &[&str]) {
    let combined = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    for secret in secrets {
        assert!(!combined.contains(secret), "writer leaked a token");
    }
}

fn assert_root_metadata(path: &Path, expected_mode: u32) {
    let metadata = fs::symlink_metadata(path).expect("secured path should exist");
    assert_eq!(metadata.uid(), 0, "{} is not owned by root", path.display());
    assert_eq!(metadata.gid(), 0, "{} is not in group root", path.display());
    assert_eq!(
        metadata.permissions().mode() & 0o7777,
        expected_mode,
        "{} has the wrong mode",
        path.display()
    );
}

fn initialized_fixture() -> (TempDir, PathBuf, PathBuf) {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("missing-legacy-env");
    assert_success_without_secret_output(&run_writer("prepare", &auth_dir, &legacy_env, None), &[]);
    (temp, auth_dir, legacy_env)
}

fn finalized_legacy_fixture() -> (TempDir, PathBuf, PathBuf, String, String) {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    write_legacy_env(
        &legacy_env,
        format!(
            "HARBOR_GATE_TO_BEACON_TOKEN={G2B_LEGACY_TOKEN}\nHARBOR_BEACON_TO_GATE_TOKEN={B2G_LEGACY_TOKEN}\n"
        ),
    )
    .unwrap();
    assert_success_without_secret_output(
        &run_writer("prepare", &auth_dir, &legacy_env, None),
        &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN],
    );
    let g2b_current = credential(&auth_dir, "gate-to-beacon.accept-current");
    let b2g_current = credential(&auth_dir, "beacon-to-gate.accept-current");
    assert_success_without_secret_output(
        &run_writer("switch", &auth_dir, &legacy_env, None),
        &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN],
    );
    assert_success_without_secret_output(
        &run_writer("finalize", &auth_dir, &legacy_env, None),
        &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN],
    );
    (temp, auth_dir, legacy_env, g2b_current, b2g_current)
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

fn write_legacy_env(path: &Path, contents: impl AsRef<[u8]>) -> std::io::Result<()> {
    fs::write(path, contents)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
}

fn set_owner(path: &Path, uid: u32, gid: u32) {
    let status = Command::new("chown")
        .arg(format!("{uid}:{gid}"))
        .arg(path)
        .status()
        .expect("chown should execute");
    assert!(status.success(), "chown failed for {}", path.display());
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn fresh_install_creates_distinct_directional_credentials() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("etc/harboros/service-auth");
    let legacy_env = temp.path().join("missing-legacy-env");

    let output = run_writer("prepare", &auth_dir, &legacy_env, None);

    assert_success_without_secret_output(&output, &[]);
    let g2b = credential(&auth_dir, "gate-to-beacon.accept-current");
    let b2g = credential(&auth_dir, "beacon-to-gate.accept-current");
    assert!(g2b.len() >= 48);
    assert!(b2g.len() >= 48);
    assert_ne!(g2b, b2g);
    assert_eq!(credential(&auth_dir, "gate-to-beacon.send"), g2b);
    assert_eq!(credential(&auth_dir, "beacon-to-gate.send"), b2g);
    assert!(credential(&auth_dir, "gate-to-beacon.accept-previous").is_empty());
    assert!(credential(&auth_dir, "beacon-to-gate.accept-previous").is_empty());
    assert_root_metadata(&auth_dir, 0o700);
    assert_root_metadata(&auth_dir.join(".credential-writer.lock"), 0o600);
    for name in CREDENTIALS {
        assert_root_metadata(&auth_dir.join(name), 0o600);
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn legacy_upgrade_uses_prepare_switch_finalize_without_downtime_gap() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    let legacy = format!(
        "HARBOR_TASK_API_BEARER_TOKEN={LEGACY_TOKEN}\nHARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
    );
    write_legacy_env(&legacy_env, &legacy).unwrap();

    let prepare = run_writer("prepare", &auth_dir, &legacy_env, None);
    assert_success_without_secret_output(&prepare, &[LEGACY_TOKEN]);
    let g2b_current = credential(&auth_dir, "gate-to-beacon.accept-current");
    let b2g_current = credential(&auth_dir, "beacon-to-gate.accept-current");
    assert_ne!(g2b_current, b2g_current);
    assert_ne!(g2b_current, LEGACY_TOKEN);
    assert_ne!(b2g_current, LEGACY_TOKEN);
    assert_eq!(credential(&auth_dir, "gate-to-beacon.send"), LEGACY_TOKEN);
    assert_eq!(credential(&auth_dir, "beacon-to-gate.send"), LEGACY_TOKEN);
    assert_eq!(
        credential(&auth_dir, "gate-to-beacon.accept-previous"),
        LEGACY_TOKEN
    );
    assert_eq!(
        credential(&auth_dir, "beacon-to-gate.accept-previous"),
        LEGACY_TOKEN
    );
    assert_eq!(fs::read_to_string(&legacy_env).unwrap(), legacy);

    let switch = run_writer("switch", &auth_dir, &legacy_env, None);
    assert_success_without_secret_output(&switch, &[LEGACY_TOKEN]);
    assert_eq!(credential(&auth_dir, "gate-to-beacon.send"), g2b_current);
    assert_eq!(credential(&auth_dir, "beacon-to-gate.send"), b2g_current);
    assert_eq!(
        credential(&auth_dir, "gate-to-beacon.accept-previous"),
        LEGACY_TOKEN
    );

    let finalize = run_writer("finalize", &auth_dir, &legacy_env, None);
    assert_success_without_secret_output(&finalize, &[LEGACY_TOKEN]);
    assert!(credential(&auth_dir, "gate-to-beacon.accept-previous").is_empty());
    assert!(credential(&auth_dir, "beacon-to-gate.accept-previous").is_empty());
    assert_eq!(fs::read_to_string(&legacy_env).unwrap(), legacy);

    let rollback = run_writer("rollback", &auth_dir, &legacy_env, None);
    assert_success_without_secret_output(&rollback, &[LEGACY_TOKEN]);
    assert_eq!(credential(&auth_dir, "gate-to-beacon.send"), LEGACY_TOKEN);
    assert_eq!(credential(&auth_dir, "beacon-to-gate.send"), LEGACY_TOKEN);
    assert_eq!(
        credential(&auth_dir, "gate-to-beacon.accept-previous"),
        LEGACY_TOKEN
    );
    assert_eq!(
        credential(&auth_dir, "beacon-to-gate.accept-previous"),
        LEGACY_TOKEN
    );
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn rollback_after_finalize_restores_legacy_senders_and_previous() {
    let (_temp, auth_dir, legacy_env, g2b_current, b2g_current) = finalized_legacy_fixture();

    let rollback = run_writer("rollback", &auth_dir, &legacy_env, None);

    assert_success_without_secret_output(&rollback, &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN]);
    assert_eq!(
        credential(&auth_dir, "gate-to-beacon.accept-current"),
        g2b_current
    );
    assert_eq!(
        credential(&auth_dir, "beacon-to-gate.accept-current"),
        b2g_current
    );
    assert_eq!(
        credential(&auth_dir, "gate-to-beacon.send"),
        G2B_LEGACY_TOKEN
    );
    assert_eq!(
        credential(&auth_dir, "gate-to-beacon.accept-previous"),
        G2B_LEGACY_TOKEN
    );
    assert_eq!(
        credential(&auth_dir, "beacon-to-gate.send"),
        B2G_LEGACY_TOKEN
    );
    assert_eq!(
        credential(&auth_dir, "beacon-to-gate.accept-previous"),
        B2G_LEGACY_TOKEN
    );
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn repeated_rollback_is_idempotent_and_can_switch_forward_again() {
    let (_temp, auth_dir, legacy_env, g2b_current, b2g_current) = finalized_legacy_fixture();
    assert_success_without_secret_output(
        &run_writer("rollback", &auth_dir, &legacy_env, None),
        &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN],
    );
    let rolled_back = snapshot(&auth_dir);

    assert_success_without_secret_output(
        &run_writer("rollback", &auth_dir, &legacy_env, None),
        &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN],
    );
    assert_eq!(snapshot(&auth_dir), rolled_back);

    assert_success_without_secret_output(
        &run_writer("switch", &auth_dir, &legacy_env, None),
        &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN],
    );
    assert_eq!(credential(&auth_dir, "gate-to-beacon.send"), g2b_current);
    assert_eq!(credential(&auth_dir, "beacon-to-gate.send"), b2g_current);
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn rollback_failpoint_and_sigkill_restore_the_finalized_snapshot() {
    for failpoint in ["after_rename_3", "after_rename_3_sigkill"] {
        let (_temp, auth_dir, legacy_env, _g2b_current, _b2g_current) = finalized_legacy_fixture();
        let finalized = snapshot(&auth_dir);

        let interrupted = run_writer("rollback", &auth_dir, &legacy_env, Some(failpoint));

        assert!(
            !interrupted.status.success(),
            "failpoint succeeded: {failpoint}"
        );
        assert_no_secret_output(&interrupted, &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN]);
        let recovery = run_writer("recover", &auth_dir, &legacy_env, None);
        assert_success_without_secret_output(&recovery, &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN]);
        assert_eq!(snapshot(&auth_dir), finalized);
        assert!(!auth_dir.join(".credential-transaction").exists());
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn concurrent_rollback_writers_are_serialized() {
    let (_temp, auth_dir, legacy_env, g2b_current, b2g_current) = finalized_legacy_fixture();
    let mut children = (0..8)
        .map(|_| {
            writer_command("rollback", &auth_dir, &legacy_env, None)
                .spawn()
                .expect("concurrent rollback writer should start")
        })
        .collect::<Vec<_>>();

    for child in &mut children {
        let status = child
            .wait()
            .expect("concurrent rollback writer should finish");
        assert!(
            status.success(),
            "concurrent rollback writer failed: {status}"
        );
    }

    assert_eq!(
        credential(&auth_dir, "gate-to-beacon.accept-current"),
        g2b_current
    );
    assert_eq!(
        credential(&auth_dir, "beacon-to-gate.accept-current"),
        b2g_current
    );
    assert_eq!(
        credential(&auth_dir, "gate-to-beacon.send"),
        G2B_LEGACY_TOKEN
    );
    assert_eq!(
        credential(&auth_dir, "beacon-to-gate.send"),
        B2G_LEGACY_TOKEN
    );
    assert!(!auth_dir.join(".credential-transaction").exists());
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn rollback_requires_complete_secure_legacy_credentials() {
    use std::os::unix::fs::symlink;

    for unsafe_kind in [
        "missing-file",
        "missing-direction",
        "invalid",
        "readable",
        "owner",
        "symlink",
    ] {
        let (temp, auth_dir, legacy_env, _g2b_current, _b2g_current) = finalized_legacy_fixture();
        let finalized = snapshot(&auth_dir);
        let protected = temp.path().join("protected-legacy");
        match unsafe_kind {
            "missing-file" => fs::remove_file(&legacy_env).unwrap(),
            "missing-direction" => {
                write_legacy_env(
                    &legacy_env,
                    format!("HARBOR_GATE_TO_BEACON_TOKEN={G2B_LEGACY_TOKEN}\n"),
                )
                .unwrap();
            }
            "invalid" => {
                write_legacy_env(
                    &legacy_env,
                    format!(
                        "HARBOR_GATE_TO_BEACON_TOKEN={G2B_LEGACY_TOKEN}\nHARBOR_BEACON_TO_GATE_TOKEN=too-short\n"
                    ),
                )
                .unwrap();
            }
            "readable" => set_mode(&legacy_env, 0o644),
            "owner" => set_owner(&legacy_env, 65534, 65534),
            "symlink" => {
                fs::rename(&legacy_env, &protected).unwrap();
                symlink(&protected, &legacy_env).unwrap();
            }
            _ => unreachable!(),
        }

        let output = run_writer("rollback", &auth_dir, &legacy_env, None);

        assert!(
            !output.status.success(),
            "rollback accepted {unsafe_kind} legacy input"
        );
        assert_no_secret_output(&output, &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN, "too-short"]);
        assert_eq!(snapshot(&auth_dir), finalized);
        assert!(!auth_dir.join(".credential-transaction").exists());
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn legacy_upgrade_parses_quoted_and_unquoted_environment_values() {
    let cases = [
        (G2B_LEGACY_TOKEN.to_string(), B2G_LEGACY_TOKEN.to_string()),
        (
            format!("\"{G2B_LEGACY_TOKEN}\""),
            format!("'{B2G_LEGACY_TOKEN}'"),
        ),
    ];

    for (g2b_assignment, b2g_assignment) in cases {
        let temp = TempDir::new().unwrap();
        let auth_dir = temp.path().join("service-auth");
        let legacy_env = temp.path().join("harboros-beacon-gate");
        write_legacy_env(
            &legacy_env,
            format!(
                "  HARBORBEACON_WEB_API_TOKEN = {g2b_assignment}  \nIM_AGENT_SERVICE_TOKEN={b2g_assignment}\n"
            ),
        )
        .unwrap();

        let output = run_writer("prepare", &auth_dir, &legacy_env, None);

        assert_success_without_secret_output(&output, &[G2B_LEGACY_TOKEN, B2G_LEGACY_TOKEN]);
        assert_eq!(
            credential(&auth_dir, "gate-to-beacon.send"),
            G2B_LEGACY_TOKEN
        );
        assert_eq!(
            credential(&auth_dir, "beacon-to-gate.send"),
            B2G_LEGACY_TOKEN
        );
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn invalid_known_legacy_assignment_fails_without_generating_credentials() {
    let invalid_assignments = [
        "HARBORBEACON_WEB_API_TOKEN=too-short\n",
        "HARBORBEACON_WEB_API_TOKEN=\"unterminated_token_0123456789abcdef0123456789\n",
        "HARBORBEACON_WEB_API_TOKEN malformed_token_0123456789abcdef0123456789\n",
    ];

    for assignment in invalid_assignments {
        let temp = TempDir::new().unwrap();
        let auth_dir = temp.path().join("service-auth");
        let legacy_env = temp.path().join("harboros-beacon-gate");
        write_legacy_env(&legacy_env, assignment).unwrap();

        let output = run_writer("prepare", &auth_dir, &legacy_env, None);

        assert!(!output.status.success());
        assert!(CREDENTIALS.iter().all(|name| !auth_dir.join(name).exists()));
        assert!(!auth_dir.join(".credential-transaction").exists());
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn unsafe_legacy_environment_file_fails_before_generating_credentials() {
    use std::os::unix::fs::symlink;

    for unsafe_kind in ["symlink", "readable", "writable", "owner"] {
        let temp = TempDir::new().unwrap();
        let auth_dir = temp.path().join("service-auth");
        let protected = temp.path().join("legacy-source");
        fs::write(
            &protected,
            format!("HARBORBEACON_WEB_API_TOKEN={G2B_LEGACY_TOKEN}\n"),
        )
        .unwrap();
        let legacy_env = temp.path().join("harboros-beacon-gate");
        match unsafe_kind {
            "symlink" => symlink(&protected, &legacy_env).unwrap(),
            "writable" => {
                fs::copy(&protected, &legacy_env).unwrap();
                set_mode(&legacy_env, 0o666);
            }
            "readable" => {
                fs::copy(&protected, &legacy_env).unwrap();
                set_mode(&legacy_env, 0o644);
            }
            "owner" => {
                fs::copy(&protected, &legacy_env).unwrap();
                set_mode(&legacy_env, 0o600);
                set_owner(&legacy_env, 65534, 65534);
            }
            _ => unreachable!(),
        }

        let output = run_writer("prepare", &auth_dir, &legacy_env, None);

        assert!(
            !output.status.success(),
            "accepted {unsafe_kind} legacy input"
        );
        assert_no_secret_output(&output, &[G2B_LEGACY_TOKEN]);
        assert!(CREDENTIALS.iter().all(|name| !auth_dir.join(name).exists()));
        assert!(!auth_dir.join(".credential-transaction").exists());
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn repeated_prepare_is_idempotent() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("missing-legacy-env");
    assert_success_without_secret_output(&run_writer("prepare", &auth_dir, &legacy_env, None), &[]);
    let first = snapshot(&auth_dir);

    assert_success_without_secret_output(&run_writer("prepare", &auth_dir, &legacy_env, None), &[]);

    assert_eq!(snapshot(&auth_dir), first);
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn recover_mode_never_initializes_or_rotates_credentials() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("missing-legacy-env");

    let uninitialized = run_writer("recover", &auth_dir, &legacy_env, None);
    assert!(!uninitialized.status.success());
    assert!(CREDENTIALS.iter().all(|name| !auth_dir.join(name).exists()));

    assert_success_without_secret_output(&run_writer("prepare", &auth_dir, &legacy_env, None), &[]);
    let before = snapshot(&auth_dir);
    assert_success_without_secret_output(&run_writer("recover", &auth_dir, &legacy_env, None), &[]);
    assert_eq!(snapshot(&auth_dir), before);
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn multiline_credential_file_fails_closed_for_every_phase() {
    let (_temp, auth_dir, legacy_env) = initialized_fixture();
    let target = auth_dir.join("beacon-to-gate.accept-current");
    let original = fs::read(&target).unwrap();

    for mode in ["prepare", "recover", "switch", "finalize", "rollback"] {
        let mut malformed = original.clone();
        malformed.extend_from_slice(b"second-line-without-final-newline");
        fs::write(&target, malformed).unwrap();
        set_mode(&target, 0o600);

        let output = run_writer(mode, &auth_dir, &legacy_env, None);

        assert!(
            !output.status.success(),
            "{mode} accepted a multiline credential"
        );
        assert!(!auth_dir.join(".credential-transaction").exists());
        fs::write(&target, &original).unwrap();
        set_mode(&target, 0o600);
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn multiline_transaction_state_fails_closed_and_preserves_the_journal() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    write_legacy_env(
        &legacy_env,
        format!(
            "HARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
        ),
    )
    .unwrap();
    assert_success_without_secret_output(
        &run_writer("prepare", &auth_dir, &legacy_env, None),
        &[LEGACY_TOKEN],
    );
    let interrupted = run_writer(
        "switch",
        &auth_dir,
        &legacy_env,
        Some("after_rename_3_sigkill"),
    );
    assert!(!interrupted.status.success());
    let interrupted_snapshot = snapshot(&auth_dir);
    let transaction = auth_dir.join(".credential-transaction");
    let state = transaction.join("state");
    fs::write(&state, b"prepared\ncommitted").unwrap();
    set_mode(&state, 0o600);

    let recovery = run_writer("recover", &auth_dir, &legacy_env, None);

    assert!(!recovery.status.success());
    assert_no_secret_output(&recovery, &[LEGACY_TOKEN]);
    assert_eq!(snapshot(&auth_dir), interrupted_snapshot);
    assert!(transaction.is_dir());
    assert_eq!(fs::read(&state).unwrap(), b"prepared\ncommitted");
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn transaction_failure_restores_all_credential_files() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    write_legacy_env(
        &legacy_env,
        format!(
            "HARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
        ),
    )
    .unwrap();
    assert_success_without_secret_output(
        &run_writer("prepare", &auth_dir, &legacy_env, None),
        &[LEGACY_TOKEN],
    );
    let before = snapshot(&auth_dir);

    let output = run_writer("switch", &auth_dir, &legacy_env, Some("after_rename_3"));

    assert!(!output.status.success());
    assert_no_secret_output(&output, &[LEGACY_TOKEN]);
    assert_eq!(snapshot(&auth_dir), before);
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn sigkill_interruption_is_recovered_to_the_complete_old_snapshot() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    write_legacy_env(
        &legacy_env,
        format!(
            "HARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
        ),
    )
    .unwrap();
    assert_success_without_secret_output(
        &run_writer("prepare", &auth_dir, &legacy_env, None),
        &[LEGACY_TOKEN],
    );
    let before = snapshot(&auth_dir);

    let interrupted = run_writer(
        "switch",
        &auth_dir,
        &legacy_env,
        Some("after_rename_3_sigkill"),
    );

    assert!(!interrupted.status.success());
    assert!(auth_dir.join(".credential-transaction").is_dir());
    assert_ne!(snapshot(&auth_dir), before);

    let recovery = run_writer("recover", &auth_dir, &legacy_env, None);
    assert_success_without_secret_output(&recovery, &[LEGACY_TOKEN]);
    assert_eq!(snapshot(&auth_dir), before);
    assert!(!auth_dir.join(".credential-transaction").exists());
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn journal_boundaries_recover_prepared_or_keep_committed_snapshot() {
    let rollback_failpoints = [
        "before_prepared_sigkill",
        "after_prepared_sigkill",
        "after_rename_6_sigkill",
        "after_auth_dir_sync_sigkill",
    ];

    for failpoint in rollback_failpoints {
        let temp = TempDir::new().unwrap();
        let auth_dir = temp.path().join("service-auth");
        let legacy_env = temp.path().join("harboros-beacon-gate");
        write_legacy_env(
            &legacy_env,
            format!(
                "HARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
            ),
        )
        .unwrap();
        assert_success_without_secret_output(
            &run_writer("prepare", &auth_dir, &legacy_env, None),
            &[LEGACY_TOKEN],
        );
        let before = snapshot(&auth_dir);

        let interrupted = run_writer("switch", &auth_dir, &legacy_env, Some(failpoint));

        assert!(
            !interrupted.status.success(),
            "failpoint succeeded: {failpoint}"
        );
        assert_no_secret_output(&interrupted, &[LEGACY_TOKEN]);
        let transaction = auth_dir.join(".credential-transaction");
        assert!(transaction.is_dir());
        if failpoint == "before_prepared_sigkill" {
            assert!(!transaction.join("state").exists());
        } else {
            assert_eq!(
                fs::read_to_string(transaction.join("state")).unwrap(),
                "prepared\n"
            );
        }

        let recovery = run_writer("recover", &auth_dir, &legacy_env, None);
        assert_success_without_secret_output(&recovery, &[LEGACY_TOKEN]);
        assert_eq!(snapshot(&auth_dir), before, "wrong recovery: {failpoint}");
        assert!(!transaction.exists());
    }

    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    write_legacy_env(
        &legacy_env,
        format!(
            "HARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
        ),
    )
    .unwrap();
    assert_success_without_secret_output(
        &run_writer("prepare", &auth_dir, &legacy_env, None),
        &[LEGACY_TOKEN],
    );
    let mut expected = snapshot(&auth_dir);
    let g2b_current = expected["gate-to-beacon.accept-current"].clone();
    let b2g_current = expected["beacon-to-gate.accept-current"].clone();
    expected.insert("gate-to-beacon.send".to_string(), g2b_current);
    expected.insert("beacon-to-gate.send".to_string(), b2g_current);

    let interrupted = run_writer(
        "switch",
        &auth_dir,
        &legacy_env,
        Some("after_committed_sigkill"),
    );

    assert!(!interrupted.status.success());
    assert_no_secret_output(&interrupted, &[LEGACY_TOKEN]);
    let transaction = auth_dir.join(".credential-transaction");
    assert_eq!(
        fs::read_to_string(transaction.join("state")).unwrap(),
        "committed\n"
    );
    let recovery = run_writer("recover", &auth_dir, &legacy_env, None);
    assert_success_without_secret_output(&recovery, &[LEGACY_TOKEN]);
    assert_eq!(snapshot(&auth_dir), expected);
    assert!(!transaction.exists());
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn recovery_is_idempotent_when_sigkill_interrupts_snapshot_restore() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    write_legacy_env(
        &legacy_env,
        format!(
            "HARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
        ),
    )
    .unwrap();
    assert_success_without_secret_output(
        &run_writer("prepare", &auth_dir, &legacy_env, None),
        &[LEGACY_TOKEN],
    );
    let before = snapshot(&auth_dir);
    let commit_interruption = run_writer(
        "switch",
        &auth_dir,
        &legacy_env,
        Some("after_rename_6_sigkill"),
    );
    assert!(!commit_interruption.status.success());
    assert_no_secret_output(&commit_interruption, &[LEGACY_TOKEN]);

    let recovery_interruption = run_writer(
        "recover",
        &auth_dir,
        &legacy_env,
        Some("after_restore_3_sigkill"),
    );

    assert!(!recovery_interruption.status.success());
    assert_no_secret_output(&recovery_interruption, &[LEGACY_TOKEN]);
    assert_ne!(snapshot(&auth_dir), before);
    assert_eq!(
        fs::read_to_string(auth_dir.join(".credential-transaction/state")).unwrap(),
        "prepared\n"
    );

    let recovery = run_writer("recover", &auth_dir, &legacy_env, None);
    assert_success_without_secret_output(&recovery, &[LEGACY_TOKEN]);
    assert_eq!(snapshot(&auth_dir), before);
    assert!(!auth_dir.join(".credential-transaction").exists());
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn concurrent_prepare_writers_are_serialized() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("missing-legacy-env");
    let mut children = (0..8)
        .map(|_| {
            writer_command("prepare", &auth_dir, &legacy_env, None)
                .spawn()
                .expect("concurrent writer should start")
        })
        .collect::<Vec<_>>();

    for child in &mut children {
        let status = child.wait().expect("concurrent writer should finish");
        assert!(status.success(), "concurrent writer failed: {status}");
    }

    let g2b = credential(&auth_dir, "gate-to-beacon.accept-current");
    let b2g = credential(&auth_dir, "beacon-to-gate.accept-current");
    assert_ne!(g2b, b2g);
    assert_eq!(credential(&auth_dir, "gate-to-beacon.send"), g2b);
    assert_eq!(credential(&auth_dir, "beacon-to-gate.send"), b2g);
    assert!(!auth_dir.join(".credential-transaction").exists());
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn repeated_prepare_repairs_previous_to_match_the_active_sender() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    write_legacy_env(
        &legacy_env,
        format!(
            "HARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
        ),
    )
    .unwrap();
    assert_success_without_secret_output(
        &run_writer("prepare", &auth_dir, &legacy_env, None),
        &[LEGACY_TOKEN],
    );
    fs::write(
        auth_dir.join("gate-to-beacon.accept-previous"),
        format!("{UNRELATED_TOKEN}\n"),
    )
    .unwrap();

    let output = run_writer("prepare", &auth_dir, &legacy_env, None);

    assert_success_without_secret_output(&output, &[LEGACY_TOKEN, UNRELATED_TOKEN]);
    assert_eq!(
        credential(&auth_dir, "gate-to-beacon.accept-previous"),
        LEGACY_TOKEN
    );
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn finalize_rejects_unswitched_callers() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    write_legacy_env(
        &legacy_env,
        format!(
            "HARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
        ),
    )
    .unwrap();
    assert_success_without_secret_output(
        &run_writer("prepare", &auth_dir, &legacy_env, None),
        &[LEGACY_TOKEN],
    );

    let output = run_writer("finalize", &auth_dir, &legacy_env, None);

    assert!(!output.status.success());
    assert_no_secret_output(&output, &[LEGACY_TOKEN]);
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn writer_refuses_symlinked_credential_target() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    fs::create_dir(&auth_dir).unwrap();
    set_mode(&auth_dir, 0o700);
    let protected = temp.path().join("protected");
    fs::write(&protected, "do-not-change\n").unwrap();
    symlink(&protected, auth_dir.join("gate-to-beacon.send")).unwrap();

    let output = run_writer(
        "prepare",
        &auth_dir,
        &temp.path().join("missing-legacy-env"),
        None,
    );

    assert!(!output.status.success());
    assert_eq!(fs::read_to_string(&protected).unwrap(), "do-not-change\n");
}

#[test]
#[ignore = "requires root to drop privileges"]
fn non_root_writer_fails_before_initializing_the_auth_directory() {
    let temp = TempDir::new().unwrap();
    set_mode(temp.path(), 0o755);
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("missing-legacy-env");
    let helper = temp.path().join("ensure-harborbeacon-token-env");
    fs::copy(
        repo_root().join("debian/ensure-harborbeacon-token-env"),
        &helper,
    )
    .unwrap();
    set_mode(&helper, 0o755);
    let output = Command::new("setpriv")
        .args(["--reuid=65534", "--regid=65534", "--clear-groups"])
        .arg("bash")
        .arg(&helper)
        .arg("prepare")
        .env("HARBOR_SERVICE_AUTH_DIR", &auth_dir)
        .env("HARBOR_LEGACY_SHARED_ENV_FILE", &legacy_env)
        .output()
        .expect("setpriv should execute the writer");

    assert!(!output.status.success());
    assert!(!auth_dir.exists());
    assert!(String::from_utf8_lossy(&output.stderr).contains("must run as root"));
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn auth_directory_mode_tampering_fails_closed_for_every_phase() {
    let (_temp, auth_dir, legacy_env) = initialized_fixture();
    let before = snapshot(&auth_dir);
    for mode in ["prepare", "recover", "switch", "finalize", "rollback"] {
        for insecure_mode in [0o755, 0o770] {
            set_mode(&auth_dir, insecure_mode);

            let output = run_writer(mode, &auth_dir, &legacy_env, None);

            assert!(
                !output.status.success(),
                "{mode} accepted mode {insecure_mode:o}"
            );
            assert_eq!(snapshot(&auth_dir), before);
            assert!(!auth_dir.join(".credential-transaction").exists());
            assert_eq!(
                fs::symlink_metadata(&auth_dir)
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                insecure_mode,
                "{mode} silently repaired the directory mode"
            );
            set_mode(&auth_dir, 0o700);
        }
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn auth_directory_owner_tampering_fails_closed_for_every_phase() {
    let (_temp, auth_dir, legacy_env) = initialized_fixture();
    let before = snapshot(&auth_dir);
    for mode in ["prepare", "recover", "switch", "finalize", "rollback"] {
        set_owner(&auth_dir, 65534, 65534);

        let output = run_writer(mode, &auth_dir, &legacy_env, None);

        assert!(!output.status.success(), "{mode} accepted a non-root owner");
        assert_eq!(snapshot(&auth_dir), before);
        assert!(!auth_dir.join(".credential-transaction").exists());
        let metadata = fs::symlink_metadata(&auth_dir).unwrap();
        assert_eq!(metadata.uid(), 65534, "{mode} silently repaired the owner");
        assert_eq!(metadata.gid(), 65534, "{mode} silently repaired the group");
        set_owner(&auth_dir, 0, 0);
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn credential_mode_tampering_fails_closed_for_every_file_and_phase() {
    let (_temp, auth_dir, legacy_env) = initialized_fixture();
    let before = snapshot(&auth_dir);
    for mode in ["prepare", "recover", "switch", "finalize", "rollback"] {
        for name in CREDENTIALS {
            for insecure_mode in [0o644, 0o660] {
                let target = auth_dir.join(name);
                set_mode(&target, insecure_mode);

                let output = run_writer(mode, &auth_dir, &legacy_env, None);

                assert!(
                    !output.status.success(),
                    "{mode} accepted mode {insecure_mode:o} for {name}"
                );
                assert_eq!(snapshot(&auth_dir), before);
                assert!(!auth_dir.join(".credential-transaction").exists());
                assert_eq!(
                    fs::symlink_metadata(&target).unwrap().permissions().mode() & 0o7777,
                    insecure_mode,
                    "{mode} silently repaired {name}"
                );
                set_mode(&target, 0o600);
            }
        }
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn credential_owner_tampering_fails_closed_for_every_file_and_phase() {
    let (_temp, auth_dir, legacy_env) = initialized_fixture();
    let before = snapshot(&auth_dir);
    for mode in ["prepare", "recover", "switch", "finalize", "rollback"] {
        for name in CREDENTIALS {
            let target = auth_dir.join(name);
            set_owner(&target, 65534, 65534);

            let output = run_writer(mode, &auth_dir, &legacy_env, None);

            assert!(
                !output.status.success(),
                "{mode} accepted a non-root owner for {name}"
            );
            assert_eq!(snapshot(&auth_dir), before);
            assert!(!auth_dir.join(".credential-transaction").exists());
            let metadata = fs::symlink_metadata(&target).unwrap();
            assert_eq!(metadata.uid(), 65534, "{mode} silently repaired {name}");
            assert_eq!(metadata.gid(), 65534, "{mode} silently repaired {name}");
            set_owner(&target, 0, 0);
        }
    }
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn lock_metadata_tampering_fails_closed_without_repairing_or_rotating() {
    let (_temp, auth_dir, legacy_env) = initialized_fixture();
    let before = snapshot(&auth_dir);
    let lock = auth_dir.join(".credential-writer.lock");
    set_mode(&lock, 0o644);

    let output = run_writer("recover", &auth_dir, &legacy_env, None);

    assert!(!output.status.success());
    assert_eq!(snapshot(&auth_dir), before);
    assert_eq!(
        fs::symlink_metadata(lock).unwrap().permissions().mode() & 0o7777,
        0o644
    );
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn transaction_metadata_tampering_blocks_recovery_and_preserves_the_journal() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    write_legacy_env(
        &legacy_env,
        format!(
            "HARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
        ),
    )
    .unwrap();
    assert_success_without_secret_output(
        &run_writer("prepare", &auth_dir, &legacy_env, None),
        &[LEGACY_TOKEN],
    );
    let interrupted = run_writer(
        "switch",
        &auth_dir,
        &legacy_env,
        Some("after_rename_3_sigkill"),
    );
    assert!(!interrupted.status.success());
    let interrupted_snapshot = snapshot(&auth_dir);
    let transaction = auth_dir.join(".credential-transaction");
    assert_root_metadata(&transaction, 0o700);
    assert_root_metadata(&transaction.join("stage"), 0o700);
    assert_root_metadata(&transaction.join("backup"), 0o700);
    assert_root_metadata(&transaction.join("absent"), 0o700);
    assert_root_metadata(&transaction.join("state"), 0o600);
    for name in CREDENTIALS {
        assert_root_metadata(&transaction.join("backup").join(name), 0o600);
        let staged = transaction.join("stage").join(name);
        if staged.exists() {
            assert_root_metadata(&staged, 0o600);
        }
    }
    let backup = transaction.join("backup/gate-to-beacon.send");
    set_mode(&backup, 0o644);

    let recovery = run_writer("recover", &auth_dir, &legacy_env, None);

    assert!(!recovery.status.success());
    assert_eq!(snapshot(&auth_dir), interrupted_snapshot);
    assert!(transaction.is_dir());
    assert_eq!(
        fs::symlink_metadata(backup).unwrap().permissions().mode() & 0o7777,
        0o644
    );
}

#[test]
#[ignore = "requires root-owned Unix credential fixtures"]
fn restore_temporary_metadata_is_validated_and_recovery_remains_idempotent() {
    let temp = TempDir::new().unwrap();
    let auth_dir = temp.path().join("service-auth");
    let legacy_env = temp.path().join("harboros-beacon-gate");
    write_legacy_env(
        &legacy_env,
        format!(
            "HARBORBEACON_WEB_API_TOKEN={LEGACY_TOKEN}\nIM_AGENT_SERVICE_TOKEN={LEGACY_TOKEN}\n"
        ),
    )
    .unwrap();
    assert_success_without_secret_output(
        &run_writer("prepare", &auth_dir, &legacy_env, None),
        &[LEGACY_TOKEN],
    );
    let before = snapshot(&auth_dir);
    let commit_interruption = run_writer(
        "switch",
        &auth_dir,
        &legacy_env,
        Some("after_rename_6_sigkill"),
    );
    assert!(!commit_interruption.status.success());
    assert_no_secret_output(&commit_interruption, &[LEGACY_TOKEN]);

    let recovery_interruption = run_writer(
        "recover",
        &auth_dir,
        &legacy_env,
        Some("before_restore_rename_1_sigkill"),
    );
    assert!(!recovery_interruption.status.success());
    assert_no_secret_output(&recovery_interruption, &[LEGACY_TOKEN]);
    let transaction = auth_dir.join(".credential-transaction");
    let restore = transaction.join("restore.gate-to-beacon.send");
    assert_root_metadata(&restore, 0o600);
    set_mode(&restore, 0o644);

    let rejected = run_writer("recover", &auth_dir, &legacy_env, None);

    assert!(!rejected.status.success());
    assert_no_secret_output(&rejected, &[LEGACY_TOKEN]);
    assert!(transaction.is_dir());
    assert_eq!(
        fs::symlink_metadata(&restore).unwrap().permissions().mode() & 0o7777,
        0o644
    );

    set_mode(&restore, 0o600);
    let recovered = run_writer("recover", &auth_dir, &legacy_env, None);
    assert_success_without_secret_output(&recovered, &[LEGACY_TOKEN]);
    assert_eq!(snapshot(&auth_dir), before);
    assert!(!transaction.exists());
}

#[test]
fn package_uses_role_scoped_systemd_credentials_and_prepare_only() {
    let root = repo_root();
    let ci = fs::read_to_string(root.join(".github/workflows/ci.yml")).unwrap();
    let workflow = fs::read_to_string(root.join(".github/workflows/release.yml")).unwrap();
    let postinst = fs::read_to_string(root.join("debian/postinst")).unwrap();
    let control = fs::read_to_string(root.join("debian/control")).unwrap();
    let unit = fs::read_to_string(root.join("debian/harboros-im-gate.service")).unwrap();
    let recovery_unit =
        fs::read_to_string(root.join("debian/harboros-service-auth-recovery.service")).unwrap();
    let package_builder = fs::read_to_string(root.join("debian/build-amd64-package")).unwrap();
    let credential_writer =
        fs::read_to_string(root.join("debian/ensure-harborbeacon-token-env")).unwrap();
    let cargo = fs::read_to_string(root.join("Cargo.toml")).unwrap();
    let server = fs::read_to_string(root.join("src/server.rs")).unwrap();

    assert!(ci.contains("debian/build-amd64-package"));
    assert!(workflow.contains("scripts/build_harborgate_k3_deb.sh"));
    let k3_builder = fs::read_to_string(root.join("scripts/build_harborgate_k3_deb.sh")).unwrap();
    assert!(k3_builder.contains("debian/ensure-harborbeacon-token-env"));
    assert!(k3_builder.contains("debian/harboros-service-auth-recovery.service"));
    assert!(k3_builder.contains("debian/harbornavi-k3/postinst"));
    let k3_postinst = fs::read_to_string(root.join("debian/harbornavi-k3/postinst")).unwrap();
    assert!(k3_postinst.contains("ensure-harborbeacon-token-env prepare"));
    for mode in ["switch", "finalize", "rollback"] {
        assert!(!k3_postinst.contains(&format!("ensure-harborbeacon-token-env {mode}")));
    }
    let k3_control = fs::read_to_string(root.join("debian/harbornavi-k3/control")).unwrap();
    assert!(k3_control
        .lines()
        .any(|line| line.starts_with("Depends: harboros-system, ")));
    assert!(!k3_control.contains("harboros-system ("));
    assert!(!k3_control.contains("Breaks: harboros-system"));
    assert!(k3_control.contains("util-linux"));
    assert!(k3_control.contains("Provides: harboros-service-auth-abi (= 1)"));
    assert!(ci.contains("Run root-owned service-auth integration tests"));
    assert!(ci.contains("sudo --non-interactive \"$test_binary\" --ignored --test-threads=1"));
    assert!(ci.contains("Build and validate AMD64 deb package"));
    assert!(control.contains("util-linux"));
    assert!(control.contains("Provides: harboros-service-auth-abi (= 1)"));
    assert!(postinst.contains("ensure-harborbeacon-token-env prepare"));
    assert!(!postinst.contains("ensure-harborbeacon-token-env switch"));
    assert!(!postinst.contains("ensure-harborbeacon-token-env finalize"));
    assert!(!postinst.contains("ensure-harborbeacon-token-env rollback"));
    assert!(credential_writer.contains("prepare|switch|finalize|rollback|recover"));
    assert!(unit.contains("Requires=harboros-service-auth-recovery.service"));
    assert!(unit.contains("After=harboros-service-auth-recovery.service"));
    assert!(!unit.contains("EnvironmentFile=-/etc/default/harboros-beacon-gate"));
    assert!(unit.contains("LoadCredential=gate-to-beacon-send:"));
    assert!(unit.contains("LoadCredential=beacon-to-gate-accept-current:"));
    assert!(unit.contains("LoadCredential=beacon-to-gate-accept-previous:"));
    assert!(!unit.contains("TOKEN_FILE=%d"));
    assert!(fs::read_to_string(root.join("src/config.rs"))
        .unwrap()
        .contains("CREDENTIALS_DIRECTORY"));
    assert!(!unit.contains("HARBOR_TASK_API_BEARER_TOKEN"));
    assert!(!unit.contains("HARBOR_MODEL_API_TOKEN"));
    assert!(recovery_unit.contains("Type=oneshot"));
    assert!(recovery_unit.contains("Before=harboros-im-gate.service harboros-beacon.service"));
    assert!(recovery_unit.contains("ensure-harborbeacon-token-env recover"));
    assert!(!recovery_unit.contains("RemainAfterExit"));
    assert!(package_builder.contains("dpkg-deb --root-owner-group --build"));
    assert!(package_builder.contains("harboros-service-auth-abi (= 1)"));
    assert!(package_builder.contains("root/root"));
    assert!(cargo.contains("constant_time_eq"));
    assert!(server.contains("constant_time_eq::constant_time_eq"));
    assert!(server.contains("let current_matches ="));
    assert!(server.contains("let previous_matches ="));
    assert!(server.contains("current_matches | previous_matches"));
}
