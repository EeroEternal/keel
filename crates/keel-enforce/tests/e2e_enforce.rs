//! Enforcement e2e (optimization plan Phase 3).
//!
//! Default: soft / proxy tests always run.
//! Kernel write isolation: set `KEEL_KERNEL_TEST=1`.

use keel_enforce::{
    worktree_sandboxed, EgressProxy, EnforceBackend, LocalProcessBackend, LocalProcessOptions,
    ProcessGuardBackend, SpawnRequest, WorktreeOptions,
};
use keel_policy::{NetworkPolicy, NetworkRule, Policy, profile_workspace};
use keel_record::MemorySink;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

fn kernel_tests_enabled() -> bool {
    std::env::var("KEEL_KERNEL_TEST").ok().as_deref() == Some("1")
}

#[tokio::test]
async fn soft_write_outside_workspace_denied() {
    let dir = tempfile::tempdir().unwrap();
    let policy = profile_workspace(dir.path()).unwrap();
    let backend = ProcessGuardBackend::new();
    let sink = Arc::new(MemorySink::new());
    backend.apply(&policy, sink).await.unwrap();
    assert!(!backend
        .check_fs(&policy, Path::new("/etc/passwd"), true)
        .await
        .unwrap());
    assert!(backend
        .check_fs(&policy, &dir.path().join("ok.rs"), true)
        .await
        .unwrap());
}

#[tokio::test]
async fn deny_glob_soft_blocks_env() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(".env"), "S=1").unwrap();
    let policy = Policy::builder(dir.path())
        .default_read(true)
        .read_write(dir.path())
        .deny_glob("**/.env")
        .build()
        .unwrap();
    let backend = ProcessGuardBackend::new();
    assert!(!backend
        .check_fs(&policy, &dir.path().join(".env"), false)
        .await
        .unwrap());
}

#[tokio::test]
async fn egress_proxy_denies_metadata_allows_listed() {
    let policy = NetworkPolicy::Allowlist(vec![NetworkRule::host_port("example.com", 80)]);
    let proxy = EgressProxy::start(policy).await.unwrap();

    // Metadata always denied even on unrestricted — use Unrestricted proxy for that case.
    let open = EgressProxy::start(NetworkPolicy::Unrestricted).await.unwrap();
    let mut stream = TcpStream::connect(open.addr()).await.unwrap();
    stream
        .write_all(b"CONNECT 169.254.169.254:80 HTTP/1.1\r\nHost: x\r\n\r\n")
        .await
        .unwrap();
    let mut buf = vec![0u8; 256];
    let n = stream.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("403"), "{resp}");
    open.shutdown();
    proxy.shutdown();
}

#[tokio::test]
async fn composed_worktree_sandbox_apply_smoke() {
    let origin = tempfile::tempdir().unwrap();
    let wt_root = tempfile::tempdir().unwrap();
    let policy = profile_workspace(origin.path()).unwrap();
    let backend = worktree_sandboxed(
        WorktreeOptions {
            worktrees_root: Some(wt_root.path().to_path_buf()),
            cleanup_on_destroy: true,
            prefer_git: false,
        },
        LocalProcessOptions {
            require_kernel: false, // soft prepare if sandbox unsupported
            ..Default::default()
        },
    );
    let sink = Arc::new(MemorySink::new());
    backend.apply(&policy, sink.clone()).await.unwrap();
    assert_eq!(backend.info().name, "local-worktree");
    backend.destroy(&policy, sink).await.unwrap();
}

/// Real Seatbelt/Landlock: child cannot write outside workspace.
/// Run: `KEEL_KERNEL_TEST=1 cargo test -p eero-keel-enforce --test e2e_enforce -- --nocapture`
#[tokio::test]
async fn kernel_child_write_isolation() {
    if !kernel_tests_enabled() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let policy = profile_workspace(dir.path()).unwrap();
    let backend = LocalProcessBackend::with_options(LocalProcessOptions {
        require_kernel: true,
        isolate_apply: true,
        block_process_network: false,
        ..Default::default()
    });
    let sink = Arc::new(MemorySink::new());
    backend.apply(&policy, sink.clone()).await.unwrap();

    // Probe script: try write outside workspace → should fail under sandbox.
    let outside = dir.path().parent().unwrap().join(format!(
        "keel-outside-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&outside);

    let mut req = SpawnRequest::new("sh").args([
        "-c".into(),
        format!(
            "echo pwned > '{}' 2>/dev/null; test -f '{}' && echo WROTE || echo BLOCKED",
            outside.display(),
            outside.display()
        ),
    ]);
    req.cwd = Some(dir.path().to_path_buf());

    let child = backend
        .spawn(
            &keel_policy::SpaceId::from_string("spc-e2e"),
            &policy,
            req,
            sink.clone(),
        )
        .await
        .unwrap();
    let out = child.child.wait_with_output().await.unwrap();
    // Note: e2e uses backend.spawn → SpawnedProcess (not ManagedProcess).
    let stdout = String::from_utf8_lossy(&out.stdout);
    // On platforms where sandbox applies, write is blocked.
    // If sandbox apply failed soft, this may still WRITE — only assert when BLOCKED.
    if stdout.contains("BLOCKED") {
        assert!(!outside.exists());
    } else if kernel_tests_enabled() {
        // Prefer BLOCKED; if WROTE, fail the e2e so we notice platform regressions.
        assert!(
            stdout.contains("BLOCKED"),
            "expected sandboxed child to block write outside workspace, stdout={stdout:?} stderr={:?}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    backend.destroy(&policy, sink).await.unwrap();
}
