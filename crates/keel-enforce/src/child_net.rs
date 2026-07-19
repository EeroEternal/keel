//! Per-child network filters (Linux seccomp). No-op elsewhere.
//!
//! - **DenyAll / full block**: block connect/bind/listen/… so children cannot dial out.
//! - **Allowlist / server block**: allow `connect` (so HTTP(S)_PROXY to localhost works)
//!   but block bind/listen/accept so children cannot open listeners. Direct outbound
//!   `connect()` is still constrained by kernel **ProxyOnly** (Landlock/Seatbelt via nono)
//!   when the sandbox applies — this seccomp layer is complementary, not a full sockaddr
//!   allowlist.

/// Install seccomp BPF filter blocking all major network syscalls (DenyAll children).
///
/// # Safety
///
/// Must be called in a `pre_exec` context (after `fork`, before `exec`).
#[cfg(target_os = "linux")]
pub unsafe fn install_child_network_filter() -> std::io::Result<()> {
    install_filter(&[
        libc::SYS_connect,
        libc::SYS_bind,
        libc::SYS_sendto,
        libc::SYS_sendmsg,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
    ])
}

/// Block server-side sockets; leave `connect` available for proxy clients (allowlist).
///
/// # Safety
///
/// Must be called in a `pre_exec` context.
#[cfg(target_os = "linux")]
pub unsafe fn install_child_server_block_filter() -> std::io::Result<()> {
    install_filter(&[
        libc::SYS_bind,
        libc::SYS_listen,
        libc::SYS_accept,
        libc::SYS_accept4,
    ])
}

#[cfg(target_os = "linux")]
unsafe fn install_filter(blocked_syscalls: &[i64]) -> std::io::Result<()> {
    use libc::{
        BPF_ABS, BPF_JEQ, BPF_JMP, BPF_K, BPF_LD, BPF_RET, BPF_W, PR_SET_NO_NEW_PRIVS,
        PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prctl, sock_filter, sock_fprog,
    };

    const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
    const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
    const EPERM_VAL: u32 = 1;

    macro_rules! bpf_stmt {
        ($code:expr, $k:expr) => {
            sock_filter {
                code: $code as u16,
                jt: 0,
                jf: 0,
                k: $k as u32,
            }
        };
    }

    macro_rules! bpf_jump {
        ($code:expr, $k:expr, $jt:expr, $jf:expr) => {
            sock_filter {
                code: $code as u16,
                jt: $jt,
                jf: $jf,
                k: $k as u32,
            }
        };
    }

    const NR_OFFSET: u32 = 0;

    let mut filter: Vec<sock_filter> = Vec::new();
    let total_checks = blocked_syscalls.len();

    filter.push(bpf_stmt!(BPF_LD | BPF_W | BPF_ABS, NR_OFFSET));

    for (i, &syscall) in blocked_syscalls.iter().enumerate() {
        let remaining = total_checks - i - 1;
        filter.push(bpf_jump!(
            BPF_JMP | BPF_JEQ | BPF_K,
            syscall,
            remaining as u8 + 1,
            0
        ));
    }

    filter.push(bpf_stmt!(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    filter.push(bpf_stmt!(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM_VAL));

    let prog = sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };

    if unsafe { prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(std::io::Error::last_os_error());
    }

    if unsafe {
        prctl(
            PR_SET_SECCOMP,
            SECCOMP_MODE_FILTER as libc::c_ulong,
            &prog as *const _ as libc::c_ulong,
            0,
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error());
    }

    Ok(())
}

/// # Safety
/// No-op on non-Linux.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub unsafe fn install_child_network_filter() -> std::io::Result<()> {
    Ok(())
}

/// # Safety
/// No-op on non-Linux.
#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub unsafe fn install_child_server_block_filter() -> std::io::Result<()> {
    Ok(())
}
