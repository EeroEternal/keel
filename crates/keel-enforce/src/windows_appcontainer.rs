//! Windows **AppContainer** profile + path grants + CreateProcess spawn.
//!
//! ## Model
//!
//! 1. Create (or open) a named AppContainer profile per policy id.
//! 2. Grant FILE access on policy write/read roots to the AppContainer SID (`icacls`).
//! 3. Spawn children with `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` so they
//!    run *as* that AppContainer identity (OS enforces the ACL).
//! 4. Still assign a Job Object for process-tree kill.
//!
//! ## Limits
//!
//! - Requires Windows 8+ AppContainer support and `icacls` for grants.
//! - Capability set is minimal (`internetClient` when network is not DenyAll).
//! - Stdio uses anonymous pipes; expose them as `std::fs::File` (not `ChildStdin`).
//! - If AppContainer creation fails, callers should fall back to Job-only mode.

#![cfg(windows)]

use crate::windows_sandbox::Job;
use keel_policy::Policy;
use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
use std::ptr;
use tracing::{info, warn};

use windows_sys::core::HRESULT;
use windows_sys::Win32::Foundation::{
    FALSE, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, LocalFree, SetHandleInformation,
    TRUE, WAIT_OBJECT_0,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSidToSidW,
};
use windows_sys::Win32::Security::{
    FreeSid, PSID, SECURITY_ATTRIBUTES, SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES,
};
use windows_sys::Win32::Security::Isolation::{
    CreateAppContainerProfile, DeleteAppContainerProfile, DeriveAppContainerSidFromAppContainerName,
};
use windows_sys::Win32::System::Pipes::CreatePipe;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, DeleteProcThreadAttributeList, GetExitCodeProcess,
    InitializeProcThreadAttributeList, ResumeThread, UpdateProcThreadAttribute, WaitForSingleObject,
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT,
    INFINITE, LPPROC_THREAD_ATTRIBUTE_LIST, PROCESS_INFORMATION, PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
    STARTUPINFOEXW, STARTUPINFOW,
};

/// Well-known capability: internetClient (S-1-15-3-1).
const CAP_INTERNET_CLIENT: &str = "S-1-15-3-1";

/// Live AppContainer profile for one space/policy.
pub struct AppContainerProfile {
    pub name: String,
    sid: PSID,
    sid_string: String,
    /// Paths we granted (for logging / cleanup notes only).
    granted: Vec<PathBuf>,
}

// SAFETY: SID is owned until FreeSid in Drop; profile is Send across host tasks.
unsafe impl Send for AppContainerProfile {}
unsafe impl Sync for AppContainerProfile {}

impl AppContainerProfile {
    /// Create or open an AppContainer profile for `policy`.
    pub fn create_for_policy(policy: &Policy) -> io::Result<Self> {
        let name = profile_name_for_policy(policy);
        let wide_name = wide(&name);
        let wide_display = wide(&format!("Keel {}", policy.id.as_str()));
        let wide_desc = wide("Keel execution space AppContainer");

        let mut sid: PSID = ptr::null_mut();
        let hr = unsafe {
            CreateAppContainerProfile(
                wide_name.as_ptr(),
                wide_display.as_ptr(),
                wide_desc.as_ptr(),
                ptr::null(),
                0,
                &mut sid,
            )
        };

        // 0x800700B7 HRESULT_FROM_WIN32(ERROR_ALREADY_EXISTS) — open existing.
        if hr < 0 {
            let hr2 = unsafe {
                DeriveAppContainerSidFromAppContainerName(wide_name.as_ptr(), &mut sid)
            };
            if hr2 < 0 {
                return Err(hresult_io(hr2, "DeriveAppContainerSidFromAppContainerName"));
            }
        }

        let sid_string = sid_to_string(sid)?;
        info!(profile = %name, sid = %sid_string, "AppContainer profile ready");

        let mut profile = Self {
            name,
            sid,
            sid_string,
            granted: Vec::new(),
        };
        profile.grant_policy_paths(policy)?;
        Ok(profile)
    }

    /// Grant read/write roots from policy to this AppContainer SID via `icacls`.
    pub fn grant_policy_paths(&mut self, policy: &Policy) -> io::Result<()> {
        let mut paths: Vec<(PathBuf, bool)> = Vec::new();
        paths.push((policy.workspace.clone(), true));
        for p in policy.read_write_paths() {
            paths.push((p.clone(), true));
        }
        for p in policy.read_only_paths() {
            paths.push((p.clone(), false));
        }
        // Always allow reading system dirs needed to launch programs (minimal).
        for p in [
            PathBuf::from(r"C:\Windows\System32"),
            PathBuf::from(r"C:\Windows\SysWOW64"),
            PathBuf::from(r"C:\Program Files"),
            PathBuf::from(r"C:\Program Files (x86)"),
        ] {
            if p.exists() {
                paths.push((p, false));
            }
        }

        for (path, write) in paths {
            if !path.exists() {
                // Create write roots so icacls has a target.
                if write {
                    let _ = std::fs::create_dir_all(&path);
                } else {
                    continue;
                }
            }
            if let Err(e) = grant_icacls(&self.sid_string, &path, write) {
                warn!(error = %e, path = %path.display(), "icacls grant failed");
            } else {
                self.granted.push(path);
            }
        }
        Ok(())
    }

    pub fn sid_string(&self) -> &str {
        &self.sid_string
    }

    pub fn name(&self) -> &str {
        &self.name
    }
}

impl Drop for AppContainerProfile {
    fn drop(&mut self) {
        if !self.sid.is_null() {
            unsafe {
                FreeSid(self.sid);
            }
            self.sid = ptr::null_mut();
        }
        // Keep profile registered for reuse across spaces with same id; do not DeleteAppContainerProfile.
    }
}

/// Explicitly delete a named profile (optional cleanup).
pub fn delete_profile(name: &str) -> io::Result<()> {
    let wide = wide(name);
    let hr = unsafe { DeleteAppContainerProfile(wide.as_ptr()) };
    if hr < 0 {
        return Err(hresult_io(hr, "DeleteAppContainerProfile"));
    }
    Ok(())
}

/// Native Windows child process (AppContainer + optional Job).
pub struct NativeChild {
    process: OwnedHandle,
    _thread: OwnedHandle,
    job: Option<Job>,
    pub stdin: Option<File>,
    pub stdout: Option<File>,
    pub stderr: Option<File>,
}

// SAFETY: handles owned exclusively.
unsafe impl Send for NativeChild {}

impl NativeChild {
    pub fn id(&self) -> Option<u32> {
        // GetProcessId
        unsafe {
            let pid = windows_sys::Win32::System::Threading::GetProcessId(
                self.process.as_raw_handle() as HANDLE,
            );
            if pid == 0 {
                None
            } else {
                Some(pid)
            }
        }
    }

    pub fn kill(&mut self) -> io::Result<()> {
        if let Some(job) = self.job.as_ref() {
            return job.terminate();
        }
        unsafe {
            let ok = windows_sys::Win32::System::Threading::TerminateProcess(
                self.process.as_raw_handle() as HANDLE,
                1,
            );
            if ok == FALSE {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    pub fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        unsafe {
            let r = WaitForSingleObject(self.process.as_raw_handle() as HANDLE, 0);
            if r == WAIT_OBJECT_0 {
                Ok(Some(self.exit_status()?))
            } else {
                Ok(None)
            }
        }
    }

    pub async fn wait(&mut self) -> io::Result<ExitStatus> {
        let handle = self.process.as_raw_handle() as isize;
        tokio::task::spawn_blocking(move || unsafe {
            let h = handle as HANDLE;
            let r = WaitForSingleObject(h, INFINITE);
            if r != WAIT_OBJECT_0 {
                return Err(io::Error::last_os_error());
            }
            let mut code: u32 = 0;
            if GetExitCodeProcess(h, &mut code) == FALSE {
                return Err(io::Error::last_os_error());
            }
            Ok(exit_status_from_code(code))
        })
        .await
        .map_err(io::Error::other)?
    }

    fn exit_status(&self) -> io::Result<ExitStatus> {
        unsafe {
            let mut code: u32 = 0;
            if GetExitCodeProcess(self.process.as_raw_handle() as HANDLE, &mut code) == FALSE {
                return Err(io::Error::last_os_error());
            }
            Ok(exit_status_from_code(code))
        }
    }
}

/// Spawn `program` + args inside the AppContainer, assign Job, wire stdio pipes.
pub fn spawn_in_appcontainer(
    profile: &AppContainerProfile,
    program: &str,
    args: &[String],
    cwd: Option<&Path>,
    env: &[(String, String)],
    stdin_null: bool,
    use_job: bool,
    allow_network: bool,
) -> io::Result<NativeChild> {
    unsafe {
        // --- pipes ---
        let mut sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: ptr::null_mut(),
            bInheritHandle: TRUE,
        };

        let (stdin_rd, stdin_wr) = if stdin_null {
            (None, None)
        } else {
            let (r, w) = create_pipe(&mut sa)?;
            SetHandleInformation(w.as_raw_handle() as HANDLE, HANDLE_FLAG_INHERIT, 0);
            (Some(r), Some(w))
        };
        let (stdout_rd, stdout_wr) = {
            let (r, w) = create_pipe(&mut sa)?;
            SetHandleInformation(r.as_raw_handle() as HANDLE, HANDLE_FLAG_INHERIT, 0);
            (r, w)
        };
        let (stderr_rd, stderr_wr) = {
            let (r, w) = create_pipe(&mut sa)?;
            SetHandleInformation(r.as_raw_handle() as HANDLE, HANDLE_FLAG_INHERIT, 0);
            (r, w)
        };

        // --- capabilities ---
        let mut cap_sid: PSID = ptr::null_mut();
        let mut caps_storage: Option<SID_AND_ATTRIBUTES> = None;
        let (caps_ptr, cap_count) = if allow_network {
            let mut wide: Vec<u16> = OsStr::new(CAP_INTERNET_CLIENT)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            if ConvertStringSidToSidW(wide.as_mut_ptr(), &mut cap_sid) == FALSE {
                return Err(io::Error::last_os_error());
            }
            caps_storage = Some(SID_AND_ATTRIBUTES {
                Sid: cap_sid,
                Attributes: 0x4, // SE_GROUP_ENABLED
            });
            (
                caps_storage
                    .as_ref()
                    .map(|a| a as *const SID_AND_ATTRIBUTES)
                    .unwrap_or(ptr::null()),
                1u32,
            )
        } else {
            (ptr::null(), 0u32)
        };
        // Keep caps_storage alive until CreateProcess returns.
        let _caps_keep = &caps_storage;

        let mut sec_caps = SECURITY_CAPABILITIES {
            AppContainerSid: profile.sid,
            Capabilities: caps_ptr as *mut SID_AND_ATTRIBUTES,
            CapabilityCount: cap_count,
            Reserved: 0,
        };

        // --- attribute list ---
        let mut size: usize = 0;
        let _ = InitializeProcThreadAttributeList(ptr::null_mut(), 1, 0, &mut size);
        let mut attr_buf = vec![0u8; size];
        let attr_list = attr_buf.as_mut_ptr() as LPPROC_THREAD_ATTRIBUTE_LIST;
        if InitializeProcThreadAttributeList(attr_list, 1, 0, &mut size) == FALSE {
            free_cap_sid(cap_sid);
            return Err(io::Error::last_os_error());
        }
        if UpdateProcThreadAttribute(
            attr_list,
            0,
            PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
            &mut sec_caps as *mut _ as *mut _,
            std::mem::size_of::<SECURITY_CAPABILITIES>(),
            ptr::null_mut(),
            ptr::null(),
        ) == FALSE
        {
            DeleteProcThreadAttributeList(attr_list);
            free_cap_sid(cap_sid);
            return Err(io::Error::last_os_error());
        }

        let mut siex: STARTUPINFOEXW = std::mem::zeroed();
        siex.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
        siex.StartupInfo.dwFlags = 0x00000100; // STARTF_USESTDHANDLES
        siex.StartupInfo.hStdInput = stdin_rd
            .as_ref()
            .map(|f| f.as_raw_handle() as HANDLE)
            .unwrap_or(INVALID_HANDLE_VALUE);
        siex.StartupInfo.hStdOutput = stdout_wr.as_raw_handle() as HANDLE;
        siex.StartupInfo.hStdError = stderr_wr.as_raw_handle() as HANDLE;
        siex.lpAttributeList = attr_list;

        // Command line: "program" arg1 arg2 ...
        let mut cmd_line = quote_arg(program);
        for a in args {
            cmd_line.push(' ');
            cmd_line.push_str(&quote_arg(a));
        }
        let mut cmd_wide = wide(&cmd_line);

        let cwd_wide = cwd.map(|c| wide(c.as_os_str()));
        let cwd_ptr = cwd_wide
            .as_ref()
            .map(|w| w.as_ptr())
            .unwrap_or(ptr::null());

        // Environment block (optional merge) — inherit parent for now.
        let _ = env;
        let env_ptr: *const std::ffi::c_void = ptr::null();

        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();
        let flags = EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED;

        let ok = CreateProcessW(
            ptr::null(),
            cmd_wide.as_mut_ptr(),
            ptr::null(),
            ptr::null(),
            TRUE, // inherit pipe handles
            flags,
            env_ptr,
            cwd_ptr,
            &siex.StartupInfo as *const STARTUPINFOW,
            &mut pi,
        );

        DeleteProcThreadAttributeList(attr_list);
        free_cap_sid(cap_sid);
        // Close child-side pipe ends in parent.
        drop(stdout_wr);
        drop(stderr_wr);
        if let Some(r) = stdin_rd {
            drop(r);
        }

        if ok == FALSE {
            return Err(io::Error::last_os_error());
        }

        let process_h = pi.hProcess;
        let thread_h = pi.hThread;
        let pid = pi.dwProcessId;

        let mut job = None;
        if use_job {
            match Job::create() {
                Ok(j) => {
                    if let Err(e) = j.assign_pid(pid) {
                        warn!(error = %e, "AppContainer child AssignProcessToJobObject failed");
                    } else {
                        job = Some(j);
                    }
                }
                Err(e) => warn!(error = %e, "AppContainer Job create failed"),
            }
        }

        // Resume after job assignment.
        ResumeThread(thread_h);

        let process = OwnedHandle::from_raw_handle(process_h as RawHandle);
        let thread = OwnedHandle::from_raw_handle(thread_h as RawHandle);

        Ok(NativeChild {
            process,
            _thread: thread,
            job,
            stdin: stdin_wr,
            stdout: Some(stdout_rd),
            stderr: Some(stderr_rd),
        })
    }
}

fn free_cap_sid(sid: PSID) {
    if !sid.is_null() {
        unsafe {
            LocalFree(sid as *mut _);
        }
    }
}

fn create_pipe(sa: &mut SECURITY_ATTRIBUTES) -> io::Result<(File, File)> {
    unsafe {
        let mut rd: HANDLE = ptr::null_mut();
        let mut wr: HANDLE = ptr::null_mut();
        if CreatePipe(&mut rd, &mut wr, sa, 0) == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok((
            File::from_raw_handle(rd as RawHandle),
            File::from_raw_handle(wr as RawHandle),
        ))
    }
}

fn grant_icacls(sid: &str, path: &Path, write: bool) -> io::Result<()> {
    // *S-1-15-...:(OI)(CI)(M)  or (RX)
    let rights = if write { "(OI)(CI)(M)" } else { "(OI)(CI)(RX)" };
    let grant = format!("*{sid}:{rights}");
    let status = std::process::Command::new("icacls")
        .arg(path)
        .arg("/grant")
        .arg(&grant)
        .arg("/C")
        .output()?;
    if !status.status.success() {
        return Err(io::Error::other(format!(
            "icacls failed: {}",
            String::from_utf8_lossy(&status.stderr)
        )));
    }
    Ok(())
}

fn profile_name_for_policy(policy: &Policy) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(policy.id.as_str().as_bytes());
    h.update(policy.workspace.to_string_lossy().as_bytes());
    let dig = h.finalize();
    // AppContainer names: alphanumeric + limited punctuation; keep short.
    format!(
        "keel.{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        dig[0], dig[1], dig[2], dig[3], dig[4], dig[5], dig[6], dig[7]
    )
}

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn quote_arg(s: &str) -> String {
    if s.is_empty() {
        return "\"\"".into();
    }
    if !s.contains([' ', '\t', '"']) {
        return s.to_string();
    }
    let mut out = String::from("\"");
    for c in s.chars() {
        if c == '"' {
            out.push('\\');
        }
        out.push(c);
    }
    out.push('"');
    out
}

fn sid_to_string(sid: PSID) -> io::Result<String> {
    unsafe {
        let mut p: windows_sys::core::PWSTR = ptr::null_mut();
        if ConvertSidToStringSidW(sid, &mut p) == FALSE {
            return Err(io::Error::last_os_error());
        }
        let mut len = 0usize;
        while *p.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
        LocalFree(p as *mut _);
        Ok(s)
    }
}

fn hresult_io(hr: HRESULT, what: &str) -> io::Error {
    io::Error::other(format!("{what} failed: HRESULT 0x{hr:08X}"))
}

fn exit_status_from_code(code: u32) -> ExitStatus {
    use std::os::windows::process::ExitStatusExt;
    ExitStatus::from_raw(code)
}

/// Whether AppContainer APIs appear usable (create+delete probe with temp name).
pub fn appcontainer_supported() -> bool {
    let name = format!("keel.probe.{}", std::process::id());
    let wide = wide(&name);
    let mut sid: PSID = ptr::null_mut();
    let hr = unsafe {
        CreateAppContainerProfile(
            wide.as_ptr(),
            wide.as_ptr(),
            wide.as_ptr(),
            ptr::null(),
            0,
            &mut sid,
        )
    };
    if !sid.is_null() {
        unsafe {
            FreeSid(sid);
        }
    }
    if hr >= 0 {
        let _ = unsafe { DeleteAppContainerProfile(wide.as_ptr()) };
        return true;
    }
    // Already exists still means supported.
    hr as u32 == 0x800700B7
}
