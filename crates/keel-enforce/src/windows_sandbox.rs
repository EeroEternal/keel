//! Windows process isolation helpers: **Job Objects** + optional **restricted token**.
//!
//! ## What this provides
//!
//! | Mechanism | Purpose |
//! |-----------|---------|
//! | Job Object (`KILL_ON_JOB_CLOSE`) | Process-tree lifecycle — kill grandchildren on cancel/timeout/Drop |
//! | Restricted token (probe) | Validate `CreateRestrictedToken` is available for future `CreateProcessAsUser` |
//! | Soft FS checks | Policy still applied via `soft_fs_allowed` before spawn |
//!
//! ## AppContainer
//!
//! Full AppContainer (capability SIDs + profile + path ACLs) is deferred. Job Objects
//! deliver the highest-value Windows gap (process-tree kill). Restricted-token and
//! AppContainer path grants can layer on without changing the Job model.
//!
//! Compiled only for `cfg(windows)`.

#![cfg(windows)]

use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, FALSE, HANDLE, HANDLE_FLAG_INHERIT, INVALID_HANDLE_VALUE, SetHandleInformation,
};
use windows_sys::Win32::Security::{
    CreateRestrictedToken, DISABLE_MAX_PRIVILEGE, TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE,
    TOKEN_QUERY,
};
use windows_sys::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
    SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
    JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, PROCESS_QUERY_INFORMATION,
    PROCESS_SET_QUOTA, PROCESS_TERMINATE,
};

/// RAII Job Object. Closing the handle terminates all processes in the job when
/// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` is set.
pub struct Job {
    handle: OwnedHandle,
}

// SAFETY: Job handle is only used from the agent host tasks.
unsafe impl Send for Job {}
unsafe impl Sync for Job {}

impl Job {
    /// Create a job that kills members when the job handle is closed.
    pub fn create() -> io::Result<Self> {
        unsafe {
            let h = CreateJobObjectW(ptr::null(), ptr::null());
            if h.is_null() || h == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let owned = OwnedHandle::from_raw_handle(h as RawHandle);

            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;

            let ok = SetInformationJobObject(
                h,
                JobObjectExtendedLimitInformation,
                &mut info as *mut _ as *mut _,
                std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            );
            if ok == FALSE {
                return Err(io::Error::last_os_error());
            }

            let _ = SetHandleInformation(h, HANDLE_FLAG_INHERIT, 0);

            Ok(Self { handle: owned })
        }
    }

    /// Assign an existing process (by PID) to this job.
    pub fn assign_pid(&self, pid: u32) -> io::Result<()> {
        unsafe {
            let access = PROCESS_SET_QUOTA | PROCESS_TERMINATE | PROCESS_QUERY_INFORMATION;
            let proc = OpenProcess(access, FALSE, pid);
            if proc.is_null() || proc == INVALID_HANDLE_VALUE {
                return Err(io::Error::last_os_error());
            }
            let result =
                AssignProcessToJobObject(self.handle.as_raw_handle() as HANDLE, proc);
            let err = if result == FALSE {
                Some(io::Error::last_os_error())
            } else {
                None
            };
            CloseHandle(proc);
            match err {
                Some(e) => Err(e),
                None => Ok(()),
            }
        }
    }

    /// Terminate every process in the job.
    pub fn terminate(&self) -> io::Result<()> {
        unsafe {
            let ok = TerminateJobObject(self.handle.as_raw_handle() as HANDLE, 1);
            if ok == FALSE {
                // Already empty / already terminated is fine for Drop.
                let e = io::Error::last_os_error();
                if e.raw_os_error() == Some(5) {
                    // ACCESS_DENIED sometimes when job already gone
                    return Ok(());
                }
                return Err(e);
            }
            Ok(())
        }
    }
}

impl Drop for Job {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

/// Options for Windows child isolation.
#[derive(Debug, Clone)]
pub struct WindowsSandboxOptions {
    /// Put each child in a Job Object (default true).
    pub use_job: bool,
    /// Probe restricted-token APIs (default true).
    pub use_restricted_token: bool,
}

impl Default for WindowsSandboxOptions {
    fn default() -> Self {
        Self {
            use_job: true,
            use_restricted_token: true,
        }
    }
}

/// Best-effort: open the current process token and create a restricted copy.
///
/// Confirms restricted-token APIs work; full `CreateProcessAsUser` spawn is a
/// follow-up (custom stdio + primary token).
pub fn try_create_restricted_token() -> io::Result<OwnedHandle> {
    unsafe {
        let mut process_token: HANDLE = ptr::null_mut();
        let ok = OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_QUERY,
            &mut process_token,
        );
        if ok == FALSE {
            return Err(io::Error::last_os_error());
        }

        let mut restricted: HANDLE = ptr::null_mut();
        let ok = CreateRestrictedToken(
            process_token,
            DISABLE_MAX_PRIVILEGE,
            0,
            ptr::null(),
            0,
            ptr::null(),
            0,
            ptr::null(),
            &mut restricted,
        );
        CloseHandle(process_token);
        if ok == FALSE {
            return Err(io::Error::last_os_error());
        }
        Ok(OwnedHandle::from_raw_handle(restricted as RawHandle))
    }
}

/// Probe whether Job Objects are usable on this machine.
pub fn job_objects_supported() -> bool {
    Job::create().is_ok()
}

/// Human-readable capability summary for audit notes.
pub fn capability_summary(opts: &WindowsSandboxOptions) -> String {
    let mut parts = Vec::new();
    if opts.use_job {
        parts.push("job-object(KILL_ON_JOB_CLOSE)");
    }
    if opts.use_restricted_token {
        parts.push("restricted-token(probe)");
    }
    parts.push("soft-fs-policy");
    parts.push("appcontainer=optional");
    parts.join(" + ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_create_and_terminate() {
        let job = Job::create().expect("CreateJobObject");
        job.terminate().expect("TerminateJobObject empty job");
    }

    #[test]
    fn restricted_token_probe() {
        let _ = try_create_restricted_token();
    }
}
