use thiserror::Error;

pub type EnforceResult<T> = Result<T, EnforceError>;

#[derive(Debug, Error)]
pub enum EnforceError {
    #[error("policy denied: {0}")]
    Denied(String),

    #[error("backend not supported on this platform: {0}")]
    Unsupported(String),

    #[error("policy expired")]
    PolicyExpired,

    #[error("space is closed")]
    Closed,

    /// Kernel sandbox was already applied to this process (irreversible).
    #[error("kernel sandbox already applied (policy {applied}); cannot re-apply {requested}")]
    AlreadyApplied {
        applied: String,
        requested: String,
    },

    /// Kernel apply failed and this backend is fail-closed.
    #[error("kernel sandbox apply failed: {0}")]
    ApplyFailed(String),

    #[error(transparent)]
    Policy(#[from] keel_policy::PolicyError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
