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

    #[error(transparent)]
    Policy(#[from] keel_policy::PolicyError),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
