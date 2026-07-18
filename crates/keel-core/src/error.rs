use thiserror::Error;

pub type KeelResult<T> = Result<T, KeelError>;

#[derive(Debug, Error)]
pub enum KeelError {
    #[error(transparent)]
    Policy(#[from] keel_policy::PolicyError),

    #[error(transparent)]
    Enforce(#[from] keel_enforce::EnforceError),

    #[error("space is not open (state={0})")]
    NotOpen(&'static str),

    #[error("record sink error: {0}")]
    Record(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}
