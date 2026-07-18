use thiserror::Error;

pub type PolicyResult<T> = Result<T, PolicyError>;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("invalid policy: {0}")]
    Invalid(String),

    #[error("policy parse error: {0}")]
    Parse(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),
}
