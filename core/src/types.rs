use ed25519_dalek::ed25519;

#[derive(thiserror::Error, Debug)]
pub enum SeedExplorerError {
    #[error(transparent)]
    OneErr(#[from] hc_seed_bundle::dependencies::one_err::OneErr),
    #[error(transparent)]
    Ed25519Error(#[from] ed25519::Error),
    #[error(transparent)]
    DecodeError(#[from] base64::DecodeError),
    #[error("Seed hash unsupported cipher type")]
    UnsupportedCipher,
    #[error("Password required to unlock seed")]
    PasswordRequired,
    #[error("Generic Error: {0}")]
    Generic(String),

    #[error("Generic Error: {0}")]
    Std(#[from] std::io::Error),
}

pub type SeedExplorerResult<T> = Result<T, SeedExplorerError>;
