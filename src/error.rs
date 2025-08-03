use error_stack::Report;
use thiserror::Error;

pub type Result<T> = error_stack::Result<T, Error>;
#[derive(Error, Debug)]
pub enum Error {
    #[error("Unexpected error related to the configuration")]
    ConfigurationError,
    #[error("Unexpected error related to the certificate")]
    CertificateError,
    #[error("Unexpected error related to the keychain")]
    KeychainError,
}

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),
    #[error("Certificate error: {0}")]
    CertError(#[from] rcgen::Error),
}

#[derive(Error, Debug)]
#[error("Unable to find the default configuration directory")]
pub struct ConfigurationDirNotFound;

#[derive(Error, Debug)]
#[error("Profile '{0}' not found in the configuration")]
pub struct ProfileNotFound(pub String);
