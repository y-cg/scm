use thiserror::Error;

pub type Result<T> = error_stack::Result<T, Error>;
#[derive(Error, Debug)]
pub enum Error {
    #[error("Unexpected error related to the configuration")]
    Configuration,
    #[error("Unexpected error related to the certificate")]
    Certificate,
    #[error("Unexpected error related to the keychain")]
    Keychain,
}

#[derive(Error, Debug)]
pub enum CertificateError {
    #[error("IO error: {0}")]
    IO(#[from] std::io::Error),
    #[error("Certificate error: {0}")]
    Cert(#[from] rcgen::Error),
}

#[derive(Error, Debug)]
#[error("Unable to find the default configuration directory")]
pub struct ConfigurationDirNotFound;

#[derive(Error, Debug)]
#[error("Profile '{0}' not found in the configuration")]
pub struct ProfileNotFound(pub String);
