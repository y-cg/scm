use crate::error::{Error, Result};
use error_stack::ResultExt;
use rcgen::{
    CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::fs;
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use time::{Duration, OffsetDateTime};

pub struct Identity {
    pub cert: rcgen::Certificate,
    pub key: KeyPair,
}

pub struct CertPath(pub PathBuf);
impl From<CertPath> for PathBuf {
    fn from(val: CertPath) -> Self {
        val.0
    }
}

impl From<PathBuf> for CertPath {
    fn from(path: PathBuf) -> Self {
        CertPath(path)
    }
}

pub struct KeyPath(pub PathBuf);

impl From<KeyPath> for PathBuf {
    fn from(val: KeyPath) -> Self {
        val.0
    }
}

impl From<PathBuf> for KeyPath {
    fn from(path: PathBuf) -> Self {
        KeyPath(path)
    }
}

pub struct RootCA {
    cert: rcgen::Certificate,
    key: KeyPair,
}

impl RootCA {
    pub fn new<S: AsRef<str>>(name: S) -> Result<Self> {
        let mut params =
            CertificateParams::new(vec![]).change_context(Error::ConfigurationError)?;

        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("{} Root CA", name.as_ref()));
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let signing_key = KeyPair::generate().change_context(Error::CertificateError)?;

        let cert = params
            .self_signed(&signing_key)
            .change_context(Error::CertificateError)?;

        Ok(Self {
            cert,
            key: signing_key,
        })
    }

    pub fn into_identity(self) -> Identity {
        Identity {
            cert: self.cert,
            key: self.key,
        }
    }
}

impl Identity {
    pub fn persist<P: AsRef<Path>>(&self, dir: P) -> Result<(CertPath, KeyPath)> {
        let dir = dir.as_ref();
        fs::create_dir_all(dir).change_context(Error::ConfigurationError)?;
        let cert_path = dir.join("crt.pem");
        let key_path = dir.join("key.pem");
        #[cfg(unix)]
        {
            let mut cert_file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&cert_path)
                .change_context(Error::ConfigurationError)?;
            let mut key_file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)
                .change_context(Error::ConfigurationError)?;
            cert_file
                .write_all(self.cert.pem().as_bytes())
                .change_context(Error::ConfigurationError)?;
            key_file
                .write_all(self.key.serialize_pem().as_bytes())
                .change_context(Error::ConfigurationError)?;
        }
        #[cfg(not(unix))]
        {
            let mut cert_file = fs::File::create(&cert_path)?;
            let mut key_file = fs::File::create(&key_path)?;
            cert_file.write_all(self.cert.pem().as_bytes())?;
            key_file.write_all(self.key.serialize_pem().as_bytes())?;
        }
        Ok((cert_path.into(), key_path.into()))
    }
}

pub struct Issuer<'a> {
    inner: rcgen::Issuer<'a, KeyPair>,
}

impl<'a> Issuer<'a> {
    pub fn new<P: AsRef<Path>, Q: AsRef<Path>>(cert_path: P, key_path: Q) -> Result<Self> {
        let cert_pem = fs::read_to_string(cert_path).change_context(Error::CertificateError)?;
        let key_pem = fs::read_to_string(key_path).change_context(Error::CertificateError)?;
        let signing_key = KeyPair::from_pem(&key_pem).change_context(Error::CertificateError)?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(&cert_pem, signing_key)
            .change_context(Error::CertificateError)?;
        Ok(Issuer { inner: issuer })
    }

    pub fn sign(&self, dns_names: Vec<String>) -> Result<Identity> {
        let mut params =
            CertificateParams::new(dns_names).change_context(Error::CertificateError)?;
        params.distinguished_name = DistinguishedName::new();
        params.key_usages = vec![
            KeyUsagePurpose::DigitalSignature,
            KeyUsagePurpose::KeyEncipherment,
        ];
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        // Set validity: now (system local time) to now + 825 days
        let now = OffsetDateTime::from(std::time::SystemTime::now());
        params.not_before = now;
        params.not_after = now + Duration::days(825);

        // Generate key and sign
        let key = KeyPair::generate().change_context(Error::CertificateError)?;
        let cert = params
            .signed_by(&key, &self.inner)
            .change_context(Error::CertificateError)?;
        Ok(Identity { cert, key })
    }
}
