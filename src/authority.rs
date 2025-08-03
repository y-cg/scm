use crate::error::CertificateError;
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

type Result<T> = ::std::result::Result<T, CertificateError>;

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
        let mut params = CertificateParams::new(vec![])?;

        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, format!("{} Root CA", name.as_ref()));
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

        let signing_key = KeyPair::generate()?;

        let cert = params.self_signed(&signing_key)?;

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
        fs::create_dir_all(dir)?;
        let cert_path = dir.join("crt.pem");
        let key_path = dir.join("key.pem");
        #[cfg(unix)]
        {
            let mut cert_file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o644)
                .open(&cert_path)?;
            let mut key_file = fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key_path)?;
            cert_file.write_all(self.cert.pem().as_bytes())?;
            key_file.write_all(self.key.serialize_pem().as_bytes())?;
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
        let cert_pem = fs::read_to_string(cert_path)?;
        let key_pem = fs::read_to_string(key_path)?;
        let signing_key = KeyPair::from_pem(&key_pem)?;
        let issuer = rcgen::Issuer::from_ca_cert_pem(&cert_pem, signing_key)?;
        Ok(Issuer { inner: issuer })
    }

    pub fn sign(&self, dns_names: Vec<String>) -> Result<Identity> {
        let mut params = CertificateParams::new(dns_names)?;
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
        let key = KeyPair::generate()?;
        let cert = params.signed_by(&key, &self.inner)?;
        Ok(Identity { cert, key })
    }
}
