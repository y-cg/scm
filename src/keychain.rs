use crate::error::{Error, Result};
use error_stack::ResultExt;
#[cfg(target_os = "macos")]
pub fn install_ca_to_keychain(cert_der: &[u8]) -> Result<()> {
    use security_framework::certificate::SecCertificate;
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework::trust_settings::{Domain, TrustSettings};

    let cert = SecCertificate::from_der(cert_der)
        .change_context(Error::Certificate)
        .attach(|| "fail to parse the given certificate")?;

    let keychain = SecKeychain::open("/Library/Keychains/System.keychain")
        .change_context(Error::Keychain)
        .attach_printable("Failed to open System keychain")?;

    cert.add_to_keychain(Some(keychain))
        .change_context(Error::Keychain)
        .attach_printable("Failed to add certificate to keychain")?;
    TrustSettings::new(Domain::Admin)
        .set_trust_settings_always(&cert)
        .change_context(Error::Keychain)
        .attach_printable("Failed to trust the certificate")?;
    Ok(())
}
