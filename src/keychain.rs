#[cfg(target_os = "macos")]
pub fn install_ca_to_keychain(cert_der: &[u8]) -> anyhow::Result<()> {
    use security_framework::certificate::SecCertificate;
    use security_framework::os::macos::keychain::SecKeychain;
    use security_framework::trust_settings::{Domain, TrustSettings};
    let cert = SecCertificate::from_der(cert_der)?;
    let keychain = SecKeychain::open("/Library/Keychains/System.keychain")?;
    cert.add_to_keychain(Some(keychain))?;
    TrustSettings::new(Domain::Admin).set_trust_settings_always(&cert)?;
    Ok(())
}

#[cfg(not(target_os = "macos"))]
pub fn install_ca_to_keychain(_cert_der: &[u8]) -> anyhow::Result<()> {
    anyhow::bail!("Keychain install is only supported on macOS.");
}
