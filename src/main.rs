mod authority;
mod cli;
mod config;
mod error;
mod keychain;

use crate::authority::{Issuer, RootCA};
use crate::cli::{CaCommands, Cli, Commands};
use crate::config::{Config, Profile};
#[cfg(target_os = "macos")]
use crate::keychain::install_ca_to_keychain;
use clap::Parser;
use error::{Error, Result};
use error_stack::ResultExt;
use std::env::current_dir;
use std::fs;

fn main() -> Result<()> {
    let cli = Cli::parse();

    let config_dir = dirs::config_dir()
        .ok_or(error::ConfigurationDirNotFound)
        .change_context(Error::Configuration)?
        .join("scm");

    fs::create_dir_all(&config_dir)
        .change_context(Error::Configuration)
        .attach_printable_lazy(|| {
            format!(
                "Failed to create config directory at {}",
                config_dir.display()
            )
        })?;

    let config_path = config_dir.join("scm.toml");
    let mut config = Config::load(&config_path)?;

    match cli.command {
        Commands::Ca { command } => match command {
            CaCommands::Gen { profile } => {
                let ca = RootCA::new(&profile)
                    .change_context(Error::Certificate)?
                    .into_identity();
                let cert_dir = config_dir.join(&profile);
                let (cert_path, key_path) =
                    ca.persist(&cert_dir).change_context(Error::Certificate)?;
                println!("Root CA generated at {}", cert_dir.display());
                config.profiles.insert(
                    profile.clone(),
                    Profile {
                        cert: cert_path.into(),
                        key: key_path.into(),
                    },
                );
            }
            CaCommands::Install { profile: name } => {
                let profile = config
                    .profiles
                    .get(&name)
                    .ok_or(error::ProfileNotFound(name))
                    .change_context(Error::Configuration)?;
                #[cfg(target_os = "macos")]
                {
                    let pem =
                        fs::read_to_string(&profile.cert).change_context(Error::Configuration)?;
                    let cert = pem::parse(&pem).change_context(Error::Certificate)?;
                    install_ca_to_keychain(cert.contents())?;
                    println!("CA installed and trusted in System keychain.");
                }
            }
        },
        Commands::Sign { root_ca: name, dns } => {
            let profile = config
                .profiles
                .get(&name)
                .ok_or(error::ProfileNotFound(name))
                .change_context(Error::Configuration)?;

            let issuer =
                Issuer::new(&profile.cert, &profile.key).change_context(Error::Certificate)?;
            let identity = issuer.sign(dns).change_context(Error::Certificate)?;
            let current_dir = current_dir()
                .change_context(Error::Configuration)
                .attach("Can't save certificate because current directory unknown")?;
            identity
                .persist(current_dir)
                .change_context(Error::Certificate)?;
        }
    }
    config.save(&config_path)?;
    Ok(())
}
