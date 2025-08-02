mod authority;
mod cli;
mod config;
mod keychain;

use crate::authority::{Issuer, RootCA};
use crate::cli::{CaCommands, Cli, Commands};
use crate::config::{Config, Profile};
use crate::keychain::install_ca_to_keychain;
use clap::Parser;
use std::env::current_dir;
use std::fs;

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config_dir = dirs::config_dir()
        .ok_or_else(|| anyhow::anyhow!("unable to find the default config directory"))?
        .join("scm");
    fs::create_dir_all(&config_dir)?;

    let config_path = config_dir.join("scm.toml");
    let mut config = Config::load(&config_path)?;

    match cli.command {
        Commands::Ca { command } => match command {
            CaCommands::Gen { profile } => {
                let ca = RootCA::new(&profile)?.into_identity();
                let cert_dir = config_dir.join(&profile);
                let (cert_path, key_path) = ca.persist(&cert_dir)?;
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
                    .ok_or_else(|| anyhow::anyhow!(format!("CA profile '{}' not found", name)))?;
                let pem = fs::read_to_string(&profile.cert)?;
                let cert = pem::parse(&pem)?;
                match install_ca_to_keychain(cert.contents()) {
                    Ok(()) => println!("CA installed and trusted in System keychain."),
                    Err(e) => eprintln!("Failed to install CA to keychain: {e}"),
                }
            }
        },
        Commands::Sign {
            root_ca: rootca,
            dns,
        } => {
            let profile = config
                .profiles
                .get(&rootca)
                .ok_or_else(|| anyhow::anyhow!(format!("CA profile '{}' not found", rootca)))?;
            let issuer = Issuer::new(&profile.cert, &profile.key)?;
            let identity = issuer.sign(dns)?;
            identity.persist(current_dir()?)?;
        }
    }
    config.save(&config_path)?;
    Ok(())
}
