use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(author, version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// CA management commands
    Ca {
        #[command(subcommand)]
        command: CaCommands,
    },
    /// Sign a certificate for a domain using a root CA
    Sign {
        /// Name of the root CA profile
        root_ca: String,
        /// DNS names to include in the certificate
        #[arg(long = "dns")]
        dns: Vec<String>,
    },
}

#[derive(Subcommand)]
pub enum CaCommands {
    /// Generate a root CA and store the certificate and key
    Gen {
        /// Name of the CA profile
        profile: String,
    },
    /// Install the CA to the system keychain and trust it (macOS only)
    Install {
        /// Name of the CA profile
        profile: String,
    },
}
