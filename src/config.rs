use crate::error::{Error, Result};
use error_stack::ResultExt;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Profile {
    pub cert: PathBuf,
    pub key: PathBuf,
}

#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Config {
    pub profiles: BTreeMap<String, Profile>,
}

impl Config {
    pub fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref();
        if path.exists() {
            let content = fs::read_to_string(path).change_context(Error::Configuration)?;
            Ok(toml::from_str(&content).change_context(Error::Configuration)?)
        } else {
            Ok(Config::default())
        }
    }
    pub fn save<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        let content = toml::to_string(self).change_context(Error::Configuration)?;
        fs::write(path.as_ref(), content).change_context(Error::Configuration)?;
        Ok(())
    }
}
