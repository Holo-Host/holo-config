//! This binary is used for generating a encoded key from the
//! seed, this is used by the `--load_ed25519_keypair_from_seed` in lair
//!

use anyhow::{Context, Result};
use ed25519_dalek::*;
use hpos_config_core::*;
use hpos_config_seed_bundle_explorer::encrypt_key;
use std::path::PathBuf;
use structopt::StructOpt;
use utils::unlock;

#[tokio::main]
async fn main() -> Result<()> {
    #[derive(StructOpt)]
    struct Cli {
        #[structopt(long = "config-path")]
        /// The path to the hpos-config file
        config_path: PathBuf,
        #[structopt(long = "password")]
        /// The password to unlock the device-bundle
        password: String,
    }

    let Cli {
        config_path,
        password,
    } = Cli::from_args();
    use std::fs::File;
    let config_file = File::open(&config_path).context(format!(
        "failed to open file {}",
        &config_path.to_string_lossy()
    ))?;
    match serde_json::from_reader(config_file)? {
        Config::V1 { seed, .. } => {
            let secret_key = SigningKey::from_bytes(&seed);
            let public_key = secret_key.verifying_key();
            println!("{}", encrypt_key(&secret_key, &public_key));
        }
        Config::V2 { device_bundle, .. } => {
            // take in password
            let secret = unlock(&device_bundle, &password).await.context(format!(
                "unable to unlock the device bundle from {}",
                &config_path.to_string_lossy()
            ))?;
            println!("{}", encrypt_key(&secret, &secret.verifying_key()));
        }
        Config::V3 { device_bundle, .. } => {
            // take in password
            let secret = unlock(&device_bundle, &password).await.context(format!(
                "unable to unlock the device bundle from {}",
                &config_path.to_string_lossy()
            ))?;
            println!("{}", encrypt_key(&secret, &secret.verifying_key()));
        }
    }

    Ok(())
}
