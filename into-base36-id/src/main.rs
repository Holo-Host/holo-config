use anyhow::{Context, Result};
use ed25519_dalek::*;
use hpos_config_core::*;
use std::fs::File;
use std::path::PathBuf;
use structopt::StructOpt;

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
        ..
    } = Cli::from_args();

    let config_file = File::open(&config_path).context(format!(
        "failed to open file {}",
        &config_path.to_string_lossy()
    ))?;
    match serde_json::from_reader(config_file)? {
        Config::V1 { seed, .. } => {
            let public_key = VerifyingKey::from_bytes(&seed)?;
            println!("{}", public_key::to_base36_id(&public_key));
        }
        Config::V2 { device_bundle, .. } => {
            // take in password
            let secret = utils::unlock(&device_bundle, &password)
                .await
                .context(format!(
                    "unable to unlock the device bundle from {}",
                    &config_path.to_string_lossy()
                ))?;
            println!("{}", public_key::to_base36_id(&secret.verifying_key()));
        }
        Config::V3 { holoport_id, .. } => {
            println!("{}", holoport_id);
        }
    }

    Ok(())
}
