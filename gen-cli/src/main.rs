use hpos_config_core::{
    config::{ConfigDiscriminants, Seed},
    public_key, Config,
};

use clap::Parser;
use ed25519_dalek::*;
use failure::{Error, ResultExt};
use sha2::{Digest, Sha512Trunc256};
use std::{fs::File, io};

#[derive(Parser, Clone)]
#[command(about = "Creates HoloPortOS config file that contains seed and admin email/password.")]
struct ClapArgs {
    #[arg(
        long,
        value_parser,
        value_name = "EMAIL",
        help = "HoloPort admin email address"
    )]
    email: String,
    #[arg(
        long,
        value_parser,
        value_name = "PASSWORD",
        help = "HoloPort admin password"
    )]
    password: String,
    #[arg(
        long,
        value_parser,
        value_name = "CODE",
        help = "HoloPort registration code"
    )]
    registration_code: String,
    #[arg(long, value_parser, value_name = "STRING", help = "Revocation key")]
    revocation_key: Option<String>,
    #[arg(
        long,
        value_parser,
        value_name = "PATH",
        help = "Derivation path of the seed"
    )]
    derivation_path: Option<u32>,
    #[arg(
        long,
        value_parser,
        value_name = "NUMBER",
        help = "HoloPort Device bundle"
    )]
    device_bundle: Option<String>,
    #[arg(
        long,
        value_parser,
        value_name = "PATH",
        help = "Use SHA-512 hash of given file, truncated to 256 bits, as seed"
    )]
    seed_from: Option<String>,

    #[arg(
        long,
        default_value_t = ConfigDiscriminants::default(),
        ignore_case = true,
        help = "Version specifier for the emitted config"
    )]
    config_version: ConfigDiscriminants,
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let args = ClapArgs::parse();

    let mut seed: Seed;

    let derivation_path = if let Some(derivation_path) = args.derivation_path {
        derivation_path
    } else {
        hpos_config_core::config::default_derivation_path(ConfigDiscriminants::default())
    };

    // TODO: don't hardcode this
    let passphrase = "pass";

    let device_bundle = if let Some(device_bundle) = args.device_bundle {
        seed = hpos_config_core::utils::unlock(&device_bundle, passphrase)
            .await?
            .to_scalar_bytes();

        device_bundle
    } else {
        let (locked_device_bundle_encoded_bytes, new_seed) =
            hpos_config_core::utils::generate_device_bundle(passphrase, Some(derivation_path))
                .await?;

        // TODO: does it make sense to get the seed from the bundle?
        seed = new_seed;

        base64::encode_config(&locked_device_bundle_encoded_bytes, base64::URL_SAFE_NO_PAD)
    };

    let _ = hpos_config_core::utils::unlock(&device_bundle, passphrase)
        .await
        .context(format!("unlocking {device_bundle} with {passphrase}"))?;

    if let Some(path) = args.seed_from {
        let mut hasher = Sha512Trunc256::new();
        let mut file = File::open(path)?;
        io::copy(&mut file, &mut hasher)?;

        seed = hasher.result().into();
    };

    // used as entropy when generating
    // used in context of the host console
    let secret_key = SigningKey::from_bytes(&seed);
    let revocation_key = match &args.revocation_key {
        None => VerifyingKey::from(&secret_key),
        Some(rk) => {
            let public_key_bytes: &[u8; PUBLIC_KEY_LENGTH] = rk.as_bytes().try_into()?;
            VerifyingKey::from_bytes(public_key_bytes)?
        }
    };

    let (config, public_key) = Config::new(
        // email: String,
        args.email,
        // password: String,
        args.password,
        // registration_code: String,
        args.registration_code,
        // revocation_pub_key: VerifyingKey,
        revocation_key,
        // derivation_path: String,
        derivation_path.to_string(),
        // device_bundle: String,
        device_bundle,
        // device_pub_key: VerifyingKey,
        VerifyingKey::from(&secret_key),
    )
    .and_then(|(config, public_key)| Ok((config.try_convert(args.config_version)?, public_key)))?;

    eprintln!("{}", public_key::to_url(&public_key)?);
    println!("{}", serde_json::to_string_pretty(&config)?);

    Ok(())
}
