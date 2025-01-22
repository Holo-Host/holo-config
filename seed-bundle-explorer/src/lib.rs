use ed25519_dalek::{SigningKey, VerifyingKey};
use hpos_config_core::{types::*, utils::unlock, Config};

/// get pub key for the device bundle in the config
pub async fn holoport_public_key(
    config: &Config,
    maybe_passphrase: Option<String>,
) -> SeedExplorerResult<VerifyingKey> {
    match config {
        Config::V1 { seed, .. } => {
            let secret_key = SigningKey::from_bytes(seed);
            Ok(VerifyingKey::from(&secret_key))
        }
        Config::V2 { device_bundle, .. } => {
            /*
                decode base64 string to locked device bundle
                password is pass for now
                unlock it and get the signPubKey
            */
            let secret = unlock(
                device_bundle,
                &maybe_passphrase.ok_or(SeedExplorerError::PasswordRequired)?,
            )
            .await?;
            Ok(secret.verifying_key())
        }
        Config::V3 { holoport_id, .. } => {
            let value = match (base36::decode(&holoport_id)
                .map_err(|err| SeedExplorerError::Generic(err.to_string()))?)[0..32]
                .try_into()
            {
                Ok(b) => b,
                Err(_) => {
                    return Err(SeedExplorerError::Generic(
                        "Holoport host public key is not 32 bytes in length".into(),
                    ))
                }
            };
            Ok(VerifyingKey::from_bytes(&value)?)
        }
    }
}

/// get key for the device bundle in the config
pub async fn holoport_key(
    config: &Config,
    maybe_passphrase: Option<String>,
) -> SeedExplorerResult<SigningKey> {
    match config {
        Config::V1 { seed, .. } => Ok(SigningKey::from_bytes(seed)),
        Config::V2 { device_bundle, .. } | Config::V3 { device_bundle, .. } => {
            /*
                decode base64 string to locked device bundle
                password is pass for now
                unlock it and get the signPubKey
            */

            unlock(
                device_bundle,
                &maybe_passphrase.ok_or(SeedExplorerError::PasswordRequired)?,
            )
            .await
        }
    }
}

/// encode the ed25519 keypair making it compatible with lair (<v0.0.6)
pub async fn encoded_ed25519_keypair(
    config: &Config,
    maybe_passphrase: Option<String>,
) -> SeedExplorerResult<String> {
    match config {
        Config::V1 { seed, .. } => {
            let secret_key = SigningKey::from_bytes(seed);
            Ok(encrypt_key(&secret_key, &VerifyingKey::from(&secret_key)))
        }
        Config::V2 { device_bundle, .. } | Config::V3 { device_bundle, .. } => {
            /*
                decode base64 string to locked device bundle
                password is pass for now
                unlock it and get the signPubKey
                Pass the Seed and VerifyingKey into `encrypt_key(seed, pubKey)`
            */
            let secret = unlock(
                device_bundle,
                &maybe_passphrase.ok_or(SeedExplorerError::PasswordRequired)?,
            )
            .await?;
            Ok(encrypt_key(&secret, &secret.verifying_key()))
        }
    }
}

/// decode the ed25519 keypair making it compatible with lair (<v0.0.6)
pub fn decoded_to_ed25519_keypair(blob: &String) -> SeedExplorerResult<SigningKey> {
    let decoded_key = base64::decode(blob)?;

    let decoded_key_bytes: [u8; 32] = match decoded_key[64..].try_into() {
        Ok(b) => b,
        Err(_) => {
            return Err(SeedExplorerError::Generic(
                "Unable to extract private key starting at position 64".into(),
            ))
        }
    };

    Ok(SigningKey::from_bytes(&decoded_key_bytes))
}

// todo: we need to update this for production
/// For now lair does not take in any encrypted bytes so we pass back an empty encrypted byte string
pub fn encrypt_key(seed: &SigningKey, public_key: &VerifyingKey) -> String {
    let mut encrypted_key = vec![
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0,
    ];
    encrypted_key.extend(&public_key.to_bytes());
    encrypted_key.extend(seed.to_bytes());
    base64::encode(&encrypted_key)
}
