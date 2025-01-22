use ed25519_dalek::SigningKey;
use failure::{bail, ResultExt};
use log::debug;

use crate::{
    config::{self, ConfigDiscriminants, Seed},
    types::{SeedExplorerError, SeedExplorerResult},
};
use hc_seed_bundle::{LockedSeedCipher, UnlockedSeedBundle};

pub fn get_seed_from_bundle(device_bundle: &UnlockedSeedBundle) -> Result<Seed, failure::Error> {
    let mut seed = Seed::default();

    let bundle_seed = device_bundle
        .get_seed()
        .read_lock()
        .iter()
        .cloned()
        .collect::<Vec<_>>();

    if bundle_seed.len() != seed.len() {
        bail!(
            "bundle_seed.len() ({}) != seed.len() ({}",
            bundle_seed.len(),
            seed.len()
        );
    }

    for (i, b) in seed.iter_mut().enumerate() {
        *b = if let Some(source) = bundle_seed.get(i) {
            *source
        } else {
            bail!("couldn't get index {i} in {bundle_seed}");
        };
    }

    Ok(seed)
}

/// Generate a new device bundle and lock it with the given passphrase.
pub async fn generate_device_bundle(
    passphrase: &str,
    maybe_derivation_path: Option<u32>,
) -> Result<(Box<[u8]>, Seed), failure::Error> {
    let passphrase = sodoken::BufRead::from(passphrase.as_bytes());
    let master = hc_seed_bundle::UnlockedSeedBundle::new_random()
        .await
        .unwrap();

    let derivation_path = maybe_derivation_path.unwrap_or(config::default_derivation_path(
        ConfigDiscriminants::default(),
    ));

    let device_bundle = master.derive(derivation_path).await.unwrap();

    let seed = get_seed_from_bundle(&device_bundle)?;

    let locked_bundle = device_bundle
        .lock()
        .add_pwhash_cipher(passphrase)
        .lock()
        .await?;

    Result::<_, failure::Error>::Ok((locked_bundle, seed))
}

/// Unlock the given device bundle with the given password.
async fn _get_seed_from_locked_device_bundle(
    locked_device_bundle: &[u8],
    passphrase: &str,
) -> Result<Seed, failure::Error> {
    let passphrase = sodoken::BufRead::from(passphrase.as_bytes());
    let unlocked_bundle =
        match hc_seed_bundle::UnlockedSeedBundle::from_locked(locked_device_bundle)
            .await
            .context("getting seed from locked device bundle")?
            .remove(0)
        {
            hc_seed_bundle::LockedSeedCipher::PwHash(cipher) => {
                cipher.unlock(passphrase).await.context("unlocking cipher")
            }
            oth => bail!("unexpected cipher: {:?}", oth),
        }?;

    let seed =
        get_seed_from_bundle(&unlocked_bundle).context("getting seed from unlocked bundle")?;

    Ok(seed)
}

/// unlock seed_bundles to access the pub-key and seed
pub async fn unlock(device_bundle: &String, passphrase: &str) -> SeedExplorerResult<SigningKey> {
    debug!("Base64 decoding device bundle.");
    if device_bundle.is_empty() {
        return Err(SeedExplorerError::Generic(
            "called with device_bundle".into(),
        ));
    }

    let cipher = base64::decode_config(device_bundle, base64::URL_SAFE_NO_PAD)?;
    debug!("Matching device bundle cipher.");
    match UnlockedSeedBundle::from_locked(&cipher).await?.remove(0) {
        LockedSeedCipher::PwHash(cipher) => {
            debug!("PwHash cipher used and password present.");
            let passphrase = sodoken::BufRead::from(passphrase.as_bytes().to_vec());
            debug!("Unlocking seed with passphrase.");
            let seed = cipher.unlock(passphrase).await?;

            debug!("Casting seed to 32-byte slice.");
            let seed_bytes: [u8; 32] = match (&*seed.get_seed().read_lock())[0..32].try_into() {
                Ok(b) => b,
                Err(_) => {
                    debug!("Seed not 32 bytes: {:?}", &seed.get_seed());
                    return Err(SeedExplorerError::Generic(
                        "Seed buffer is not 32 bytes long".into(),
                    ));
                }
            };

            Ok(SigningKey::from_bytes(&seed_bytes))
        }
        _ => Err(SeedExplorerError::UnsupportedCipher),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use failure::ResultExt;

    use super::*;

    const PASSPHRASE: &str = "p4ssw0rd";
    const WRONG_PASSPHRASE: &str = "wr0ngp4ssw0rd";

    pub(crate) async fn generate_base64() -> String {
        let (device_bundle, _) = generate_device_bundle(PASSPHRASE, None).await.unwrap();

        base64::encode_config(&device_bundle, base64::URL_SAFE_NO_PAD)
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unlock_correct_password_succeeds() {
        let encoded_device_bundle = generate_base64().await;

        unlock(&encoded_device_bundle, WRONG_PASSPHRASE)
            .await
            .context(format!(
                "unlocking {encoded_device_bundle} with {PASSPHRASE}"
            ))
            .unwrap_err();

        unlock(&encoded_device_bundle, PASSPHRASE)
            .await
            .context(format!(
                "unlocking {encoded_device_bundle} with {PASSPHRASE}"
            ))
            .unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn unlock_wrong_password_fails() {
        let encoded_device_bundle = generate_base64().await;
        unlock(&encoded_device_bundle, WRONG_PASSPHRASE)
            .await
            .context(format!(
                "unlocking {encoded_device_bundle} with {PASSPHRASE}"
            ))
            .unwrap_err();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn extract_seed_from_locked_succeeds() {
        let encoded_device_bundle = generate_base64().await;
        let device_bundle =
            base64::decode_config(&encoded_device_bundle, base64::URL_SAFE_NO_PAD).unwrap();

        let a = _get_seed_from_locked_device_bundle(&device_bundle, PASSPHRASE)
            .await
            .unwrap();

        let b = unlock(&encoded_device_bundle, PASSPHRASE).await.unwrap();

        assert_eq!(a, *b.as_bytes());
    }
}
