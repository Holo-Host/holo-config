use ed25519_dalek::VerifyingKey;
use failure::Error;

use crate::Config;

/// Can be used akin to a test fixture
pub(crate) async fn generate_test_hpos_config() -> Result<(Config, VerifyingKey), Error> {
    // emulate the UI

    let master = hc_seed_bundle::UnlockedSeedBundle::new_random()
        .await
        .unwrap();

    let passphrase = sodoken::BufRead::from(b"test-passphrase".to_vec());
    let revocation_bundle = master.derive(0).await.unwrap();
    let revocation_pub_key = revocation_bundle.get_sign_pub_key().read_lock().to_vec();

    let device_derivation_path = 2;
    let device_bundle = master.derive(device_derivation_path).await.unwrap();
    let device_bundle_encoded_bytes = device_bundle
        .lock()
        .add_pwhash_cipher(passphrase)
        .lock()
        .await
        .unwrap();
    let device_bundle_base64 = base64::encode(&device_bundle_encoded_bytes);

    // derive the holoport ID

    let holoport_id = device_bundle.derive(1).await.unwrap();

    let holoport_id = holoport_id.get_sign_pub_key().read_lock().to_vec();

    // initialize a new Config struct
    let email = "joel@holo.host".to_string();
    let password = "password".to_string();
    let registration_code = "registration-code".to_string();
    let rev_key_bytes = revocation_pub_key[0..32].try_into().unwrap();
    let revocation_pub_key = VerifyingKey::from_bytes(&rev_key_bytes).unwrap();
    let holoport_id_bytes = holoport_id[0..32].try_into().unwrap();
    let holoport_id = VerifyingKey::from_bytes(&holoport_id_bytes).unwrap();

    Config::new(
        // email: String,
        email.clone(),
        // password: String,
        password,
        // registration_code: String,
        registration_code,
        // revocation_pub_key: VerifyingKey,
        revocation_pub_key,
        // derivation_path: String,
        device_derivation_path.to_string(),
        // device_bundle: String,
        device_bundle_base64.clone(),
        // device_pub_key: VerifyingKey,
        holoport_id,
    )
}
