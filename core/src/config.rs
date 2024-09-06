use arrayref::array_ref;
use ed25519_dalek::{Digest, Sha512, SigningKey, VerifyingKey};
use failure::{bail, Error};
use serde::*;
use strum::{EnumDiscriminants, EnumString, VariantNames};

use crate::public_key;
pub const SEED_SIZE: usize = 32;

fn public_key_from_base64<'de, D>(deserializer: D) -> Result<VerifyingKey, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)
        .and_then(|s| {
            base64::decode_config(s, base64::STANDARD_NO_PAD)
                .map_err(|err| de::Error::custom(err.to_string()))
        })
        .map(|bytes| match bytes[0..32].try_into() {
            Ok(b) => VerifyingKey::from_bytes(&b).map_err(|e| e.to_string()),
            Err(_) => Err("Public key is not 32 bytes long".to_string()),
        })
        .and_then(|maybe_key| maybe_key.map_err(|err| de::Error::custom(err.to_string())))
}

pub fn seed_from_base64<'de, D>(deserializer: D) -> Result<Seed, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer)
        .and_then(|s| base64::decode(s).map_err(|err| de::Error::custom(err.to_string())))
        .map(|bytes| *array_ref!(bytes, 0, SEED_SIZE))
}

fn to_base64<T, S>(x: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    T: AsRef<[u8]>,
    S: Serializer,
{
    serializer.serialize_str(&base64::encode_config(x.as_ref(), base64::STANDARD_NO_PAD))
}

const ARGON2_ADDITIONAL_DATA: &[u8] = b"hpos-config admin ed25519 key v1";

pub type Seed = [u8; SEED_SIZE];

#[cfg_attr(test, derive(Clone, PartialEq))]
#[derive(Debug, Deserialize, Serialize)]
pub struct Admin {
    pub email: String,
    #[serde(
        deserialize_with = "public_key_from_base64",
        serialize_with = "to_base64"
    )]
    pub public_key: VerifyingKey,
}

#[cfg_attr(test, derive(Clone, PartialEq))]
#[derive(Debug, Deserialize, Serialize)]
pub struct Settings {
    pub admin: Admin,
}

/// Returns the default derivation path per config version.
pub const fn default_derivation_path(config: ConfigDiscriminants) -> u32 {
    match config {
        // TODO: what should these be?
        ConfigDiscriminants::V1 => 2,
        ConfigDiscriminants::V2 => 2,
        ConfigDiscriminants::V3 => 2,
    }
}

#[allow(clippy::large_enum_variant)]
#[cfg_attr(test, derive(Clone, PartialEq))]
#[derive(Debug, Deserialize, Serialize, EnumDiscriminants)]
#[strum_discriminants(
    derive(VariantNames, EnumString, strum::Display, Default),
    strum(ascii_case_insensitive)
)]
pub enum Config {
    #[serde(rename = "v1")]
    V1 {
        #[serde(deserialize_with = "seed_from_base64", serialize_with = "to_base64")]
        seed: Seed,
        settings: Settings,
    },
    #[serde(rename = "v2")]
    V2 {
        /// This is the Device Seed Bundle as a base64 string which is compatible with lair-keystore >=v0.0.8
        device_bundle: String,
        /// Derivation path of the seed in this config that was generated for a Master Seed
        derivation_path: String,
        /// Holo registration code is used to identify and authenticate its users
        registration_code: String,
        /// The pub-key in settings is the holoport key that is used for verifying login signatures
        settings: Settings,
    },
    #[serde(rename = "v3")]
    #[strum_discriminants(default)]
    V3 {
        /// This is the Device Seed Bundle as a base64 string which is compatible with lair-keystore >=v0.0.8
        /// And is encoded with a password that will be needed to be used to decrypt it
        device_bundle: String,
        /// Derivation path of the seed in this config that was generated for a Master Seed
        device_derivation_path: String,
        // The revocation key is usually the /0 derivation path of the master seed
        #[serde(
            deserialize_with = "public_key_from_base64",
            serialize_with = "to_base64"
        )]
        revocation_pub_key: VerifyingKey,
        // /1 derivation path of the device bundle base36 encoded
        holoport_id: String,
        /// Holo registration code is used to identify and authenticate its users
        // This is a HoloHash version of the holoport_id
        initial_host_pub_key: String,
        registration_code: String,
        /// The pub-key in settings is the holoport key that is used for verifying login signatures
        settings: Settings,
    },
}

impl Config {
    pub fn new(
        email: String,
        password: String,
        registration_code: String,
        revocation_pub_key: VerifyingKey,
        device_derivation_path: String,
        device_bundle: String,
        device_pub_key: VerifyingKey,
    ) -> Result<(Self, VerifyingKey), Error> {
        let admin_keypair = admin_keypair_from(device_pub_key, &email, &password)?;
        let admin = Admin {
            email,
            public_key: admin_keypair.verifying_key(),
        };
        let holoport_id = public_key::to_base36_id(&device_pub_key);
        Ok((
            Config::V3 {
                device_bundle,
                device_derivation_path,
                revocation_pub_key,
                holoport_id,
                initial_host_pub_key: public_key::to_holochain_encoded_agent_key(&device_pub_key),
                registration_code,
                settings: Settings { admin },
            },
            device_pub_key,
        ))
    }

    pub fn email(&self) -> String {
        match self {
            Config::V1 { settings, .. }
            | Config::V2 { settings, .. }
            | Config::V3 { settings, .. } => settings.admin.email.clone(),
        }
    }

    pub fn admin_public_key(&self) -> VerifyingKey {
        match self {
            Config::V1 { settings, .. }
            | Config::V2 { settings, .. }
            | Config::V3 { settings, .. } => settings.admin.public_key,
        }
    }

    /// Try to convert Config instance to the desired ConfigDiscriminants.
    /// As some conversions are impossible they will return an error accordingly.
    pub fn try_convert(self, desired: ConfigDiscriminants) -> Result<Self, Error> {
        match (self, desired) {
            (cfg @ Config::V1 { .. }, ConfigDiscriminants::V1) => Ok(cfg),
            (Config::V1 { .. }, ConfigDiscriminants::V2) => bail!("cannot convert V1 to V2"),
            (Config::V1 { .. }, ConfigDiscriminants::V3) => bail!("cannot convert V1 to V3"),
            (
                Config::V2 {
                    device_bundle,
                    derivation_path,
                    registration_code,
                    settings,
                },
                ConfigDiscriminants::V1,
            ) => Ok(Config::V2 {
                device_bundle,
                derivation_path,
                registration_code,
                settings,
            }),
            (cfg @ Config::V2 { .. }, ConfigDiscriminants::V2) => Ok(cfg),
            (Config::V2 { .. }, ConfigDiscriminants::V3) => bail!("cannot convert V2 to V3"),
            (
                Config::V3 {
                    // device_bundle,
                    // settings,
                    ..
                },
                ConfigDiscriminants::V1,
            ) => {
                unimplemented!("convert V3 to V1 (lossy)");
            }
            (
                Config::V3 {
                    device_bundle,
                    device_derivation_path,
                    registration_code,
                    settings,
                    ..
                },
                ConfigDiscriminants::V2,
            ) => Ok(Config::V2 {
                device_bundle,
                derivation_path: device_derivation_path,
                registration_code,
                settings,
            }),
            (cfg @ Config::V3 { .. }, ConfigDiscriminants::V3) => Ok(cfg),
        }
    }
}

// fn generate_keypair(
//     email: String,
//     password: String,
//     maybe_seed: Option<Seed>,
// ) -> Result<(Seed, Keypair, VerifyingKey), Error> {
//     let master_seed = match maybe_seed {
//         None => OsRng::new()?.gen::<Seed>(),
//         Some(s) => s,
//     };
//     let master_secret_key = SecretKey::from_bytes(&master_seed)?;
//     let master_public_key = VerifyingKey::from(&master_secret_key);
//     let admin_keypair = admin_keypair_from(master_public_key, &email, &password)?;
//     Ok((master_seed, admin_keypair, master_public_key))
// }

pub fn admin_keypair_from(
    holochain_public_key: VerifyingKey,
    email: &str,
    password: &str,
) -> Result<SigningKey, Error> {
    // This allows to use email addresses shorter than 8 bytes.
    let salt = Sha512::digest(email.as_bytes());
    let mut hash = [0; SEED_SIZE];

    argon2min::Argon2::new(2, 4, 1 << 16, argon2min::Variant::Argon2id)?.hash(
        &mut hash,
        password.as_bytes(),
        &salt,
        &holochain_public_key.to_bytes(),
        ARGON2_ADDITIONAL_DATA,
    );

    Ok(SigningKey::from_bytes(&hash))
}

#[cfg(test)]
mod tests {
    use crate::{test_utils::generate_test_hpos_config, Config};

    #[tokio::test]
    async fn convert_v3_to_v2() {
        let (config, _) = generate_test_hpos_config().await.unwrap();

        // ensure we start with a v3 config
        let v3 = config
            .clone()
            .try_convert(crate::config::ConfigDiscriminants::V3)
            .unwrap();
        assert_eq!(config, v3);

        let v2 = config
            .clone()
            .try_convert(crate::config::ConfigDiscriminants::V2)
            .unwrap();

        if let Config::V2 {
            device_bundle,
            derivation_path,
            registration_code,
            settings,
        } = v2
        {
            let v2_device_bundle = device_bundle;
            let v2_derivation_path = derivation_path;
            let v2_registration_code = registration_code;
            let v2_settings = settings;

            if let Config::V3 {
                device_bundle,
                device_derivation_path,
                registration_code,
                settings,
                ..
            } = config
            {
                assert_eq!(v2_device_bundle, device_bundle);
                assert_eq!(v2_derivation_path, device_derivation_path);
                assert_eq!(v2_registration_code, registration_code);
                assert_eq!(v2_settings, settings);
            } else {
                panic!("config isn't v3");
            };
        } else {
            panic!("must match v2");
        }
    }
}
