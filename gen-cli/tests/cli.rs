use assert_cmd::prelude::*;
use hpos_config_core::config::ConfigDiscriminants;
use once_cell::sync::Lazy;
// Add methods on commands
use std::{process::Command, str::FromStr}; // Run programs

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct TestedCliArgs {
    email: String,
    password: String,
    registration_code: String,
    device_bundle: Option<String>,
    config_version: Option<String>,
}

static HPOS_API_TESTS_MOCK_DATA_JSON: Lazy<TestedCliArgs> = Lazy::new(|| {
    /*
        TODO: where do we want to the authority to be for the main supported use-cases?
        per status-quo this test data is read from the test in holo-nixpkgs. we could also reverse the relationship.

       generated with:

       $ nix eval ../holo-nixpkgs#legacyPackages.x86_64-linux.tests.hpos-api-tests.nodes.machine.config.services.mock-hpos-config --json | jq .
    */
    let json = r#"
    {
        "autoStart": true,
        "configVersion": "v2",
        "deviceBundle": "k6VoY3NiMJGWonB3xBAp9K2BbqRJd0sS3pD1FHcGzhAAAAADxBhyjcHi1prEESr_g9g5aHDUaAm0CloHDBPEMSdaH_eSV94Qi_VUVZ626mV-dAYaHhcCNVbsJ06dWzMQnVtTaQQLtmW_o3qXFmBK6QrEAA",
        "email": "vhpos.18379@holotest.dev",
        "enable": true,
        "extraArgs": "",
        "outputPath": "/media/v/hp-config.json",
        "password": "17999p4ssw0rd10402",
        "registrationCode": "jQEAxhmwxrQq1duo7D6K/SiO92tLqNgo67sQ2uHolmlwGQ5y12ZrfFfFGiUvF3Kvf2Qx4aCtu6CYGZy9CtFonQ=="
    }"#;

    serde_json::from_str(json).unwrap()
});

#[test]
fn gen_with_device_bundle() -> Result<(), Box<dyn std::error::Error>> {
    let args = &HPOS_API_TESTS_MOCK_DATA_JSON;

    let mut cmd = Command::cargo_bin("hpos-config-gen-cli")?;

    let mut cmd_args = vec![
        "--email",
        &args.email,
        "--password",
        &args.password,
        "--registration-code",
        &args.registration_code,
    ];

    let config_version = if let Some(config_version) = &args.config_version {
        config_version.to_string()
    } else {
        ConfigDiscriminants::default().to_string()
    };
    let derivation_path = hpos_config_core::config::default_derivation_path(ConfigDiscriminants::from_str(&config_version)?);

    cmd_args.extend_from_slice(&["--config-version", &config_version]);

    if let Some(device_bundle) = &args.device_bundle {
        cmd_args.extend_from_slice(&["--device-bundle", device_bundle])
    }

    cmd.args(cmd_args);
    cmd.assert().success();

    let stdout = cmd.output().unwrap().stdout;
    let output = String::from_utf8_lossy(&stdout);

    println!("{output}");

    fn clean_str(src: &str) -> String {
        src.replace(['\n', ' '], "")
    }

    assert_eq!(
        clean_str(&output),
        clean_str(&format!(
            r#"
            {{
                "v2": {{
                    "device_bundle": "k6VoY3NiMJGWonB3xBAp9K2BbqRJd0sS3pD1FHcGzhAAAAADxBhyjcHi1prEESr_g9g5aHDUaAm0CloHDBPEMSdaH_eSV94Qi_VUVZ626mV-dAYaHhcCNVbsJ06dWzMQnVtTaQQLtmW_o3qXFmBK6QrEAA",
                    "derivation_path": "{derivation_path}",
                    "registration_code": "jQEAxhmwxrQq1duo7D6K/SiO92tLqNgo67sQ2uHolmlwGQ5y12ZrfFfFGiUvF3Kvf2Qx4aCtu6CYGZy9CtFonQ==",
                    "settings": {{
                        "admin": {{
                            "email": "vhpos.18379@holotest.dev",
                            "public_key": "8TH/5P1R21uOiCUOevs0f3FE2RwHiLXWoIjbqS8cxWU"
                        }}
                    }}
                }}
            }}
            "#
        ))
    );

    Ok(())
}
