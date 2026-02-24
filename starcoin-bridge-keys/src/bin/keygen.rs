// Bridge Authority Key Generation Tool
// Generates Secp256k1 keypairs for bridge validators

use anyhow::Result;
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "keygen")]
#[command(about = "Generate Secp256k1 keypairs for Starcoin Bridge", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate bridge authority key (validator key)
    Authority {
        /// Output file path for the generated key
        #[arg(short, long)]
        output: PathBuf,
    },
    /// Generate bridge client key
    Client {
        /// Output file path for the generated key
        #[arg(short, long)]
        output: PathBuf,

        /// Use ECDSA (Secp256k1) instead of Ed25519
        #[arg(long, default_value = "false")]
        ecdsa: bool,
    },
    /// Examine an existing key file
    Examine {
        /// Path to the key file to examine
        path: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Authority { output } => {
            println!("Generating bridge authority key (Secp256k1)...");
            starcoin_bridge_keys::keygen::generate_bridge_authority_key_and_write_to_file(&output)?;
            println!("\n✓ Bridge authority key generated successfully!");
            println!("  File: {:?}", output);

            // Print derived Ethereum address so automation can parse it.
            // Format is intentionally stable: "Ethereum address: 0x..."
            examine_key_file(&output)?;

            println!("\nIMPORTANT:");
            println!("  1. Keep this key file secure and backed up");
            println!(
                "  2. Update your bridge config 'bridge_authority_key_path' to point to this file"
            );
        }
        Commands::Client { output, ecdsa } => {
            let key_type = if ecdsa { "Secp256k1" } else { "Ed25519" };
            println!("Generating bridge client key ({})...", key_type);
            starcoin_bridge_keys::keygen::generate_bridge_client_key_and_write_to_file(
                &output, ecdsa,
            )?;
            println!("\n✓ Bridge client key generated successfully!");
            println!("  File: {:?}", output);
        }
        Commands::Examine { path } => {
            println!("Examining key file: {:?}", path);
            examine_key_file(&path)?;
        }
    }

    Ok(())
}

fn examine_key_file(path: &PathBuf) -> Result<()> {
    use fastcrypto::traits::{KeyPair, ToFromBytes};
    use starcoin_bridge_keys::keypair_file::read_key;
    use starcoin_bridge_keys::StarcoinKeyPair;

    let key = read_key(path, false)?;

    match key {
        StarcoinKeyPair::Secp256k1(kp) => {
            println!("Key type: Secp256k1");
            println!("Public key (hex): {}", hex::encode(kp.public().as_bytes()));

            // Calculate Ethereum address correctly using k256 to decompress
            use k256::elliptic_curve::sec1::ToEncodedPoint;
            use k256::PublicKey;
            use sha3::{Digest, Keccak256};

            let compressed_bytes = kp.public().as_bytes();
            let pk = PublicKey::from_sec1_bytes(compressed_bytes).expect("Invalid public key");
            let uncompressed = pk.to_encoded_point(false);
            let pubkey_bytes = &uncompressed.as_bytes()[1..]; // Skip 0x04 prefix
            let hash = Keccak256::digest(pubkey_bytes);
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&hash[12..]);
            println!("Ethereum address: 0x{}", hex::encode(addr));
        }
        StarcoinKeyPair::Ed25519(kp) => {
            println!("Key type: Ed25519");
            println!("Public key (hex): {}", hex::encode(kp.public().as_bytes()));
        }
    }

    Ok(())
}
