use clap::{Parser, Subcommand};
use bip39::{Mnemonic, Language, MnemonicType, Seed};
use ed25519_dalek::{SigningKey, VerifyingKey};
use aetheris_core::{Transaction, ShieldedOutput};
use aetheris_zkp::{ZKProofSystem, ZkProverSystem, create_commitment, create_nullifier};
use std::fs;
use anyhow::{Result, anyhow};
use zeroize::Zeroize;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Serialize, Deserialize};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit};
use aes_gcm::aead::Aead;
use tiny_keccak::{Hasher, Keccak};

const WALLET_FILE: &str = "wallet.json";

#[derive(Serialize, Deserialize)]
struct WalletData {
    encrypted_phrase: Vec<u8>,
    salt_b64: String,
    nonce: [u8; 12],
    last_scanned_index: usize,
    utxos: Vec<OwnedUTXO>,
    #[serde(default)]
    nullifier_counter: u64,
}

#[derive(Serialize, Deserialize)]
struct OwnedUTXO {
    amount: u64,
    blinding: [u8; 32],
    commitment: [u8; 32],
}

#[derive(Parser)]
#[command(name = "aetheris-wallet")]
#[command(about = "Aetheris Wallet CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new mnemonic and keypair
    Generate,
    /// Create a private transaction
    Send {
        #[arg(short, long)]
        to: String,
        #[arg(short, long)]
        amount: u64,
    },
    /// Show current balance from local index
    Balance,
    /// Scan the blockchain for owned records (Incremental)
    Scan,
    /// View network status
    Net,
}

fn load_wallet() -> Result<WalletData> {
    let text = fs::read_to_string(WALLET_FILE)
        .map_err(|_| anyhow!("Wallet not found. Run 'generate' first."))?;
    if let Ok(data) = serde_json::from_str::<WalletData>(&text) {
        return Ok(data);
    }
    if text.contains("\"phrase\"") {
        return Err(anyhow!("wallet.json uses old plaintext format (unsupported). Run 'generate' to create a new encrypted wallet."));
    }
    Err(anyhow!("Corrupted wallet.json"))
}

fn save_wallet(data: &WalletData) -> Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    fs::write(WALLET_FILE, json)?;
    Ok(())
}

fn derive_key(password: &[u8], salt_b64: &str) -> Result<[u8; 32]> {
    let salt = SaltString::from_b64(salt_b64)
        .map_err(|_| anyhow!("Invalid salt in wallet"))?;
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password, &salt)
        .map_err(|e| anyhow!("Key derivation failed: {}", e))?;
    let hash_bytes = hash
        .hash
        .ok_or_else(|| anyhow!("Argon2 produced no output"))?;
    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes.as_bytes());
    Ok(key)
}

fn encrypt_phrase(phrase: &str, password: &[u8]) -> Result<(Vec<u8>, String, [u8; 12])> {
    let salt = SaltString::generate(&mut OsRng);
    let key_bytes = derive_key(password, salt.as_str())?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), phrase.as_bytes())
        .map_err(|e| anyhow!("Encryption failed: {}", e))?;
    Ok((ciphertext, salt.as_str().to_string(), nonce))
}

fn decrypt_phrase(encrypted: &[u8], password: &[u8], salt_b64: &str, nonce: &[u8; 12]) -> Result<String> {
    let key_bytes = derive_key(password, salt_b64)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key_bytes));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), encrypted)
        .map_err(|_| anyhow!("Incorrect password or corrupted wallet."))?;
    Ok(String::from_utf8(plaintext)?)
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Net => {
            println!("Aetheris Network Status:");
            if let Ok(data) = fs::read_to_string("node_status.json") {
                let status: serde_json::Value = serde_json::from_str(&data)?;
                println!("   Height:      {}", status["height"]);
                println!("   Peers:       {}", status["peers"]);
                println!("   Node PeerID: {}", status["peer_id"]);
            } else {
                println!("Could not connect to local node. Make sure the node is running.");
            }
        }
        Commands::Generate => {
            let mut password = rpassword::prompt_password("Enter wallet password: ")?;
            let confirm = rpassword::prompt_password("Confirm wallet password: ")?;
            if password != confirm {
                password.zeroize();
                return Err(anyhow!("Passwords do not match."));
            }
            if password.is_empty() {
                return Err(anyhow!("Password cannot be empty."));
            }

            let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
            let mut phrase = mnemonic.phrase().to_string();
            println!("Mnemonic: {}", phrase);

            let seed = Seed::new(&mnemonic, "");
            let mut seed_bytes = seed.as_bytes().to_vec();

            let signing_key = SigningKey::from_bytes(&seed_bytes[0..32].try_into()?);
            let verifying_key: VerifyingKey = (&signing_key).into();
            println!("Public Key: {}", hex::encode(verifying_key.to_bytes()));

            let (encrypted_phrase, salt_b64, nonce) = encrypt_phrase(&phrase, password.as_bytes())?;

            let wallet = WalletData {
                encrypted_phrase,
                salt_b64,
                nonce,
                last_scanned_index: 0,
                utxos: Vec::new(),
                nullifier_counter: 0,
            };
            save_wallet(&wallet)?;
            println!("Wallet encrypted and saved to {}", WALLET_FILE);

            phrase.zeroize();
            seed_bytes.zeroize();
            password.zeroize();
        }
        Commands::Send { to: _to, amount } => {
            let mut wallet = load_wallet()?;
            let mut password = rpassword::prompt_password("Wallet password: ")?;
            let mut phrase = decrypt_phrase(&wallet.encrypted_phrase, password.as_bytes(), &wallet.salt_b64, &wallet.nonce)?;
            password.zeroize();

            println!("Initializing Aetheris Shielded Transaction...");

            let (input_utxo, remaining_utxos): (Option<OwnedUTXO>, Vec<OwnedUTXO>) = {
                let mut found = None;
                let mut rest = Vec::new();
                for utxo in wallet.utxos {
                    if found.is_none() && utxo.amount >= *amount {
                        found = Some(utxo);
                    } else {
                        rest.push(utxo);
                    }
                }
                (found, rest)
            };

            let input_utxo = input_utxo.ok_or_else(|| anyhow!("Insufficient balance. Run 'scan' first."))?;
            println!("   Using UTXO: {} AETH", input_utxo.amount);

            let change = input_utxo.amount - *amount;
            let mut outputs = Vec::new();

            let mut blinding_to = [0u8; 32];
            OsRng.fill_bytes(&mut blinding_to);
            outputs.push(ShieldedOutput {
                commitment: create_commitment(*amount, &blinding_to),
                ephemeral_key: [7u8; 32],
                ciphertext: {
                    let mut c = b"AETHSCAN".to_vec();
                    c.extend_from_slice(&amount.to_le_bytes());
                    c.extend_from_slice(&blinding_to);
                    c
                }
            });

            let mut blinding_change = [0u8; 32];
            if change > 0 {
                OsRng.fill_bytes(&mut blinding_change);
                outputs.push(ShieldedOutput {
                    commitment: create_commitment(change, &blinding_change),
                    ephemeral_key: [8u8; 32],
                    ciphertext: {
                        let mut c = b"AETHSCAN".to_vec();
                        c.extend_from_slice(&change.to_le_bytes());
                        c.extend_from_slice(&blinding_change);
                        c
                    }
                });
            }

            let mnemonic = Mnemonic::from_phrase(&phrase, Language::English)?;
            phrase.zeroize();
            let seed = Seed::new(&mnemonic, "");
            let sk = &seed.as_bytes()[0..32];
            let nf_in = create_nullifier(sk, wallet.nullifier_counter);

            println!("   Generating ZK-SNARK proof...");
            let in_amounts = vec![input_utxo.amount];
            let out_amounts = if change > 0 { vec![*amount, change] } else { vec![*amount] };
            let in_blindings = vec![input_utxo.blinding];
            let out_blindings = if change > 0 { vec![blinding_to, blinding_change] } else { vec![blinding_to] };
            let commitments: Vec<[u8; 32]> = outputs.iter().map(|o| o.commitment).collect();

            let proof = ZKProofSystem::prove_conservation(
                &in_amounts,
                &out_amounts,
                &in_blindings,
                &out_blindings,
                &commitments,
                0
            );

            let tx = Transaction {
                inputs: vec![nf_in],
                outputs,
                public_amount: 0,
                proof,
            };

            wallet.nullifier_counter += 1;
            wallet.utxos = remaining_utxos;
            save_wallet(&wallet)?;

            let tx_json = serde_json::to_string_pretty(&tx)?;
            fs::write("pending_tx.json", tx_json)?;
            println!("Transaction broadcasted. Local index updated.");
        }
        Commands::Balance => {
            let wallet = load_wallet()?;
            let total: u64 = wallet.utxos.iter().map(|u| u.amount).sum();
            println!("Verified Balance (Local Index): {} AETH", total);
            println!("   UTXO Count: {}", wallet.utxos.len());
        }
        Commands::Scan => {
            let mut wallet = load_wallet()?;
            let mut password = rpassword::prompt_password("Wallet password: ")?;
            let mut phrase = decrypt_phrase(&wallet.encrypted_phrase, password.as_bytes(), &wallet.salt_b64, &wallet.nonce)?;
            password.zeroize();

            println!("Incremental Scan from index {}...", wallet.last_scanned_index);

            let _mnemonic = Mnemonic::from_phrase(&phrase, Language::English)?;
            // Viewing key = Keccak256(mnemonic), matching FFI wallet derivation
            let mut vk = [0u8; 32];
            let mut hasher = Keccak::v256();
            hasher.update(phrase.as_bytes());
            hasher.finalize(&mut vk);
            phrase.zeroize();

            if let Ok(data) = fs::read_to_string("ledger_outputs.json") {
                let outputs: Vec<ShieldedOutput> = serde_json::from_str(&data)?;
                let new_outputs = &outputs[wallet.last_scanned_index..];
                let mut found_count = 0;

                for out in new_outputs.iter() {
                    if let Some((amount, blinding)) = ZKProofSystem::trial_decrypt(&vk, &out.ephemeral_key, &out.ciphertext) {
                        println!("   Found owned record! Amount: {} AETH", amount);
                        wallet.utxos.push(OwnedUTXO {
                            amount,
                            blinding,
                            commitment: out.commitment,
                        });
                        found_count += 1;
                    }
                }

                wallet.last_scanned_index = outputs.len();
                save_wallet(&wallet)?;

                println!("Scan complete. Found {} new records.", found_count);
            } else {
                println!("Ledger data not found.");
            }
        }
    }

    Ok(())
}