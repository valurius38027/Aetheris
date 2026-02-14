use clap::{Parser, Subcommand};
use bip39::{Mnemonic, Language, MnemonicType, Seed};
use ed25519_dalek::{SigningKey, VerifyingKey};
use aetheris_core::{Transaction, ShieldedOutput};
use aetheris_zkp::{ZKProofSystem, create_commitment, create_nullifier};
use std::fs;
use anyhow::{Result, anyhow};
use zeroize::Zeroize;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Default)]
struct WalletData {
    phrase: String,
    last_scanned_index: usize,
    utxos: Vec<OwnedUTXO>,
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
    if let Ok(data) = fs::read_to_string("wallet.json") {
        Ok(serde_json::from_str(&data)?)
    } else {
        Err(anyhow!("Wallet not found. Run 'generate' first."))
    }
}

fn save_wallet(data: &WalletData) -> Result<()> {
    let json = serde_json::to_string_pretty(data)?;
    fs::write("wallet.json", json)?;
    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Net => {
            println!("🌐 Aetheris Network Status:");
            if let Ok(data) = fs::read_to_string("node_status.json") {
                let status: serde_json::Value = serde_json::from_str(&data)?;
                println!("   Height:      {}", status["height"]);
                println!("   Peers:       {}", status["peers"]);
                println!("   Node PeerID: {}", status["peer_id"]);
            } else {
                println!("❌ Could not connect to local node. Make sure the node is running.");
            }
        }
        Commands::Generate => {
            let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
            let mut phrase = mnemonic.phrase().to_string();
            println!("Mnemonic: {}", phrase);
            
            let seed = Seed::new(&mnemonic, "");
            let mut seed_bytes = seed.as_bytes().to_vec();
            
            let signing_key = SigningKey::from_bytes(&seed_bytes[0..32].try_into()?);
            let verifying_key: VerifyingKey = (&signing_key).into();
            
            println!("Public Key: {}", hex::encode(verifying_key.to_bytes()));
            
            let wallet = WalletData {
                phrase: phrase.clone(),
                ..Default::default()
            };
            save_wallet(&wallet)?;
            println!("Wallet saved to wallet.json");

            phrase.zeroize();
            seed_bytes.zeroize();
        }
        Commands::Send { to: _to, amount } => {
            let mut wallet = load_wallet()?;
            println!("🔒 Initializing Aetheris Shielded Transaction...");
            
            // 1. Select UTXO (Simplified: take first sufficient)
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

            let input_utxo = input_utxo.ok_or_else(|| anyhow!("Insufficient balance in local index. Run 'scan' first."))?;
            
            println!("   Using UTXO: {} AETH", input_utxo.amount);
            
            // 2. Create Change Output if needed
            let change = input_utxo.amount - *amount;
            let mut outputs = Vec::new();
            
            // Recipient Output
            let blinding_to = [1u8; 32]; // In production, randomized
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

            // Change Output
            if change > 0 {
                let blinding_change = [2u8; 32];
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
            
            // 3. Create Nullifier for input
            let sk = [0u8; 32]; // Mocked
            let nf_in = create_nullifier(&sk, 0); 
            
            // 4. ZK Proof
            println!("   Generating ZK-SNARK proof...");
            let in_amounts = vec![input_utxo.amount];
            let out_amounts = if change > 0 { vec![*amount, change] } else { vec![*amount] };
            let in_blindings = vec![input_utxo.blinding];
            let out_blindings = if change > 0 { vec![[1u8; 32], [2u8; 32]] } else { vec![[1u8; 32]] };
            let commitments: Vec<[u8; 32]> = outputs.iter().map(|o| o.commitment).collect();
            
            let proof = ZKProofSystem::prove_conservation(
                &in_amounts, 
                &out_amounts,
                &in_blindings,
                &out_blindings,
                &commitments,
                0 // public_amount
            );
            
            let tx = Transaction {
                inputs: vec![nf_in],
                outputs,
                public_amount: 0,
                proof,
            };
            
            // 5. Update local state
            wallet.utxos = remaining_utxos;
            save_wallet(&wallet)?;

            let tx_json = serde_json::to_string_pretty(&tx)?;
            fs::write("pending_tx.json", tx_json)?;
            println!("📡 Transaction broadcasted. Local index updated.");
        }
        Commands::Balance => {
            let wallet = load_wallet()?;
            let total: u64 = wallet.utxos.iter().map(|u| u.amount).sum();
            println!("💰 Verified Balance (Local Index): {} AETH", total);
            println!("   UTXO Count: {}", wallet.utxos.len());
        }
        Commands::Scan => {
            let mut wallet = load_wallet()?;
            println!("🔍 Incremental Scan from index {}...", wallet.last_scanned_index);
            
            let vk = [0u8; 32]; 
            
            if let Ok(data) = fs::read_to_string("ledger_outputs.json") {
                let outputs: Vec<ShieldedOutput> = serde_json::from_str(&data)?;
                let new_outputs = &outputs[wallet.last_scanned_index..];
                let mut found_count = 0;
                
                for out in new_outputs.iter() {
                    if let Some((amount, blinding)) = ZKProofSystem::trial_decrypt(&vk, &out.ephemeral_key, &out.ciphertext) {
                        println!("   ✨ New owned record! Amount: {} AETH", amount);
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
                
                println!("✅ Scan complete. Found {} new records.", found_count);
            } else {
                println!("❌ Ledger data not found.");
            }
        }
    }

    Ok(())
}
