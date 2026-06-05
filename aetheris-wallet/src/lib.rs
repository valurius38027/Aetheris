#[cfg(test)]
mod tests {
    use bip39::{Mnemonic, Language, MnemonicType, Seed};
    use ed25519_dalek::{SigningKey, VerifyingKey};
    use aetheris_core::{Transaction, ShieldedOutput};
    use aetheris_zkp::{create_commitment, create_nullifier, ZKProofSystem, ZkProverSystem};

    fn create_wallet_from_phrase(phrase: &str) -> (SigningKey, VerifyingKey) {
        let mnemonic = Mnemonic::from_phrase(phrase, Language::English).unwrap();
        let seed = Seed::new(&mnemonic, "");
        let seed_bytes = seed.as_bytes();
        let signing_key = SigningKey::from_bytes(seed_bytes[0..32].try_into().unwrap());
        let verifying_key: VerifyingKey = (&signing_key).into();
        (signing_key, verifying_key)
    }

    fn generate_wallet() -> (String, SigningKey, VerifyingKey) {
        let mnemonic = Mnemonic::new(MnemonicType::Words24, Language::English);
        let phrase = mnemonic.phrase().to_string();
        let (sk, vk) = create_wallet_from_phrase(&phrase);
        (phrase, sk, vk)
    }

    #[test]
    fn test_wallet_creation() {
        let (phrase, sk, vk) = generate_wallet();
        println!("Mnemonic: {}", phrase);
        println!("Spending key: {}", hex::encode(sk.to_bytes()));
        println!("Verifying key: {}", hex::encode(vk.to_bytes()));

        assert!(!phrase.is_empty(), "Mnemonic phrase should not be empty");
        assert_ne!(sk.to_bytes(), [0u8; 32], "Spending key should not be all zeros");
        assert_ne!(vk.to_bytes(), [0u8; 32], "Verifying key should not be all zeros");
    }

    #[test]
    fn test_deterministic_address_from_mnemonic() {
        let mnemonic_phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art";

        let (sk1, vk1) = create_wallet_from_phrase(mnemonic_phrase);
        let (sk2, vk2) = create_wallet_from_phrase(mnemonic_phrase);

        println!("SK1: {}", hex::encode(sk1.to_bytes()));
        println!("SK2: {}", hex::encode(sk2.to_bytes()));
        println!("VK1: {}", hex::encode(vk1.to_bytes()));
        println!("VK2: {}", hex::encode(vk2.to_bytes()));

        assert_eq!(sk1.to_bytes(), sk2.to_bytes(), "Same mnemonic must produce same spending key");
        assert_eq!(vk1.to_bytes(), vk2.to_bytes(), "Same mnemonic must produce same verifying key");
    }

    #[test]
    fn test_transaction_creation() {
        let amount = 100u64;
        let blinding = [42u8; 32];

        let nullifier = create_nullifier(&[0u8; 32], 0);
        let commitment = create_commitment(amount, &blinding);

        let output = ShieldedOutput {
            commitment,
            ephemeral_key: [7u8; 32],
            ciphertext: {
                let mut c = b"AETHSCAN".to_vec();
                c.extend_from_slice(&amount.to_le_bytes());
                c.extend_from_slice(&blinding);
                c
            },
        };

        let proof = ZKProofSystem::prove_conservation(
            &[amount],
            &[amount],
            &[blinding],
            &[blinding],
            &[commitment],
            0,
        );

        let tx = Transaction {
            inputs: vec![nullifier],
            outputs: vec![output.clone()],
            public_amount: 0,
            proof,
        };

        println!("Transaction: {} input(s), {} output(s)", tx.inputs.len(), tx.outputs.len());
        println!("Nullifier: {}", hex::encode(tx.inputs[0]));
        println!("Output commitment: {}", hex::encode(tx.outputs[0].commitment));

        assert_eq!(tx.inputs.len(), 1, "Transaction should have one input");
        assert_eq!(tx.outputs.len(), 1, "Transaction should have one output");
        assert_eq!(tx.public_amount, 0, "Public amount should be zero for shielded tx");
        assert!(!tx.proof.is_empty(), "Proof should not be empty");
        assert_eq!(output.commitment, commitment, "Output commitment must match");
    }

    #[test]
    fn test_change_output() {
        let input_amount = 200u64;
        let output_amount = 150u64;
        let change_amount = input_amount - output_amount;

        let input_blinding = [10u8; 32];
        let output_blinding = [20u8; 32];
        let change_blinding = [30u8; 32];

        assert!(change_amount > 0, "Change amount must be positive");

        let mut outputs = Vec::new();

        outputs.push(ShieldedOutput {
            commitment: create_commitment(output_amount, &output_blinding),
            ephemeral_key: [7u8; 32],
            ciphertext: {
                let mut c = b"AETHSCAN".to_vec();
                c.extend_from_slice(&output_amount.to_le_bytes());
                c.extend_from_slice(&output_blinding);
                c
            },
        });

        if change_amount > 0 {
            outputs.push(ShieldedOutput {
                commitment: create_commitment(change_amount, &change_blinding),
                ephemeral_key: [8u8; 32],
                ciphertext: {
                    let mut c = b"AETHSCAN".to_vec();
                    c.extend_from_slice(&change_amount.to_le_bytes());
                    c.extend_from_slice(&change_blinding);
                    c
                },
            });
        }

        let in_amounts = vec![input_amount];
        let out_amounts = if change_amount > 0 {
            vec![output_amount, change_amount]
        } else {
            vec![output_amount]
        };
        let in_blindings = vec![input_blinding];
        let out_blindings = if change_amount > 0 {
            vec![output_blinding, change_blinding]
        } else {
            vec![output_blinding]
        };
        let commitments: Vec<[u8; 32]> = outputs.iter().map(|o| o.commitment).collect();

        let proof = ZKProofSystem::prove_conservation(
            &in_amounts,
            &out_amounts,
            &in_blindings,
            &out_blindings,
            &commitments,
            0,
        );

        let tx = Transaction {
            inputs: vec![create_nullifier(&[0u8; 32], 0)],
            outputs,
            public_amount: 0,
            proof,
        };

        println!("Input amount: {} AETH", input_amount);
        println!("Output amount: {} AETH", output_amount);
        println!("Change amount: {} AETH", change_amount);
        println!("Transaction outputs: {}", tx.outputs.len());

        assert_eq!(tx.outputs.len(), 2, "Should have two outputs (recipient + change)");
        assert!(change_amount > 0, "Change should be positive when output < input");
    }

    #[test]
    fn test_balance_computation() {
        let utxos = vec![
            (100u64, [1u8; 32], [0xaa; 32]),
            (200u64, [2u8; 32], [0xbb; 32]),
            (50u64,  [3u8; 32], [0xcc; 32]),
        ];

        let total_balance: u64 = utxos.iter().map(|(amount, _, _)| amount).sum();
        let utxo_count = utxos.len();

        println!("UTXOs found: {}", utxo_count);
        for (i, (amount, blinding, commitment)) in utxos.iter().enumerate() {
            println!("  UTXO {}: {} AETH, blinding={}, commitment={}",
                i, amount, hex::encode(blinding), hex::encode(commitment));
        }
        println!("Total balance: {} AETH", total_balance);

        assert_eq!(total_balance, 350, "Total balance should be 100 + 200 + 50 = 350");
        assert_eq!(utxo_count, 3, "Should have 3 UTXOs");

        let filtered: Vec<_> = utxos.iter().filter(|(amt, _, _)| *amt >= 150).collect();
        println!("UTXOs sufficient for 150 AETH: {}", filtered.len());
        assert_eq!(filtered.len(), 1, "Only one UTXO has >= 150 AETH");
    }
}
