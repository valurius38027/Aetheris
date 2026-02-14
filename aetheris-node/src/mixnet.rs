use serde::{Deserialize, Serialize};
use rand::{self, Rng, thread_rng};
use x25519_dalek::{StaticSecret, PublicKey};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, aead::Aead};
use anyhow::{Result, anyhow};
use std::collections::HashMap;
use libp2p::PeerId;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    pub ephemeral_pk: [u8; 32],    // DH ephemeral public key for this hop
    pub encrypted_payload: Vec<u8>, // AES-GCM encrypted inner layer or payload (fixed size)
    pub nonce: [u8; 12],            // AES-GCM nonce
}

pub const MAX_PACKET_SIZE: usize = 32768; // Increased to 32KB to accommodate real ZK-SNARK proofs

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MixMessage {
    pub payload: OnionLayer, // Outermost onion layer
    pub delay: u64,          // Delay in milliseconds
    pub target_hop: Option<String>, // Routing hint for the current node
}

pub struct LoopixMixer;

impl LoopixMixer {
    /// Selects a random path of peers from the Kademlia DHT.
    /// This enhances privacy by ensuring the path is not static.
    pub fn select_random_path(
        peer_pks: &HashMap<PeerId, [u8; 32]>, 
        target_count: usize
    ) -> Vec<(String, [u8; 32])> {
        let mut rng = thread_rng();
        let peers: Vec<_> = peer_pks.iter().collect();
        
        if peers.is_empty() {
            return Vec::new();
        }

        let mut path = Vec::new();
        let actual_count = std::cmp::min(target_count, peers.len());
        
        let mut indices: Vec<usize> = (0..peers.len()).collect();
        for _ in 0..actual_count {
            let idx = rng.gen_range(0..indices.len());
            let peer_idx = indices.remove(idx);
            let (peer_id, pk) = peers[peer_idx];
            path.push((peer_id.to_string(), *pk));
        }
        
        path
    }
    /// Wraps a message into an Onion-routed packet using real X25519 DH and AES-GCM.
    /// Implements fixed-size padding to prevent traffic analysis.
    pub fn wrap(payload: Vec<u8>, path_pks: Vec<(String, [u8; 32])>) -> Result<MixMessage> {
        if path_pks.is_empty() {
            return Err(anyhow!("Mixnet path cannot be empty for onion routing"));
        }

        let mut rng = thread_rng();
        
        // Initial padding: ensure the innermost payload is padded before encryption
        // This ensures the final onion packet is always the same size regardless of payload
        let mut current_payload = payload;
        if current_payload.len() > MAX_PACKET_SIZE / 2 {
            return Err(anyhow!("Payload too large for fixed-size packet"));
        }

        let mut last_hop: Option<String> = None;

        // Build the onion from the inside out (reverse order of path)
        for (i, (node_id, pk_bytes)) in path_pks.iter().rev().enumerate() {
            let ephemeral_sk = StaticSecret::random_from_rng(&mut rng);
            let ephemeral_pk = PublicKey::from(&ephemeral_sk);
            let remote_pk = PublicKey::from(*pk_bytes);
            
            // DH Key Exchange
            let shared_secret = ephemeral_sk.diffie_hellman(&remote_pk);
            let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
            let cipher = Aes256Gcm::new(key);
            
            let mut nonce_bytes = [0u8; 12];
            rng.fill(&mut nonce_bytes);
            let nonce = Nonce::from_slice(&nonce_bytes);

            // Construct the inner structure
            let inner_struct = (last_hop.clone(), current_payload);
            let mut inner_bytes = bincode::serialize(&inner_struct)?;
            
            // Add padding to keep size constant for all layers if needed, 
            // or at least ensure the final outermost layer is constant.
            // For a true Sphinx packet, the size remains constant at each hop.
            // Here we ensure the encrypted_payload has a consistent growth or fixed target.
            if i == 0 {
                // Innermost layer: pad to a base size
                let pad_len = MAX_PACKET_SIZE.saturating_sub(inner_bytes.len() + 32); // 32 for overhead estimate
                let mut padding = vec![0u8; pad_len];
                rng.fill(padding.as_mut_slice());
                inner_bytes.extend(padding);
            }
            
            // Encrypt
            let encrypted = cipher.encrypt(nonce, inner_bytes.as_slice())
                .map_err(|e| anyhow!("Encryption failed: {}", e))?;

            current_payload = bincode::serialize(&OnionLayer {
                ephemeral_pk: *ephemeral_pk.as_bytes(),
                encrypted_payload: encrypted,
                nonce: nonce_bytes,
            })?;
            
            last_hop = Some(node_id.clone());
        }

        // The final current_payload is the outermost OnionLayer
        let outermost: OnionLayer = bincode::deserialize(&current_payload)?;

        Ok(MixMessage {
            payload: outermost,
            delay: rng.gen_range(500..2000),
            target_hop: last_hop,
        })
    }

    /// Decapsulates one layer of the onion using the node's static private key.
    pub fn unwrap(msg: MixMessage, my_sk: &[u8; 32]) -> Result<(Option<String>, Vec<u8>)> {
        let layer = msg.payload;
        let ephemeral_pk = PublicKey::from(layer.ephemeral_pk);
        let static_sk = StaticSecret::from(*my_sk);
        
        // DH Key Exchange to recover the shared secret
        let shared_secret = static_sk.diffie_hellman(&ephemeral_pk);
        let key = Key::<Aes256Gcm>::from_slice(shared_secret.as_bytes());
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&layer.nonce);

        // Decrypt the payload
        let decrypted = cipher.decrypt(nonce, layer.encrypted_payload.as_slice())
            .map_err(|_| anyhow!("Decryption failed: Possibly wrong key or corrupted packet"))?;

        // Deserialize the inner content: (next_hop_hint, inner_payload)
        // We use a partial deserialization or just handle the padding
        let (next_hop, inner_payload): (Option<String>, Vec<u8>) = bincode::deserialize(&decrypted)
            .map_err(|e| anyhow!("Deserialization failed: {}", e))?;
        
        Ok((next_hop, inner_payload))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_onion_routing_3_hops() {
        let node_a_sk = [1u8; 32];
        let node_a_pk = *PublicKey::from(&StaticSecret::from(node_a_sk)).as_bytes();
        let node_b_sk = [2u8; 32];
        let node_b_pk = *PublicKey::from(&StaticSecret::from(node_b_sk)).as_bytes();
        let node_c_sk = [3u8; 32];
        let node_c_pk = *PublicKey::from(&StaticSecret::from(node_c_sk)).as_bytes();

        let original_payload = b"Deep Privacy".to_vec();
        let path = vec![
            ("NodeA".to_string(), node_a_pk),
            ("NodeB".to_string(), node_b_pk),
            ("NodeC".to_string(), node_c_pk),
        ];

        // 1. Wrap
        let msg_a = LoopixMixer::wrap(original_payload.clone(), path).unwrap();
        assert_eq!(msg_a.target_hop, Some("NodeA".to_string()));

        // 2. NodeA unwrap
        let (hop_b, inner_b_bytes) = LoopixMixer::unwrap(msg_a.clone(), &node_a_sk).unwrap();
        assert_eq!(hop_b, Some("NodeB".to_string()));

        // --- DoS/Panic Audit Test Case ---
        let mut corrupted_msg = msg_a.clone();
        corrupted_msg.payload.encrypted_payload = vec![0u8; 32]; // Invalid payload
        let result = LoopixMixer::unwrap(corrupted_msg, &node_a_sk);
        assert!(result.is_err(), "Should return error for corrupted payload instead of panicking");
        println!("✅ Mixnet DoS/Panic audit passed: Corrupted payload handled safely.");
        let msg_b = MixMessage {
            payload: bincode::deserialize(&inner_b_bytes).unwrap(),
            delay: 0,
            target_hop: hop_b,
        };

        // 3. NodeB unwrap
        let (hop_c, inner_c_bytes) = LoopixMixer::unwrap(msg_b, &node_b_sk).unwrap();
        assert_eq!(hop_c, Some("NodeC".to_string()));
        let msg_c = MixMessage {
            payload: bincode::deserialize(&inner_c_bytes).unwrap(),
            delay: 0,
            target_hop: hop_c,
        };

        // 4. NodeC unwrap (Destination)
        let (hop_final, final_payload) = LoopixMixer::unwrap(msg_c, &node_c_sk).unwrap();
        assert_eq!(hop_final, None);
        assert_eq!(final_payload, original_payload);

        println!("✅ 3-hop Onion routing verified!");
    }

    #[test]
    fn test_onion_packet_size_constancy() {
        let node_sk = [1u8; 32];
        let node_pk = *PublicKey::from(&StaticSecret::from(node_sk)).as_bytes();
        let path = vec![("Node".to_string(), node_pk)];

        let payload_small = vec![1u8; 10];
        let payload_large = vec![2u8; 500];

        let msg_small = LoopixMixer::wrap(payload_small, path.clone()).unwrap();
        let msg_large = LoopixMixer::wrap(payload_large, path).unwrap();

        let size_small = bincode::serialize(&msg_small).unwrap().len();
        let size_large = bincode::serialize(&msg_large).unwrap().len();

        println!("Small payload packet size: {}", size_small);
        println!("Large payload packet size: {}", size_large);

        // They should be very close in size due to fixed-size padding
        // Allow for small bincode overhead differences (e.g. length prefixes)
        assert!((size_small as i64 - size_large as i64).abs() < 100);
    }
}
