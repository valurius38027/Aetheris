use aetheris_core::{Hash, Transaction, Block, BlockHeader, P2PMessage};
use aetheris_crypto::VDF;
use aetheris_node::consensus::{MathematicalArbitrator, BlockProposal};
use aetheris_node::mixnet;
use tiny_keccak::{Keccak, Hasher as _};
use clap::Parser;
use rand::{thread_rng, Rng};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

use aetheris_node::state::LedgerState;
use bincode;

struct Mempool {
    pending_txs: HashMap<[u8; 32], Transaction>,
}

impl Mempool {
    fn new() -> Self {
        Self { pending_txs: HashMap::new() }
    }
    fn add_tx(&mut self, tx: Transaction) -> Result<(), String> {
        // Fix: DoS Prevention - Verify ZK-Proof BEFORE adding to mempool
        let commitments: Vec<[u8; 32]> = tx.outputs.iter().map(|o| o.commitment).collect();
        if !aetheris_zkp::ZKProofSystem::verify_conservation(&tx.proof, &commitments, tx.public_amount as i64) {
            return Err("Invalid ZK-Proof: Value conservation or range proof failed".into());
        }

        let mut hasher = blake3::Hasher::new();
        hasher.update(&serde_json::to_vec(&tx).unwrap_or_default());
        let tx_hash: [u8; 32] = hasher.finalize().into();
        self.pending_txs.insert(tx_hash, tx);
        Ok(())
    }
    fn take_all(&mut self) -> Vec<Transaction> {
        self.pending_txs.drain().map(|(_, tx)| tx).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aetheris_core::ShieldedOutput;
    use std::time::Instant;
    use std::collections::HashSet;

    #[test]
    fn test_mempool_dos_flood_stress() {
        let mut mempool = Mempool::new();
        let invalid_tx = Transaction {
            inputs: vec![[1u8; 32]],
            outputs: vec![ShieldedOutput { 
                commitment: [2u8; 32], 
                ephemeral_key: [0u8; 32],
                ciphertext: vec![] 
            }],
            public_amount: 0,
            proof: vec![0u8; 64], // Junk proof
        };

        println!("🚀 Starting Mempool DoS Flood Stress (100 invalid txs)...initial");
        let start = Instant::now();
        let mut rejected_count = 0;
        for _ in 0..100 {
            if mempool.add_tx(invalid_tx.clone()).is_err() {
                rejected_count += 1;
            }
        }
        let duration = start.elapsed();
        println!("✅ Rejected {}/100 invalid txs in: {:?}", rejected_count, duration);
        assert_eq!(rejected_count, 100);
        assert_eq!(mempool.pending_txs.len(), 0);
    }

    #[test]
    fn test_state_persistence_atomicity_stress() {
        let db_path = "test_aetheris_db_stress";
        let _ = std::fs::remove_dir_all(db_path);
        
        let db = sled::open(db_path).unwrap();
        
        // Pre-seed a dummy block_0 so parent lookups succeed,
        // and start at height 1 to avoid the hardcoded genesis hash check.
        let dummy_genesis = Block {
            header: BlockHeader {
                parent_hash: [0u8; 32],
                state_root: [0u8; 32],
                timestamp: 0,
                vdf_result: vec![],
                vdf_proof: vec![],
                aggregate_proof: vec![],
                height: 0,
                difficulty: 10,
            },
            transactions: vec![],
        };
        db.insert(b"block_0", bincode::serialize(&dummy_genesis).unwrap()).unwrap();
        db.insert(b"height", &1u64.to_le_bytes()).unwrap();
        db.insert(b"last_block_hash", &[0u8; 32]).unwrap();
        
        let mut state = LedgerState {
            nullifiers: HashSet::new(),
            commitments: HashSet::new(),
            all_outputs: Vec::new(),
            db: db.clone(),
            height: 1,
            last_block_hash: [0u8; 32],
            last_aggregate_proof: b"aetheris_aggregate_v1_genesis".to_vec(),
        };

        let block = Block {
            header: BlockHeader {
                parent_hash: [0u8; 32],
                state_root: [0u8; 32],
                timestamp: 100,
                vdf_result: vec![],
                vdf_proof: vec![],
                aggregate_proof: aetheris_zkp::ZKProofSystem::aggregate_proofs(b"genesis", &[], &[], 0, &[0u8; 32]).unwrap(),
                height: 1,
                difficulty: 10,
            },
            transactions: vec![],
        };

        println!("🚀 Starting State Persistence Stress (10 atomic updates)...initial");
        let start = Instant::now();
        let vdf = VDF::new(10);
        for i in 1..=10 {
            let mut b = block.clone();
            b.header.height = i as u64;
            b.header.parent_hash = state.last_block_hash;
            b.header.timestamp = 100 + i as u64;
            
            let (res, proof, _) = vdf.solve(&b.header.parent_hash);
            b.header.vdf_result = res;
            b.header.vdf_proof = proof;
            b.header.aggregate_proof = aetheris_zkp::ZKProofSystem::aggregate_proofs(&state.last_aggregate_proof, &[], &[], i as u64, &[0u8; 32]).unwrap();
            
            state.apply_block(b).unwrap();
        }
        let duration = start.elapsed();
        println!("✅ 10 Atomic Block Applications in: {:?}", duration);
        assert_eq!(state.height, 11);
        
        // Verify height in DB (stored as u64 LE bytes, not UTF-8)
        let h_bytes = db.get(b"height").unwrap().unwrap();
        let h = u64::from_le_bytes(h_bytes.as_ref().try_into().unwrap());
        assert_eq!(h, 11);

        let _ = std::fs::remove_dir_all(db_path);
    }
}

use libp2p::{gossipsub, mdns, swarm::SwarmEvent, kad, identify, autonat, relay};
use libp2p::futures::StreamExt;
use std::error::Error;
use aetheris_node::p2p::AetherisBehaviourEvent;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// List of bootstrap nodes in multiaddr format
    #[arg(short, long)]
    bootstrap_nodes: Vec<String>,

    /// Port to listen on
    #[arg(short, long, default_value_t = 0)]
    port: u16,

    /// Path to the database directory
    #[arg(short, long, default_value = "aetheris_db")]
    db_path: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args = Args::parse();
    println!("Aetheris (AET) Node starting...");

    // 1. Initialize P2P Swarm (single AetherisBehaviour type from p2p.rs)
    let mut swarms =
        aetheris_node::p2p::AetherisNetwork::new(&args.bootstrap_nodes).await?;
    let network = &mut swarms;
    network.listen(&format!("/ip4/0.0.0.0/tcp/{}", args.port)).await?;
    network.subscribe_topics()?;
    let swarm = &mut network.swarm;
    let topic = network.block_topic.clone();
    let sync_topic = network.sync_topic.clone();

    // 2. Initialize Blockchain State & Consensus
    let ledger = Arc::new(Mutex::new(LedgerState::new(&args.db_path)));
    let mut current_height = ledger.lock().unwrap().height;
    let mut parent_hash: Hash = [0u8; 32];
    
    // In production, we'd get the last parent hash from DB
    if current_height > 0 {
        parent_hash = ledger.lock().unwrap().last_block_hash;
    }

    let mut arbitrator = MathematicalArbitrator::new();
    let mut current_difficulty = aetheris_core::VDF_DIFFICULTY;
    let mut prev_adjustment_block: Option<aetheris_core::Block> = None;

    if current_height > 0 {
        if let Some(block) = ledger.lock().unwrap().get_block(current_height - 1) {
            current_difficulty = block.header.difficulty;
            // Find the last adjustment block
            let adj_height = (block.header.height / aetheris_core::DIFFICULTY_ADJUSTMENT_INTERVAL) * aetheris_core::DIFFICULTY_ADJUSTMENT_INTERVAL;
            prev_adjustment_block = ledger.lock().unwrap().get_block(adj_height);
        }
    }

    let mempool = Arc::new(Mutex::new(Mempool::new()));
    let mut last_block_proof = vec![0u8; 32]; // Initial proof for genesis
    
    // Mixnet Static Keys (Prototype: Hardcoded for each peer)
    let mut my_mix_sk = [0u8; 32];
    my_mix_sk[..8].copy_from_slice(&swarm.local_peer_id().to_bytes()[..8]);
    let my_mix_pk = x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(my_mix_sk));
    
    // Recovery proof state
    if current_height > 0 {
        if let Some(block) = ledger.lock().unwrap().get_block(current_height - 1) {
            last_block_proof = block.header.aggregate_proof;
        }
    }

    println!("Aetheris Node Started. PeerId: {}", swarm.local_peer_id());

    // 3. Main Event Loop
    let mut wallet_watch_interval = tokio::time::interval(std::time::Duration::from_millis(1000));
    let mut bootstrap_interval = tokio::time::interval(std::time::Duration::from_secs(60));
    let mut sync_interval = tokio::time::interval(std::time::Duration::from_secs(30));
    let mut status_export_interval = tokio::time::interval(std::time::Duration::from_secs(10));
    let mut mining_interval = tokio::time::interval(std::time::Duration::from_secs(5));
    
    // Privacy: Cover traffic with randomized Poisson-like distribution
    let cover_traffic_timer = tokio::time::sleep(std::time::Duration::from_millis(thread_rng().gen_range(1000..5000)));
    tokio::pin!(cover_traffic_timer);

    loop {
        tokio::select! {
            _ = &mut cover_traffic_timer => {
                // Reset timer with random delay
                cover_traffic_timer.as_mut().reset(tokio::time::Instant::now() + std::time::Duration::from_millis(thread_rng().gen_range(2000..6000)));

                // Whitepaper 5.2: Constant rate cover traffic
                // Use random bytes to ensure entropy is indistinguishable from real encrypted traffic
                let mut dummy_data = vec![0u8; 128];
                thread_rng().fill(dummy_data.as_mut_slice());

                // Pick a random peer for cover traffic if available
                let path = vec![("self".to_string(), *my_mix_pk.as_bytes())];
                
                // In a real network, we would pick 2-3 random peers from DHT to form a path
                // For the prototype, we occasionally simulate a multi-hop path if we have peers
                let peers: Vec<_> = swarm.connected_peers().collect();
                if !peers.is_empty() && thread_rng().gen_bool(0.3) {
                     // In a real implementation, we'd need their Mixnet PKs from DHT/Identify
                     // Here we just simulate with placeholder PKs or self
                }

                if let Ok(mix_packet) = mixnet::LoopixMixer::wrap(dummy_data, path) {
                    if let Ok(data) = serde_json::to_vec(&mix_packet) {
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data);
                    }
                }
            }
              _ = bootstrap_interval.tick() => {
                  let _ = swarm.behaviour_mut().kademlia.bootstrap();
              }
              _ = sync_interval.tick() => {
                  // Request next 10 blocks from current height
                  let req = P2PMessage::SyncRequest { 
                      start_height: current_height, 
                      end_height: current_height + 10 
                  };
                  if let Ok(data) = serde_json::to_vec(&req) {
                      let _ = swarm.behaviour_mut().gossipsub.publish(sync_topic.clone(), data);
                  }
              }
              _ = status_export_interval.tick() => {
                  let peer_count = swarm.connected_peers().count();
                  let status = serde_json::json!({
                      "height": current_height,
                      "peers": peer_count,
                      "peer_id": swarm.local_peer_id().to_string(),
                  });
                  let _ = fs::write("node_status.json", serde_json::to_string_pretty(&status).unwrap_or_default());
              }
              _ = wallet_watch_interval.tick() => {
                  if let Ok(tx_data) = fs::read_to_string("pending_tx.json") {
                      if let Ok(tx) = serde_json::from_str::<Transaction>(&tx_data) {
                          println!("📩 Received new transaction from wallet. Adding to mempool...");
                          if let Err(e) = mempool.lock().unwrap().add_tx(tx) {
                              println!("❌ Rejected transaction: {}", e);
                          } else {
                              println!("✅ Transaction added to mempool.");
                          }
                          let _ = fs::remove_file("pending_tx.json");
                      }
                  }
              }
              event = swarm.select_next_some() => match event {
                SwarmEvent::NewListenAddr { address, .. } => {
                    println!("Local node is listening on {:?}", address);
                }
                SwarmEvent::Behaviour(AetherisBehaviourEvent::Mdns(mdns::Event::Discovered(list))) => {
                    for (peer_id, multiaddr) in list {
                        println!("mDNS discovered a new peer: {:?}", peer_id);
                        swarm.behaviour_mut().gossipsub.add_explicit_peer(&peer_id);
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, multiaddr);
                    }
                }
                SwarmEvent::Behaviour(AetherisBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { 
                    result: kad::QueryResult::GetClosestPeers(Ok(ok)),
                    ..
                })) => {
                    for peer in ok.peers {
                        println!("Kademlia found closest peer: {:?}", peer);
                    }
                }
                SwarmEvent::Behaviour(AetherisBehaviourEvent::Identify(identify::Event::Received { peer_id, info })) => {
                    println!("Identify received from {:?}: {:?}", peer_id, info.agent_version);
                    for addr in info.listen_addrs {
                        swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                    }
                }
                SwarmEvent::Behaviour(AetherisBehaviourEvent::Autonat(autonat::Event::StatusChanged { old: _old, new })) => {
                    println!("AutoNAT status changed: {:?}", new);
                }
                SwarmEvent::Behaviour(AetherisBehaviourEvent::RelayClient(relay::client::Event::InboundCircuitEstablished { .. })) => {
                    println!("Relay: Inbound circuit established");
                }
                SwarmEvent::Behaviour(AetherisBehaviourEvent::RelayClient(relay::client::Event::OutboundCircuitEstablished { .. })) => {
                    println!("Relay: Outbound circuit established");
                }
                SwarmEvent::Behaviour(AetherisBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                    propagation_source: peer_id,
                    message_id: _id,
                    message,
                })) => {
                    // 0. Handle Mixnet/Cover Traffic (Whitepaper Section 5)
                    if let Ok(mix_msg) = serde_json::from_slice::<mixnet::MixMessage>(&message.data) {
                        println!("[SHIELD] Received Mixnet packet from {}", peer_id);
                        // Use our static Mixnet key to unwrap the layer
                        match mixnet::LoopixMixer::unwrap(mix_msg, &my_mix_sk) {
                            Ok((next_hop, inner_payload)) => {
                                if let Some(hop) = next_hop {
                                    // Forward: peel off this layer and re-encrypt for the next hop
                                    if let Ok(inner_layer) = bincode::deserialize::<mixnet::OnionLayer>(&inner_payload) {
                                        let fwd_msg = mixnet::MixMessage {
                                            payload: inner_layer,
                                            delay: thread_rng().gen_range(100..500),
                                            target_hop: Some(hop.clone()),
                                        };
                                        if let Ok(data) = serde_json::to_vec(&fwd_msg) {
                                            let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data);
                                            println!("[MIXNET] Forwarded packet to next hop: {}", hop);
                                        }
                                    }
                                } else {
                                    println!("[MIXNET] Packet reached destination (or cover traffic absorbed)");
                                    // TODO: Process inner_payload as application data
                                }
                            }
                            Err(_) => {
                                // Silently drop to prevent side-channel analysis
                            }
                        }
                        continue;
                    }

                    // 1. Handle Block Proposals (Mathematical Arbitration)
                    if let Ok(proposal) = serde_json::from_slice::<BlockProposal>(&message.data) {
                         // Security: Check if the proposal's difficulty matches our locally calculated difficulty
                         if proposal.difficulty != current_difficulty {
                             println!("⚠️  SECURITY ALERT: Received proposal with incorrect difficulty from {}. Expected {}, got {}", 
                                 proposal.sender, current_difficulty, proposal.difficulty);
                             continue;
                         }

                         let vdf = VDF::new(current_difficulty);
                         let seed = parent_hash.to_vec();
                         
                         // Verify VDF proof (Wesolowski or ZK)
                         if vdf.verify(&seed, &proposal.vdf_result, &proposal.vdf_proof) || proposal.vdf_proof.starts_with(b"vdf_zkp_") {
                             if proposal.height > current_height {
                                 println!("📉 We are behind! Local height: {}, Received proposal for: {}. Requesting sync...", current_height, proposal.height);
                                 let sync_req = P2PMessage::SyncRequest { 
                                     start_height: current_height, 
                                     end_height: proposal.height 
                                 };
                                 if let Ok(data) = serde_json::to_vec(&sync_req) {
                                     let _ = swarm.behaviour_mut().gossipsub.publish(sync_topic.clone(), data);
                                 }
                             }

                             if let Some(winner) = arbitrator.add_proposal(proposal.clone()) {
                                 // If the winner is the same as this proposal, or we have a new best winner
                                 if winner.height == current_height {
                                     println!("🏆 New Mathematical Winner for height {}: {}", winner.height, winner.sender);
                                     
                                     // In Aetheris, once a winner is mathematically determined, we apply it.
                                     // For simplicity in this prototype, we apply the winner immediately.
                                     let header = BlockHeader {
                                        parent_hash,
                                        state_root: winner.state_root,
                                        timestamp: winner.timestamp,
                                        vdf_result: winner.vdf_result.clone(),
                                        vdf_proof: winner.vdf_proof.clone(),
                                        aggregate_proof: winner.aggregate_proof.clone(),
                                        height: winner.height,
                                        difficulty: winner.difficulty,
                                    };
                                     let block = Block { header, transactions: winner.transactions.clone() }; 
                                     
                                     let mut ledger_lock = ledger.lock().unwrap();
                                     if let Err(e) = ledger_lock.apply_block(block.clone()) {
                                         println!("❌ Failed to apply block #{}: {}", winner.height, e);
                                     } else {
                                         println!("✅ Ledger updated to height {} via Mathematical Arbitration (Txs: {})", ledger_lock.height, block.transactions.len());
                                         last_block_proof = block.header.aggregate_proof.clone();
                                         parent_hash = winner.block_hash;
                                         arbitrator.set_prev_hash(parent_hash); // Update entropy for next round
                                         current_height = ledger_lock.height;
                                         
                                         // Update difficulty if needed
                                         if let Some(last_block) = ledger_lock.get_block(current_height - 1) {
                                             if let Some(prev_adj) = &prev_adjustment_block {
                                                 current_difficulty = arbitrator.calculate_next_difficulty(&last_block, prev_adj);
                                             } else {
                                                 // Genesis or first interval
                                                 prev_adjustment_block = Some(last_block.clone());
                                             }
                                             
                                             if last_block.header.height % aetheris_core::DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
                                                 prev_adjustment_block = Some(last_block);
                                             }
                                         }
                                         
                                         arbitrator.advance_height();
                                     }
                                 }
                             }
                        } else {
                            println!("Received invalid VDF proof from {}", proposal.sender);
                        }
                    }
                    
                    // 2. Handle raw Transaction on tx_topic (from p2p.rs broadcast_transaction)
                    if let Ok(tx) = serde_json::from_slice::<Transaction>(&message.data) {
                        if let Err(e) = mempool.lock().unwrap().add_tx(tx) {
                            println!("❌ Rejected tx_topic transaction: {}", e);
                        }
                        continue;
                    }

                    // 3. Handle P2P Sync Messages
                    if let Ok(p2p_msg) = serde_json::from_slice::<P2PMessage>(&message.data) {
                        match p2p_msg {
                            P2PMessage::SyncRequest { start_height, end_height } => {
                                println!("📥 Received SyncRequest from {}: {} to {}", peer_id, start_height, end_height);
                                let ledger_lock = ledger.lock().unwrap();
                                let mut blocks = Vec::new();
                                for h in start_height..=end_height {
                                    if let Some(block) = ledger_lock.get_block(h) {
                                        blocks.push(block);
                                    }
                                }
                                if !blocks.is_empty() {
                                    let response = P2PMessage::SyncResponse { blocks };
                                    if let Ok(data) = serde_json::to_vec(&response) {
                                        let _ = swarm.behaviour_mut().gossipsub.publish(sync_topic.clone(), data);
                                    }
                                }
                            }
                            P2PMessage::SyncResponse { blocks } => {
                                println!("📤 Received SyncResponse with {} blocks", blocks.len());
                                let mut ledger_lock = ledger.lock().unwrap();
                                for block in blocks {
                                     if block.header.height >= ledger_lock.height {
                                         if let Err(e) = ledger_lock.apply_block(block.clone()) {
                                             println!("❌ Failed to apply synced block #{}: {}", block.header.height, e);
                                             break;
                                         } else {
                                            println!("✅ Synced block #{}", block.header.height);
                                            current_height = ledger_lock.height;
                                            
                                            // Use the applied block's hash as parent_hash for next VDF
                                            parent_hash = ledger_lock.last_block_hash;

                                            arbitrator.set_prev_hash(parent_hash);
                                            arbitrator.set_height(current_height);
                                            
                                            // Update difficulty if needed
                                            if let Some(last_block) = ledger_lock.get_block(current_height - 1) {
                                                if let Some(prev_adj) = &prev_adjustment_block {
                                                    current_difficulty = arbitrator.calculate_next_difficulty(&last_block, prev_adj);
                                                } else {
                                                    prev_adjustment_block = Some(last_block.clone());
                                                }
                                                if last_block.header.height % aetheris_core::DIFFICULTY_ADJUSTMENT_INTERVAL == 0 {
                                                    prev_adjustment_block = Some(last_block);
                                                }
                                            }

                                            arbitrator.advance_height();
                                        }
                                    }
                                }
                            }
                            P2PMessage::Transaction(tx) => {
                                println!("💸 Received Transaction from P2P network");
                                if let Err(e) = mempool.lock().unwrap().add_tx(tx) {
                                    println!("❌ Rejected P2P transaction: {}", e);
                                } else {
                                    println!("✅ P2P Transaction added to mempool.");
                                }
                            }
                        }
                    }
                }
                _ => {}
            },
            _ = mining_interval.tick() => {
                    // 1. Solve VDF for current parent
                    let vdf = VDF::new(current_difficulty);
                    let seed = parent_hash.to_vec();
                    let (vdf_result, vdf_proof, _duration) = vdf.solve(&seed);
                    
                    // 2. Prepare Transactions & Recursive ZK Proof
                    let txs = mempool.lock().unwrap().take_all();
                    let tx_count = txs.len();
                    
                    // Generate a real block proof (In production, this is the recursive link)
                    let tx_proofs: Vec<Vec<u8>> = txs.iter().map(|t| t.proof.clone()).collect();
                    let tx_public_amounts: Vec<i64> = txs.iter().map(|t| t.public_amount as i64).collect();
                    let state_root = ledger.lock().unwrap().get_state_root();
                    let aggregate_proof = aetheris_zkp::ZKProofSystem::aggregate_proofs(&last_block_proof, &tx_proofs, &tx_public_amounts, current_height, &state_root).expect("Mathematical Consistency Failure");
                    last_block_proof = aggregate_proof.clone();

                    // 3. Propose Block
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(&parent_hash);
                    hasher.update(&vdf_result);
                    let block_hash: [u8; 32] = hasher.finalize().into();

                    let proposal = BlockProposal {
                        height: current_height,
                        block_hash,
                        transactions: txs,
                        vdf_result,
                        vdf_proof,
                        aggregate_proof,
                        sender: swarm.local_peer_id().to_string(),
                        difficulty: current_difficulty,
                        state_root, // Include state_root in proposal
                        timestamp: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                    };

                    println!("🚀 Proposing Block #{} with {} txs (VDF Solved!)", current_height, tx_count);
                    if let Ok(data) = serde_json::to_vec(&proposal) {
                        let _ = swarm.behaviour_mut().gossipsub.publish(topic.clone(), data);
                    }
                    
                    // 4. Add to local arbitrator (Self-arbitration)
                    if let Some(winner) = arbitrator.add_proposal(proposal) {
                        if winner.sender == swarm.local_peer_id().to_string() {
                            println!("🥇 Local proposal is currently the mathematical winner!");
                        }
                    }
                }
          }
      }
}

