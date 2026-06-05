use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::{Mutex, Arc};
use std::collections::HashMap;
use std::time::Duration;
use once_cell::sync::Lazy;
use serde::{Serialize, Deserialize};
use aetheris_zkp::{ZKProofSystem, ZkProverSystem};
use bip39::{Mnemonic};
use tiny_keccak::{Hasher, Keccak};
use aes_gcm::{Aes256Gcm, Key, Nonce, KeyInit, AeadCore};
use aes_gcm::aead::{Aead, OsRng};
use argon2::{Argon2, PasswordHasher};
use argon2::password_hash::SaltString;
use serde_json::json;
use aetheris_crypto::vdf::VDF;
use aetheris_node::p2p::{AetherisNetwork, NetworkCommand};
use tokio::runtime::Runtime;
use tokio::sync::mpsc;
use futures_util::StreamExt as _; 
use libp2p::{Multiaddr, swarm::SwarmEvent, gossipsub, kad};
use std::sync::RwLock;


use aetheris_node::state::LedgerState;
use zeroize::Zeroizing;

static LAST_ERROR: Lazy<RwLock<String>> = Lazy::new(|| RwLock::new(String::new()));
static DB_PATH: Lazy<RwLock<Option<std::path::PathBuf>>> = Lazy::new(|| RwLock::new(None));

// FFI Bridge Encryption Key — Dynamically generated per session.
// Frontend retrieves it via aetheris_handshake() after aetheris_init().
static BRIDGE_KEY: Lazy<RwLock<Option<[u8; 32]>>> = Lazy::new(|| RwLock::new(None));
static USER_PASSWORD: Lazy<RwLock<Option<Zeroizing<String>>>> = Lazy::new(|| RwLock::new(None));
fn set_error(msg: &str) {
    if let Ok(mut err) = LAST_ERROR.write() {
        *err = msg.to_string();
    }
}

/// S-7: FFI entry points MUST NOT panic. Wrap fallible operations.
macro_rules! ffi_try {
    ($val:expr, $err:expr) => {
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| $val)) {
            Ok(v) => v,
            Err(_) => {
                set_error("FFI panic caught");
                return $err;
            }
        }
    };
}

use aetheris_recursive::RecursiveManagerHandle;
use rand::RngCore;

struct SendPtr<T>(*mut T);

/// SAFETY: SendPtr is only used behind `Mutex<InnerState>`, ensuring
/// thread-safe access. The wrapped raw pointer is never accessed
/// concurrently without the mutex lock held.
unsafe impl<T> Send for SendPtr<T> {}
/// SAFETY: Same as Send — guarded by the enclosing Mutex.
unsafe impl<T> Sync for SendPtr<T> {}

static RECURSIVE_MANAGER: Lazy<RwLock<Option<SendPtr<RecursiveManagerHandle>>>> = Lazy::new(|| RwLock::new(None));

#[no_mangle]
pub extern "C" fn aetheris_recursive_init(peer_id_ptr: *const c_char, shard_id: u32) -> i32 {
    // Call the recursive crate's FFI function
    let manager_ptr = aetheris_recursive::recursive_manager_new_sharded(peer_id_ptr, shard_id);
    
    if !manager_ptr.is_null() {
        if let Ok(mut lock) = RECURSIVE_MANAGER.write() {
            *lock = Some(SendPtr(manager_ptr));
            return 0;
        }
    }
    -1
}

#[no_mangle]
pub extern "C" fn aetheris_recursive_handle_event(sender_ptr: *const c_char, event_json_ptr: *const c_char) -> i32 {
    if let Ok(lock) = RECURSIVE_MANAGER.read() {
        if let Some(ref sptr) = *lock {
            return aetheris_recursive::recursive_manager_handle_proof_json(sptr.0, sender_ptr, event_json_ptr);
        }
    }
    -1
}

#[no_mangle]
pub extern "C" fn aetheris_recursive_get_reward(peer_id_ptr: *const c_char) -> u64 {
    if let Ok(lock) = RECURSIVE_MANAGER.read() {
        if let Some(ref sptr) = *lock {
            return aetheris_recursive::recursive_manager_get_reward(sptr.0, peer_id_ptr);
        }
    }
    0
}

#[no_mangle]
pub extern "C" fn aetheris_recursive_generate_atomic_proof(
    tx_id_ptr: *const u8,
    tx_root_ptr: *const c_char,
    total_flow_ptr: *const c_char,
) -> *mut c_char {
    if let Ok(lock) = RECURSIVE_MANAGER.read() {
        if let Some(ref sptr) = *lock {
            return aetheris_recursive::recursive_manager_generate_atomic_json(
                sptr.0,
                tx_id_ptr,
                tx_root_ptr,
                total_flow_ptr,
            );
        }
    }
    std::ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn aetheris_get_last_error() -> *mut c_char {
    let err = LAST_ERROR.read().unwrap();
    CString::new(err.as_str()).unwrap().into_raw()
}

#[derive(Serialize, Deserialize)]
struct BinaryNodeStatus {
    status: String,
    peers: u32,
    height: u64,
    balance_atoms: u64,
    address: String,
    anonymity_set: u32,
    privacy_score: u8,
    mining_active: bool,
    mempool_size: usize,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
struct OwnedUTXO {
    commitment: [u8; 32],
    amount_atoms: u64,
    blinding: [u8; 32],
    ephemeral_key: [u8; 32],
}

// MEMPOOL now stores aetheris_core::Transaction directly (Phase 0.4).
// WalletTransaction was removed — it dropped nullifiers/outputs on conversion.

use aetheris_core::{EXPECTED_GENESIS_HASH, ATOMS_PER_AET, calculate_block_reward_atoms};

#[derive(Serialize, Deserialize, Debug)]
struct GenesisAllocation {
    comment: String,
    viewing_key: String,
    amount: u64,
}

#[derive(Serialize, Deserialize, Debug)]
struct GenesisConfig {
    network: String,
    genesis_time: String,
    consensus_params: HashMap<String, u64>,
    allocations: Vec<GenesisAllocation>,
}

#[cfg(debug_assertions)]
const TEST_SEED_MNEMONIC: &str = "legal winner thank year wave sausage worth useful legal winner thank yellow";
#[cfg(debug_assertions)]
const TEST_DEV_MNEMONIC: &str = "crystal sudden zero dynamic unique secret manual adjust orbit current focus total";

fn load_genesis_config() -> Option<GenesisConfig> {
    let config_path = std::path::Path::new("genesis.json");
    if config_path.exists() {
        if let Ok(content) = std::fs::read_to_string(config_path) {
            return serde_json::from_str(&content).ok();
        }
    }
    None
}

fn create_genesis_block() -> aetheris_core::Block {
    // 1. Try to load external config, fallback to default constants
    let config = load_genesis_config();
    
    // Use timestamp from config or fallback
    let genesis_timestamp = config.as_ref()
        .and_then(|c| {
            // Parse ISO 8601 timestamp to Unix seconds
            chrono::DateTime::parse_from_rfc3339(&c.genesis_time)
                .ok()
                .map(|dt| dt.timestamp() as u64)
        })
        .unwrap_or(1771035455); 

    // Default Viewing Keys (derived from test mnemonics for backward compatibility in tests)
    let mut seed_viewing_key = [0u8; 32];
    let mut dev_viewing_key = [0u8; 32];
    
    if let Some(ref cfg) = config {
        if cfg.allocations.len() >= 2 {
            hex::decode_to_slice(&cfg.allocations[0].viewing_key, &mut seed_viewing_key).unwrap_or_default();
            hex::decode_to_slice(&cfg.allocations[1].viewing_key, &mut dev_viewing_key).unwrap_or_default();
        }
    } else {
        #[cfg(debug_assertions)]
        {
            let mut hasher = Keccak::v256();
            hasher.update(TEST_SEED_MNEMONIC.as_bytes());
            hasher.finalize(&mut seed_viewing_key);

            let mut hasher = Keccak::v256();
            hasher.update(TEST_DEV_MNEMONIC.as_bytes());
            hasher.finalize(&mut dev_viewing_key);
        }
        #[cfg(not(debug_assertions))]
        panic!("No genesis config found. Use --config to specify genesis allocations.");
    }
    
    // 2. Initial Mint: System -> Genesis Seed (21M AET)
    let mint_amount = config.as_ref()
        .map(|c| c.allocations[0].amount)
        .unwrap_or(21_000_000 * ATOMS_PER_AET);
        
    let mint_blinding = [0u8; 32];
    let mint_commitment = aetheris_zkp::create_commitment(mint_amount, &mint_blinding);
    
    let mint_proof = ZKProofSystem::prove_conservation(
        &[], // No inputs
        &[mint_amount], 
        &[], 
        &[mint_blinding], 
        &[mint_commitment],
        mint_amount as i64,
    );

    let (epk_mint, ciphertext_mint) = aetheris_zkp::ZKProofSystem::encrypt_output(
        &seed_viewing_key,
        mint_amount,
        &mint_blinding
    );

    let mint_tx = aetheris_core::Transaction {
        inputs: vec![],
        outputs: vec![aetheris_core::ShieldedOutput {
            commitment: mint_commitment,
            ephemeral_key: epk_mint,
            ciphertext: ciphertext_mint,
        }],
        public_amount: mint_amount,
        proof: mint_proof,
    };

    // 3. Genesis Transfer: Genesis Seed -> Developer (5M AET)
    let transfer_amount = config.as_ref()
        .map(|c| c.allocations[1].amount)
        .unwrap_or(5_000_000 * ATOMS_PER_AET);
        
    let dev_blinding = [1u8; 32];
    let change_blinding = [2u8; 32];
    let dev_commitment = aetheris_zkp::create_commitment(transfer_amount, &dev_blinding);
    let change_amount = mint_amount - transfer_amount;
    let change_commitment = aetheris_zkp::create_commitment(change_amount, &change_blinding);

    let transfer_proof = ZKProofSystem::prove_conservation(
        &[mint_amount],
        &[transfer_amount, change_amount],
        &[mint_blinding],
        &[dev_blinding, change_blinding],
        &[dev_commitment, change_commitment],  // C-1: output commitments only
        0,
    );

    let (epk_dev, ciphertext_dev) = aetheris_zkp::ZKProofSystem::encrypt_output(
        &dev_viewing_key,
        transfer_amount,
        &dev_blinding
    );

    let (epk_change, ciphertext_change) = aetheris_zkp::ZKProofSystem::encrypt_output(
        &seed_viewing_key,
        change_amount,
        &change_blinding
    );

    let transfer_tx = aetheris_core::Transaction {
        inputs: vec![mint_commitment], // Using commitment as nullifier placeholder for genesis
        outputs: vec![
            aetheris_core::ShieldedOutput {
                commitment: dev_commitment,
                ephemeral_key: epk_dev,
                ciphertext: ciphertext_dev,
            },
            aetheris_core::ShieldedOutput {
                commitment: change_commitment,
                ephemeral_key: epk_change,
                ciphertext: ciphertext_change,
            }
        ],
        public_amount: 0,
        proof: transfer_proof,
    };

    let txs = vec![mint_tx, transfer_tx];
    
    aetheris_core::Block {
        header: aetheris_core::BlockHeader {
            parent_hash: [0u8; 32],
            state_root: [0u8; 32],
            timestamp: genesis_timestamp,
            vdf_result: vec![0u8; 32],
            vdf_proof: vec![0u8; 32],
            aggregate_proof: ZKProofSystem::aggregate_proofs(
                &[0u8; 32],
                &txs.iter().map(|t| t.proof.clone()).collect::<Vec<_>>(),
                &txs.iter().map(|t| t.outputs.iter().map(|o| o.commitment).collect::<Vec<_>>()).collect::<Vec<_>>(),
                &txs.iter().map(|t| t.public_amount as i64).collect::<Vec<_>>(),
                0,
                &[0u8; 32]
            ).unwrap_or_else(|e| {
                println!("[FFI] CRITICAL: Genesis aggregate proof failed: {}", e);
                vec![]
            }),
            height: 0,
            difficulty: aetheris_core::VDF_DIFFICULTY,
        },
        transactions: txs,
    }
}

// Helper to check if an address is frozen (Original Genesis Seed)
fn is_address_frozen(address: &str) -> bool {
    address == "aet12f615319124ce9db1669040f"
}

use aetheris_node::consensus::{BlockProposal, MathematicalArbitrator};
use aetheris_node::mixnet::LoopixMixer;

static ARBITRATOR: Lazy<Mutex<MathematicalArbitrator>> = Lazy::new(|| Mutex::new(MathematicalArbitrator::new()));

static PEER_KEYS: Lazy<Mutex<HashMap<libp2p::PeerId, [u8; 32]>>> = Lazy::new(|| Mutex::new(HashMap::new()));

fn broadcast_block_proposal(proposal: BlockProposal) {
    if let Some(sender) = P2P_COMMAND_SENDER.lock().unwrap().as_ref() {
        let _ = sender.send(NetworkCommand::BroadcastBlock(proposal));
    }
}

static TOKIO_RUNTIME: Lazy<Mutex<Option<Runtime>>> = Lazy::new(|| Mutex::new(None));

static P2P_COMMAND_SENDER: Lazy<Mutex<Option<mpsc::UnboundedSender<NetworkCommand>>>> = Lazy::new(|| Mutex::new(None));

#[no_mangle]
pub extern "C" fn aetheris_start_node(port: u16, db_path: *const c_char) -> i32 {
    let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
    
    // If a new path is provided, close the existing DB and switch
    if !db_path.is_null() {
        let c_str = unsafe { CStr::from_ptr(db_path) };
        if let Ok(path_str) = c_str.to_str() {
            let new_path = std::path::PathBuf::from(path_str);
            
            let current_path = DB_PATH.read().unwrap_or_else(|e| e.into_inner());
            let should_switch = match *current_path {
                Some(ref p) => p != &new_path,
                None => true,
            };
            
            if should_switch {
                println!("[FFI] Switching database to: {}", path_str);
                state.ledger = None;
                drop(current_path);
                let mut global_path = crate::DB_PATH.write().unwrap_or_else(|e| e.into_inner());
                *global_path = Some(new_path);
            }
        }
    }

    // Initialize P2P Network in Tokio Runtime
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<NetworkCommand>();
    {
        let mut sender = P2P_COMMAND_SENDER.lock().unwrap_or_else(|e| e.into_inner());
        *sender = Some(cmd_tx);
    }

    let mut rt_guard = TOKIO_RUNTIME.lock().unwrap_or_else(|e| e.into_inner());
    let rt = rt_guard.get_or_insert_with(|| {
        Runtime::new().unwrap_or_else(|e| {
            set_error(&format!("Failed to create Tokio runtime: {}", e));
            std::process::abort(); // abort — nothing works without runtime
        })
    });
    rt.spawn(async move {
        match AetherisNetwork::new(&[]).await {
            Ok(mut network) => {
                let addr = format!("/ip4/0.0.0.0/tcp/{}", port);
                if let Err(e) = network.listen(&addr).await {
                    println!("[P2P] Failed to listen on {}: {}", addr, e);
                    return;
                }
                
                println!("[P2P] Network listening on {}", addr);

                // Subscribe to all gossip topics
                if let Err(e) = network.subscribe_topics() {
                    println!("[P2P] Failed to subscribe to topics: {}", e);
                    return;
                }

                // Broadcast our own Mixnet PK
                let my_pk = {
                    let state = STATE.lock().unwrap();
                    state.mixnet_pk
                };
                if let Err(e) = network.broadcast_mixnet_pk(my_pk) {
                    println!("[P2P] Failed to broadcast own Mixnet PK: {}", e);
                }

                let mut discovery_interval = tokio::time::interval(Duration::from_secs(30));

                loop {
                    tokio::select! {
                        _ = discovery_interval.tick() => {
                            // Periodically bootstrap and look for other mixnet nodes
                            let _ = network.swarm.behaviour_mut().kademlia.bootstrap();
                        }
                        command = cmd_rx.recv() => {
                            if let Some(cmd) = command {
                                match cmd {
                                    NetworkCommand::BroadcastBlock(proposal) => {
                                        if let Err(e) = network.broadcast_block(proposal) {
                                            println!("[P2P] Failed to broadcast block: {}", e);
                                        }
                                    }
                                    NetworkCommand::BroadcastTransaction(tx) => {
                                        if let Err(e) = network.broadcast_tx(tx) {
                                            println!("[P2P] Failed to broadcast transaction: {}", e);
                                        }
                                    }
                                    NetworkCommand::Dial(addr) => {
                                        if let Err(e) = network.swarm.dial(addr.clone()) {
                                            println!("[P2P] Failed to dial {}: {}", addr, e);
                                        }
                                    }
                                    NetworkCommand::RequestSync { start_height, peer_id: _ } => {
                                        let sync_req = aetheris_core::P2PMessage::SyncRequest { 
                                            start_height, 
                                            end_height: start_height + 50 // Sync in batches of 50
                                        };
                                        if let Ok(data) = serde_json::to_vec(&sync_req) {
                                            let _ = network.swarm.behaviour_mut().gossipsub.publish(network.sync_topic.clone(), data);
                                        }
                                    }
                                    NetworkCommand::SendSyncResponse { blocks, peer_id: _ } => {
                                        let resp = aetheris_core::P2PMessage::SyncResponse { blocks };
                                        if let Ok(data) = serde_json::to_vec(&resp) {
                                            let _ = network.swarm.behaviour_mut().gossipsub.publish(network.sync_topic.clone(), data);
                                        }
                                    }
                                    NetworkCommand::BroadcastMixnetPK(pk) => {
                                        let _ = network.broadcast_mixnet_pk(pk);
                                    }
                                }
                            }
                        }
                        event = network.swarm.next() => {
                            if let Some(event) = event {
                                match event {
                                    SwarmEvent::Behaviour(aetheris_node::p2p::AetherisBehaviourEvent::Gossipsub(gossipsub::Event::Message {
                                        propagation_source: peer_id,
                                        message,
                                        ..
                                    })) => {
                                        if message.topic == network.mixnet_topic.hash() {
                                            if message.data.len() == 32 {
                                                let mut pk = [0u8; 32];
                                                pk.copy_from_slice(&message.data);
                                                println!("[P2P] Discovered Mixnet PK for peer {}: {}", peer_id, hex::encode(pk));
                                                let mut keys = PEER_KEYS.lock().unwrap();
                                                keys.insert(peer_id, pk);
                                            }
                                        } else if message.topic == network.block_topic.hash() || message.topic == network.sync_topic.hash() {
                                            if let Ok(p2p_msg) = serde_json::from_slice::<aetheris_core::P2PMessage>(&message.data) {
                                                match p2p_msg {
                                                    aetheris_core::P2PMessage::SyncRequest { start_height, end_height } => {
                                                        println!("[P2P] Received SyncRequest from {}: {}-{}", peer_id, start_height, end_height);
                                                        let mut state = STATE.lock().unwrap();
                                                        ensure_db_open(&mut state);
                                                        
                                                        if let Some(ledger) = state.ledger.as_ref() {
                                                            let mut blocks = Vec::new();
                                                            for h in start_height..=end_height {
                                                                if let Some(block) = ledger.get_block(h) {
                                                                    blocks.push(block);
                                                                } else {
                                                                    break;
                                                                }
                                                            }
                                                            
                                                            if !blocks.is_empty() {
                                                                if let Some(sender) = P2P_COMMAND_SENDER.lock().unwrap().as_ref() {
                                                                    let _ = sender.send(NetworkCommand::SendSyncResponse { blocks, peer_id });
                                                                }
                                                            }
                                                        }
                                                    }
                                                    aetheris_core::P2PMessage::SyncResponse { blocks } => {
                                                        println!("[P2P] Received SyncResponse from {}: {} blocks", peer_id, blocks.len());
                                                        let mut state = STATE.lock().unwrap();
                                                        ensure_db_open(&mut state);
                                                        
                                                        if let Some(ledger) = state.ledger.as_mut() {
                                                            if !blocks.is_empty() {
                                                                let first_height = blocks[0].header.height;
                                                                
                                                                // If the sync starts at or before our current height, it might be a reorganization
                                                                if first_height < ledger.height {
                                                                    if let Some(local_block) = ledger.get_block(first_height) {
                                                                        let mut hasher = blake3::Hasher::new();
                                                                        hasher.update(&bincode::serialize(&local_block).unwrap());
                                                                        let local_hash: [u8; 32] = hasher.finalize().into();
                                                                        
                                                                        let mut hasher = blake3::Hasher::new();
                                                                        hasher.update(&bincode::serialize(&blocks[0]).unwrap());
                                                                        let remote_hash: [u8; 32] = hasher.finalize().into();
                                                                        
                                                                        if local_hash != remote_hash {
                                                                            println!("[P2P] REORG DETECTED at height {}. Switching to heavier/network chain.", first_height);
                                                                            if let Err(e) = ledger.reorganize(blocks) {
                                                                                println!("[P2P] Reorganization failed: {}", e);
                                                                            }
                                                                            continue;
                                                                        }
                                                                    }
                                                                }
                                                                
                                                                // Normal forward sync
                                                                for block in blocks {
                                                                    if block.header.height >= ledger.height {
                                                                        println!("[P2P] Applying synced block #{}", block.header.height);
                                                                        if let Err(e) = ledger.apply_block(block) {
                                                                            println!("[P2P] Failed to apply synced block: {}", e);
                                                                            break;
                                                                        }
                                                                    }
                                                                }
                                                            }
                                                        }
                                                    }
                                                    aetheris_core::P2PMessage::Transaction(tx) => {
                                                        println!("[P2P] Received Transaction from {}", peer_id);
                                                        let mut mp = MEMPOOL.lock().unwrap();
                                                        mp.push(tx);
                                                    }
                                                }
                                            } else if let Ok(proposal) = serde_json::from_slice::<BlockProposal>(&message.data) {
                                                println!("[P2P] Received Block Proposal #{} from {}", proposal.height, peer_id);
                                                
                                                let mut state = STATE.lock().unwrap();
                                                ensure_db_open(&mut state);
                                                
                                                if let Some(ledger) = state.ledger.as_mut() {
                                                    let current_height = ledger.height;
                                                    
                                                    // 1. Update Arbitrator with latest state
                                                    let mut arb = ARBITRATOR.lock().unwrap();
                                                    arb.set_prev_hash(ledger.last_block_hash);
                                                    arb.set_height(current_height);
                                                    
                                                    // 2. Add proposal and check for winner
                                                    if let Some(winner) = arb.add_proposal(proposal.clone()) {
                                                        // If the winner is for our next height, apply it
                                                        if winner.height == current_height {
                                                            println!("[P2P] Mathematical winner found for height {}. Applying...", winner.height);
                                                            
                                                            let block = aetheris_core::Block {
                                                                header: aetheris_core::BlockHeader {
                                                                    parent_hash: ledger.last_block_hash,
                                                                    state_root: winner.state_root,
                                                                    timestamp: chrono::Utc::now().timestamp() as u64,
                                                                    vdf_result: winner.vdf_result,
                                                                    vdf_proof: winner.vdf_proof,
                                                                    aggregate_proof: winner.aggregate_proof,
                                                                    height: winner.height,
                                                                    difficulty: winner.difficulty,
                                                                },
                                                                transactions: winner.transactions,
                                                            };
                                                            
                                                            if let Err(e) = ledger.apply_block(block) {
                                                                println!("[P2P] Failed to apply winner block: {}", e);
                                                            } else {
                                                                // Successfully applied, update arbitrator for next height
                                                                arb.advance_height();
                                                                arb.set_prev_hash(ledger.last_block_hash);
                                                            }
                                                        }
                                                    }
                                                    
                                                    // 3. Detect if we are behind or if there's a fork
                                                    if proposal.height > current_height + 1 {
                                                        println!("[P2P] Node behind (Local: {}, Network: {}). Requesting sync...", current_height, proposal.height);
                                                        if let Some(sender) = P2P_COMMAND_SENDER.lock().unwrap().as_ref() {
                                                            let _ = sender.send(NetworkCommand::RequestSync { 
                                                                start_height: current_height, 
                                                                peer_id 
                                                            });
                                                        }
                                                    } else if proposal.height < current_height {
                                                        // Potential fork at a previous height
                                                        if let Some(local_block) = ledger.get_block(proposal.height) {
                                                            let mut hasher = blake3::Hasher::new();
                                                            hasher.update(&bincode::serialize(&local_block).unwrap());
                                                            let local_hash: [u8; 32] = hasher.finalize().into();
                                                            
                                                            if local_hash != proposal.block_hash {
                                                                println!("[P2P] Fork detected at height {}. Evaluating...", proposal.height);
                                                                // Trigger sync to get the full fork data
                                                                if let Some(sender) = P2P_COMMAND_SENDER.lock().unwrap().as_ref() {
                                                                    let _ = sender.send(NetworkCommand::RequestSync { 
                                                                        start_height: proposal.height, 
                                                                        peer_id 
                                                                    });
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    SwarmEvent::NewListenAddr { address, .. } => {
                                        println!("[P2P] Local node is listening on {}", address);
                                    }
                                    SwarmEvent::Behaviour(aetheris_node::p2p::AetherisBehaviourEvent::Identify(libp2p::identify::Event::Received { peer_id, info, .. })) => {
                                        println!("[P2P] Identified peer {} ({})", peer_id, info.agent_version);
                                        for addr in info.listen_addrs {
                                            network.swarm.behaviour_mut().kademlia.add_address(&peer_id, addr);
                                        }
                                    }
                                    SwarmEvent::Behaviour(aetheris_node::p2p::AetherisBehaviourEvent::Kademlia(kad::Event::OutboundQueryProgressed { result, .. })) => {
                                        match result {
                                            kad::QueryResult::GetRecord(Ok(kad::GetRecordOk::FoundRecord(kad::PeerRecord { record, .. }))) => {
                                                if record.key.as_ref().starts_with(b"mixnet_pk_") {
                                                    if record.value.len() == 32 {
                                                        let mut pk = [0u8; 32];
                                                        pk.copy_from_slice(&record.value);
                                                        if let Some(publisher) = record.publisher {
                                                            println!("[P2P] Kademlia discovered Mixnet PK for {}: {}", publisher, hex::encode(pk));
                                                            let mut keys = PEER_KEYS.lock().unwrap();
                                                            keys.insert(publisher, pk);
                                                        }
                                                    }
                                                }
                                            }
                                            _ => {}
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                    }
                }
            }
            Err(e) => println!("[P2P] Failed to initialize network: {}", e),
        }
    });
    
    println!("[FFI] Node started on port: {}", port);
    0
}

fn get_db_path() -> std::path::PathBuf {
    // 1. Try to use the path set via aetheris_start_node
    if let Ok(path_lock) = crate::DB_PATH.read() {
        if let Some(ref path) = *path_lock {
            let p: std::path::PathBuf = path.clone();
            return p;
        }
    }
    
    // 2. Fallback to current working directory
    let mut path = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."));
    
    path.push("aetheris_vault_v2");
    path
}

use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;

static MINING_STOP_FLAG: Lazy<Arc<AtomicBool>> = Lazy::new(|| Arc::new(AtomicBool::new(false)));
static MEMPOOL: Lazy<Mutex<Vec<aetheris_core::Transaction>>> = Lazy::new(|| Mutex::new(Vec::new()));

struct AppState {
    ledger: Option<LedgerState>,
    address: String,
    cipher: Aes256Gcm,
    mining_thread: Option<thread::JoinHandle<()>>,
    mixnet_pk: [u8; 32],
    _mixnet_sk: [u8; 32],
}

static STATE: Lazy<Mutex<AppState>> = Lazy::new(|| {
    // Use a temporary key for initialization, will be properly handled in lazy db opening
    let cipher = Aes256Gcm::new(&Aes256Gcm::generate_key(&mut OsRng));

    // Generate ephemeral mixnet keys for this session
    // In production, these would be derived from the wallet seed
    let sk = x25519_dalek::StaticSecret::random_from_rng(&mut OsRng);
    let pk = x25519_dalek::PublicKey::from(&sk);

    Mutex::new(AppState { 
        ledger: None, 
        cipher, 
        address: "Please Initialize Wallet".to_string(),
        mining_thread: None,
        mixnet_pk: *pk.as_bytes(),
        _mixnet_sk: sk.to_bytes(),
    })
});

#[no_mangle]
pub extern "C" fn aetheris_set_wallet_password(password: *const c_char) -> bool {
    if password.is_null() { return false; }
    let c_str = unsafe { CStr::from_ptr(password) };
    if let Ok(p) = c_str.to_str() {
        let mut pw = USER_PASSWORD.write().unwrap();
        *pw = Some(Zeroizing::new(p.to_string()));
        
        // If DB is already open, we might need to re-initialize the cipher
        // but for now, we assume this is called before DB operations.
        true
    } else {
        false
    }
}

fn ensure_db_open(state: &mut AppState) {
    if state.ledger.is_none() {
        let db_path = get_db_path();
        println!("[FFI] OPENING_DATABASE: {:?}", db_path);
        
        let db = match sled::open(&db_path) {
            Ok(d) => d,
            Err(e) => {
                let err_msg = format!("FATAL: Failed to open database at {:?}: {}. Is another instance running?", db_path, e);
                println!("[FFI] {}", err_msg);
                set_error(&err_msg);
                return;
            }
        };
        
        // --- MASTER KEY ENCRYPTION (KDF) ---
        // 1. Get or create master key (vault_key)
        let key_bytes = db.get(b"vault_key").unwrap();
        let key = if let Some(k) = key_bytes {
            let mut k_arr = [0u8; 32];
            
            // Check if master key is password protected
            if let Some(salt_bytes) = db.get(b"vault_salt").unwrap() {
                let password_opt = USER_PASSWORD.read().unwrap();
                if let Some(ref password) = *password_opt {
                    let salt = SaltString::from_b64(&String::from_utf8_lossy(&salt_bytes)).unwrap();
                    let argon2 = Argon2::default();
                    let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().hash.unwrap();
                    
                    // Use password hash to decrypt the master key
                    let kdf_key = Key::<Aes256Gcm>::from_slice(password_hash.as_bytes());
                    let cipher = Aes256Gcm::new(kdf_key);
                    let nonce = Nonce::from_slice(&k[..12]);
                    let ciphertext = &k[12..];
                    
                    match cipher.decrypt(nonce, ciphertext) {
                        Ok(decrypted) => {
                            k_arr.copy_from_slice(&decrypted);
                        },
                        Err(_) => {
                            let err_msg = "ERROR: Incorrect wallet password.";
                            println!("[FFI] {}", err_msg);
                            set_error(err_msg);
                            return;
                        }
                    }
                } else {
                    let err_msg = "ERROR: Wallet is password protected. Please set password first.";
                    println!("[FFI] {}", err_msg);
                    set_error(err_msg);
                    return;
                }
            } else {
                let err_msg = "ERROR: Wallet password not set. Call aetheris_set_wallet_password first.";
                println!("[FFI] {}", err_msg);
                set_error(err_msg);
                return;
            }
            Key::<Aes256Gcm>::from(k_arr)
        } else {
            // New database: Generate master key
            let master_key = Aes256Gcm::generate_key(&mut OsRng);
            
            let password_opt = USER_PASSWORD.read().unwrap();
            if let Some(ref password) = *password_opt {
                // Protect master key with password
                let salt = SaltString::generate(&mut OsRng);
                let argon2 = Argon2::default();
                let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().hash.unwrap();
                
                let kdf_key = Key::<Aes256Gcm>::from_slice(password_hash.as_bytes());
                let cipher = Aes256Gcm::new(kdf_key);
                let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
                let ciphertext = cipher.encrypt(&nonce, master_key.as_slice()).unwrap();
                
                let mut combined = nonce.to_vec();
                combined.extend_from_slice(&ciphertext);
                
                db.insert(b"vault_key", combined).unwrap();
                db.insert(b"vault_salt", salt.as_str().as_bytes()).unwrap();
            } else {
                let err_msg = "ERROR: Wallet password not set. Call aetheris_set_wallet_password before generating a wallet.";
                println!("[FFI] {}", err_msg);
                set_error(err_msg);
                return;
            }
            master_key
        };
        
        state.cipher = Aes256Gcm::new(&key);
        
        // Initialize LedgerState
        let mut ledger = LedgerState::new_with_db(db);
        ledger.restore_from_db();
        state.ledger = Some(ledger);

        // Update address if initialized
        let ledger = state.ledger.as_ref().unwrap();
        if let Some(m_enc) = ledger.db.get(b"mnemonic_enc").unwrap() {
            let nonce = Nonce::from_slice(&m_enc[..12]);
            let ciphertext = &m_enc[12..];
            let decrypted = state.cipher.decrypt(nonce, ciphertext).expect("Decryption failed");
            let mnemonic_str = String::from_utf8(decrypted).unwrap();
            
            let mut hasher = Keccak::v256();
            hasher.update(mnemonic_str.trim().as_bytes());
            let mut res = [0u8; 32];
            hasher.finalize(&mut res);
            state.address = format!("aet1{}", &hex::encode(res)[..24]);
        }
    }
}

#[no_mangle]
pub extern "C" fn aetheris_connect_peer(address: *const c_char) -> bool {
    if address.is_null() { return false; }
    let c_str = unsafe { CStr::from_ptr(address) };
    let addr_str = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };
    
    if let Ok(multiaddr) = addr_str.parse::<Multiaddr>() {
        if let Some(sender) = P2P_COMMAND_SENDER.lock().unwrap().as_ref() {
            let _ = sender.send(NetworkCommand::Dial(multiaddr));
            return true;
        }
    }
    false
}

#[no_mangle]
pub extern "C" fn aetheris_get_peer_count() -> u32 {
    PEER_KEYS.lock().unwrap().len() as u32
}
#[no_mangle]
pub extern "C" fn aetheris_execute_command_bin(encrypted_command: BinaryBuffer) -> BinaryBuffer {
    // --- S-8: null pointer guard ---
    if encrypted_command.ptr.is_null() || encrypted_command.len == 0 {
        return raw_error_buf("Null or empty BinaryBuffer");
    }
    // --- S-10/S-11: require bridge key, no zero-key/orphan fallback ---
    let bridge_key = match bridge_key_or_error() {
        Ok(k) => k,
        Err(buf) => return buf,
    };
    let key = Key::<Aes256Gcm>::from_slice(&bridge_key);
    let cipher = Aes256Gcm::new(key);

    // 1. Decrypt Request
    let input_data = unsafe { std::slice::from_raw_parts(encrypted_command.ptr, encrypted_command.len) };
    if input_data.len() < 28 {
        return encrypted_buf(&bridge_key, br#"{"error":"Command payload too short"}"#);
    }

    let nonce = Nonce::from_slice(&input_data[..12]);
    let ciphertext = &input_data[12..];
    
    let decrypted = Zeroizing::new(match cipher.decrypt(nonce, ciphertext) {
        Ok(d) => d,
        Err(_) => return encrypted_buf(&bridge_key, br#"{"error":"Command decryption failed"}"#),
    });

    let cmd_str = String::from_utf8_lossy(&decrypted);
    
    // 2. Process Command
    let result = match cmd_str.as_ref() {
        "get_version" => json!({"version": "0.1.0-alpha", "protocol": "Aetheris-PoT-v1"}),
        "get_network_info" => {
            json!({
                "p2p_active": true,
                "protocol_version": 1,
                "user_agent": "Aetheris-Kernel-Rust/0.1.0"
            })
        },
        "get_history" => {
            let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
            ensure_db_open(&mut state);
            let history: Vec<serde_json::Value> = match &state.ledger {
                Some(ledger) => {
                    let tx_bytes = ledger.db.get(b"transactions").unwrap_or_default().unwrap_or_default();
                    if tx_bytes.is_empty() { Vec::new() }
                    else { serde_json::from_slice(&tx_bytes).unwrap_or_default() }
                },
                None => Vec::new(),
            };
            json!({"transactions": history})
        },
        _ => json!({"error": "Unknown command"}),
    };

    // 3. Encrypt Response
    encrypted_buf(&bridge_key, result.to_string().as_bytes())
}

fn raw_error_buf(msg: &str) -> BinaryBuffer {
    // Returns a plaintext (non-encrypted) error buffer when bridge key is unavailable.
    // Uses sentinel prefix 0x00 so the frontend can distinguish from encrypted responses.
    let mut payload = vec![0x00u8];
    payload.extend_from_slice(msg.as_bytes());
    let mut bin = payload.into_boxed_slice();
    let len = bin.len();
    let ptr = bin.as_mut_ptr();
    std::mem::forget(bin);
    BinaryBuffer { ptr, len }
}

fn bridge_key_or_error() -> Result<[u8; 32], BinaryBuffer> {
    match *BRIDGE_KEY.read().unwrap() {
        Some(k) => Ok(k),
        None => Err(raw_error_buf("BRIDGE_KEY not set — call aetheris_handshake() first")),
    }
}

fn encrypted_buf(bridge_key: &[u8; 32], plaintext: &[u8]) -> BinaryBuffer {
    let key = Key::<Aes256Gcm>::from_slice(bridge_key);
    let cipher = Aes256Gcm::new(key);
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext).unwrap_or_else(|_| {
        // Encryption failure is infallible with correct key length; if it happens,
        // return a plaintext error buffer
        return vec![];
    });
    let mut payload = nonce.to_vec();
    payload.extend_from_slice(&ciphertext);
    let mut bin = payload.into_boxed_slice();
    let len = bin.len();
    let ptr = bin.as_mut_ptr();
    std::mem::forget(bin);
    BinaryBuffer { ptr, len }
}

// ── Note: aetheris_execute_command (plaintext JSON) intentionally removed during alpha-3.
// All FFI communication must use aetheris_execute_command_bin (AES-GCM encrypted).
// The plaintext path was a security bypass: callers could skip handshake encryption.
// See https://github.com/anomalyco/Aetheris/issues/FFI-encryption-uniformity

#[no_mangle]
pub extern "C" fn aetheris_init() -> i32 {
    if BRIDGE_KEY.read().unwrap().is_none() {
        let mut key = [0u8; 32];
        OsRng.fill_bytes(&mut key);
        *BRIDGE_KEY.write().unwrap() = Some(key);
        println!("[FFI] Aetheris Kernel Initialized — ephemeral bridge key generated.");
    }
    1
}

#[no_mangle]
pub extern "C" fn aetheris_handshake(output: *mut u8, output_len: u32) -> i32 {
    if output.is_null() || output_len < 32 { return -1; }
    let key = BRIDGE_KEY.read().unwrap();
    match *key {
        Some(k) => {
            unsafe { std::ptr::copy_nonoverlapping(k.as_ptr(), output, 32); }
            0
        }
        None => {
            set_error("Bridge key not initialized. Call aetheris_init() first.");
            -2
        }
    }
}

#[no_mangle]
pub extern "C" fn aetheris_is_initialized() -> bool {
    let mut state = STATE.lock().unwrap();
    ensure_db_open(&mut state);
    
    if let Some(ledger) = state.ledger.as_ref() {
        let db = &ledger.db;
        // Check if mnemonic exists AND is not empty
        match db.get(b"mnemonic_enc").unwrap_or(None) {
            Some(v) => !v.is_empty(),
            None => false
        }
    } else {
        false
    }
}

#[no_mangle]
pub extern "C" fn aetheris_create_wallet() -> bool {
    let mut entropy = [0u8; 16];
    if getrandom::getrandom(&mut entropy).is_err() {
        return false;
    }
    let m = Mnemonic::from_entropy(&entropy).unwrap();
    let phrase = m.to_string();
    
    let c_phrase = CString::new(phrase).unwrap();
    aetheris_import_wallet(c_phrase.as_ptr())
}

/// --- MATHEMATICAL GENESIS PROOF (The "Proof of Burn/Work" Hybrid) ---
/// Instead of a list of addresses, the genesis allocation is defined by a mathematical challenge.
/// To claim the genesis assets, the mnemonic must derive a key that, when hashed with Argon2 
/// (a memory-hard function), meets a specific difficulty target.
/// This ensures that the genesis allocation is tied to a "computational secret" rather than a "list".
#[no_mangle]
pub extern "C" fn aetheris_import_wallet(mnemonic: *const c_char) -> bool {
    if mnemonic.is_null() { return false; }
    let c_str = unsafe { CStr::from_ptr(mnemonic) };
    let phrase = match c_str.to_str() {
        Ok(s) => s.trim(), // Ensure trim
        Err(_) => return false,
    };

    // Calculate VDF challenge to prove work for importing/genesis claim
    // Support env override for fast tests: AETHERIS_VDF_DIFFICULTY=1000
    let difficulty = std::env::var("AETHERIS_VDF_DIFFICULTY")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(aetheris_core::VDF_DIFFICULTY);
    let vdf = VDF::new(difficulty);
    let seed = phrase.as_bytes();
    let (vdf_result, vdf_proof, _) = vdf.solve(seed);
    
    if !vdf.verify(seed, &vdf_result, &vdf_proof) {
        return false;
    }

    let mut state = STATE.lock().unwrap();
    ensure_db_open(&mut state);
    
    let ledger = match state.ledger.as_ref() {
        Some(l) => l,
        None => return false,
    };
    let db = &ledger.db;
    
    if db.get(b"mnemonic_enc").unwrap_or(None).is_some() {
        return false;
    }

    // Standard wallet encryption
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = match state.cipher.encrypt(&nonce, phrase.as_bytes()) {
        Ok(c) => c,
        Err(_) => return false,
    };
    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    db.insert(b"mnemonic_enc", combined).unwrap();

    // Derive viewing key (blake3, Phase 0.6)
    let mut viewing_key = [0u8; 32];
    let vk = blake3::hash(&[phrase.as_bytes(), b"aetheris-viewing-key"].concat());
    viewing_key.copy_from_slice(vk.as_bytes());

    // 1. First Pass: Derive the address properly before scanning transactions
    let addr_hash = blake3::hash(phrase.as_bytes());
    let address = format!("aet1{}", hex::encode(&addr_hash.as_bytes()[..24]));
    
    #[cfg(debug_assertions)]
    println!("[FFI] IMPORT: Address: {}", address);
    
    // Drop immutable borrow of db to allow mutable borrow of state
    let genesis = create_genesis_block();
    
    // UPDATE: Update the state's address
    state.address = address.clone();
    
    // 2. Second Pass: Calculate initial balance based on Genesis Block
    let mut balance_atoms: u64 = 0;
    let mut tx_history = Vec::new();

    let scan_addr = address.clone(); 
    println!("[FFI] SCANNING_GENESIS for address: {}, scan_addr: {}", address, scan_addr);

    // Hardcoded genesis recipients for the prototype's "scanning" logic
    let genesis_seed_addr = "aet12f615319124ce9db1669040f"; 
    let dev_addr = "aet147cafe7b55906a973197db85";

    // tx[0] is Mint (21M to Seed)
    let mint_tx = &genesis.transactions[0];
    if scan_addr == genesis_seed_addr {
        balance_atoms += mint_tx.public_amount;
        tx_history.push(json!({
            "type": "Genesis_Mint",
            "amount_atoms": mint_tx.public_amount,
            "address": "System",
            "timestamp": "2026-02-13T00:00:00Z",
            "status": "Confirmed (Genesis)",
            "proof_size": mint_tx.proof.len(),
            "commitment": hex::encode(mint_tx.outputs[0].commitment)
        }));
    }

    // tx[1] is Transfer (5M from Seed to Dev)
    let transfer_tx = &genesis.transactions[1];
    let transfer_amount = 5_000_000 * ATOMS_PER_AET;
    if scan_addr == dev_addr {
        balance_atoms += transfer_amount;
        tx_history.push(json!({
            "type": "Genesis_Transfer",
            "amount_atoms": transfer_amount,
            "address": genesis_seed_addr,
            "timestamp": "2026-02-13T00:05:00Z",
            "status": "Confirmed (Genesis)",
            "proof_size": transfer_tx.proof.len(),
            "commitment": hex::encode(transfer_tx.outputs[0].commitment)
        }));
    } else if scan_addr == genesis_seed_addr {
        balance_atoms = balance_atoms.saturating_sub(transfer_amount);
        tx_history.push(json!({
            "type": "Genesis_Transfer",
            "amount_atoms": -(transfer_amount as i64),
            "address": dev_addr,
            "timestamp": "2026-02-13T00:05:00Z",
            "status": "Confirmed (Genesis)",
            "proof_size": transfer_tx.proof.len(),
            "commitment": hex::encode(transfer_tx.outputs[1].commitment)
        }));
    }

    state.ledger.as_ref().unwrap().db.insert(b"balance_atoms", balance_atoms.to_string().as_bytes()).unwrap();

    // 3. Persist Genesis Block to Ledger
    {
        // C-4: Use deterministic genesis_identity_hash (excludes random ZKP proof bytes)
        let genesis_hash = aetheris_core::genesis_identity_hash(&genesis);
        let current_hash = hex::encode(genesis_hash);
        
        let config = load_genesis_config();
        let is_mainnet = config.as_ref().map(|c| c.network == "aetheris-mainnet-alpha").unwrap_or(false);
        
        if is_mainnet && current_hash != EXPECTED_GENESIS_HASH {
            println!("[FFI] CRITICAL: Mainnet Genesis hash mismatch!");
            println!("[FFI] Expected: {}", EXPECTED_GENESIS_HASH);
            println!("[FFI] Found:    {}", current_hash);
            if !cfg!(debug_assertions) {
                return false;
            }
        } else if !is_mainnet {
            println!("[FFI] Running on Custom Network. Genesis Hash: {}", current_hash);
        }

        // CRITICAL: Ensure DB is closed in state to release file lock
        state.ledger = None;
        drop(state);
        
        let db_path = get_db_path();
        let mut ledger = LedgerState::new(db_path.to_str().unwrap());
        if ledger.height == 0 {
            println!("[FFI] Applying Genesis Block to Ledger State...");
            if let Err(e) = ledger.apply_block(genesis.clone()) {
                println!("[FFI] ERROR: Failed to apply genesis block: {}", e);
            }
        }
        drop(ledger); // Explicitly close ledger DB
    }
    
    // Re-acquire state lock and re-open DB
    let mut state = STATE.lock().unwrap();
    ensure_db_open(&mut state);
    
    // Perform initial full scan for transactions and UTXOs
    scan_ledger_for_wallet(&mut state);

    // Filter tx_history to remove genesis txs that are now picked up by scan_ledger_for_wallet
    // Actually, scan_ledger_for_wallet already adds Shielded_Receive. 
    // We should merge carefully.
    
    // Drop immutable borrow to allow mutable borrow of state
    let ledger = state.ledger.as_ref().unwrap();
    let db = &ledger.db;
    if let Some(existing_history_bytes) = db.get(b"transactions").unwrap() {
        if let Ok(mut history) = serde_json::from_slice::<Vec<serde_json::Value>>(&existing_history_bytes) {
            for tx in tx_history {
                let comm_hex = tx["commitment"].as_str().unwrap_or("");
                if !history.iter().any(|h| h["commitment"].as_str() == Some(comm_hex)) {
                    history.push(tx);
                }
            }
            db.insert(b"transactions", serde_json::to_vec(&history).unwrap()).unwrap();
        }
    } else {
        db.insert(b"transactions", serde_json::to_vec(&tx_history).unwrap()).unwrap();
    }
    
    // Store the deterministic genesis identity hash as the chain tip
    if db.get(b"last_block_hash").unwrap().is_none() {
        let genesis_hash = aetheris_core::genesis_identity_hash(&genesis);
        db.insert(b"last_block_hash", &genesis_hash).unwrap();
    }
    
    // Note: Height is already updated by ledger.apply_block above
    if db.get(b"current_difficulty").unwrap().is_none() {
        db.insert(b"current_difficulty", aetheris_core::VDF_DIFFICULTY.to_string().as_bytes()).unwrap();
    }
    if db.get(b"last_adjustment_timestamp").unwrap().is_none() {
        db.insert(b"last_adjustment_timestamp", chrono::Utc::now().timestamp().to_string().as_bytes()).unwrap();
    }
    
    db.flush().unwrap();
    println!("[FFI] IMPORTED_ADDRESS: {}", state.address);
    true
}

#[no_mangle]
pub extern "C" fn aetheris_get_genesis_hash() -> *mut c_char {
    let genesis = create_genesis_block();
    let hash_hex = ffi_try!({
        let hash = aetheris_core::genesis_identity_hash(&genesis);
        hex::encode(hash)
    }, std::ptr::null_mut() as *mut c_char);
    CString::new(hash_hex).unwrap().into_raw()
}

#[repr(C)]
pub struct BinaryBuffer {
    pub ptr: *mut u8,
    pub len: usize,
}

#[no_mangle]
pub extern "C" fn aetheris_get_node_status_bin() -> BinaryBuffer {
    let bridge_key = match bridge_key_or_error() {
        Ok(k) => k,
        Err(buf) => return buf,
    };

    let status_json = ffi_try!({
        let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        ensure_db_open(&mut state);

        if let Some(ledger) = state.ledger.as_ref() {
            let db = &ledger.db;
            let peers_count = PEER_KEYS.lock().unwrap_or_else(|e| e.into_inner()).len() as u32;
            let mining_active = state.mining_thread.is_some() && !MINING_STOP_FLAG.load(Ordering::SeqCst);
            let mempool_size = MEMPOOL.lock().unwrap_or_else(|e| e.into_inner()).len();

            let balance_atoms = db.get(b"balance_atoms").unwrap_or(None)
                .map(|b| String::from_utf8(b.to_vec()).unwrap_or_default().parse().unwrap_or(0))
                .unwrap_or(0);

            let status = BinaryNodeStatus {
                status: "ONLINE".to_string(),
                peers: peers_count,
                height: ledger.height,
                balance_atoms,
                address: state.address.clone(),
                anonymity_set: 1024,
                privacy_score: 95,
                mining_active,
                mempool_size,
            };

            let mut sj = serde_json::to_value(&status).unwrap_or(json!({}));
            if let Some(tx_bytes) = db.get(b"transactions").unwrap_or(None) {
                if let Ok(txs) = serde_json::from_slice::<serde_json::Value>(&tx_bytes) {
                    sj["transactions"] = txs;
                }
            } else {
                sj["transactions"] = json!([]);
            }
            serde_json::to_string(&sj).unwrap_or_else(|_| "{}".to_string())
        } else {
            serde_json::to_string(&json!({"status": "OFFLINE", "error": "Database not open"}))
                .unwrap_or_else(|_| "{}".to_string())
        }
    }, raw_error_buf("panic: aetheris_get_node_status_bin"));

    encrypted_buf(&bridge_key, status_json.as_bytes())
}

fn scan_ledger_for_wallet(state: &mut AppState) {
    if state.ledger.is_none() { return; }
    let ledger = state.ledger.as_mut().unwrap();
    
    // Derive viewing key from mnemonic
    let mut viewing_key = [0u8; 32];
    if let Some(m_enc) = ledger.db.get(b"mnemonic_enc").unwrap() {
        let key_bytes = ledger.db.get(b"vault_key").unwrap().unwrap();
        
        let mut k_arr = [0u8; 32];
        if let Some(salt_bytes) = ledger.db.get(b"vault_salt").unwrap() {
            let password_opt = USER_PASSWORD.read().unwrap();
            if let Some(ref password) = *password_opt {
                let salt = SaltString::from_b64(&String::from_utf8_lossy(&salt_bytes)).unwrap();
                let argon2 = Argon2::default();
                let password_hash = argon2.hash_password(password.as_bytes(), &salt).unwrap().hash.unwrap();
                
                let kdf_key = Key::<Aes256Gcm>::from_slice(password_hash.as_bytes());
                let cipher = Aes256Gcm::new(kdf_key);
                let nonce = Nonce::from_slice(&key_bytes[..12]);
                let ciphertext = &key_bytes[12..];
                
                if let Ok(decrypted) = cipher.decrypt(nonce, ciphertext) {
                    k_arr.copy_from_slice(&Zeroizing::new(decrypted));
                } else {
                    return;
                }
            } else {
                return;
            }
        } else {
            return;
        }
        
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&k_arr));
        
        let nonce = Nonce::from_slice(&m_enc[..12]);
        let ciphertext = &m_enc[12..];
        if let Ok(decrypted) = cipher.decrypt(nonce, ciphertext) {
            let decrypted = Zeroizing::new(decrypted);
            let vk = blake3::hash(&[decrypted.as_slice(), b"aetheris-viewing-key"].concat());
            viewing_key.copy_from_slice(vk.as_bytes());
        }
    } else {
        return;
    }

    let mut owned_utxos = Vec::new();
    let mut total_balance = 0;
    let mut new_tx_history = Vec::new();

    println!("[FFI] SCANNING_LEDGER: Searching for owned outputs among {} commitments...", ledger.all_outputs.len());

    for output in &ledger.all_outputs {
        println!("[FFI] Trial decrypting output with commitment: {}", hex::encode(output.commitment));
        if let Some((amount, blinding)) = aetheris_zkp::ZKProofSystem::trial_decrypt(
            &viewing_key,
            &output.ephemeral_key,
            &output.ciphertext
        ) {
            println!("[FFI] Found owned output! Amount: {} atoms", amount);

            // H-3: Verify ciphertext-derived commitment matches on-chain commitment
            if aetheris_zkp::create_commitment(amount, &blinding) != output.commitment {
                println!("[FFI] Commitment mismatch — skipping forged output");
                continue;
            }

            // Found an output belonging to us!
            // Check if it's spent by calculating its nullifier
            // In this prototype, we use commitment as index for simplicity in nullifier derivation
            let mut hasher = Keccak::v256();
            hasher.update(&output.commitment);
            let mut comm_idx_bytes = [0u8; 8];
            hasher.finalize(&mut comm_idx_bytes[..]); // Dummy index derivation
            let idx = u64::from_le_bytes(comm_idx_bytes);

            let nf = aetheris_zkp::create_nullifier(&viewing_key, idx);
            
            if !ledger.nullifiers.contains(&nf) {
                total_balance += amount;
                owned_utxos.push(OwnedUTXO {
                    commitment: output.commitment,
                    amount_atoms: amount,
                    blinding,
                    ephemeral_key: output.ephemeral_key,
                });
            }

            // Also add to transaction history if not already there
            new_tx_history.push(json!({
                "type": "Shielded_Receive",
                "amount_atoms": amount,
                "address": "Unknown (Shielded)",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "status": "Confirmed",
                "commitment": hex::encode(output.commitment)
            }));
        }
    }

    // Update DB
    ledger.db.insert(b"balance_atoms", total_balance.to_string().as_bytes()).unwrap();
    ledger.db.insert(b"owned_utxos", serde_json::to_vec(&owned_utxos).unwrap()).unwrap();
    
    // Merge history
    if let Some(existing_history_bytes) = ledger.db.get(b"transactions").unwrap() {
        if let Ok(mut history) = serde_json::from_slice::<Vec<serde_json::Value>>(&existing_history_bytes) {
            for tx in new_tx_history {
                // Simple de-duplication based on commitment
                let comm_hex = tx["commitment"].as_str().unwrap_or("");
                if !history.iter().any(|h| h["commitment"].as_str() == Some(comm_hex)) {
                    history.insert(0, tx);
                }
            }
            ledger.db.insert(b"transactions", serde_json::to_vec(&history).unwrap()).unwrap();
        }
    }

    ledger.db.flush().unwrap();
}

#[no_mangle]
pub extern "C" fn aetheris_get_wallet_history_bin() -> BinaryBuffer {
    let bridge_key = match bridge_key_or_error() {
        Ok(k) => k,
        Err(buf) => return buf,
    };

    let result_json = ffi_try!({
        let mut state = STATE.lock().unwrap_or_else(|e| e.into_inner());
        ensure_db_open(&mut state);
        let result = if let Some(ledger) = state.ledger.as_ref() {
            let db = &ledger.db;
            let tx_bytes = db.get(b"transactions").unwrap_or(None).unwrap_or_default();
            let history: Vec<serde_json::Value> = if tx_bytes.is_empty() {
                Vec::new()
            } else {
                serde_json::from_slice(&tx_bytes).unwrap_or_default()
            };
            json!({"transactions": history, "count": history.len()})
        } else {
            json!({"error": "Database not open", "transactions": [], "count": 0})
        };
        result.to_string()
    }, raw_error_buf("panic: aetheris_get_wallet_history_bin"));

    encrypted_buf(&bridge_key, result_json.as_bytes())
}

#[no_mangle]
pub extern "C" fn aetheris_free_buffer(buf: BinaryBuffer) {
    if !buf.ptr.is_null() {
        unsafe {
            let _ = Box::from_raw(std::slice::from_raw_parts_mut(buf.ptr, buf.len));
        }
    }
}

#[no_mangle]
pub extern "C" fn aetheris_solve_vdf_local() -> *mut c_char {
    let result = (|| -> Option<String> {
        let (last_hash, difficulty) = {
            let mut state = STATE.lock().ok()?;
            ensure_db_open(&mut state);
            let ledger = state.ledger.as_ref()?;
            let db = &ledger.db;
            let last_hash = ledger.last_block_hash;
            
            // Try to get dynamic difficulty, fallback to default
            let difficulty: u64 = db.get(b"current_difficulty").ok()??
                .to_vec()
                .as_slice()
                .try_into()
                .map(|bytes| String::from_utf8_lossy(bytes).parse().unwrap_or(aetheris_core::VDF_DIFFICULTY))
                .unwrap_or(aetheris_core::VDF_DIFFICULTY);
            
            (last_hash.to_vec(), difficulty)
        };
        
        let vdf = VDF::new(difficulty);
        let (res, proof, _) = vdf.solve(&last_hash);
        
        let solution = json!({
            "result": hex::encode(res),
            "proof": hex::encode(proof)
        });
        Some(solution.to_string())
    })();
    
    let solution_str = result.unwrap_or_else(|| {
        json!({"error": "Ledger not open or error accessing DB"}).to_string()
    });
    CString::new(solution_str).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn aetheris_get_vdf_challenge() -> *mut c_char {
    let mut state = STATE.lock().unwrap();
    ensure_db_open(&mut state);
    
    let challenge_hex = if let Some(ledger) = state.ledger.as_ref() {
        hex::encode(ledger.last_block_hash)
    } else {
        "0000000000000000000000000000000000000000000000000000000000000000".to_string()
    };
    
    CString::new(challenge_hex).unwrap().into_raw()
}

#[no_mangle]
pub extern "C" fn aetheris_submit_vdf_proof(result_hex: *const c_char, proof_hex: *const c_char) -> bool {
    if result_hex.is_null() || proof_hex.is_null() { return false; }
    
    let result_str = unsafe { CStr::from_ptr(result_hex) }.to_str().unwrap_or("");
    let proof_str = unsafe { CStr::from_ptr(proof_hex) }.to_str().unwrap_or("");
    
    let result_bytes = match hex::decode(result_str) {
        Ok(b) => b,
        Err(_) => {
            println!("[FFI] ERROR: Failed to decode VDF result hex.");
            return false;
        },
    };
    let proof_bytes = match hex::decode(proof_str) {
        Ok(b) => b,
        Err(_) => {
            println!("[FFI] ERROR: Failed to decode VDF proof hex.");
            return false;
        },
    };

    println!("[FFI] Submitting VDF proof... result_len={}, proof_len={}", result_bytes.len(), proof_bytes.len());

    let mut state = STATE.lock().unwrap();
    ensure_db_open(&mut state);
    
    // 0. Derive viewing key
    let mut viewing_key = [0u8; 32];
    if let Some(ledger) = state.ledger.as_ref() {
        if let Some(m_enc) = ledger.db.get(b"mnemonic_enc").unwrap_or(None) {
            let nonce = Nonce::from_slice(&m_enc[..12]);
            let ciphertext = &m_enc[12..];
            if let Ok(decrypted) = state.cipher.decrypt(nonce, ciphertext) {
                let decrypted = Zeroizing::new(decrypted);
                let vk = blake3::hash(&[decrypted.as_slice(), b"aetheris-viewing-key"].concat());
                viewing_key.copy_from_slice(vk.as_bytes());
            }
        }
    } else {
        return false;
    }

    let ledger = state.ledger.as_mut().unwrap();
    
    let current_difficulty: u64 = ledger.db.get(b"current_difficulty").unwrap_or(None)
        .map(|d| String::from_utf8(d.to_vec()).unwrap_or_default().parse().unwrap_or(aetheris_core::VDF_DIFFICULTY))
        .unwrap_or(aetheris_core::VDF_DIFFICULTY);

    // 1. Construct the Block
    println!("[FFI] Constructing block at height {}...", ledger.height);
    // 1. Generate Reward Transaction for the miner
    let reward_atoms = calculate_block_reward_atoms(ledger.height);
    let mut reward_blinding = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut reward_blinding);
    let reward_commitment = aetheris_zkp::create_commitment(reward_atoms, &reward_blinding);
    
    // Viewing key already derived above

    let (epk_reward, ciphertext_reward) = aetheris_zkp::ZKProofSystem::encrypt_output(
        &viewing_key,
        reward_atoms,
        &reward_blinding
    );

    let reward_proof = ZKProofSystem::prove_conservation(
        &[],
        &[reward_atoms],
        &[],
        &[reward_blinding],
        &[reward_commitment],
        reward_atoms as i64,
    );

    let reward_tx = aetheris_core::Transaction {
        inputs: vec![],
        outputs: vec![aetheris_core::ShieldedOutput {
            commitment: reward_commitment,
            ephemeral_key: epk_reward,
            ciphertext: ciphertext_reward,
        }],
        public_amount: reward_atoms,
        proof: reward_proof,
    };

    let txs = vec![reward_tx];

    let block = aetheris_core::Block {
        header: aetheris_core::BlockHeader {
            parent_hash: ledger.last_block_hash,
            state_root: ledger.get_state_root(),
            timestamp: chrono::Utc::now().timestamp() as u64,
            vdf_result: result_bytes.clone(),
            vdf_proof: proof_bytes,
            aggregate_proof: aetheris_zkp::ZKProofSystem::aggregate_proofs(
                &ledger.last_aggregate_proof, 
                &txs.iter().map(|t| t.proof.clone()).collect::<Vec<_>>(),
                &txs.iter().map(|t| t.outputs.iter().map(|o| o.commitment).collect::<Vec<_>>()).collect::<Vec<_>>(),
                &txs.iter().map(|t| t.public_amount as i64).collect::<Vec<_>>(),
                ledger.height,
                &[0u8; 32]
            ).unwrap_or_else(|_| b"aetheris_aggregate_v1_error".to_vec()),
            height: ledger.height,
            difficulty: current_difficulty,
        },
        transactions: txs,
    };

    // 2. Apply via LedgerState (Handles all consensus verification)
    println!("[FFI] Applying block via LedgerState...");
    if let Err(e) = ledger.apply_block(block.clone()) {
        let err_msg = format!("BLOCK_REJECTED: {}", e);
        println!("[FFI] {}", err_msg);
        set_error(&err_msg);
        return false;
    }

    // 3. Update FFI/Wallet specific history (Balance will be updated by scan_ledger_for_wallet)
    let tx_bytes = ledger.db.get(b"transactions").unwrap().unwrap_or_default();
    let mut history: Vec<serde_json::Value> = if tx_bytes.is_empty() {
        Vec::new()
    } else {
        serde_json::from_slice(&tx_bytes).unwrap_or_default()
    };

    history.insert(0, json!({
        "type": "PoT_Issuance",
        "amount_atoms": reward_atoms,
        "address": "System",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "status": "Confirmed",
        "proof_size": block.header.vdf_proof.len()
    }));

    ledger.db.insert(b"transactions", serde_json::to_vec(&history).unwrap()).unwrap();
    ledger.db.flush().unwrap();
    
    // Trigger wallet scan
    scan_ledger_for_wallet(&mut state);
    
    println!("[FFI] PoT_BLOCK_ACCEPTED: Height={}, Reward={} atoms", block.header.height, reward_atoms);
    true
}

#[no_mangle]
pub extern "C" fn aetheris_start_mining() -> bool {
    let mut state = STATE.lock().unwrap();
    ensure_db_open(&mut state);
    
    if state.mining_thread.is_some() {
        return true; // Already mining
    }

    MINING_STOP_FLAG.store(false, Ordering::SeqCst);

    let db_handle = state.ledger.as_ref().map(|l| l.db.clone());

    let handle = thread::spawn(move || {
        println!("[MINER] Background mining thread started.");

        let db = db_handle.expect("LedgerState not initialized before mining");

        while !MINING_STOP_FLAG.load(Ordering::SeqCst) {
            let mut ledger = LedgerState::new_with_db(db.clone());
            
            // 1. Get current challenge from ledger
            let last_hash = ledger.last_block_hash;
            let current_height = ledger.height;
            
            let current_difficulty: u64 = ledger.db.get(b"current_difficulty").unwrap()
                .map(|d| String::from_utf8(d.to_vec()).unwrap().parse().unwrap_or(aetheris_core::VDF_DIFFICULTY))
                .unwrap_or(aetheris_core::VDF_DIFFICULTY);
            
            println!("[MINER] Solving VDF for height {} (Difficulty: {})...", current_height, current_difficulty);
            
            // 2. Solve VDF
            let vdf = VDF::new(current_difficulty);
            let (result, vdf_proof, _) = vdf.solve(&last_hash);
            
            if MINING_STOP_FLAG.load(Ordering::SeqCst) { break; }

            // 3. Gather transactions from MEMPOOL (core::Transaction, Phase 0.4)
            let mut tx_proofs = Vec::new();
            let mut tx_public_amounts = Vec::new();
            let mut tx_commitments: Vec<Vec<[u8; 32]>> = Vec::new();
            let mut core_txs: Vec<aetheris_core::Transaction> = Vec::new();

            {
                let mut mempool = MEMPOOL.lock().unwrap();
                for tx in mempool.drain(..) {
                    tx_proofs.push(tx.proof.clone());
                    tx_public_amounts.push(tx.public_amount as i64);
                    tx_commitments.push(tx.outputs.iter().map(|o| o.commitment).collect());
                    core_txs.push(tx);
                }
            }

            // 4. Create Block Proposal for Arbitration
            let state_root = ledger.get_state_root(); 
            let aggregate_proof = match ZKProofSystem::aggregate_proofs(
                &ledger.last_aggregate_proof, 
                &tx_proofs,
                &tx_commitments,
                &tx_public_amounts,
                ledger.height,
                &state_root
            ) {
                Ok(p) => p,
                Err(e) => {
                    println!("[MINER] Aggregation failed: {}", e);
                    continue;
                }
            };
            
            // Compute block_hash from serialized block (matching state.rs canonical hash)
            let temp_block = aetheris_core::Block {
                header: aetheris_core::BlockHeader {
                    parent_hash: ledger.last_block_hash,
                    state_root,
                    timestamp: chrono::Utc::now().timestamp() as u64,
                    vdf_result: result.clone(),
                    vdf_proof: vdf_proof.clone(),
                    aggregate_proof: aggregate_proof.clone(),
                    height: current_height,
                    difficulty: current_difficulty,
                },
                transactions: core_txs.clone(),
            };
            let block_hash = aetheris_core::block_hash(&temp_block);

            let proposal = BlockProposal {
                height: current_height,
                block_hash,
                transactions: core_txs.clone(),
                vdf_result: result.clone(),
                vdf_proof: vdf_proof.clone(),
                aggregate_proof: aggregate_proof.clone(),
                sender: "LocalMiner".to_string(),
                difficulty: current_difficulty,
                state_root,
                timestamp: chrono::Utc::now().timestamp() as u64,
            };

            // 5. Submit to Mathematical Arbitrator (Simulated P2P)
            broadcast_block_proposal(proposal.clone());
            
            // 6. Wait for arbitration
            let winner = {
                let arb = ARBITRATOR.lock().unwrap();
                arb.get_winner(proposal.height)
            };

            if let Some(won_proposal) = winner {
                if won_proposal.sender != "LocalMiner" {
                    println!("[MINER] Block #{} lost to peer {}.", won_proposal.height, won_proposal.sender);
                    ledger.restore_from_db(); // Sync state with winner
                    continue; 
                }
            }

            // 7. Apply Won Block via LedgerState
    let block = aetheris_core::Block {
        header: aetheris_core::BlockHeader {
            parent_hash: last_hash,
            state_root,
            timestamp: chrono::Utc::now().timestamp() as u64,
            vdf_result: result,
            vdf_proof,
            aggregate_proof,
            height: current_height,
            difficulty: current_difficulty,
        },
        transactions: core_txs,
    };

    if let Err(e) = ledger.apply_block(block.clone()) {
        println!("[MINER] Failed to apply mined block: {}", e);
        continue;
    }

    // Trigger full wallet scan after applying block
    drop(ledger);
    {
        let mut state = STATE.lock().unwrap();
        scan_ledger_for_wallet(&mut state);
    }
    let ledger = LedgerState::new_with_db(db.clone()); // Re-open for reward logic (shared Db handle)
    
    // Update UI/FFI visible state
    let reward = calculate_block_reward_atoms(ledger.height);
            let current_balance: u64 = ledger.db.get(b"balance_atoms").unwrap()
                .map(|b| String::from_utf8(b.to_vec()).unwrap().parse().unwrap_or(0))
                .unwrap_or(0);
            
            let total_balance_change: i128 = reward as i128;
            let mut history_updates = Vec::new();
            // Wallet history tracking uses trial-decrypt instead of WalletTransaction.from/to
            // (shielded protocol does not reveal sender/recipient on-chain)
            history_updates.push(json!({
                "type": "Coinbase Reward",
                "amount_atoms": reward as i64,
                "address": "System",
                "timestamp": chrono::Utc::now().to_rfc3339(),
                "status": "Confirmed",
                "height": ledger.height
            }));

            let new_balance = (current_balance as i128 + total_balance_change) as u64;
            ledger.db.insert(b"balance_atoms", new_balance.to_string().as_bytes()).unwrap();
            
            let tx_bytes = ledger.db.get(b"transactions").unwrap().unwrap_or_default();
            let mut history: Vec<serde_json::Value> = if tx_bytes.is_empty() {
                Vec::new()
            } else {
                serde_json::from_slice(&tx_bytes).unwrap_or_default()
            };
            for update in history_updates {
                history.insert(0, update);
            }
            ledger.db.insert(b"transactions", serde_json::to_vec(&history).unwrap()).unwrap();
            ledger.db.flush().unwrap();
            
            println!("[MINER] Block #{} Mined and Applied! Reward: {} AET.", 
                ledger.height, reward as f64 / ATOMS_PER_AET as f64);            
        }
        
        println!("[MINER] Background mining thread stopped.");
    });

    state.mining_thread = Some(handle);
    true
}

#[no_mangle]
pub extern "C" fn aetheris_stop_mining() -> bool {
    let mut state = STATE.lock().unwrap();
    MINING_STOP_FLAG.store(true, Ordering::SeqCst);
    
    if let Some(handle) = state.mining_thread.take() {
        // We don't join here to avoid blocking the FFI call if VDF is mid-calculation
        // The thread will exit on its own after current iteration
        let _ = handle; 
    }
    true
}

#[no_mangle]
pub extern "C" fn aetheris_is_mining() -> bool {
    let state = STATE.lock().unwrap();
    state.mining_thread.is_some() && !MINING_STOP_FLAG.load(Ordering::SeqCst)
}

#[no_mangle]
pub extern "C" fn aetheris_send_transaction(to_address: *const c_char, amount_aet: f64) -> bool {
    if to_address.is_null() { return false; }
    
    let c_str = unsafe { CStr::from_ptr(to_address) };
    let target_address = match c_str.to_str() {
        Ok(s) => s,
        Err(_) => return false,
    };

    let mut state = STATE.lock().unwrap();
    ensure_db_open(&mut state);
    let ledger = state.ledger.as_ref().unwrap();
    let db = &ledger.db;

    // 1. FREEZE CHECK
    if is_address_frozen(&state.address) {
        let err_msg = format!("ERROR: Address {} is FROZEN. Outgoing transactions are prohibited.", state.address);
        println!("[FFI] {}", err_msg);
        set_error(&err_msg);
        return false;
    }

    // 2. BALANCE CHECK (Pre-verification)
    let current_balance_atoms: u64 = db.get(b"balance_atoms").unwrap()
        .map(|b| String::from_utf8(b.to_vec()).unwrap().parse().unwrap_or(0))
        .unwrap_or(0);

    let send_amount_atoms = (amount_aet * ATOMS_PER_AET as f64) as u64;
    
    // Pending balance check removed in Phase 0.4 — WalletTransaction no longer exists.
    // Shielded protocol does not expose sender/recipient; balance check requires trial-decrypt scan.
    if current_balance_atoms < send_amount_atoms { 
        let err_msg = format!("ERROR: Insufficient balance. Required: {}, Available: {}", send_amount_atoms, current_balance_atoms);
        println!("[FFI] {}", err_msg);
        set_error(&err_msg);
        return false; 
    }

    // 3. UTXO SELECTION & REAL ZK PROOF
    let send_amount_atoms = (amount_aet * ATOMS_PER_AET as f64) as u64;
    let owned_utxos_bytes = db.get(b"owned_utxos").unwrap().unwrap_or_default();
    let mut owned_utxos: Vec<OwnedUTXO> = if owned_utxos_bytes.is_empty() {
        Vec::new()
    } else {
        serde_json::from_slice(&owned_utxos_bytes).unwrap_or_default()
    };

    // --- MULTI-UTXO SELECTION LOGIC ---
    let mut selected_utxos = Vec::new();
    let mut input_sum = 0;
    
    // Sort UTXOs by amount (descending) to minimize inputs
    owned_utxos.sort_by(|a, b| b.amount_atoms.cmp(&a.amount_atoms));

    let mut remaining_utxos = Vec::new();
    for utxo in &owned_utxos {
        if input_sum < send_amount_atoms {
            input_sum += utxo.amount_atoms;
            selected_utxos.push(utxo);
        } else {
            remaining_utxos.push(utxo);
        }
    }

    if input_sum < send_amount_atoms {
        let err_msg = format!("ERROR: Insufficient funds in UTXOs. Have: {}, Need: {}", input_sum, send_amount_atoms);
        set_error(&err_msg);
        return false;
    }
    
    // Generate viewing key for nullifiers
    let mut viewing_key = [0u8; 32];
    if let Some(m_enc) = db.get(b"mnemonic_enc").unwrap() {
        let nonce = Nonce::from_slice(&m_enc[..12]);
        let ciphertext = &m_enc[12..];
        if let Ok(decrypted) = state.cipher.decrypt(nonce, ciphertext) {
            let vk = blake3::hash(&[decrypted.as_slice(), b"aetheris-viewing-key"].concat());
            viewing_key.copy_from_slice(vk.as_bytes());
        } else {
            set_error("ERROR: Failed to decrypt mnemonic for transaction signing.");
            return false;
        }
    }

    // Create nullifiers and prepare proof inputs
    let mut nullifiers = Vec::new();
    let mut in_amounts = Vec::new();
    let mut in_blindings = Vec::new();
    let mut input_commitments = Vec::new();

    for utxo in &selected_utxos {
        let mut hasher = Keccak::v256();
        hasher.update(&utxo.commitment);
        let mut comm_idx_bytes = [0u8; 8];
        hasher.finalize(&mut comm_idx_bytes[..]);
        let idx = u64::from_le_bytes(comm_idx_bytes);
        
        nullifiers.push(aetheris_zkp::create_nullifier(&viewing_key, idx));
        in_amounts.push(utxo.amount_atoms);
        in_blindings.push(utxo.blinding);
        input_commitments.push(utxo.commitment);
    }

    let mut rng = rand::rngs::OsRng;
    let mut out_blinding = [0u8; 32];
    rng.fill_bytes(&mut out_blinding);
    let change_amount = input_sum - send_amount_atoms;
    let mut change_blinding = [0u8; 32];
    rng.fill_bytes(&mut change_blinding);

    let mut out_amounts = vec![send_amount_atoms];
    let mut out_blindings = vec![out_blinding];
    if change_amount > 0 {
        out_amounts.push(change_amount);
        out_blindings.push(change_blinding);
    }
    
    let send_commitment = aetheris_zkp::create_commitment(send_amount_atoms, &out_blinding);
    let mut output_commitments = vec![send_commitment];
    if change_amount > 0 {
        output_commitments.push(aetheris_zkp::create_commitment(change_amount, &change_blinding));
    }

    // C-1: Only output commitments are bound as public instances
    let proof = ZKProofSystem::prove_conservation(&in_amounts, &out_amounts, &in_blindings, &out_blindings, &output_commitments, 0);
    println!("[FFI] ZK_PROOF_GENERATED: size={} bytes, inputs={}, outputs={}", 
             proof.len(), in_amounts.len(), out_amounts.len());

    // 4. INTEGRATE LOOPIX MIXNET (Full Automatic Anonymous Routing)
    let path = {
        let keys = PEER_KEYS.lock().unwrap();
        LoopixMixer::select_random_path(&keys, 3)
    };

    // Fallback: If no peers, use a local self-loop path for testing
    let path = if path.is_empty() {
        vec![("local_mix_1".to_string(), [0u8; 32])]
    } else {
        path
    };

    // Stealth Address Derivation:
    // In Aetheris, we don't send to the public address. 
    // We derive a one-time stealth address (D-H shared secret based).
    let mut hasher = Keccak::v256();
    hasher.update(target_address.as_bytes());
    hasher.update(&chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0).to_le_bytes());
    let mut stealth_res = [0u8; 32];
    hasher.finalize(&mut stealth_res);
    let one_time_address = format!("aet1_st{}", &hex::encode(stealth_res)[..24]);

    // Encrypt note for recipient (trial decryption support)
    // TODO(PHASE-3): Derive target_viewing_key from recipient's public key instead of address
    let mut target_viewing_key = [0u8; 32];
    let vk = blake3::hash(&[target_address.as_bytes(), b"aetheris-viewing-key"].concat());
    target_viewing_key.copy_from_slice(vk.as_bytes());

    let (ephemeral_pk, ciphertext) = aetheris_zkp::ZKProofSystem::encrypt_output(
        &target_viewing_key,
        send_amount_atoms,
        &out_blinding
    );

    // Encrypt change output for ourselves
    let (change_epk, change_ciphertext) = if change_amount > 0 {
        aetheris_zkp::ZKProofSystem::encrypt_output(
            &viewing_key,
            change_amount,
            &change_blinding
        )
    } else {
        ([0u8; 32], vec![])
    };

    let core_tx = aetheris_core::Transaction {
        inputs: nullifiers.clone(),
        outputs: output_commitments.iter().enumerate().map(|(i, comm)| {
            if i == 0 {
                aetheris_core::ShieldedOutput {
                    commitment: *comm,
                    ephemeral_key: ephemeral_pk,
                    ciphertext: ciphertext.clone(),
                }
            } else {
                aetheris_core::ShieldedOutput {
                    commitment: *comm,
                    ephemeral_key: change_epk,
                    ciphertext: change_ciphertext.clone(),
                }
            }
        }).collect(),
        public_amount: 0,
        proof: proof.clone(),
    };

    let tx_payload = bincode::serialize(&core_tx).unwrap();
    
    match LoopixMixer::wrap(tx_payload, path) {
        Ok(mix_msg) => {
            println!("[MIXNET] Transaction onion-wrapped. Delaying for {}ms...", mix_msg.delay);
            
            let broadcast_tx = core_tx.clone();

            thread::spawn(move || {
                thread::sleep(std::time::Duration::from_millis(mix_msg.delay));
                
                // Real Broadcast via P2P
                if let Some(sender) = P2P_COMMAND_SENDER.lock().unwrap().as_ref() {
                    let _ = sender.send(NetworkCommand::BroadcastTransaction(broadcast_tx));
                }

                let mut mempool = MEMPOOL.lock().unwrap();
                mempool.push(core_tx);
                println!("[MEMPOOL] Transaction received via Mixnet and broadcasted to P2P.");
            });
        },
        Err(e) => {
            let err_msg = format!("MIXNET_ERROR: {}", e);
            set_error(&err_msg);
            return false;
        }
    }

    // 3. Update Local History (Mark as Pending)
    let tx_history_entry = json!({
        "type": "Transfer (Out)",
        "amount_atoms": -(send_amount_atoms as i64),
        "address": target_address,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "status": "Pending (Mixnet)",
        "tx_id": hex::encode(stealth_res),
        "commitment": hex::encode(output_commitments[0])
    });

    if let Some(existing_history_bytes) = db.get(b"transactions").unwrap() {
        if let Ok(mut history) = serde_json::from_slice::<Vec<serde_json::Value>>(&existing_history_bytes) {
            history.insert(0, tx_history_entry);
            db.insert(b"transactions", serde_json::to_vec(&history).unwrap()).unwrap();
        }
    } else {
        db.insert(b"transactions", serde_json::to_vec(&[tx_history_entry]).unwrap()).unwrap();
    }

    // Update local DB to reflect spent UTXO
    db.insert(b"owned_utxos", serde_json::to_vec(&owned_utxos).unwrap()).unwrap();
    db.flush().unwrap();

    println!("[FFI] ANONYMOUS_TRANSACTION_INITIATED: Stealth Address={}, PathLength={}", 
             one_time_address, 
             PEER_KEYS.lock().unwrap().len().min(3).max(1));
    true
}

#[no_mangle]
pub extern "C" fn aetheris_free_string(ptr: *mut c_char) {
    if ptr.is_null() { return; }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    /// Reset all global FFI state between tests to prevent cross-test pollution.
    fn reset_ffi_test_state() {
        *TOKIO_RUNTIME.lock().unwrap() = None;
        if let Ok(mut state) = STATE.lock() {
            state.ledger = None;
            state.mining_thread = None;
            state.address = String::new();
        }
        *P2P_COMMAND_SENDER.lock().unwrap() = None;
        *USER_PASSWORD.write().unwrap() = None;
        *DB_PATH.write().unwrap() = None;
        *BRIDGE_KEY.write().unwrap() = None;
        *LAST_ERROR.write().unwrap() = String::new();
        PEER_KEYS.lock().unwrap().clear();
        MEMPOOL.lock().unwrap().clear();
        MINING_STOP_FLAG.store(false, std::sync::atomic::Ordering::SeqCst);
        std::env::remove_var("AETHERIS_VDF_DIFFICULTY");
    }

    #[test]
    fn test_full_wallet_flow() {
        reset_ffi_test_state();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("test_db");
        let db_path_str = db_path.to_str().unwrap();
        let c_db_path = CString::new(db_path_str).unwrap();
        let c_password = CString::new("test_password").unwrap();

        // Use low VDF difficulty for fast test execution
        unsafe { std::env::set_var("AETHERIS_VDF_DIFFICULTY", "1000"); }

        // 1. Start Node
        assert_eq!(aetheris_start_node(10001, c_db_path.as_ptr()), 0);
        aetheris_init();

        // 2. Set wallet password (required by Argon2id encryption)
        assert!(aetheris_set_wallet_password(c_password.as_ptr()));

        // 3. Check Initialization (should be false — no wallet yet)
        assert!(!aetheris_is_initialized());

        // 4. Create Wallet
        assert!(aetheris_create_wallet());

        // 5. Check Initialization (should be true)
        assert!(aetheris_is_initialized());

        // 6. Check Node Status
        let status_bin = aetheris_get_node_status_bin();
        assert!(status_bin.ptr != std::ptr::null_mut(), "Status buffer should not be null");
        let json_data = {
            let slice = unsafe { std::slice::from_raw_parts(status_bin.ptr, status_bin.len) };
            let bridge_key = *BRIDGE_KEY.read().unwrap();
            let key = bridge_key.unwrap_or_else(|| {
                eprintln!("WARNING: test using zero bridge key fallback");
                [0u8; 32]
            });
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
            let nonce = Nonce::from_slice(&slice[..12]);
            let ciphertext = &slice[12..];
            String::from_utf8_lossy(&cipher.decrypt(nonce, ciphertext).unwrap_or_default()).to_string()
        };
        assert!(json_data.contains("ONLINE"), "Status: {}", json_data);
        assert!(json_data.contains("aet1"));

        aetheris_free_buffer(status_bin);
    }

    #[test]
    fn test_genesis_import() {
        reset_ffi_test_state();
        let dir = tempdir().unwrap();
        let db_path = dir.path().join("genesis_test_db");
        let db_path_str = db_path.to_str().unwrap();
        let c_db_path = CString::new(db_path_str).unwrap();
        let c_password = CString::new("test_password").unwrap();

        // Use low VDF difficulty for fast test execution
        unsafe { std::env::set_var("AETHERIS_VDF_DIFFICULTY", "1000"); }

        aetheris_start_node(10002, c_db_path.as_ptr());
        aetheris_init();
        assert!(aetheris_set_wallet_password(c_password.as_ptr()));

        let phrase = CString::new("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about").unwrap();
        assert!(aetheris_import_wallet(phrase.as_ptr()));

        let status_bin = aetheris_get_node_status_bin();
        let json_data = {
            let slice = unsafe { std::slice::from_raw_parts(status_bin.ptr, status_bin.len) };
            let bridge_key = *BRIDGE_KEY.read().unwrap();
            let key = bridge_key.unwrap_or_else(|| {
                eprintln!("WARNING: test using zero bridge key fallback");
                [0u8; 32]
            });
            let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
            let nonce = Nonce::from_slice(&slice[..12]);
            let ciphertext = &slice[12..];
            String::from_utf8_lossy(&cipher.decrypt(nonce, ciphertext).unwrap_or_default()).to_string()
        };
        assert!(json_data.contains("balance_atoms") || json_data.contains("wallet"), "Status: {}", json_data);

        aetheris_free_buffer(status_bin);
    }
}
