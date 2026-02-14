use libp2p::{
    gossipsub,
    identify,
    kad,
    noise,
    swarm::NetworkBehaviour,
    tcp,
    yamux,
    Multiaddr,
    PeerId,
    Swarm,
};
use std::collections::hash_map::DefaultHasher;
use std::hash::Hasher;
use std::time::Duration;
use anyhow::Result;
use aetheris_core::Transaction;
use crate::consensus::BlockProposal;

#[derive(NetworkBehaviour)]
pub struct AetherisBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    BlockProposed(BlockProposal),
    TransactionReceived(Transaction),
    NewPeerDiscovered(PeerId),
}

pub enum NetworkCommand {
    BroadcastBlock(BlockProposal),
    BroadcastTransaction(Transaction),
    Dial(Multiaddr),
    RequestSync { start_height: u64, peer_id: PeerId },
    SendSyncResponse { blocks: Vec<aetheris_core::Block>, peer_id: PeerId },
    BroadcastMixnetPK([u8; 32]),
}

pub struct AetherisNetwork {
    pub swarm: Swarm<AetherisBehaviour>,
    pub block_topic: gossipsub::IdentTopic,
    pub tx_topic: gossipsub::IdentTopic,
    pub mixnet_topic: gossipsub::IdentTopic,
}

impl AetherisNetwork {
    pub async fn new() -> Result<Self> {
        let local_key = libp2p::identity::Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        println!("[P2P] Local PeerId: {:?}", local_peer_id);

        // Gossipsub setup
        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = DefaultHasher::new();
            std::hash::Hash::hash(&message.data, &mut s);
            gossipsub::MessageId::from(s.finish().to_string())
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            // 增强高负载下的稳定性
            .max_transmit_size(10 * 1024 * 1024) // 支持最大 10MB 的区块消息
            .mesh_n_low(6)
            .mesh_n(12)
            .mesh_n_high(18)
            .gossip_lazy(10)
            .history_length(10)
            .history_gossip(3) // history_gossip is usize (number of heartbeats)
            .build()
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;

        let mut gossipsub = gossipsub::Behaviour::new(
            gossipsub::MessageAuthenticity::Signed(local_key.clone()),
            gossipsub_config,
        ).map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?;

        let genesis_prefix = "78096181"; // First 8 chars of Genesis Hash
        let block_topic = gossipsub::IdentTopic::new(format!("aetheris_blocks_{}", genesis_prefix));
        let tx_topic = gossipsub::IdentTopic::new(format!("aetheris_txs_{}", genesis_prefix));
        let mixnet_topic = gossipsub::IdentTopic::new(format!("aetheris_mixnet_pks_{}", genesis_prefix));
        gossipsub.subscribe(&block_topic)?;
        gossipsub.subscribe(&tx_topic)?;
        gossipsub.subscribe(&mixnet_topic)?;

        // Kademlia setup
        let store = kad::store::MemoryStore::new(local_peer_id);
        let kademlia = kad::Behaviour::new(local_peer_id, store);

        // Identify setup
        let identify = identify::Behaviour::new(identify::Config::new(
            format!("/aetheris/1.0.0/{}", genesis_prefix),
            local_key.public(),
        ));

        let behaviour = AetherisBehaviour {
            gossipsub,
            kademlia,
            identify,
        };

        let swarm = libp2p::SwarmBuilder::with_existing_identity(local_key)
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_behaviour(|_| behaviour)
            .map_err(|e| anyhow::anyhow!(format!("{:?}", e)))?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        Ok(Self {
            swarm,
            block_topic,
            tx_topic,
            mixnet_topic,
        })
    }

    pub async fn listen(&mut self, addr: &str) -> Result<()> {
        let multiaddr: Multiaddr = addr.parse()?;
        self.swarm.listen_on(multiaddr)?;
        Ok(())
    }

    pub fn broadcast_block(&mut self, proposal: BlockProposal) -> Result<()> {
        let data = bincode::serialize(&proposal)?;
        self.swarm.behaviour_mut().gossipsub.publish(self.block_topic.clone(), data)?;
        Ok(())
    }

    pub fn broadcast_tx(&mut self, tx: Transaction) -> Result<()> {
        let data = bincode::serialize(&tx)?;
        self.swarm.behaviour_mut().gossipsub.publish(self.tx_topic.clone(), data)?;
        Ok(())
    }

    pub fn broadcast_mixnet_pk(&mut self, pk: [u8; 32]) -> Result<()> {
        // 1. Gossipsub for fast propagation
        self.swarm.behaviour_mut().gossipsub.publish(self.mixnet_topic.clone(), pk.to_vec())?;
        
        // 2. Kademlia for long-term storage/lookup
        let key = kad::RecordKey::new(&format!("mixnet_pk_{}", self.swarm.local_peer_id()));
        let record = kad::Record {
            key,
            value: pk.to_vec(),
            publisher: Some(*self.swarm.local_peer_id()),
            expires: None,
        };
        self.swarm.behaviour_mut().kademlia.put_record(record, kad::Quorum::One)?;
        
        Ok(())
    }
}
