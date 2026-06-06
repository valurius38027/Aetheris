use libp2p::{
    gossipsub, identify, kad, mdns, noise,
    swarm::NetworkBehaviour,
    tcp, yamux, autonat, relay, dcutr,
    Multiaddr, PeerId, StreamProtocol,
};
use libp2p::identity::Keypair;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::time::Duration;
use anyhow::Result;
use aetheris_core::Transaction;
use aetheris_recursive::AggregateProofGossip;
use crate::consensus::BlockProposal;

#[derive(NetworkBehaviour)]
pub struct AetherisBehaviour {
    pub gossipsub: gossipsub::Behaviour,
    pub mdns: mdns::tokio::Behaviour,
    pub kademlia: kad::Behaviour<kad::store::MemoryStore>,
    pub identify: identify::Behaviour,
    pub autonat: autonat::Behaviour,
    pub relay_client: relay::client::Behaviour,
    pub dcutr: dcutr::Behaviour,
}

#[derive(Debug, Clone)]
pub enum NetworkEvent {
    BlockProposed(BlockProposal),
    TransactionReceived(Transaction),
    AggregateGossipReceived(AggregateProofGossip),
    NewPeerDiscovered(PeerId),
    PeerDiscoveredMdns(PeerId, Multiaddr),
    PeerIdentified(PeerId, String, Vec<Multiaddr>),
    NatStatusChanged(autonat::NatStatus),
    RelayInboundCircuitEstablished,
    RelayOutboundCircuitEstablished,
}

#[derive(Debug, Clone)]
pub enum NetworkCommand {
    BroadcastBlock(BlockProposal),
    BroadcastTransaction(Transaction),
    BroadcastAggregateGossip(AggregateProofGossip),
    Dial(Multiaddr),
    RequestSync { start_height: u64, peer_id: PeerId },
    SendSyncResponse { blocks: Vec<aetheris_core::Block>, peer_id: PeerId },
    BroadcastMixnetPK([u8; 32]),
}

pub struct AetherisNetwork {
    pub swarm: libp2p::Swarm<AetherisBehaviour>,
    pub block_topic: gossipsub::IdentTopic,
    pub tx_topic: gossipsub::IdentTopic,
    pub accumulator_topic: gossipsub::IdentTopic,
    pub mixnet_topic: gossipsub::IdentTopic,
    pub sync_topic: gossipsub::IdentTopic,
}

impl AetherisNetwork {
    pub async fn new(bootstrap_nodes: &[String]) -> Result<Self> {
        let local_key = Keypair::generate_ed25519();
        let local_peer_id = PeerId::from(local_key.public());
        println!("[P2P] Local PeerId: {:?}", local_peer_id);

        let message_id_fn = |message: &gossipsub::Message| {
            let mut s = DefaultHasher::new();
            Hash::hash(&message.data, &mut s);
            gossipsub::MessageId::from(s.finish().to_string())
        };

        let gossipsub_config = gossipsub::ConfigBuilder::default()
            .heartbeat_interval(Duration::from_secs(1))
            .validation_mode(gossipsub::ValidationMode::Strict)
            .message_id_fn(message_id_fn)
            .max_transmit_size(10 * 1024 * 1024)
            .mesh_n_low(6)
            .mesh_n(12)
            .mesh_n_high(18)
            .gossip_lazy(10)
            .history_length(10)
            .history_gossip(3)
            .build()
            .map_err(|e| anyhow::anyhow!("{:?}", e))?;

        let topic = gossipsub::IdentTopic::new("aetheris-blocks");
        let sync_topic = gossipsub::IdentTopic::new("aetheris-sync");

        let mut swarm = libp2p::SwarmBuilder::with_existing_identity(local_key.clone())
            .with_tokio()
            .with_tcp(
                tcp::Config::default(),
                noise::Config::new,
                yamux::Config::default,
            )?
            .with_dns()?
            .with_relay_client(noise::Config::new, yamux::Config::default)?
            .with_behaviour(|key: &Keypair, relay_client: relay::client::Behaviour| {
                let peer_id = key.public().to_peer_id();

                let gossipsub = gossipsub::Behaviour::new(
                    gossipsub::MessageAuthenticity::Signed(key.clone()),
                    gossipsub_config.clone(),
                )
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                let mut kad_config = kad::Config::default();
                kad_config.set_protocol_names(vec![StreamProtocol::new("/aetheris/kad/1.0.0")]);
                let store = kad::store::MemoryStore::new(peer_id);
                let kademlia = kad::Behaviour::with_config(peer_id, store, kad_config);

                let mut identify_config =
                    identify::Config::new("/aetheris/1.0.0".into(), key.public());
                identify_config =
                    identify_config.with_agent_version("aetheris-node/0.1.0".into());
                let identify = identify::Behaviour::new(identify_config);

                let autonat = autonat::Behaviour::new(peer_id, autonat::Config::default());
                let dcutr = dcutr::Behaviour::new(peer_id);
                let mdns = mdns::tokio::Behaviour::new(mdns::Config::default(), peer_id)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?;

                Ok(AetherisBehaviour {
                    gossipsub,
                    mdns,
                    kademlia,
                    identify,
                    autonat,
                    relay_client,
                    dcutr,
                })
            })?
            .with_swarm_config(|c| c.with_idle_connection_timeout(Duration::from_secs(60)))
            .build();

        let block_topic = topic.clone();
        let tx_topic = gossipsub::IdentTopic::new("aetheris-txs");
        let accumulator_topic = gossipsub::IdentTopic::new("aetheris-accumulators");
        let mixnet_topic = gossipsub::IdentTopic::new("aetheris-mixnet-pks");

        for addr_str in bootstrap_nodes {
            let addr: Multiaddr = addr_str.parse()?;
            if let Some(peer_id) = addr.iter().last().and_then(|protocol| {
                if let libp2p::multiaddr::Protocol::P2p(peer_id) = protocol {
                    Some(peer_id)
                } else {
                    None
                }
            }) {
                swarm.behaviour_mut().kademlia.add_address(&peer_id, addr.clone());
                println!("[P2P] Added bootstrap node: {}", addr_str);
            }
        }
        if !bootstrap_nodes.is_empty() {
            let _ = swarm.behaviour_mut().kademlia.bootstrap();
        }

        Ok(Self {
            swarm,
            block_topic,
            tx_topic,
            accumulator_topic,
            mixnet_topic,
            sync_topic,
        })
    }

    pub fn subscribe_topics(&mut self) -> Result<()> {
        self.swarm.behaviour_mut().gossipsub.subscribe(&self.block_topic)?;
        self.swarm.behaviour_mut().gossipsub.subscribe(&self.accumulator_topic)?;
        self.swarm.behaviour_mut().gossipsub.subscribe(&self.sync_topic)?;
        self.swarm.behaviour_mut().gossipsub.subscribe(&self.tx_topic)?;
        self.swarm.behaviour_mut().gossipsub.subscribe(&self.mixnet_topic)?;
        Ok(())
    }

    pub async fn listen(&mut self, addr: &str) -> Result<()> {
        let multiaddr: Multiaddr = addr.parse()?;
        self.swarm.listen_on(multiaddr)?;
        Ok(())
    }

    pub fn broadcast_block(&mut self, proposal: BlockProposal) -> Result<()> {
        let data = serde_json::to_vec(&proposal)?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.block_topic.clone(), data)?;
        Ok(())
    }

    pub fn broadcast_tx(&mut self, tx: Transaction) -> Result<()> {
        let data = serde_json::to_vec(&tx)?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.tx_topic.clone(), data)?;
        Ok(())
    }

    pub fn broadcast_accumulator(&mut self, gossip: AggregateProofGossip) -> Result<()> {
        let data = serde_json::to_vec(&gossip)?;
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.accumulator_topic.clone(), data)?;
        Ok(())
    }

    pub fn broadcast_mixnet_pk(&mut self, pk: [u8; 32]) -> Result<()> {
        self.swarm
            .behaviour_mut()
            .gossipsub
            .publish(self.mixnet_topic.clone(), pk.to_vec())?;
        let key = kad::RecordKey::new(&format!("mixnet_pk_{}", self.swarm.local_peer_id()));
        let record = kad::Record {
            key,
            value: pk.to_vec(),
            publisher: Some(*self.swarm.local_peer_id()),
            expires: None,
        };
        self.swarm
            .behaviour_mut()
            .kademlia
            .put_record(record, kad::Quorum::One)?;
        Ok(())
    }
}
