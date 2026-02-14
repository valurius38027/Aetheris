                                    NetworkCommand::RequestSync { start_height, end_height } => {
                                        let sync_req = P2PMessage::SyncRequest { start_height, end_height };
                                        let data = bincode::serialize(&sync_req).unwrap();
                                        if let Err(e) = network.swarm.behaviour_mut().gossipsub.publish(network.tx_topic.clone(), data) {
                                            println!("[P2P] Failed to publish sync request: {}", e);
                                        }
                                    }

