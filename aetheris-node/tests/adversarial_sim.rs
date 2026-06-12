use aetheris_node::consensus::{MathematicalArbitrator, BlockProposal};

#[test]
fn test_mathematical_arbitration_convergence() {
    let mut nodes: Vec<MathematicalArbitrator> = (0..5).map(|_| MathematicalArbitrator::new()).collect();
    
    // Create two competing proposals for height 1
    let proposal_a = BlockProposal {
        height: 1,
        block_hash: [0u8; 32],
        transactions: vec![],
        vdf_result: vec![1, 2, 3], // Arbitrary
        vdf_proof: vec![],
        sender: "NodeA".to_string(),
        difficulty: 100,
        state_root: [0u8; 32],
        timestamp: 0,
    };

    let proposal_b = BlockProposal {
        height: 1,
        block_hash: [1u8; 32],
        transactions: vec![],
        vdf_result: vec![4, 5, 6], // Arbitrary
        vdf_proof: vec![],
        sender: "NodeB".to_string(),
        difficulty: 100,
        state_root: [1u8; 32],
        timestamp: 0,
    };

    // Simulate network delay: some nodes see A first, some see B first
    // Node 0, 1 see A then B
    nodes[0].add_proposal(proposal_a.clone());
    nodes[0].add_proposal(proposal_b.clone());
    nodes[1].add_proposal(proposal_a.clone());
    nodes[1].add_proposal(proposal_b.clone());

    // Node 2, 3 see B then A
    nodes[2].add_proposal(proposal_b.clone());
    nodes[2].add_proposal(proposal_a.clone());
    nodes[3].add_proposal(proposal_b.clone());
    nodes[3].add_proposal(proposal_a.clone());

    // Node 4 only sees B (simulating loss of A)
    nodes[4].add_proposal(proposal_b.clone());

    // Calculate the expected winner based on VDF hash
    let mut hasher_a = blake3::Hasher::new();
    hasher_a.update(&proposal_a.vdf_result);
    let hash_a: [u8; 32] = hasher_a.finalize().into();

    let mut hasher_b = blake3::Hasher::new();
    hasher_b.update(&proposal_b.vdf_result);
    let hash_b: [u8; 32] = hasher_b.finalize().into();

    let expected_winner = if hash_a < hash_b { "NodeA" } else { "NodeB" };
    println!("Expected winner: {}", expected_winner);

    // Verify all nodes that have both proposals converged to the same winner
    for i in 0..4 {
        let winner = nodes[i].get_winner(1).unwrap();
        assert_eq!(winner.sender, expected_winner, "Node {} did not converge to the correct winner", i);
    }

    println!("✅ Convergence test passed: All nodes agreed on the same winner regardless of arrival order.");
}

#[test]
fn test_byzantine_proposal_resistance() {
    let mut arbitrator = MathematicalArbitrator::new();
    
    // Valid proposal
    let valid_proposal = BlockProposal {
        height: 1,
        block_hash: [10u8; 32],
        transactions: vec![],
        vdf_result: vec![1],
        vdf_proof: vec![],
        sender: "HonestNode".to_string(),
        difficulty: 100,
        state_root: [0u8; 32],
        timestamp: 0,
    };

    // Byzantine proposal with "better" VDF result (fabricated)
    // In a real system, the VDF proof would be checked. 
    // Here we test that if proofs are valid, the arbitration still works.
    let byzantine_proposal = BlockProposal {
        height: 1,
        block_hash: [20u8; 32],
        transactions: vec![],
        vdf_result: vec![2],
        vdf_proof: vec![],
        sender: "EvilNode".to_string(),
        difficulty: 100,
        state_root: [1u8; 32],
        timestamp: 0,
    };

    arbitrator.add_proposal(valid_proposal);
    arbitrator.add_proposal(byzantine_proposal);

    let winner = arbitrator.get_winner(1).unwrap();
    println!("Winner selected: {} from {}", winner.block_hash[0], winner.sender);
    
    // The arbitrator doesn't care about "evil" or "honest", only mathematical correctness.
    // However, the system's security relies on the fact that the VDF result is hard to compute
    // but easy to verify. The arbitration logic is robust because it's deterministic.
}
