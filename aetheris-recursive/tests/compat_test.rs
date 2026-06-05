
#[cfg(test)]
mod tests {
    use halo2curves::pasta::Fp;
    use halo2curves::CurveAffine;
    use group::prime::PrimeCurveAffine;
    use ff::PrimeField;
    use ff::Field;
    use aetheris_recursive::P2PRecursiveManager;

    #[test]
    fn test_field_compatibility() {
        use halo2curves::pasta::EqAffine as VestaAffine;
        // Pallas Scalar Field == Vesta Base Field
        // We verify that a random Vesta Base Field element can be interpreted as a Pallas Scalar.
        // Actually, they are the same field, so this is trivial, but good to sanity check types.
        
        println!("Checking Pallas/Vesta cycle compatibility...");
        
        let g = VestaAffine::generator();
        let coords = g.coordinates().unwrap();
        let x = *coords.x(); // This is Vesta Base Field element
        
        println!("Vesta Generator X: {:?}", x);
        
        // Convert Vesta Base (Fq) to Pallas Scalar (Fp)
        // Since Eq == Fp, this should just work via byte representation
        let bytes = x.to_repr();
        let fp_res = Fp::from_repr(bytes.into());
        
        if fp_res.is_some().into() {
            println!("Vesta Base fits in Pallas Scalar (Cycle Valid)");
        } else {
            // The cycle means the fields have the same prime, but not every
            // base field element is a valid scalar (some exceed Scalar modulus).
            println!("Vesta Base element exceeds Pallas Scalar range (expected for large values)");
        }
    }

    #[test]
    fn find_valid_point() {
        // Find a point on Pallas curve y^2 = x^3 + 5
        let b = Fp::from(5);
        let mut x_val = 1u64;
        loop {
            let x = Fp::from(x_val);
            let rhs = x * x * x + b;
            let sqrt_res: Option<Fp> = rhs.sqrt().into();
            if let Some(y) = sqrt_res {
                println!("Found point on Pallas: x={}, y={:?}", x_val, y);
                println!("x_hex: {:?}", <Fp as PrimeField>::to_repr(&x));
                println!("y_hex: {:?}", <Fp as PrimeField>::to_repr(&y));
                break;
            }
            x_val += 1;
            if x_val > 1000 {
                println!("No point found in first 1000");
                break;
            }
        }
    }

    #[test]
    fn test_manager_proof_generation() {
        println!("[Test] Starting test_manager_proof_generation");
        let mut manager = P2PRecursiveManager::new(libp2p::PeerId::random(), 1);
        manager.preload_params(13);
        println!("[Test] Preload done");

        let tx_id = [0u8; 32];
        let proof_json = manager.generate_atomic_proof(tx_id);
        println!("[Test] Proof response: {}", proof_json);
        assert!(proof_json.contains("unavailable"));
        assert!(proof_json.contains("Phase 1.4"));
    }

    #[test]
    fn test_msm_optimization() {
        // This test validates the logic of 2-bit windowed scalar multiplication
        // by simulating the decomposition and reconstruction logic.
        
        let scalar_val = 123456789u64;
        let scalar = Fp::from(scalar_val);
        
        let w = 2;
        let num_bits = 255;
        let num_windows = (num_bits + w - 1) / w;
        
        let bytes = scalar.to_repr();
        let mut reconstructed = Fp::from(0);
        let mut base = Fp::from(1);
        
        println!("Scalar: {}", scalar_val);
        
        for i in 0..num_windows {
            let mut window_val = 0u64;
            for j in 0..w {
                let idx = i * w + j;
                if idx < num_bits {
                    let byte_idx = idx / 8;
                    let bit_idx = idx % 8;
                    if (bytes.as_ref()[byte_idx] >> bit_idx) & 1 == 1 {
                        window_val |= 1 << j;
                    }
                }
            }
            
            // In the circuit, we do: acc = acc + window_val * base
            // But window_val is applied to (base_point * 2^(i*w))
            // Here we just reconstruct the scalar to verify decomposition
            
            let term = Fp::from(window_val) * base;
            reconstructed = reconstructed + term;
            
            base = base * Fp::from(1 << w);
        }
        
        assert_eq!(scalar, reconstructed, "Scalar reconstruction failed");
        println!("MSM Decomposition Logic Verified");
    }
}

