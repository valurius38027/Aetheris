//! Generates KZG CRS using true random entropy (designed to be called from
//! the `gen_crs.ps1` script which fetches seed from random.org).
//!
//! Usage: gen_crs <hex-seed> [output-path]
//!   hex-seed: 64 hex chars (32 bytes) from a true random source
//!   output-path: defaults to "crs.bin" in current directory
//!
//! The seed is used once and discarded.

use std::env;
use std::fs;
use std::path::PathBuf;
use halo2_proofs::poly::commitment::Params;
use halo2_proofs::poly::kzg::commitment::ParamsKZG;
use halo2curves::bn256::Bn256;
use rand_chacha::ChaCha20Rng;
use rand_core::SeedableRng;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: gen_crs <hex-seed> [output-path]");
        eprintln!("  hex-seed: 64 hex chars (32 bytes) from random.org");
        std::process::exit(1);
    }

    let hex_seed = &args[1];
    if hex_seed.len() != 64 {
        eprintln!("Error: hex seed must be 64 chars, got {}", hex_seed.len());
        std::process::exit(1);
    }

    let seed_bytes = hex::decode(hex_seed).expect("invalid hex seed");
    let seed: [u8; 32] = seed_bytes.try_into().expect("32 bytes");
    let k: u32 = 11;

    let output_path: PathBuf = args.get(2).cloned().map(PathBuf::from).unwrap_or_else(|| PathBuf::from("crs.bin"));

    eprintln!("Generating ParamsKZG<Bn256> with k={} (this may take a minute)...", k);
    let params = ParamsKZG::<Bn256>::setup(k, &mut ChaCha20Rng::from_seed(seed));
    let _ = seed; // scope ends; seed is discarded

    let mut buf = Vec::new();
    params.write(&mut buf).expect("serialization failed");
    fs::write(&output_path, &buf).expect("failed to write CRS file");

    eprintln!("CRS written to {} ({} bytes)", output_path.display(), buf.len());
    eprintln!("Seed has been discarded. CRS is now the canonical trusted setup.");
}
