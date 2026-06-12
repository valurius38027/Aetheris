use ff::PrimeField;
use halo2_proofs::halo2curves::pasta::Fq;
use num_bigint::{BigUint, BigInt};
use std::ops::Rem;

fn main() {
    let fp_mod = BigUint::from_bytes_le(&[
        0x00, 0x00, 0x00, 0x00, 0x21, 0xeb, 0x46, 0x8c, 0xdd, 0xa8, 0x94, 0x09,
        0xfc, 0x98, 0x46, 0x22, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40,
    ]);
    
    // Known Pallas base field: 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000
    let fp_known = BigUint::parse_bytes(b"40000000000000000000000000000000224698fc0994a8dd8c46eb2100000000", 16).unwrap();
    println!("Fp (known from hex) = {}", fp_known);
    println!("Fp (from LE bytes) = {}", fp_mod);
    println!("Match? {}", fp_mod == fp_known);

    // Compute inv(7) using EEA
    let a_int = BigUint::from(7u64);
    let mut a = BigInt::from(fp_mod.clone());
    let mut b = BigInt::from(a_int.clone());
    let mut x0 = BigInt::ZERO;
    let mut x1 = BigInt::from(1u64);
    
    while b != BigInt::ZERO {
        let q = &a / &b;
        let r = &a % &b;
        a = b;
        b = r;
        let tmp = x1.clone();
        x1 = &x0 - &q * &x1;
        x0 = tmp;
    }
    
    let inv_eea = if x0 >= BigInt::ZERO { x0 } else { x0 + BigInt::from(fp_mod.clone()) };
    let inv_eea_bu = inv_eea.to_biguint().expect("positive");

    let prod = &a_int * &inv_eea_bu;
    let prod_mod = &prod % &fp_mod;
    let quotient = &prod / &fp_mod;
    
    println!("\na = 7");
    println!("inv(7) via EEA = {}", inv_eea_bu);
    println!("7 * inv = {}", prod);
    println!("7 * inv >= Fp? {}", prod >= fp_mod);
    println!("quotient = {}", quotient);
    println!("7 * inv mod Fp = {}", prod_mod);
    println!("Expected (mod Fp): 1");
    
    if prod_mod == BigUint::from(1u64) {
        println!("\n✅ 7 * inv ≡ 1 (mod Fp) confirmed!");
    } else {
        println!("\n❌ 7 * inv ≠ 1 (mod Fp)");
        println!("   This means Fp is NOT the Pallas base field.");
        println!("   Check if FP_MOD_BYTES is correct.");
    }
}
