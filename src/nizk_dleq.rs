use std::ops::{Mul, Sub};
use blstrs::G1Affine;
use ff::Field;
use group::{Curve, GroupEncoding};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};
use crate::Fr;
use crate::util::sha3_256;

const DOMAIN_PROOF_OF_DLEQ_CHALLENGE: &str = "blsttc-zk-proof-of-dleq-challenge";

///   instance = (g,h,g^x,h^x)
///   g and h are different generators of g1
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DLEqInstance {
    pub g: G1Affine,
    pub h: G1Affine,
    pub g_x: G1Affine,
    pub h_x: G1Affine,
}

/// Witness for the validity of a sharing instance.
///   Witness = (x,r)
pub struct DLEqWitness {
    pub scalar_x: Fr,
    pub scalar_r: Fr,
}

/// Zero-knowledge proof of equality of discrete log.
#[derive(Clone, Debug, Serialize, Deserialize,Default)]
pub struct ZkProofDLEq {
    pub c: Fr,
    pub s: Fr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ZkProofDLEqError {
    InvalidProof,
    InvalidInstance,
}

fn dleq_proof_challenge(g: &G1Affine, g_x: &G1Affine, h: &G1Affine, h_x: &G1Affine, g_k: &G1Affine, h_k: &G1Affine) -> Fr {
    let mut map = Vec::new();
    let g_bytes = g.to_bytes();
    let g_x_bytes = g_x.to_bytes();
    let h_bytes = h.to_bytes();
    let h_x_bytes = h_x.to_bytes();
    let g_k_bytes = g_k.to_bytes();
    let h_k_bytes = h_k.to_bytes();

    map.append(&mut "g-value".as_bytes().to_vec());
    map.append(&mut g_bytes.as_ref().to_vec());
    map.append(&mut "g_x".as_bytes().to_vec());
    map.append(&mut g_x_bytes.as_ref().to_vec());
    map.append(&mut "h-value".as_bytes().to_vec());
    map.append(&mut h_bytes.as_ref().to_vec());
    map.append(&mut "h_x".as_bytes().to_vec());
    map.append(&mut h_x_bytes.as_ref().to_vec());
    map.append(&mut "g_k".as_bytes().to_vec());
    map.append(&mut g_k_bytes.as_ref().to_vec());
    map.append(&mut "h_k".as_bytes().to_vec());
    map.append(&mut h_k_bytes.as_ref().to_vec());
    map.append(&mut DOMAIN_PROOF_OF_DLEQ_CHALLENGE.as_bytes().to_vec());

    let seed = sha3_256(&map);
    let mut rng = StdRng::from_seed(seed);
    let big = Fr::random(&mut rng);
    return big;
}

pub fn prove_gen(instance: &DLEqInstance, witness: &DLEqWitness) -> ZkProofDLEq {

    let k = witness.scalar_r;
    let g_k = instance.g.mul(&k).to_affine();
    let h_k = instance.h.mul(&k).to_affine();

    // challenge: c = oracle(g,g^x,h,h^x,g^k,h^k)
    let c = dleq_proof_challenge(
        &instance.g,
        &instance.g_x,
        &instance.h,
        &instance.h_x,
        &g_k,
        &h_k,
    );

    let s = k.sub(&c.mul(&witness.scalar_x));
    ZkProofDLEq { c, s }
}

pub fn verify_proof(instance: &DLEqInstance, nizk: &ZkProofDLEq) -> Result<(), ZkProofDLEqError> {

    let mut g_k_prime = instance.g.mul(&nizk.s).to_affine();
    g_k_prime = G1Affine::from(g_k_prime + instance.g_x.mul(&nizk.c));

    let mut h_k_prime = instance.h.mul(&nizk.s).to_affine();
    h_k_prime = G1Affine::from(h_k_prime + instance.h_x.mul( &nizk.c)
    );

    // Verifier's challenge
    // c' = oracle(g,g^x,h,h^x,g^k',h^k')
    let c_prime = dleq_proof_challenge(
        &instance.g,
        &instance.g_x,
        &instance.h,
        &instance.h_x,
        &g_k_prime,
        &h_k_prime,
    );

    if nizk.c == c_prime {
        Ok(())
    } else {
        return Err(ZkProofDLEqError::InvalidProof);
    }
}