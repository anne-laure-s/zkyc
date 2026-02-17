use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::{Field, PrimeField64};
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

use crate::arith::Scalar;
use crate::encoding::LEN_SCALAR;

fn u64_to_bits_le(mut v: u64, out: &mut Vec<bool>, n: usize) {
    for _ in 0..n {
        out.push((v & 1) == 1);
        v >>= 1;
    }
}

/// Performs poseidon on the provided message to return a scalar.
/// This function is not safe for nonce generation
pub fn poseidon_xof_bits_native(base_inputs: &[GoldilocksField]) -> Scalar {
    let mut bits = Vec::with_capacity(LEN_SCALAR);

    // h0
    let h0 = PoseidonHash::hash_no_pad(base_inputs);
    for &x in &h0.elements {
        u64_to_bits_le(x.to_canonical_u64(), &mut bits, 64);
    }

    // blocs additionnels h1, h2, ...
    let mut ctr = GoldilocksField::ONE;
    while bits.len() < LEN_SCALAR {
        let mut inp = vec![ctr];
        inp.extend_from_slice(&h0.elements);

        let hi = PoseidonHash::hash_no_pad(&inp);
        for &x in &hi.elements {
            u64_to_bits_le(x.to_canonical_u64(), &mut bits, 64);
        }
        ctr += GoldilocksField::ONE;
    }

    bits.truncate(LEN_SCALAR);
    // FIXME: check if ignoring overflow here is ok
    let bits: [bool; LEN_SCALAR] = bits.try_into().unwrap();
    Scalar::from_bits_le(&bits)
}
