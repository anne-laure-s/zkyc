use plonky2::{field::types::Field, hash::hash_types::RichField};

use super::Point;
use crate::arith::{
    self,
    field::{GFp, GFp5},
};

pub trait ToField<F: Field, const N: usize> {
    fn to_field(&self) -> [F; N];
}

pub trait ToSingleField<F: Field> {
    fn to_field(&self) -> F;
}

pub trait ToPointField<F: Field> {
    fn to_field(&self) -> Point<F>;
}

pub trait ToVecField<F: Field> {
    /// Buids a Vec<F> of expected_len size; if the provided bytes sequence
    /// is too small, the result will be padded with zeroes; if it’s too big,
    /// remaining bytes will be ignored.
    fn to_field(&self, expected_len: usize) -> Vec<F>;
}

impl<F: Field> ToSingleField<F> for u8 {
    fn to_field(&self) -> F {
        F::from_canonical_u8(*self)
    }
}

impl<F: Field> ToSingleField<F> for u16 {
    fn to_field(&self) -> F {
        F::from_canonical_u16(*self)
    }
}

impl<F: Field> ToSingleField<F> for u32 {
    fn to_field(&self) -> F {
        F::from_canonical_u32(*self)
    }
}

impl<F: Field> ToVecField<F> for &[u8] {
    fn to_field(&self, expected_len: usize) -> Vec<F> {
        assert!(expected_len > 0);
        let mut res = vec![F::ZERO; expected_len];
        let mut count = 0;
        for chunk in self.chunks(4) {
            let mut buf = [0u8; 4];
            buf[..chunk.len()].copy_from_slice(chunk);
            res[count] = F::from_canonical_u32(u32::from_le_bytes(buf));
            count += 1;
            if count == expected_len {
                return res;
            }
        }
        res
    }
}

impl<F: Field> ToPointField<F> for arith::Point {
    fn to_field(&self) -> Point<F> {
        Point {
            x: self.X.0.map(|x| F::from_canonical_u64(x.to_u64())),
            z: self.Z.0.map(|x| F::from_canonical_u64(x.to_u64())),
            u: self.U.0.map(|x| F::from_canonical_u64(x.to_u64())),
            t: self.T.0.map(|x| F::from_canonical_u64(x.to_u64())),
        }
    }
}

impl<F: RichField> From<&Point<F>> for arith::Point {
    fn from(value: &Point<F>) -> Self {
        Self {
            X: GFp5(value.x.map(|x| GFp::from_u64_reduce(x.to_canonical_u64()))),
            Z: GFp5(value.z.map(|x| GFp::from_u64_reduce(x.to_canonical_u64()))),
            U: GFp5(value.u.map(|x| GFp::from_u64_reduce(x.to_canonical_u64()))),
            T: GFp5(value.t.map(|x| GFp::from_u64_reduce(x.to_canonical_u64()))),
        }
    }
}
