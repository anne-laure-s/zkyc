use plonky2::field::types::Field;

use crate::circuit::Point;

pub trait ToField<F: Field, const N: usize> {
    fn to_field(&self) -> [F; N];
}

pub trait ToSingleField<F: Field> {
    fn to_field(&self) -> F;
}

pub trait ToPointField<F: Field> {
    fn to_field(&self) -> Point<F>;
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
