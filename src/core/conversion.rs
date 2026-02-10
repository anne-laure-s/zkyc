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
