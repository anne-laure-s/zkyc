use plonky2::{field::types::Field, hash::hash_types::RichField};

use super::Point;
use crate::{
    arith::{
        self,
        field::{GFp, GFp5},
    },
    encoding::{
        Credential, Signature, LEN_CREDENTIAL, LEN_EXTENSION_FIELD, LEN_PASSPORT_NUMBER, LEN_POINT,
        LEN_SIGNATURE, LEN_STRING,
    },
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

impl<T: Copy> From<&[T; LEN_POINT]> for Point<T> {
    fn from(value: &[T; LEN_POINT]) -> Self {
        Self {
            x: value[..LEN_EXTENSION_FIELD].try_into().unwrap(),
            z: value[LEN_EXTENSION_FIELD..LEN_EXTENSION_FIELD * 2]
                .try_into()
                .unwrap(),
            u: value[LEN_EXTENSION_FIELD * 2..LEN_EXTENSION_FIELD * 3]
                .try_into()
                .unwrap(),
            t: value[LEN_EXTENSION_FIELD * 3..].try_into().unwrap(),
        }
    }
}

impl<T: Copy> From<&Point<T>> for [T; LEN_POINT] {
    fn from(value: &Point<T>) -> Self {
        let mut res = Vec::with_capacity(LEN_POINT);
        res.extend(value.x);
        res.extend(value.z);
        res.extend(value.u);
        res.extend(value.t);
        res.try_into()
            .unwrap_or_else(|_| panic!("Given signature don't fit the right length"))
    }
}

impl<T: Copy> From<&Signature<T>> for [T; LEN_SIGNATURE] {
    fn from(value: &Signature<T>) -> Self {
        let mut res = Vec::with_capacity(LEN_SIGNATURE);
        let r: [T; LEN_POINT] = (&value.r).into();
        res.extend(r);
        res.push(value.s);
        res.try_into()
            .unwrap_or_else(|_| panic!("Given signature don't fit the right length"))
    }
}

impl<T: Copy> From<&[T; LEN_SIGNATURE]> for Signature<T> {
    fn from(value: &[T; LEN_SIGNATURE]) -> Self {
        let r: &[T; LEN_POINT] = &value[..LEN_POINT].try_into().unwrap();
        let s: T = value[LEN_POINT];
        Self { r: r.into(), s }
    }
}

impl<T: Copy> From<&Credential<T>> for [T; LEN_CREDENTIAL] {
    fn from(value: &Credential<T>) -> Self {
        let mut res = Vec::with_capacity(LEN_CREDENTIAL);
        res.extend(value.first_name);
        res.extend(value.family_name);
        res.extend(value.place_of_birth);
        res.extend(value.passport_number);
        res.push(value.birth_date);
        res.push(value.expiration_date);
        res.push(value.gender);
        res.push(value.nationality);
        let point: [T; LEN_POINT] = (&value.issuer).into();
        res.extend(point);
        res.try_into()
            .unwrap_or_else(|_| panic!("Given credential don't fit the right length"))
    }
}

const POS_BIRTH_DATE: usize = LEN_STRING * 3 + LEN_PASSPORT_NUMBER;
const START_ISSUER: usize = POS_BIRTH_DATE + 4;
impl<T: Copy> From<&[T; LEN_CREDENTIAL]> for Credential<T> {
    fn from(value: &[T; LEN_CREDENTIAL]) -> Self {
        let issuer: &[T; LEN_POINT] = &value[START_ISSUER..].try_into().unwrap();
        Self {
            first_name: value[0..LEN_STRING].try_into().unwrap(),
            family_name: value[LEN_STRING..LEN_STRING * 2].try_into().unwrap(),
            place_of_birth: value[LEN_STRING * 2..LEN_STRING * 3].try_into().unwrap(),
            passport_number: value[LEN_STRING * 3..LEN_STRING * 3 + LEN_PASSPORT_NUMBER]
                .try_into()
                .unwrap(),
            birth_date: value[POS_BIRTH_DATE],
            expiration_date: value[POS_BIRTH_DATE + 1],
            gender: value[POS_BIRTH_DATE + 2],
            nationality: value[POS_BIRTH_DATE + 3],
            issuer: issuer.into(),
        }
    }
}
