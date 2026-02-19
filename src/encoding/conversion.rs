use plonky2::{field::types::Field, hash::hash_types::RichField};

use super::Point;
use crate::{
    arith::{
        self,
        field::{GFp, GFp5},
    },
    encoding::{
        self, Credential, Scalar, Signature, LEN_CREDENTIAL, LEN_FIELD, LEN_PASSPORT_NUMBER,
        LEN_POINT, LEN_SCALAR, LEN_STRING,
    },
};

pub trait ToBool<TBool> {
    fn to_bool(&self) -> TBool;
}
impl<F: Field> ToBool<bool> for F {
    fn to_bool(&self) -> bool {
        if self.is_zero() {
            false
        } else if self.is_one() {
            true
        } else {
            panic!("boolean conversion failed")
        }
    }
}
pub trait FromBool<T> {
    fn from_bool(self) -> T;
}

impl<F: Field> FromBool<F> for bool {
    fn from_bool(self) -> F {
        if self {
            F::ONE
        } else {
            F::ZERO
        }
    }
}

pub trait ToField<F: Field, const N: usize> {
    fn to_field(&self) -> [F; N];
}

pub trait ToSingleField<F: Field> {
    fn to_field(&self) -> F;
}

pub trait ToScalarField {
    fn to_field(&self) -> Scalar<bool>;
}

pub trait ToGFp5Field<F: Field> {
    fn to_field(&self) -> encoding::GFp5<F>;
}

pub trait ToPointField<F: Field> {
    fn to_field(&self) -> Point<F>;
}

pub trait ToSignatureField<F: Field, B: Copy> {
    fn to_field(&self) -> Signature<F, B>;
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

impl<F: Field> ToSingleField<F> for GFp {
    fn to_field(&self) -> F {
        F::from_canonical_u64(self.to_u64())
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

// maybe this name is not appropriate
impl ToScalarField for arith::Scalar {
    fn to_field(&self) -> Scalar<bool> {
        Scalar(self.to_bits_le())
    }
}

impl<F: Field> ToGFp5Field<F> for GFp5 {
    fn to_field(&self) -> encoding::GFp5<F> {
        encoding::GFp5(self.0.map(|x| x.to_field()))
    }
}

impl<F: Field> ToPointField<F> for arith::Point {
    fn to_field(&self) -> Point<F> {
        Point {
            x: self.X.to_field(),
            z: self.Z.to_field(),
            u: self.U.to_field(),
            t: self.T.to_field(),
        }
    }
}
impl<T: Copy> From<[T; LEN_SCALAR]> for Scalar<T> {
    fn from(value: [T; LEN_SCALAR]) -> Self {
        Self(value)
    }
}

impl<T: Copy> From<[T; LEN_FIELD]> for encoding::GFp5<T> {
    fn from(value: [T; LEN_FIELD]) -> Self {
        Self(value)
    }
}

impl<F: RichField> From<encoding::GFp5<F>> for GFp5 {
    fn from(value: encoding::GFp5<F>) -> Self {
        GFp5(value.0.map(|x| GFp::from_u64_reduce(x.to_canonical_u64())))
    }
}

impl<F: RichField> From<GFp5> for encoding::GFp5<F> {
    fn from(value: GFp5) -> Self {
        Self(value.0.map(|x| F::from_canonical_u64(x.to_u64())))
    }
}

impl<F: RichField> From<Point<F>> for arith::Point {
    fn from(value: Point<F>) -> Self {
        Self {
            X: value.x.into(),
            Z: value.z.into(),
            U: value.u.into(),
            T: value.t.into(),
        }
    }
}

impl<T: Copy> From<[T; LEN_POINT]> for Point<T> {
    fn from(value: [T; LEN_POINT]) -> Self {
        let x: [T; LEN_FIELD] = value[..LEN_FIELD].try_into().unwrap();
        let z: [T; LEN_FIELD] = value[LEN_FIELD..LEN_FIELD * 2].try_into().unwrap();
        let u: [T; LEN_FIELD] = value[LEN_FIELD * 2..LEN_FIELD * 3].try_into().unwrap();
        let t: [T; LEN_FIELD] = value[LEN_FIELD * 3..].try_into().unwrap();
        Self {
            x: x.into(),
            z: z.into(),
            u: u.into(),
            t: t.into(),
        }
    }
}

impl<T: Copy> From<Point<T>> for [T; LEN_POINT] {
    fn from(value: Point<T>) -> Self {
        let mut res = Vec::with_capacity(LEN_POINT);
        res.extend(value.x.0);
        res.extend(value.z.0);
        res.extend(value.u.0);
        res.extend(value.t.0);
        res.try_into()
            .unwrap_or_else(|_| panic!("Given point don't fit the right length"))
    }
}

impl<T: Copy, TBool: Copy + FromBool<T>> From<&Credential<T, TBool>> for [T; LEN_CREDENTIAL] {
    fn from(value: &Credential<T, TBool>) -> Self {
        let mut res = Vec::with_capacity(LEN_CREDENTIAL);
        res.extend(value.first_name.0);
        res.extend(value.family_name.0);
        res.extend(value.place_of_birth.0);
        res.extend(value.passport_number.0);
        res.push(value.birth_date);
        res.push(value.expiration_date);
        res.push(value.gender.from_bool());
        res.push(value.nationality);
        let point: [T; LEN_POINT] = value.issuer.into();
        res.extend(point);
        res.try_into()
            .unwrap_or_else(|_| panic!("Given credential don't fit the right length"))
    }
}

const POS_BIRTH_DATE: usize = LEN_STRING * 3 + LEN_PASSPORT_NUMBER;
const START_ISSUER: usize = POS_BIRTH_DATE + 4;
impl<T: Copy + ToBool<TBool>, TBool: Copy> From<&[T; LEN_CREDENTIAL]> for Credential<T, TBool> {
    fn from(value: &[T; LEN_CREDENTIAL]) -> Self {
        let first_name: [T; LEN_STRING] = value[0..LEN_STRING].try_into().unwrap();
        let family_name: [T; LEN_STRING] = value[LEN_STRING..LEN_STRING * 2].try_into().unwrap();
        let place_of_birth: [T; LEN_STRING] =
            value[LEN_STRING * 2..LEN_STRING * 3].try_into().unwrap();
        let passport_number = value[LEN_STRING * 3..LEN_STRING * 3 + LEN_PASSPORT_NUMBER]
            .try_into()
            .unwrap();
        let issuer: [T; LEN_POINT] = value[START_ISSUER..].try_into().unwrap();

        Self {
            first_name: encoding::String(first_name),
            family_name: encoding::String(family_name),
            place_of_birth: encoding::String(place_of_birth),
            passport_number: encoding::PassportNumber(passport_number),
            birth_date: value[POS_BIRTH_DATE],
            expiration_date: value[POS_BIRTH_DATE + 1],
            gender: value[POS_BIRTH_DATE + 2].to_bool(),
            nationality: value[POS_BIRTH_DATE + 3],
            issuer: issuer.into(),
        }
    }
}
