// FIXME: arbitrary limit of 20 chars for now, each char is 1/4 of u32 -> 5 field elements (of 32 bits, to avoid overfow)

// TODO: add tests for lengths

use crate::arith;

pub mod conversion;

pub const LEN_STRING: usize = 5;
pub const LEN_PASSPORT_NUMBER: usize = 3;
pub const LEN_FIELD: usize = 5;
pub const LEN_POINT: usize = 4 * LEN_FIELD;
pub const LEN_SCALAR: usize = arith::Scalar::NB_BITS;

/// size of a credential<T> in number of T elements
pub const LEN_CREDENTIAL: usize = 3 * LEN_STRING + LEN_PASSPORT_NUMBER + 4 + LEN_POINT;

/// Representation of a string inside a circuit
#[derive(Clone, Copy, Debug)]
pub struct String<T>(pub [T; LEN_STRING]);
/// Representation of a passport number inside a circuit.
/// Passport number is assumed to b french (fits on 9 u8)
#[derive(Clone, Copy, Debug)]
pub struct PassportNumber<T>(pub [T; LEN_PASSPORT_NUMBER]);

/// Representation of a credential inside a circuit
#[derive(Clone, Copy, Debug)]
pub struct Credential<T> {
    pub first_name: String<T>,
    pub family_name: String<T>,
    pub place_of_birth: String<T>,
    pub passport_number: PassportNumber<T>, // assumed to be french (9 u8)
    pub birth_date: T,                      // number of days since origin
    pub expiration_date: T,
    pub gender: T,
    pub nationality: T,
    pub issuer: Point<T>,
}

// 1 u32 = 4 ascii chars

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GFp5<T>(pub [T; LEN_FIELD]);

/// /!\ Eq is formal equality of the coordinates here
/// Note that the same point can have different representation,
/// so the equality should only be used to compare coordinates
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Point<T> {
    pub x: GFp5<T>,
    pub z: GFp5<T>,
    pub u: GFp5<T>,
    pub t: GFp5<T>,
}

#[derive(Clone, Copy, Debug)]
pub struct Scalar<T>(pub(crate) [T; LEN_SCALAR]);

#[derive(Clone, Copy, Debug)]
pub struct Signature<T, TBool> {
    pub(crate) r: Point<T>,
    pub(crate) s: Scalar<TBool>,
}
