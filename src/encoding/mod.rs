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
pub const LEN_CREDENTIAL: usize = 3 * LEN_STRING + LEN_PASSPORT_NUMBER + 4 + LEN_POINT * 2;

pub const LEN_SIGNATURE: usize = LEN_POINT + LEN_SCALAR;

pub const LEN_HASH: usize = 4;

/// Pseudonym is the result of poseidon, so it’s convenient to set it at 4
pub const LEN_PSEUDONYM: usize = LEN_HASH;

/// Representation of a string inside a circuit
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct String<T>(pub [T; LEN_STRING]);
/// Representation of a passport number inside a circuit.
/// Passport number is assumed to b french (fits on 9 u8)
#[derive(Clone, Copy, Debug)]
pub struct PassportNumber<T>(pub [T; LEN_PASSPORT_NUMBER]);

/// Representation of a credential inside a circuit
#[derive(Clone, Copy, Debug)]
pub struct Credential<T, TBool> {
    pub first_name: String<T>,
    pub family_name: String<T>,
    pub place_of_birth: String<T>,
    pub passport_number: PassportNumber<T>, // assumed to be french (9 u8)
    pub birth_date: T,                      // number of days since origin
    pub expiration_date: T,
    pub gender: TBool, // boolean
    pub nationality: T,
    pub issuer: Point<T>,
    pub public_key: Point<T>,
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
pub struct SchnorrProof<T, TBool> {
    pub(crate) r: Point<T>,
    pub(crate) s: Scalar<TBool>,
}

#[derive(Clone, Copy, Debug)]
pub struct Signature<T, TBool>(pub(crate) SchnorrProof<T, TBool>);

#[derive(Clone, Copy, Debug)]
pub struct Authentification<T, TBool>(pub(crate) SchnorrProof<T, TBool>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthentificationChallengeRaw<S> {
    /// service, unique per bank
    pub service: S,
    /// nonce, unique per connection
    pub nonce: S,
}

pub type AuthentificationChallenge<T> = AuthentificationChallengeRaw<String<T>>;
// TODO: maybe service & nonce should have a longer type
pub struct AuthentificationContext<T> {
    pub public_key: Point<T>,
    pub challenge: AuthentificationChallenge<T>,
}

// FIXME: centralize every hash of the repository (this, schnorr, etc)
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hash<T>(pub [T; LEN_HASH]);

pub type Pseudonym<T> = Hash<T>;

// does not contain the root
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MerklePath<const D: usize, T, TBool> {
    pub path: [Hash<T>; D],
    /// True for left, false for right
    pub positions: [TBool; D],
}
