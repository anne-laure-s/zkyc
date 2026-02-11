// FIXME: arbitrary limit of 20 chars for now, each char is 1/4 of u32 -> 5 field elements (of 32 bits, to avoid overfow)

// TODO: add tests for lengths

pub mod conversion;

pub const LEN_STRING: usize = 5;
pub const LEN_PASSPORT_NUMBER: usize = 3;
pub const LEN_EXTENSION_FIELD: usize = 5;
pub const LEN_POINT: usize = 4 * LEN_EXTENSION_FIELD;

/// size of a credential<T> in number of T elements
pub const LEN_CREDENTIAL: usize = 3 * LEN_STRING + LEN_PASSPORT_NUMBER + 4 + LEN_POINT;

pub const LEN_SIGNATURE: usize = LEN_POINT + 1;
/// Representation of a credential inside a circuit
#[derive(Clone)]
pub struct Credential<T> {
    pub first_name: [T; LEN_STRING],
    pub family_name: [T; LEN_STRING],
    pub place_of_birth: [T; LEN_STRING],
    pub passport_number: [T; LEN_PASSPORT_NUMBER], // assumed to be french (9 u8)
    pub birth_date: T,                             // number of days since origin
    pub expiration_date: T,
    pub gender: T,
    pub nationality: T,
    pub issuer: Point<T>,
}

// 1 u32 = 4 ascii chars

#[derive(Clone)]
pub struct Point<T> {
    pub x: [T; LEN_EXTENSION_FIELD],
    pub z: [T; LEN_EXTENSION_FIELD],
    pub u: [T; LEN_EXTENSION_FIELD],
    pub t: [T; LEN_EXTENSION_FIELD],
}

#[derive(Clone)]
pub struct Signature<T> {
    r: Point<T>,
    s: T,
}
