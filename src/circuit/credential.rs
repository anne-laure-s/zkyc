// FIXME: arbitrary limit of 20 chars for now, each char is 1/4 of u32 -> 5 field elements (of 32 bits, to avoid overfow)

use crate::circuit::Point;

/// Representation of a credential inside a circuit
pub struct Credential<T> {
    pub first_name: [T; 5],
    pub family_name: [T; 5],
    pub birth_date: T, // number of days since origin
    pub place_of_birth: [T; 5],
    pub gender: T,
    pub nationality: T,
    pub passport_number: [T; 3], // assumed to be french (9 u8)
    pub expiration_date: T,
    pub issuer: Point<T>,
}

// 1 u32 = 4 ascii chars
