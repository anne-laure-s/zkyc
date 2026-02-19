use std::fmt::Write;

use chrono::{Datelike, NaiveDate};
use plonky2::field::types::Field;
use rand::Rng;

use crate::{
    core::date::{
        days_from_origin, generate_birth_date, generate_birth_date_minor, generate_expiration_date,
    },
    encoding::{
        self,
        conversion::{ToBool, ToField, ToPointField, ToSingleField, ToVecField},
        LEN_PASSPORT_NUMBER, LEN_STRING,
    },
    issuer,
    schnorr::{
        keys::{PublicKey, SecretKey},
        signature::{Context, Signature},
    },
};

#[derive(Clone)]
pub struct Credential {
    first_name: Name,
    family_name: Name,
    birth_date: NaiveDate,
    place_of_birth: Place,
    gender: Gender,
    nationality: Nationality,
    passport_number: PassportNumber,
    expiration_date: NaiveDate,
    issuer: Issuer, // TODO: public_key instead
}

// ----

#[derive(Debug, Clone)]
struct Name(String);

#[derive(Debug, Clone)]
struct Place(String);

#[derive(Debug, Clone)]
struct Issuer(PublicKey);

#[derive(Debug, Clone)]
enum Gender {
    M,
    F,
}

#[derive(Debug, Clone)]
pub enum Nationality {
    FR,
    // EN,
}

#[derive(Debug, Clone)]
enum PassportNumber {
    French(FrenchPassportNumber),
}

#[derive(Debug, Clone)]
struct FrenchPassportNumber([u8; 9]);

impl ToBool<bool> for Gender {
    fn to_bool(&self) -> bool {
        match self {
            Self::M => false,
            Self::F => true,
        }
    }
}

impl<F: Field> ToSingleField<F> for Nationality {
    fn to_field(&self) -> F {
        self.code().to_field()
    }
}

impl<F: Field> ToSingleField<F> for NaiveDate {
    fn to_field(&self) -> F {
        days_from_origin(*self).to_field()
    }
}

// TODO: maybe this conversion is not necessary
impl<F: Field> ToPointField<F> for Issuer {
    fn to_field(&self) -> crate::encoding::Point<F> {
        self.0 .0.to_field()
    }
}

impl<F: Field> ToField<F, LEN_PASSPORT_NUMBER> for PassportNumber {
    fn to_field(&self) -> [F; LEN_PASSPORT_NUMBER] {
        match self {
            Self::French(n) => n.to_field(),
        }
    }
}

impl<F: Field> ToField<F, LEN_PASSPORT_NUMBER> for FrenchPassportNumber {
    fn to_field(&self) -> [F; LEN_PASSPORT_NUMBER] {
        self.0
            .as_slice()
            .to_field(LEN_PASSPORT_NUMBER)
            .try_into()
            .unwrap()
    }
}

// TODO: all lengths should be checked at construction
/// for now, 20 chars max, encoded on u32 converted to field elements
impl<F: Field> ToField<F, LEN_STRING> for String {
    fn to_field(&self) -> [F; LEN_STRING] {
        self.as_bytes().to_field(LEN_STRING).try_into().unwrap()
    }
}

impl Gender {
    fn rnd(rng: &mut impl Rng) -> Self {
        match rng.random_range(0..2) {
            0 => Self::M,
            1 => Self::F,
            _ => unreachable!(),
        }
    }
}

impl std::fmt::Display for Gender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::F => f.write_str("F"),
            Self::M => f.write_str("M"),
        }
    }
}

// TODO: We may be able to use country code, or smth similar instead
impl Nationality {
    // TODO: smoother way to deal with nationalities
    fn rnd(rng: &mut impl Rng) -> Self {
        match rng.random_range(0..1) {
            0 => Self::FR,
            // 1 => Self::EN,
            _ => unreachable!(),
        }
    }
    pub fn code(&self) -> u16 {
        match self {
            Nationality::FR => 250,
        }
    }
}

impl std::fmt::Display for Nationality {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FR => f.write_str("FR"),
        }
    }
}

impl PassportNumber {
    fn rnd(rng: &mut impl Rng) -> Self {
        Self::French(FrenchPassportNumber::rnd(rng))
    }
}

impl std::fmt::Display for PassportNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PassportNumber::French(number) => number.fmt(f),
        }
    }
}

impl FrenchPassportNumber {
    fn rnd(rng: &mut impl Rng) -> Self {
        let mut res = [0; 9];
        res[0..2]
            .iter_mut()
            .for_each(|z| *z = b'0' + rng.random_range(0..10) as u8);
        res[2..4]
            .iter_mut()
            .for_each(|z| *z = b'A' + (rng.random_range(0..26) as u8));
        res[4..9]
            .iter_mut()
            .for_each(|z| *z = b'0' + rng.random_range(0..10) as u8);
        FrenchPassportNumber(res)
    }
    fn check(&self) -> bool {
        self.0[0..2].iter().all(u8::is_ascii_digit)
            && self.0[2..4].iter().all(u8::is_ascii_uppercase)
            && self.0[4..9].iter().all(u8::is_ascii_digit)
    }
}

impl std::fmt::Display for FrenchPassportNumber {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for &b in self.0.iter() {
            f.write_char(b as char)?
        }
        Ok(())
    }
}

impl Credential {
    pub fn issuer(&self) -> PublicKey {
        self.issuer.0.clone()
    }
    pub fn nationality(&self) -> &Nationality {
        &self.nationality
    }
    pub fn birth_date(&self) -> &NaiveDate {
        &self.birth_date
    }
    pub fn random(rng: &mut impl Rng) -> (SecretKey, Self) {
        fn generate_name(rng: &mut impl Rng) -> String {
            let len = rng.random_range(3..20);
            let mut res = String::with_capacity(len);
            res.push((b'A' + rng.random_range(0..26)) as char);
            for _ in 1..len {
                res.push((b'a' + rng.random_range(0..26)) as char);
            }
            res
        }
        let sk = SecretKey::random(rng);
        let issuer = Issuer(PublicKey::from(&sk));
        (
            sk,
            Credential {
                first_name: Name(generate_name(rng)),
                family_name: Name(generate_name(rng)),
                birth_date: generate_birth_date(rng),
                place_of_birth: Place(generate_name(rng)),
                gender: Gender::rnd(rng),
                nationality: Nationality::rnd(rng),
                passport_number: PassportNumber::rnd(rng),
                expiration_date: generate_expiration_date(rng),
                issuer,
            },
        )
    }
    pub fn random_with_issuer(sk: &SecretKey, rng: &mut impl Rng) -> Self {
        let (_sk, mut credential) = Self::random(rng);
        let pk = PublicKey::from(sk);
        credential.issuer = Issuer(pk);
        credential
    }
    pub fn random_minor(rng: &mut impl Rng) -> Self {
        fn generate_name(rng: &mut impl Rng) -> String {
            let len = rng.random_range(3..19);
            let mut res = String::with_capacity(len);
            res.push((b'A' + rng.random_range(0..26)) as char);
            for _ in 1..len {
                res.push((b'a' + rng.random_range(0..26)) as char);
            }
            res
        }
        Credential {
            first_name: Name(generate_name(rng)),
            family_name: Name(generate_name(rng)),
            birth_date: generate_birth_date_minor(rng),
            place_of_birth: Place(generate_name(rng)),
            gender: Gender::rnd(rng),
            nationality: Nationality::rnd(rng),
            passport_number: PassportNumber::rnd(rng),
            expiration_date: generate_expiration_date(rng),
            issuer: Issuer(issuer::keys::public()),
        }
    }
    pub fn switch_names_char(&mut self) {
        let c = self.first_name.0.pop().unwrap();
        self.family_name.0.insert(0, c);
    }
    pub fn switch_issuer(&mut self, rng: &mut impl Rng) -> SecretKey {
        let sk = SecretKey::random(rng);
        let pk = PublicKey::from(&sk);
        self.issuer = Issuer(pk);
        sk
    }

    // TODO: fn new, with relevant checks (especially that everything is ascii, and not too long; dates’ year non negative (will overflow otherwise))

    // assumes every field is less than 255 bytes in size
    /// TODO: a versioning bytes could be added as a heading
    /// Everything is represented as big endian
    pub fn as_bytes(&self) -> Vec<u8> {
        fn push_str(res: &mut Vec<u8>, s: &str) {
            res.push(s.len() as u8); // everything is ascii so s.len() == s.as_bytes().len()
            res.extend_from_slice(s.as_bytes());
        }
        fn push_date(res: &mut Vec<u8>, date: &NaiveDate) {
            let y = date.year() as u32;
            let m = date.month();
            let d = date.day();
            let v = y * 10_000 + m * 100 + d;
            res.extend_from_slice(&v.to_le_bytes());
        }
        let mut res = vec![];
        push_str(&mut res, &self.first_name.0);
        push_str(&mut res, &self.family_name.0);
        push_date(&mut res, &self.birth_date);
        push_str(&mut res, &self.place_of_birth.0);
        res.push(match self.gender {
            Gender::M => 0,
            Gender::F => 1,
        });
        res.extend_from_slice(self.nationality.code().to_le_bytes().as_slice());
        push_str(&mut res, &self.passport_number.to_string());
        push_date(&mut res, &self.expiration_date);
        res.extend_from_slice(&self.issuer.0 .0.to_affine().x.encode());
        res.extend_from_slice(&self.issuer.0 .0.to_affine().u.encode());
        res
    }

    pub fn sign(&self, sk: &SecretKey) -> Signature {
        Signature::sign(sk, &Context::new(self))
    }

    pub fn check(&self, signature: &Signature) -> bool {
        signature.verify(&Context::new(self))
    }

    pub fn to_field<F: Field>(&self) -> encoding::Credential<F, bool> {
        encoding::Credential {
            first_name: encoding::String(self.first_name.0.to_field()),
            family_name: encoding::String(self.family_name.0.to_field()),
            birth_date: self.birth_date.to_field(),
            place_of_birth: encoding::String(self.place_of_birth.0.to_field()),
            gender: self.gender.to_bool(),
            nationality: self.nationality.to_field(),
            passport_number: encoding::PassportNumber(self.passport_number.to_field()),
            expiration_date: self.expiration_date.to_field(),
            issuer: self.issuer.to_field(),
        }
    }
}
