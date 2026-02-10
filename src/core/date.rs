use chrono::{Datelike, NaiveDate};
use rand::Rng;

const ORIGIN: NaiveDate = NaiveDate::from_ymd_opt(1900, 1, 1).unwrap();

// Deterministic "today" for tests
const TODAY_FOR_TESTS: NaiveDate = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();

/// The generated birth date is generated such that it’s more than 18 years from TODAY_FOR_TESTS
pub fn generate_birth_date(rng: &mut impl Rng) -> NaiveDate {
    let start_birth_date = NaiveDate::from_ymd_opt(1900, 1, 1).unwrap();
    let end_birth_date = NaiveDate::from_ymd_opt(2000, 1, 1).unwrap();
    start_birth_date
        + chrono::Duration::days(
            rng.random_range(0..(end_birth_date - start_birth_date).num_days()),
        )
}

/// The generated birth date is generated such that it’s less than 18 years from TODAY_FOR_TESTS
pub fn generate_birth_date_minor(rng: &mut impl Rng) -> NaiveDate {
    let start_birth_date = NaiveDate::from_ymd_opt(2008, 1, 1).unwrap();
    let end_birth_date = NaiveDate::from_ymd_opt(2026, 1, 1).unwrap();
    // let end_birth_date = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    start_birth_date
        + chrono::Duration::days(
            rng.random_range(0..(end_birth_date - start_birth_date).num_days()),
        )
}

pub fn generate_expiration_date(rng: &mut impl Rng) -> NaiveDate {
    // here we take the same date as end_birth_date
    let start_credential = NaiveDate::from_ymd_opt(2025, 1, 1).unwrap();
    let end_credential = NaiveDate::from_ymd_opt(3000, 1, 1).unwrap();
    start_credential
        + chrono::Duration::days(
            rng.random_range(0..(end_credential - start_credential).num_days()),
        )
}

/// /!\ This does not use today’s date
pub fn from_today_for_tests(date: &NaiveDate) -> u32 {
    // Origin is chosen old enough such that num_days won’t be < 0
    (TODAY_FOR_TESTS - *date).num_days() as u32
}

/// returns the numbers of days spent from ORIGIN to date
pub fn days_from_origin(date: NaiveDate) -> u32 {
    (date - ORIGIN).num_days() as u32
}

/// /!\ This does not use today’s date
/// returns the minimal numbers of days spent from ORIGIN to be eighteen today
/// In the circuit we want days_from_origin(date) <= cutoff18
pub fn cutoff18_from_today_for_tests() -> u32 {
    let date_18 = NaiveDate::from_ymd_opt(TODAY_FOR_TESTS.year() - 18, 1, 1).unwrap();
    days_from_origin(date_18)
}
