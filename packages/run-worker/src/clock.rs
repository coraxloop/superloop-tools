const SECONDS_PER_MINUTE: u64 = 60;
const SECONDS_PER_HOUR: u64 = 3_600;
const SECONDS_PER_DAY: u64 = 86_400;

/// The civil year, month, and day of one count of days since 1970-01-01.
///
/// The era arithmetic is the standard shift to a 400-year cycle beginning in
/// March, which makes the leap day the last day of its cycle and needs no table.
const fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let shifted = days + 719_468;
    let era = shifted / 146_097;
    let day_of_era = shifted % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    if month <= 2 {
        (year + 1, month, day)
    } else {
        (year, month, day)
    }
}

/// The count of days since 1970-01-01 for one civil year, month, and day.
///
/// The era arithmetic subtracts a fixed epoch offset, so a year before 1970 would
/// leave the unsigned range; every caller rejects such a year first, which is why
/// this takes a validated date rather than defending itself.
const fn days_from_civil(year: u64, month: u64, day: u64) -> u64 {
    let shifted_year = if month <= 2 { year - 1 } else { year };
    let era = shifted_year / 400;
    let year_of_era = shifted_year - era * 400;
    let shifted_month = if month > 2 { month - 3 } else { month + 9 };
    let day_of_year = (153 * shifted_month + 2) / 5 + day - 1;
    let day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 + day_of_year;
    era * 146_097 + day_of_era - 719_468
}

/// Read back one timestamp this module rendered.
///
/// A waiter attached after a lane started must measure the budget from the lane's
/// own start, so the launch record's stamp has to become seconds again.
#[must_use]
pub fn epoch_from_stamp(stamp: &str) -> Option<u64> {
    let original = stamp;
    if stamp.len() != 20 || !stamp.is_ascii() {
        return None;
    }
    let stamp = stamp.strip_suffix('Z')?;
    let (date, clock) = stamp.split_once('T')?;
    let mut date_parts = date.split('-');
    let year = date_parts.next()?.parse::<u64>().ok()?;
    let month = date_parts.next()?.parse::<u64>().ok()?;
    let day = date_parts.next()?.parse::<u64>().ok()?;
    if date_parts.next().is_some()
        || year < 1970
        || !(1..=12).contains(&month)
        || !(1..=31).contains(&day)
    {
        return None;
    }
    let mut clock_parts = clock.split(':');
    let hour = clock_parts.next()?.parse::<u64>().ok()?;
    let minute = clock_parts.next()?.parse::<u64>().ok()?;
    let second = clock_parts.next()?.parse::<u64>().ok()?;
    if clock_parts.next().is_some() || hour > 23 || minute > 59 || second > 60 {
        return None;
    }
    let epoch = days_from_civil(year, month, day) * SECONDS_PER_DAY
        + hour * SECONDS_PER_HOUR
        + minute * SECONDS_PER_MINUTE
        + second;
    (utc_stamp(epoch) == original).then_some(epoch)
}

/// Render one epoch second as a UTC timestamp for the run table.
///
/// The conversion is arithmetic rather than a shelled-out `date`, so a lane
/// launched where no shell answers still records when it started.
#[must_use]
pub fn utc_stamp(epoch: u64) -> String {
    let (year, month, day) = civil_from_days(epoch / SECONDS_PER_DAY);
    let second_of_day = epoch % SECONDS_PER_DAY;
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        second_of_day / SECONDS_PER_HOUR,
        (second_of_day / SECONDS_PER_MINUTE) % SECONDS_PER_MINUTE,
        second_of_day % SECONDS_PER_MINUTE
    )
}
