//! Step-name and initial brief declarations; mail publication belongs to the service.
use super::{lock_mailbox, read_reservation, reservation_path};
use crate::error::LaneError;
use serde_json::Value;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// Keep a round name to one plain mailbox word.
///
/// # Errors
///
/// Refuses punctuation, whitespace and names beyond the mailbox bound.
pub fn valid_step(step: &str) -> Result<(), LaneError> {
    let bytes = step.as_bytes();
    if (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        Ok(())
    } else {
        Err(LaneError::input(
            "round-step",
            format!("{step:?} is not a plain step word"),
        ))
    }
}

pub(crate) fn unix_ns() -> Result<u64, LaneError> {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| LaneError::operation("letter-clock", error.to_string()))?
        .as_nanos();
    u64::try_from(nanos).map_err(|_| LaneError::operation("letter-clock", "instant exceeds u64"))
}

/// Read the optional stop declaration from the opening letter block.
///
/// # Errors
///
/// Refuses a repeated declaration or any value other than `yes`.
pub(crate) fn stop_declaration(letter: &[u8]) -> Result<bool, LaneError> {
    let text = std::str::from_utf8(letter)
        .map_err(|_| LaneError::input("letter-stop", "letter is not UTF-8"))?;
    let mut stop = None;
    for line in text.lines().take(16) {
        let line = line.trim().trim_start_matches("- ");
        let Some((key, value)) = line.split_once(':').or_else(|| line.split_once('=')) else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("stop")
            && stop.replace(value.trim().to_owned()).is_some()
        {
            return Err(LaneError::input(
                "letter-stop",
                "Stop is repeated in the opening declaration",
            ));
        }
    }
    match stop.as_deref() {
        None => Ok(false),
        Some("yes") => Ok(true),
        Some(value) => Err(LaneError::input(
            "letter-stop",
            format!("Stop has unsupported value {value:?}; expected yes"),
        )),
    }
}

/// Read the protected mail reservation without inspecting a legacy mailbox.
///
/// # Errors
/// Refuses legacy schemas and mismatched run identity; cutover reconciles them.
pub(crate) fn reconcile_run(
    plan: &crate::plan::Plan,
    run: &str,
    _owner_home: &Path,
    owner_uid: u32,
    _publish: bool,
) -> Result<(Value, Vec<Value>), LaneError> {
    let root = plan
        .driver_dir
        .parent()
        .ok_or_else(|| LaneError::input("mail-record", "runs root absent"))?;
    let _mailbox = lock_mailbox(root, run, owner_uid)?;
    let record = read_reservation(&reservation_path(root, run))?
        .ok_or_else(|| LaneError::input("mail-record", "reservation absent"))?;
    if record.get("letters").is_some() || !record["mail"].is_array() {
        return Err(LaneError::input(
            "mail-record",
            "legacy reservation requires mail cutover reconciliation",
        ));
    }
    if record["run"] != run
        || record["loop"] != plan.document["loop"]
        || record["plan"]["home"] != plan.home.display().to_string()
        || record["plan"]["driver_dir"] != plan.driver_dir.display().to_string()
    {
        return Err(LaneError::input(
            "mail-record",
            "reservation names another run or home",
        ));
    }
    Ok((record, Vec::new()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::os::unix::fs::PermissionsExt as _;

    /// ´test:unit:stop-declaration-is-bounded-and-explicit´
    #[test]
    fn stop_declaration_is_bounded_and_explicit() {
        assert!(!stop_declaration(b"Model: gpt-6-sol\nEffort: high\n").expect("ordinary letter"));
        assert!(
            stop_declaration(b"Model: gpt-6-sol\nEffort: high\nStop: yes\n").expect("stop letter")
        );
        for letter in [
            b"Stop: no\n".as_slice(),
            b"Stop: yes\nStop: yes\n".as_slice(),
            b"Stop: perhaps\n".as_slice(),
        ] {
            assert_eq!(
                stop_declaration(letter).expect_err("bad stop").kind,
                "letter-stop"
            );
        }
    }

    /// ´test:unit:letter-step-refuses-nonwords´
    #[test]
    fn letter_step_refuses_nonwords() {
        for word in ["", "two words", "x/y", "x.y", "-x", "x\n"] {
            assert_eq!(valid_step(word).expect_err("not a word").kind, "round-step");
        }
        valid_step("review_2").expect("plain word");
    }

    /// ´test:unit:legacy-reservation-schema-refuses-without-reading-its-mailbox´
    #[test]
    fn legacy_reservation_schema_refuses_without_reading_its_mailbox() {
        let root = tempfile::tempdir_in("/tmp").expect("fixture");
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700))
            .expect("root custody");
        let plan = crate::plan::Plan {
            home: root.path().join("absent-home"),
            driver_dir: root.path().join("R"),
            letter: root.path().join("absent-letter"),
            document: json!({"loop":"alpha"}),
        };
        let path = reservation_path(root.path(), "R");
        let mut record = json!({"schema":1,"phase":"started","worker_uid":nix::unistd::Uid::effective().as_raw(),"run":"R","loop":"alpha","plan":{"home":plan.home,"driver_dir":plan.driver_dir},"letters":[]});
        super::super::publish_reservation(&path, &record).expect("legacy record");
        let before = std::fs::read(&path).expect("before");
        let error = reconcile_run(
            &plan,
            "R",
            root.path(),
            nix::unistd::Uid::effective().as_raw(),
            true,
        )
        .expect_err("cutover required");
        assert!(
            error.detail.contains("cutover reconciliation"),
            "{}",
            error.line()
        );
        assert_eq!(std::fs::read(&path).expect("after"), before);
        record.as_object_mut().expect("object").remove("letters");
        record["mail"] = json!([]);
        super::super::publish_reservation(&path, &record).expect("mail record");
        let (read, changes) = reconcile_run(
            &plan,
            "R",
            root.path(),
            nix::unistd::Uid::effective().as_raw(),
            true,
        )
        .expect("no mailbox inspection");
        assert_eq!(read, record);
        assert_eq!(changes, [] as [Value; 0]);
        assert!(!plan.home.exists());
        assert!(!plan.letter.exists());
    }
}
