//! Content-free vendor accounting and a bounded, process-local volume alarm.

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::sync::Mutex;
use std::time::Instant;

pub const DEFAULT_EXPECTED_TOKENS: u64 = 16_384;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Status {
    NotStarted,
    Unknown,
    Partial,
    Complete,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    NotStarted,
    MissingUsage,
    StreamCut,
    CounterOverflow,
    VendorFailure,
    MalformedEvent,
    Interrupted,
    Complete,
    EnvelopeUnavailable,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub status: Status,
    pub reason: Reason,
    pub turns: u64,
    pub input_tokens: Option<u64>,
    pub cached_input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
}

impl Usage {
    #[must_use]
    pub const fn absent(started: bool) -> Self {
        Self {
            status: if started {
                Status::Unknown
            } else {
                Status::NotStarted
            },
            reason: if started {
                Reason::EnvelopeUnavailable
            } else {
                Reason::NotStarted
            },
            turns: 0,
            input_tokens: None,
            cached_input_tokens: None,
            output_tokens: None,
        }
    }

    #[must_use]
    pub fn read(value: &Value) -> Self {
        let Ok(usage) = serde_json::from_value::<Self>(value.clone()) else {
            return Self::absent(true);
        };
        let measured = matches!(usage.status, Status::Partial | Status::Complete);
        let valid = if measured {
            usage.turns > 0
                && usage
                    .input_tokens
                    .zip(usage.cached_input_tokens)
                    .is_some_and(|(input, cached)| cached <= input)
                && usage.output_tokens.is_some()
                && matches!(
                    (usage.status, usage.reason),
                    (Status::Complete, Reason::Complete)
                        | (
                            Status::Partial,
                            Reason::MalformedEvent | Reason::Interrupted
                        )
                )
        } else {
            usage.input_tokens.is_none()
                && usage.cached_input_tokens.is_none()
                && usage.output_tokens.is_none()
                && if usage.status == Status::NotStarted {
                    usage.reason == Reason::NotStarted && usage.turns == 0
                } else {
                    !matches!(usage.reason, Reason::NotStarted | Reason::Complete)
                }
        };
        if valid { usage } else { Self::absent(true) }
    }

    #[must_use]
    pub fn value(&self) -> Value {
        json!(self)
    }

    fn score(&self) -> Option<u128> {
        let input = self.input_tokens?;
        let cached = self.cached_input_tokens?;
        Some(
            8 * u128::from(input.checked_sub(cached)?)
                + u128::from(cached)
                + 64 * u128::from(self.output_tokens?),
        )
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct Bucket {
    second: u64,
    score: u128,
    unknown: u64,
}

/// Fixed-size storage, independent of request population. Clock buckets include
/// at most one extra second at the old boundary, conservatively, never undercounting.
#[derive(Debug)]
struct Window {
    buckets: Vec<Bucket>,
    alarms: u64,
}
impl Window {
    fn new() -> Self {
        Self {
            buckets: vec![Bucket::default(); 3601],
            alarms: 0,
        }
    }
    fn add(&mut self, second: u64, score: Option<u128>) -> (u128, u64) {
        let index = usize::try_from(second % 3601).unwrap_or(0);
        let bucket = &mut self.buckets[index];
        if bucket.second != second {
            *bucket = Bucket {
                second,
                ..Bucket::default()
            };
        }
        if let Some(score) = score {
            bucket.score = bucket.score.saturating_add(score);
        } else {
            bucket.unknown = bucket.unknown.saturating_add(1);
        }
        self.buckets
            .iter()
            .filter(|bucket| second.saturating_sub(bucket.second) <= 3600)
            .fold((0_u128, 0_u64), |(score, unknown), bucket| {
                (
                    score.saturating_add(bucket.score),
                    unknown.saturating_add(bucket.unknown),
                )
            })
    }
}

/// The future owner-side publisher receives this closed, typed alarm, never text.
#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AlarmKind {
    CallExcess,
    HourExcess,
}

#[derive(Debug)]
pub struct Alarm {
    pub kind: AlarmKind,
    pub score8: u128,
    pub threshold8: u64,
}

#[derive(Debug)]
pub struct Monitor {
    pub expected: u64,
    started: Instant,
    window: Mutex<Window>,
}
impl Monitor {
    #[must_use]
    pub fn new(expected: u64) -> Self {
        Self {
            expected,
            started: Instant::now(),
            window: Mutex::new(Window::new()),
        }
    }
    pub fn observe(&self, usage: &Usage) -> (Value, Vec<Alarm>) {
        let second = self.started.elapsed().as_secs();
        let mut window = self
            .window
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let score = usage.score();
        let (hour, unknown) = window.add(
            second,
            if usage.status == Status::NotStarted {
                Some(0)
            } else {
                score
            },
        );
        let mut alarms = Vec::with_capacity(2);
        let per_call = self.expected.saturating_mul(64);
        let hourly = self.expected.saturating_mul(512);
        if let Some(score) = score.filter(|score| *score > u128::from(per_call)) {
            alarms.push(Alarm {
                kind: AlarmKind::CallExcess,
                score8: score,
                threshold8: per_call,
            });
        }
        if hour > u128::from(hourly) {
            alarms.push(Alarm {
                kind: AlarmKind::HourExcess,
                score8: hour,
                threshold8: hourly,
            });
        }
        window.alarms = window
            .alarms
            .saturating_add(u64::try_from(alarms.len()).unwrap_or(u64::MAX));
        (
            json!({"score8":score.map(bounded), "score_saturated":score.is_some_and(saturated),
            "hour_score8":bounded(hour), "hour_score_saturated":saturated(hour),
            "hour_unknown_calls":unknown, "coverage_seconds":second.min(3600),
            "window_extra_ms_max":1000, "alarm_count":window.alarms}),
            alarms,
        )
    }
}

fn saturated(value: u128) -> bool {
    value > u128::from(u64::MAX)
}
fn bounded(value: u128) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

pub fn journal(identity: &Value, event: &str, body: &Value, error: bool) {
    use std::io::Write as _;
    let line = json!({"identity":identity,"event":event,"severity":if error {"error"} else {"info"},"data":body});
    // syslog's priority prefix makes this an error in the service journal too.
    let _logged = writeln!(
        std::io::stderr().lock(),
        "{}door-agent-usage {}",
        if error { "<3>" } else { "<6>" },
        line
    );
}

#[must_use]
pub fn alarm_value(alarm: &Alarm, usage: &Usage) -> Value {
    json!({"kind":alarm.kind,"usage":usage,"score8":bounded(alarm.score8),
        "score_saturated":saturated(alarm.score8),"threshold8":alarm.threshold8})
}

#[cfg(test)]
mod tests {
    use super::*;

    fn measured(input: u64, cached: u64, output: u64) -> Usage {
        Usage {
            status: Status::Complete,
            reason: Reason::Complete,
            turns: 1,
            input_tokens: Some(input),
            cached_input_tokens: Some(cached),
            output_tokens: Some(output),
        }
    }

    /// ´test:unit:agent-usage-score-weights-cache-and-output-exactly´
    #[test]
    fn agent_usage_score_weights_cache_and_output_exactly() {
        assert_eq!(measured(100, 80, 3).score(), Some(432));
        assert_eq!(measured(100, 0, 0).score(), Some(800));
        assert_eq!(measured(100, 100, 0).score(), Some(100));
        assert_eq!(measured(0, 0, 1).score(), Some(64));
        let monitor = Monitor::new(1);
        assert!(monitor.observe(&measured(0, 0, 1)).1.is_empty());
        let (value, alarms) = monitor.observe(&measured(0, 0, 2));
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0].kind, AlarmKind::CallExcess);
        assert_eq!(alarms[0].threshold8, 64);
        assert_eq!(value["hour_score8"], 192);
        let (value, alarms) = Monitor::new(1).observe(&measured(u64::MAX, 0, u64::MAX));
        assert_eq!(alarms.len(), 2);
        assert_eq!(value["score_saturated"], true);
        assert_eq!(value["score8"], u64::MAX);
        assert!(alarms[0].score8 > u128::from(u64::MAX));
    }

    /// ´test:unit:agent-usage-hour-counts-volume-without-history-reads´
    #[test]
    fn agent_usage_hour_counts_volume_without_history_reads() {
        let monitor = Monitor::new(1);
        for _ in 0..8 {
            assert!(monitor.observe(&measured(0, 0, 1)).1.is_empty());
        }
        let (value, alarms) = monitor.observe(&measured(0, 0, 1));
        assert_eq!(alarms.len(), 1);
        assert_eq!(alarms[0].kind, AlarmKind::HourExcess);
        assert_eq!(alarms[0].threshold8, 512);
        assert_eq!(value["hour_score8"], 576);
        assert_eq!(value["alarm_count"], 1);
        let mut window = Window::new();
        assert_eq!(window.add(1, Some(7)), (7, 0));
        assert_eq!(window.add(3601, None), (7, 1));
        assert_eq!(window.add(3602, Some(3)), (3, 1));
        assert_eq!(window.add(7203, Some(0)), (0, 0));
        assert_eq!(window.buckets.len(), 3601);
        let (fresh, _) = Monitor::new(1).observe(&Usage::absent(true));
        assert_eq!(fresh["hour_unknown_calls"], 1);
        assert!(fresh["score8"].is_null());
        assert_eq!(fresh["hour_score8"], 0);
        assert_eq!(fresh["coverage_seconds"], 0);
    }

    /// ´test:unit:agent-usage-reader-keeps-unknown-distinct-from-zero´
    #[test]
    fn agent_usage_reader_keeps_unknown_distinct_from_zero() {
        let control = measured(0, 0, 0).value();
        assert_eq!(Usage::read(&control).status, Status::Complete);
        for (key, bad) in [
            ("input_tokens", json!(-1)),
            ("cached_input_tokens", json!(1)),
            ("output_tokens", json!(false)),
            ("turns", json!(0)),
            ("status", json!("vendor-text")),
            ("reason", json!("vendor-text")),
            ("extra", json!("private")),
        ] {
            let mut value = control.clone();
            value[key] = bad;
            let result = Usage::read(&value);
            assert_eq!(result.status, Status::Unknown, "{key}");
            assert!(result.input_tokens.is_none(), "{key}");
        }
        let mut partial = control;
        partial["status"] = json!("partial");
        partial["reason"] = json!("interrupted");
        assert_eq!(Usage::read(&partial).status, Status::Partial);
        assert_eq!(
            Usage::read(&Usage::absent(false).value()).status,
            Status::NotStarted
        );
        assert_eq!(Usage::read(&Value::Null).status, Status::Unknown);
    }
}
