//! Impossible Linux task IDs shared by process-absence fixtures.

/// A positive `pid_t` above Linux's `PID_MAX_LIMIT` (`4_194_304`).
/// Offsets through four remain representable by `pid_t` and cannot be allocated,
/// including to non-leader tasks or after the kernel PID counter wraps.
pub const DEAD_LOCK_PID: u32 = 2_147_483_640;
