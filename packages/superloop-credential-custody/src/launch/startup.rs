//! Entry-only descriptor closure before the keeper acquires any case objects.
type Result<T> = std::result::Result<T, &'static str>;
#[derive(Clone)]
pub(super) struct RootStartup {
    owner: u32,
}
impl RootStartup {
    pub const fn owner(&self) -> u32 {
        self.owner
    }
    #[cfg(test)]
    pub fn test_owner() -> Self {
        Self {
            owner: nix::unistd::geteuid().as_raw(),
        }
    }
    /// Establish the root host-map precondition before admitting policy bytes.
    ///
    /// # Safety
    /// Call only in a fresh single-threaded process with no owned descriptors
    /// above stderr. Every inherited descriptor from 3 is closed, not just marked.
    #[allow(unsafe_code)]
    pub unsafe fn initialize() -> Result<Self> {
        if nix::unistd::geteuid().as_raw() != 0 {
            return Err("keeper-root-required");
        }
        let _host = loop_home::anchor::HostVerifier::current().map_err(|_| "keeper-host-map")?;
        // SAFETY: caller establishes the entry-only descriptor ownership boundary.
        unsafe {
            close_inherited()?;
        }
        Ok(Self { owner: 0 })
    }
}
/// Close ambient descriptors before the process may become resident.
///
/// # Safety
/// The caller owns no nonstandard descriptors and has started no other threads.
#[allow(unsafe_code)]
pub(super) unsafe fn close_inherited() -> Result<()> {
    // SAFETY: scalar close_range under the caller's startup ownership contract.
    if unsafe { nix::libc::syscall(nix::libc::SYS_close_range, 3_u32, u32::MAX, 0_u32) } == -1 {
        return Err("keeper-inherited-descriptors");
    }
    Ok(())
}
