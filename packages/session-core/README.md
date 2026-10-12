# Session core · `guide:sessioncore:session-core`

Internal tier 1 session decisions and persistence. The heartbeat and rulebook graphs retain their guards, ordered effects, state filenames and failure behavior. The library accepts typed observations rather than Claude payloads. Timer correlation, expiry, prompting, block limits, rulebook comparison and deduplication belong here; a harness supplies decoded transcript entries, letters observations and a rulebook-marker witness, then renders the neutral result into its own reply protocol.

The heartbeat and orchestrator compatibility entry points use this same core. Explicit and default status read existing state without establishing its directory. On and off still establish that directory before changing the selected project or global flag. The project-root resolver preserves the exclusive home boundary and nearest plausible repository marker behavior.

The library has no internal source dependencies. Registry lookup and entry execution remain in its callers; it does not import the other tier 1 libraries. Its Rust API is internal and is not part of the consumable product-library set.
