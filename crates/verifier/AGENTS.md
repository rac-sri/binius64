# AGENTS: crates/verifier

OVERVIEW
- The verifier crate implements proof validation and verification logic for Binius64 proofs.
- It is designed to be simple, robust, and readable, with a strict no-panic policy for untrusted input.
- All error paths should map to VerificationError variants; do not expose panics to callers.

STRUCTURE
- src/ - verification engine and public API (verify_proof, verify_batch, etc.)
- src/errors.rs (or equivalent) - VerificationError and error mapping to caller-facing results
- src/validation/ - input and proof-structure sanity checks
- src/core/ - core verification algorithms and checks (polynomials, sumcheck checks, etc.)
- circuits/ - prebuilt verification circuits and related logic
- tests/ - unit/integration tests and property tests
- utils/ - helper utilities (logging, timing, constant-time comparisons)

WHERE TO LOOK
- Primary entry: lib.rs (exposes verify_proof and verification utilities)
- VerificationError handling: conversions from internal failures to VerificationError
- Core verification modules: how checks are ordered, short-circuits, and error propagation
- Test fixtures under tests/ to validate edge cases and security properties

CONVENTIONS
- Verifier patterns emphasize deterministic, single-pass checks with clear error reporting
- SECURITY: avoid any data-dependent branches that could leak information; use constant-time comparisons where applicable
- No use of Rayon; verifier code stays single-threaded or uses tightly controlled parallelism with explicit safeguards
- Avoid unwrap/expect on untrusted input; return meaningful VerificationError instead
- Precondition contracts are documented; invalid inputs should be rejected with VerificationError

ANTI-PATTERNS
- MUST NOT panic on untrusted input; MUST return a VerificationError
- DO NOT log or leak sensitive proof data; sanitize error messages
- DO NOT use unwrap/expect in verification paths; prefer explicit match or map_err
- DO NOT rely on unstable or multi-threaded patterns without explicit review
