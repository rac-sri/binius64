OVERVIEW
- The crates/prover crate implements the main proving engine for Binius64. It handles witness processing, protocol execution, and arithmetic ops with a focus on performance via Rayon-based parallelism.
- It coordinates proof generation end-to-end, from per-witness preparation to the final proof artifact, using specialized protocols implemented in this crate.

STRUCTURE
- src/ — core proving primitives, pipeline orchestration, and hot paths for witness processing and arithmetic.
- benches/ — microbenchmarks and performance tests used to quantify prover throughput and latency.
- src/protocols/ — protocol implementations (e.g., SumCheck and related proof protocols) that drive the prover flow.
- src/and_reduction/ — reduction steps that collapse complex expressions into tractable subproblems within protocols.
- src/shift/ — utilities for index/coordinate shifting used in polynomial commitments and evaluation domains.

WHERE TO LOOK
- Main proving entry points: the public API exposed by crates/prover/src/lib.rs (Prover, prove, and high-level orchestration hooks).
- Protocol implementations: crates/prover/src/protocols/ and their orchestration wrappers used by the Prover to advance a proof step.
- Witness processing: hot-path modules in crates/prover/src/ that transform and validate witness data before protocol execution.
- Arithmetic operations: field and polynomial arithmetic helpers used throughout the proving flow.

CONVENTIONS
- Rayon is used to parallelize independent proof computations and witness processing tasks to maximize throughput on multi-core CPUs.
- Prefers pre-allocated buffers and affine-friendly layouts to minimize allocations and cache misses in hot paths.
- Clear separation between protocol logic and data formatting; interfaces minimize heap churn and promote zero-copy where feasible.
- Thread-safety is paramount: shared data is accessed via read-only references or properly synchronized primitives; mutation is centralized to per-task scopes.
- Code should lean on precondition contracts (assertions) to catch invalid inputs early in development and tests.
- Profiling and bench targets are part of the regular workflow to keep the prover fast as the workload grows.

ANTI-PATTERNS
- Do not sprinkle I/O or non-deterministic randomness into hot proving paths; these slowdowns or nondeterminism break reproducibility.
- Avoid per-element allocations in inner loops; reuse buffers and avoid obvious allocations inside par_iter closures.
- Do not overuse locks or global state; prefer thread-local data or per-task ownership to retain scalability.
- Avoid unwrap-based error handling in library code; where a failure is a user error, propagate Result/Option or use preconditions with clear panics only in truly exceptional situations.
- Never rely on non-deterministic optimizations that trade correctness for marginal speedups; correctness and reproducibility come first, with performance tuned afterward.
- Refrain from adding broad, non-local changes that ripple through multiple modules; unit-test and bench-isolate changes to preserve stability.
