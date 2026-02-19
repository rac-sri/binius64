# Work Plan: FRI PCS Additional Query Step

## TL;DR

> **Quick Summary**: Add a new `prove_with_openings()` method to PCSProver that generates L random points from input r, traces each through all FRI folding layers, and returns Merkle inclusion proofs for each opening.
> 
> **Deliverables**:
> - New data structures: `LayerOpening`, `TracedPointOpenings`, `AdditionalOpeningsProof`
> - New method: `PCSProver::prove_with_openings()` 
> - Helper methods for deterministic point generation and layer tracing
> - Unit and integration tests
> 
> **Estimated Effort**: Medium (1-2 days)
> **Parallel Execution**: NO - sequential implementation
> **Critical Path**: Design data structures → Implement point generation → Implement layer tracing → Integrate with FRIQueryProver → Add tests

---

## Context

### Original Request
Add an additional step to the FRI PCS prove method that:
1. Takes a value `r` as input parameter
2. Generates L random points in the original codeword
3. Traces each point through all folding layers (lowest to final)
4. Creates queries to open those points at each layer
5. Gets Merkle inclusion proofs for each opening
6. Returns the Merkle inclusion proofs as additional output from a new dedicated method

### Interview Summary
**Key Discussions**:
- r usage: Pass as input parameter (flexibility for future integration)
- Output format: New dedicated method `prove_with_openings()` - keep existing `prove()` unchanged
- Scope: Separate API (keep existing prove() unchanged)
- Point distribution: L points traced through ALL layers (original → each folded layer → final)
- Random point generation: Use r to deterministically derive L unique indices
- L parameter: Passed as usize, no enforced maximum (caller responsibility)
- Index uniqueness: Unique indices only (sample without replacement)
- L > codeword length: Use all available indices (L effectively capped at codeword length)

### Research Findings
**Architecture** (from explore agent):
- PCSProver in `crates/spartan-prover/src/pcs.rs` - main entry point
- FRIFoldProver in `crates/iop-prover/src/fri/fold.rs` - handles folding rounds
- FRIQueryProver in `crates/iop-prover/src/fri/query.rs` - generates openings with Merkle proofs
- MerkleTreeScheme in `crates/iop/src/merkle_tree/scheme.rs` - Merkle proof interface
- Current prove() creates FRIFoldProver → BaseFoldProver, writes to transcript

**Key Insight**: FRIQueryProver already has `prove_query()` method that generates openings with Merkle proofs. We need to:
1. Generate L random indices from r
2. For each index, compute its position at each layer using fold_arities
3. Call prove_query() for each (layer, index) pair
4. Collect and structure the results

### Metis Review
**Identified Gaps** (addressed):
- [Gap: Parameter types]: r will be generic input (flexible), L is usize parameter
- [Gap: Index uniqueness]: Unique indices enforced via sampling without replacement
- [Gap: L bounds]: When L > codeword length, use all indices (L = codeword length)
- [Gap: Determinism]: Same r produces same points (deterministic PRNG seeded with r)
- [Gap: Verifier scope]: Verifier integration explicitly OUT OF SCOPE
- [Gap: Error handling]: Use Result types, not panics

---

## Work Objectives

### Core Objective
Add a new `prove_with_openings()` method to PCSProver that generates L random points from input r, traces each through all FRI folding layers, and collects Merkle inclusion proofs for each opening.

### Concrete Deliverables
1. **New data structures** in `crates/spartan-prover/src/pcs.rs`:
   - `LayerOpening` - single opening at a layer
   - `TracedPointOpenings` - all openings for one traced point
   - `AdditionalOpeningsProof` - complete proof structure

2. **New method** `prove_with_openings()` in `PCSProver`

3. **Helper methods**:
   - `generate_random_indices()` - deterministic PRNG from r
   - `trace_index_through_layers()` - compute index at each layer

4. **Tests**:
   - Unit tests for data structures
   - Integration test for prove_with_openings()
   - Edge case tests (L=0, single layer, etc.)

### Definition of Done
- [ ] New method generates correct number of unique indices
- [ ] Each point traced through all layers correctly
- [ ] Merkle proofs collected for each opening
- [ ] All tests pass: `cargo test -p binius-spartan-prover`
- [ ] No clippy warnings: `cargo clippy -p binius-spartan-prover -- -D warnings`
- [ ] Code formatted: `cargo +nightly fmt`

### Must Have
- Deterministic point generation from r
- Unique indices (no duplicates)
- All layers traced for each point
- Valid Merkle inclusion proofs
- Proper error handling with Result types

### Must NOT Have (Guardrails)
- Changes to existing `prove()` method
- Changes to FRIFoldProver or FRIQueryProver internals
- Verifier modifications (out of scope)
- New dependencies (use existing crypto primitives)
- Performance optimizations (use existing methods as-is)
- `unwrap()` in library code

---

## Verification Strategy

### Test Infrastructure Assessment
**Infrastructure exists**: YES - Rust test framework via `cargo test`
**User wants tests**: YES (Tests after implementation)
**Framework**: Built-in Rust test framework

### Test Strategy
Each TODO includes test verification:

**For Library/Module changes** (using cargo test):
```bash
# Agent runs:
cargo test -p binius-spartan-prover prove_with_openings
# Assert: All tests pass

cargo test -p binius-spartan-prover layer_opening
# Assert: Unit tests for data structures pass

cargo clippy -p binius-spartan-prover -- -D warnings
# Assert: No warnings
```

**Evidence to Capture:**
- [ ] Test output showing all tests pass
- [ ] Clippy output showing no warnings
- [ ] Documentation test output

---

## Execution Strategy

### Sequential Execution (No Parallelization)
This is a single cohesive feature that builds on itself:
1. First design data structures
2. Then implement point generation
3. Then implement layer tracing
4. Then integrate with FRIQueryProver
5. Finally add tests

### Dependency Matrix
| Task | Depends On | Blocks | Can Parallelize With |
|------|------------|--------|---------------------|
| 1 (Data structures) | None | 2, 3, 4, 5 | None |
| 2 (Point generation) | 1 | 4 | 3 |
| 3 (Layer tracing) | 1 | 4 | 2 |
| 4 (Integration) | 1, 2, 3 | 5 | None |
| 5 (Tests) | 1, 2, 3, 4 | None | None |

---

## TODOs

### Task 1: Define Data Structures

**What to do**:
- Add `LayerOpening` struct to `crates/spartan-prover/src/pcs.rs`
- Add `TracedPointOpenings` struct
- Add `AdditionalOpeningsProof` struct
- Implement basic methods (new, getters)
- Add doc comments with examples

**Must NOT do**:
- Add serialization support (out of scope)
- Add complex validation logic
- Modify existing structs

**Recommended Agent Profile**:
- **Category**: `quick`
  - Reason: Simple struct definitions with basic methods
- **Skills**: []
  - No special skills needed for struct definitions

**Parallelization**:
- **Can Run In Parallel**: NO
- **Parallel Group**: Sequential
- **Blocks**: Tasks 2, 3, 4, 5
- **Blocked By**: None (can start immediately)

**References**:
- Pattern: Look at existing proof structures in `crates/iop/src/fri/proof.rs`
- Type: `MerkleProof` type from `crates/iop/src/merkle_tree/scheme.rs`
- Field: `F` type parameter used throughout PCS

**Acceptance Criteria**:
- [ ] All three structs defined with proper fields
- [ ] Doc comments include usage examples
- [ ] Basic constructor methods implemented
- [ ] `cargo check -p binius-spartan-prover` passes

**Commit**: YES
- Message: `feat(spartan-prover): add data structures for additional openings proof`
- Files: `crates/spartan-prover/src/pcs.rs`
- Pre-commit: `cargo check -p binius-spartan-prover`

---

### Task 2: Implement Random Point Generation

**What to do**:
- Implement helper function `generate_random_indices(r, l, max_index) -> Vec<usize>`
- Use deterministic PRNG seeded with r
- Ensure unique indices (sample without replacement)
- Handle case when l > max_index (return all indices)
- Add unit tests

**Must NOT do**:
- Use external PRNG libraries (use existing crypto primitives)
- Allow duplicate indices
- Panic on invalid input (return Result)

**Recommended Agent Profile**:
- **Category**: `unspecified-low`
  - Reason: Algorithm implementation with clear requirements
- **Skills**: []
  - Standard Rust implementation

**Parallelization**:
- **Can Run In Parallel**: YES
- **Parallel Group**: Wave 1 (with Task 3)
- **Blocks**: Task 4
- **Blocked By**: Task 1

**References**:
- Pattern: Look at transcript challenge generation in `crates/iop/src/transcript/`
- External: ChaCha20Rng from `rand_chacha` (if available in workspace)
- Alternative: Use transcript's challenge_bytes if available

**Acceptance Criteria**:
- [ ] Function generates exactly l unique indices (or max_index if l > max_index)
- [ ] Same r produces same indices (deterministic)
- [ ] All indices in valid range [0, max_index)
- [ ] Unit tests pass: `cargo test -p binius-spartan-prover random_indices`
- [ ] Edge case: l=0 returns empty vec
- [ ] Edge case: l > max_index returns all indices

**Commit**: YES
- Message: `feat(spartan-prover): implement deterministic random point generation`
- Files: `crates/spartan-prover/src/pcs.rs`
- Pre-commit: `cargo test -p binius-spartan-prover random_indices`

---

### Task 3: Implement Layer Tracing Logic

**What to do**:
- Implement helper function `trace_index_through_layers(index, fold_arities) -> Vec<(usize, usize)>`
- Input: original index and fold_arities from FRIParams
- Output: vector of (layer_depth, index_at_layer) pairs
- Compute index at each layer using fold_arities
- Add unit tests

**Must NOT do**:
- Modify FRIFoldProver internals
- Assume specific fold_arities structure
- Panic on edge cases

**Recommended Agent Profile**:
- **Category**: `unspecified-low`
  - Reason: Mathematical algorithm with clear specification
- **Skills**: []
  - Standard Rust implementation

**Parallelization**:
- **Can Run In Parallel**: YES
- **Parallel Group**: Wave 1 (with Task 2)
- **Blocks**: Task 4
- **Blocked By**: Task 1

**References**:
- Pattern: Look at `fold_arities()` usage in `crates/iop-prover/src/fri/fold.rs`
- Algorithm: For layer i, index = original_index / product(fold_arities[0..i])
- Test: Verify against existing FRI query logic

**Acceptance Criteria**:
- [ ] Function returns correct (layer, index) pairs for all layers
- [ ] Layer 0 index equals original index
- [ ] Final layer index is correct
- [ ] Unit tests pass: `cargo test -p binius-spartan-prover trace_index`
- [ ] Edge case: single layer (no folding) returns vec with just (0, index)

**Commit**: YES
- Message: `feat(spartan-prover): implement layer tracing for FRI indices`
- Files: `crates/spartan-prover/src/pcs.rs`
- Pre-commit: `cargo test -p binius-spartan-prover trace_index`

---

### Task 4: Implement prove_with_openings Method (CORRECTED)

**CRITICAL IMPLEMENTATION DETAIL**: 
The method must NOT call the existing `prove()` method because we need to capture the Merkle authentication paths BEFORE the FRIFoldProver is consumed. Instead, we need to replicate the BaseFold proof logic while capturing the openings.

**CRITICAL: EXISTING prove() FUNCTION MUST REMAIN UNCHANGED**
- The existing `prove()` method at lines ~306-345 must NOT be modified
- It should continue to use `BaseFoldProver::new()` and `basefold_prover.prove(transcript)`
- `prove_with_openings()` is a NEW method that replicates the logic manually

**What to do**:
- Add `prove_with_openings()` method to `PCSProver` impl (NEW method, do NOT modify existing prove())
- Signature similar to `prove()` but with additional `r: F` and `l: usize` parameters
- Returns `Result<AdditionalOpeningsProof, Error>`
- Implementation steps:
  1. Generate L random indices from r
  2. Create FRIFoldProver and BivariateProductSumcheckProver manually
  3. Execute sumcheck + FRI folding rounds (replicate BaseFoldProver::prove logic):
     - For each of n_vars rounds:
       - Execute sumcheck round, write coefficients to transcript
       - Execute FRI fold round, write commitment to transcript if present
       - Sample challenge from transcript
       - Fold sumcheck and receive challenge in FRI folder
     - Execute final FRI fold round
  4. Finalize FRI folder to get FRIQueryProver
  5. Write terminate codeword and standard FRI test queries to transcript
  6. For each random index:
     - Trace through layers using fold_arities
     - For each layer, call query_prover.prove_query() to generate Merkle proof
     - Collect values from original codeword for layer 0
     - Store Merkle proof bytes from transcript
  7. Return AdditionalOpeningsProof with actual data (NOT empty vectors)

**Must NOT do**:
- Modify existing `prove()` method in any way
- Call existing `prove()` method from `prove_with_openings()` (it consumes the FRIFoldProver)
- Use BaseFoldProver in `prove_with_openings()` (it consumes the FRIFoldProver)
- Return mock/empty data in the openings
- Use unwrap() - use proper error handling
- Change FRIFoldProver or FRIQueryProver

**Key Implementation Details**:
- Import `BivariateProductSumcheckProver` from `binius_ip_prover::sumcheck::bivariate_product`
- Import `FoldRoundOutput` from `binius_prover::fri`
- The sumcheck prover is created with `[multilinear, eq_ind]` and `evaluation_claim`
- Use `fri_folder.execute_fold_round()` and `fri_folder.receive_challenge(challenge)`
- Use `query_prover.prove_query(index, &mut advice)` to generate Merkle proofs
- For layer 0 values: `committed_codeword.chunk(log_coset_size, coset_index)`

**CRITICAL FIX NEEDED - Layer Opening Generation**:
The current implementation calls `prove_query()` for EACH layer separately, which is inefficient and wrong. `prove_query()` generates proofs for ALL layers in one call. 

**Correct approach**:
1. For each `original_index`, call `prove_query(original_index, ...)` ONCE
2. This generates a FULL proof containing all layers' Merkle proofs
3. Store this full proof in EACH `LayerOpening` for that traced point
4. Each layer opening represents one step in the full proof path

**Why this works**:
- `prove_query` internally iterates through all layers (original + folded)
- For each layer, it calls `prove_coset_opening` which writes values + Merkle proof
- The proof bytes contain concatenated: [layer0_values, layer0_proof, layer1_values, layer1_proof, ...]
- Each `LayerOpening` at depth N represents the Nth step in this proof path
- All layers share the same full proof bytes (the complete authentication path)

**Alternative (if per-layer proofs are required)**:
Would need access to `query_prover.round_committed` (currently `pub(super)`) to manually call `prove_coset_opening` for each layer with the appropriate codeword and committed data.

**Recommended Agent Profile**:
- **Category**: `unspecified-high`
  - Reason: Complex integration with existing FRI machinery
- **Skills**: []
  - Requires understanding of FRI protocol

**Parallelization**:
- **Can Run In Parallel**: NO
- **Parallel Group**: Sequential
- **Blocks**: Task 5
- **Blocked By**: Tasks 1, 2, 3

**References**:
- Pattern: Replicate `BaseFoldProver::prove()` logic from `crates/iop-prover/src/basefold.rs`
- API: `FRIFoldProver::new()`, `execute_fold_round()`, `finalize()`, `receive_challenge()`
- API: `FRIQueryProver::prove_query()` in `crates/iop-prover/src/fri/query.rs`
- API: `BivariateProductSumcheckProver::new()`, `execute()`, `fold()`
- Type: `FRIParams::fold_arities()` for layer information

**Acceptance Criteria**:
- [ ] Method signature matches specification
- [ ] **EXISTING prove() function is completely unchanged**
- [ ] `prove_with_openings()` replicates BaseFold prove logic (does NOT call existing prove())
- [ ] Generates correct number of traced points
- [ ] Each point has openings for all layers
- [ ] Merkle proofs are valid (non-empty, can be verified)
- [ ] Values are populated for all layers
- [ ] Returns error for invalid inputs (l=0, etc.)
- [ ] `cargo test -p binius-spartan-prover` passes
- [ ] No mock/empty data in returned structures
- [ ] Both `prove()` and `prove_with_openings()` tests pass

**Commit**: YES
- Message: `feat(spartan-prover): add prove_with_openings with full Merkle proofs`
- Files: `crates/spartan-prover/src/pcs.rs`
- Pre-commit: `cargo test -p binius-spartan-prover`

---

### Task 5: Add Tests (WITH VERIFICATION STEP)

**What to do**:
- Add unit tests for data structures
- Add unit tests for random point generation
- Add unit tests for layer tracing
- Add integration test for prove_with_openings()
- **Add verification step to validate Merkle proofs are non-empty and valid**
- Test edge cases: L=0, single layer, L > codeword length
- Test determinism: same r produces same results

**Verification Step Implementation**:
Modify `test_prove_with_openings_basic` to include verification:
1. After calling `prove_with_openings()`, iterate through `traced_points`
2. For each `TracedPointOpenings`, iterate through `layer_openings`
3. Assert that:
   - `layer_openings` is not empty
   - `proof_bytes` is not empty (Merkle proof exists)
   - For layer 0: `values` is not empty
4. Optional: Use `merkle_prover.scheme().verify_opening()` to cryptographically verify proofs

**Must NOT do**:
- Add property-based tests (out of scope)
- Add benchmarks (out of scope)
- Modify existing tests

**Recommended Agent Profile**:
- **Category**: `unspecified-low`
  - Reason: Test writing with clear requirements
- **Skills**: []
  - Standard Rust testing

**Parallelization**:
- **Can Run In Parallel**: NO
- **Parallel Group**: Sequential
- **Blocks**: None (final task)
- **Blocked By**: Tasks 1, 2, 3, 4

**References**:
- Pattern: Look at existing tests in `crates/spartan-prover/src/pcs.rs` or nearby test files
- Test data: Use small field elements and simple polynomials
- Mock: Can use existing test fixtures if available
- API: `MerkleTreeScheme::verify_opening()` for cryptographic verification

**Acceptance Criteria**:
- [ ] Unit tests for all data structures pass
- [ ] Random point generation tests pass
- [ ] Layer tracing tests pass
- [ ] Integration test for prove_with_openings passes
- [ ] **Verification step confirms Merkle proofs are non-empty and valid**
- [ ] Edge case tests pass
- [ ] All tests: `cargo test -p binius-spartan-prover` passes
- [ ] No test failures

**Commit**: YES
- Message: `test(spartan-prover): add tests with Merkle proof verification`
- Files: `crates/spartan-prover/src/pcs.rs` (tests module)
- Pre-commit: `cargo test -p binius-spartan-prover`

---

## Commit Strategy

| After Task | Message | Files | Verification |
|------------|---------|-------|--------------|
| 1 | `feat(spartan-prover): add data structures for additional openings proof` | `crates/spartan-prover/src/pcs.rs` | `cargo check` |
| 2 | `feat(spartan-prover): implement deterministic random point generation` | `crates/spartan-prover/src/pcs.rs` | `cargo test random_indices` |
| 3 | `feat(spartan-prover): implement layer tracing for FRI indices` | `crates/spartan-prover/src/pcs.rs` | `cargo test trace_index` |
| 4 | `feat(spartan-prover): add prove_with_openings method for additional FRI queries` | `crates/spartan-prover/src/pcs.rs` | `cargo check` |
| 5 | `test(spartan-prover): add tests for prove_with_openings and helpers` | `crates/spartan-prover/src/pcs.rs` | `cargo test` |

---

## Success Criteria

### Verification Commands
```bash
# All tests pass
cargo test -p binius-spartan-prover

# No clippy warnings
cargo clippy -p binius-spartan-prover -- -D warnings

# Code is formatted
cargo +nightly fmt -- --check

# Documentation builds
cargo doc -p binius-spartan-prover --no-deps
```

### Final Checklist
- [ ] All "Must Have" items implemented
- [ ] All "Must NOT Have" guardrails respected
- [ ] All tests pass
- [ ] No clippy warnings
- [ ] Code formatted
- [ ] Documentation complete with examples
- [ ] Existing prove() method unchanged
- [ ] No breaking changes to public APIs
