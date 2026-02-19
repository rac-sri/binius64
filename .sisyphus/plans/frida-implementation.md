# FRIDA p+1 Query Phase Implementation Plan

## Objective

Implement FRIDA-style p+1 query generation for FRI-based DAS (Data Availability Sampling) security in Binius64. This prevents the proximity gap attack where a prover strategically places errors at positions unlikely to be queried.

## Background

**The Problem:**
- FRI is a proximity test, not an exact validity test
- A prover can commit to a vector "close" to a valid codeword but with strategic errors
- Standard Fiat-Shamir derives queries deterministically from transcript
- Prover can predict which positions will be queried and avoid placing errors there
- Result: Verification passes even though data has errors (breaks DAS guarantees)

**FRIDA's Solution:**
- Prover generates p+1 queries using prover-controlled randomness (NOT transcript-derived)
- Prover cannot predict queries when committing, forcing honest commitment
- +1 provides security margin against manipulation
- Queries written to transcript for binding (can't change after generation)

## Requirements

### Functional Requirements
1. Generate p+1 query indices using prover-controlled RNG (not Fiat-Shamir)
2. Create FRIDA FRI prover wrapper around existing `FRIFoldProver`
3. Create FRIDA FRI verifier wrapper around existing `FRIQueryVerifier`
4. Reuse existing `prove_query()` and `verify_query()` functions unchanged
5. Add comprehensive tests for FRIDA functionality

### Non-Functional Requirements
- Do NOT modify any existing files
- Create new file: `crates/iop-prover/src/fri/frida.rs`
- All existing functions (`prove_query`, `verify_query`, etc.) reused as-is
- Code must compile and tests must pass

## Implementation Details

### New File: `crates/iop-prover/src/fri/frida.rs`

#### Function 1: `generate_frida_queries()`

```rust
pub fn generate_frida_queries<F, R>(params: &FRIParams<F>, prover_rng: &mut R) -> Vec<u32>
where
    F: BinaryField,
    R: RngCore + CryptoRng,
```

**Purpose:** Generate p+1 query indices using prover-controlled randomness

**Algorithm:**
1. Get p = `params.n_test_queries()`
2. Set num_queries = p + 1 (FRIDA's +1)
3. For each query:
   - Sample from prover_rng (NOT transcript)
   - Map to valid index range [0, 2^index_bits)
4. Sort queries for canonical representation
5. Return sorted vector

**Key Points:**
- Uses `prover_rng.next_u64()` NOT `transcript.sample_bits()`
- Prover cannot predict these when committing
- Sorting ensures deterministic verification

#### Function 2: `FridaFRIProver::finish()`

```rust
pub fn finish<R, Challenger_>(
    self,
    transcript: &mut ProverTranscript<Challenger_>,
    prover_rng: &mut R,
) -> Result<(), Error>
```

**Purpose:** Finish FRI proof with FRIDA-style p+1 prover-generated queries

**Algorithm:**
1. Finalize FRI folding: `self.fri_folder.finalize()`
2. Write terminal codeword to advice
3. Write VCS layers to advice
4. Generate p+1 FRIDA queries: `generate_frida_queries(params, prover_rng)`
5. Write queries to transcript (BINDING - prover can't change)
6. For each query index:
   - Call existing `query_prover.prove_query(index, advice)`
   - REUSE existing function - NO CHANGES

**Key Points:**
- Wraps existing `FRIFoldProver`
- Delegates to `prove_query()` for actual proof generation
- Only difference is WHO generates queries (prover RNG vs transcript)

#### Function 3: `FridaFRIVerifier::verify()`

```rust
pub fn verify<Challenger_, NTT>(
    &self,
    transcript: &mut VerifierTranscript<Challenger_>,
    ntt: &NTT,
) -> Result<F, Error>
```

**Purpose:** Verify FRIDA-style FRI proof

**Algorithm:**
1. Read terminal codeword from advice
2. Verify terminal codeword is valid
3. Read and verify VCS layers
4. Read p+1 prover-generated queries from transcript:
   `transcript.message().read_vec(n_test_queries + 1)`
5. For each query index:
   - Call existing `self.inner.verify_query(...)`
   - REUSE existing function - NO CHANGES

**Key Points:**
- Wraps existing `FRIQueryVerifier`
- Delegates to `verify_query()` for actual verification
- Reads queries from transcript (prover-generated) instead of deriving

### Supporting Structures

#### `FridaFRIProver`

Wrapper around `FRIFoldProver` that provides FRIDA-compliant query generation.

**Fields:**
- `fri_folder: FRIFoldProver` - underlying FRI folder
- `_marker: PhantomData<MerkleScheme>` - type marker

**Methods:**
- `new(fri_folder)` - constructor
- `folder()` / `folder_mut()` - access underlying folder
- `execute_fold_round()` - delegate to folder
- `fold(challenge)` - delegate to folder
- `receive_challenge(challenge)` - delegate to folder
- `n_rounds()` / `current_round()` - delegate to folder
- `finish(transcript, prover_rng)` - FRIDA finish with p+1 queries

#### `FridaFRIVerifier`

Wrapper around `FRIQueryVerifier` that verifies FRIDA-style proofs.

**Fields:**
- `inner: FRIQueryVerifier` - underlying verifier

**Methods:**
- `new(params, vcs, codeword_commitment, round_commitments, fold_challenges)` - constructor
- `verify(transcript, ntt)` - verify with FRIDA p+1 queries

### Helper Function: `frida_sumcheck_fri_consistency()`

```rust
pub fn frida_sumcheck_fri_consistency<F: Field>(
    final_fri_value: F,
    final_sumcheck_value: F,
    evaluation_point: &[F],
    challenges: Vec<F>,
) -> bool
```

**Purpose:** Verify FRI and sumcheck components are consistent

**Algorithm:**
1. Check challenges.len() == evaluation_point.len()
2. Compute eq_ind evaluations
3. Compute expected FRI value from sumcheck
4. Compare with actual FRI value

## Tests to Implement

### Unit Tests

1. **`test_generate_frida_queries_basic`**
   - Generate queries with known seed
   - Verify count is p+1
   - Verify all queries in valid range

2. **`test_generate_frida_queries_sorted`**
   - Generate multiple sets of queries
   - Verify all are sorted

3. **`test_generate_frida_queries_deterministic_seed`**
   - Generate with same seed twice
   - Verify identical output

4. **`test_generate_frida_queries_different_seeds`**
   - Generate with different seeds
   - Verify different output

5. **`test_frida_queries_coverage`**
   - Generate many queries
   - Verify most are unique (high coverage)

6. **`test_frida_prover_creation`**
   - Create FridaFRIProver
   - Verify it wraps FRI folder correctly

7. **`test_frida_consistency_helper`**
   - Test consistency check with valid values

8. **`test_frida_consistency_mismatched_length`**
   - Test consistency check fails with mismatched lengths

### Integration Tests

9. **`test_frida_prove_verify_roundtrip`**
   - Full prove/verify cycle with FRIDA
   - Generate random message
   - Commit with standard FRI
   - Finish with FRIDA prover
   - Verify with FRIDA verifier
   - Assert success

10. **`test_frida_vs_standard_different_queries`**
    - Generate proof with standard FRI
    - Generate proof with FRIDA FRI
    - Verify queries are different
    - Both should verify successfully

## File Structure

```
crates/iop-prover/src/fri/
├── mod.rs           (existing - add pub mod frida)
├── frida.rs         (NEW FILE - this implementation)
├── fold.rs          (existing - unchanged)
├── query.rs         (existing - unchanged)
├── commit.rs        (existing - unchanged)
└── tests.rs         (existing - add FRIDA tests)
```

## Dependencies

The new file uses these existing Binius64 crates:
- `binius_field` - Field types
- `binius_iop` - FRI params and verifier
- `binius_math` - NTT, Reed-Solomon, field buffers
- `binius_transcript` - Transcript handling
- `binius_utils` - Serialization
- `rand` - RNG traits

## Success Criteria

1. ✅ New file `crates/iop-prover/src/fri/frida.rs` created
2. ✅ `generate_frida_queries()` implemented correctly
3. ✅ `FridaFRIProver` with `finish()` method implemented
4. ✅ `FridaFRIVerifier` with `verify()` method implemented
5. ✅ All unit tests pass
6. ✅ Integration test passes (prove/verify roundtrip)
7. ✅ No existing files modified
8. ✅ Code compiles without warnings
9. ✅ Existing `prove_query()` and `verify_query()` reused unchanged

## Execution Steps

1. Create new file `crates/iop-prover/src/fri/frida.rs`
2. Add module declaration to `crates/iop-prover/src/fri/mod.rs`
3. Implement `generate_frida_queries()`
4. Implement `FridaFRIProver` struct and methods
5. Implement `FridaFRIVerifier` struct and methods
6. Implement helper `frida_sumcheck_fri_consistency()`
7. Add all unit tests
8. Add integration test
9. Run tests: `cargo test -p binius-iop-prover fri::frida`
10. Verify compilation: `cargo build -p binius-iop-prover`

## Risks and Mitigations

| Risk | Mitigation |
|------|-----------|
| Compilation errors | Test incrementally, fix type mismatches |
| Test failures | Check RNG determinism, index bounds |
| Import errors | Verify all use statements correct |
| Trait bound issues | Add explicit trait bounds where needed |

## Notes

- DO NOT modify `prove_query()` in `query.rs`
- DO NOT modify `verify_query()` in `verify.rs`
- DO NOT modify `finish_proof()` in `fold.rs`
- DO NOT modify `verify()` in `verify.rs`
- All existing functions are reused as-is
- Only query generation mechanism changes (prover-controlled vs transcript-derived)
