# Full Formal FRIDA Erasure Code Commitment Implementation Plan

## Objective

Implement the complete formal FRIDA erasure code commitment algorithm with full security guarantees, matching the specification from the FRIDA paper. This provides cryptographic binding of queries to commitments, deterministic query derivation, and strict verification enforcement.

## Background

The current FRIDA-inspired implementation lacks critical security properties:
- No state chain binding
- No deterministic query derivation (QSelect)
- No multi-layer authentication (OpenAuth)
- No strict query enforcement (CheckAuth)

This plan implements the FULL formal FRIDA algorithm with all security guarantees.

## Formal FRIDA Algorithm Components

### 1. State Chain (hst)

**Structure:**
```
hst_{-1} = 1^ε (initial state)
hst_0 = H^↑(root_0, hst_{-1}, 0)  // binds root_0
hst_1 = H^↑(root_1, hst_0, 1)    // binds root_1 + chain
...
hst_r = H^↑(root_r, hst_{r-1}, r) // binds root_r + full chain
```

**Security Property:** Changing any root_i requires changing all subsequent hst_j

### 2. Challenge Derivation

**Algorithm:**
```
ϑ_1 = H(hst_0)      // Challenge from state
ϑ_2 = H(hst_1)      // Challenge from updated state
...
ϑ_r = H(hst_{r-1})  // Challenge from chain
```

**Security Property:** Challenges cryptographically bound to commitment chain

### 3. Layer Commitments

**Structure:**
```
root_0 = RootH(c)              // Initial codeword
ω_1 = P(c, ϑ_1)                // Folded once
root_1 = RootH(ω_1)            // Commit to folded
ω_2 = P(c, ϑ_1, ϑ_2)           // Folded twice
root_2 = RootH(ω_2)            // Commit again
...
ω_r = P(c, ϑ_1, ..., ϑ_r)    // Fully folded
root_r = RootH(ω_r)            // Final commitment
```

**Security Property:** Each FRI round produces SEPARATE commitment

### 4. QSelect - Query Selection

**Algorithm:**
```
QSelect: (ϑ_1, ..., ϑ_r, ϑ_{r+1}) → j

j = hash(ϑ_1 || ϑ_2 || ... || ϑ_r || ϑ_{r+1}) mod |C|
```

**Security Property:** Query position deterministically derived from ALL challenges

### 5. OpenAuth - Multi-Layer Authentication

**Structure:**
```
OpenAuth(c, (ω_i)_{i=1}^r, (ϑ_i)_{i=1}^r, ϑ_{r+1}) → auth

auth = {
  j = QSelect(ϑ_1, ..., ϑ_r, ϑ_{r+1})  // Query position
  path_0,j = MerklePath(c, j)           // Path in initial codeword
  for i ∈ [r]:
    j_i = fold_index(j, ϑ_1, ..., ϑ_i)  // Folded position
    path_i,j_i = MerklePath(ω_i, j_i)   // Path in folded layer
}
```

**Security Property:** Authenticates value at position j across ALL layers

### 6. CheckAuth - Verification with Enforcement

**Algorithm:**
```
CheckAuth((root_i)_{i=0}^r, (ϑ_i)_{i=1}^r, ϑ_{r+1}, auth) → {0, 1}

1. Reconstruct state chain:
   hst_{-1} = 1^ε
   for i ∈ [0, r]:
     hst_i = H^↑(root_i, hst_{i-1}, i)

2. Verify challenges:
   for i ∈ [1, r]:
     assert ϑ_i == H(hst_{i-1})

3. Verify ϑ_{r+1} derivation:
   assert ϑ_{r+1} matches expected (from state or external)

4. Parse auth = ((path_{i,j'})_{j'∈Q_i})_{i=0}^r

5. Verify paths authenticate to roots:
   for i ∈ [0, r]:
     assert VerifyMerklePath(path_{i,j}, root_i) == 1

6. ENFORCE query constraint:
   j = QSelect(ϑ_1, ..., ϑ_r, ϑ_{r+1})
   assert j ∈ Q_0  // Position MUST be in allowed set

7. ENFORCE value binding:
   value_0 = ValueFromPath(path_{0,j})
   for i ∈ [1, r]:
     value_i = ValueFromPath(path_{i,j_i})
     assert value_i == Fold(value_{i-1}, ϑ_i)

8. Return 1 if all checks pass, 0 otherwise
```

**Security Properties:**
- Verifier can ONLY query positions in Q (enforced)
- Verifier MUST query ALL positions in Q (batch verification)
- Values MUST be consistent across all layers (folding check)
- Any deviation = immediate failure

## Implementation Structure

### New File: `crates/iop-prover/src/fri/frida_full.rs`

**Core Types:**

```rust
/// FRIDA state chain that binds all commitments together
pub struct FridaState<F: Field> {
    /// State values hst_{-1}, hst_0, ..., hst_r
    states: Vec<F>,
    /// Challenges ϑ_1, ..., ϑ_r derived from states
    challenges: Vec<F>,
    /// Merkle roots root_0, root_1, ..., root_r
    roots: Vec<Digest>,
}

/// FRIDA erasure code commitment
pub struct FridaCommitment<F: Field, D: Clone> {
    /// State chain with all challenges and roots
    state: FridaState<F>,
    /// Query challenges ϑ^{(l)}_{r+1} for l ∈ [L]
    query_challenges: Vec<F>,
    /// Multi-layer authentications auth^{(l)} for each query
    auths: Vec<FridaAuth<F, D>>,
}

/// Multi-layer authentication for a single query
pub struct FridaAuth<F: Field, D: Clone> {
    /// Query challenge ϑ_{r+1}
    query_challenge: F,
    /// Query position j = QSelect(...)
    query_position: usize,
    /// Merkle paths for each layer
    /// path[i] = path in layer i at folded position
    paths: Vec<Vec<D>>, // paths[0] for layer 0, paths[1] for layer 1, etc.
}

/// FRIDA prover with full commitment scheme
pub struct FridaProver<'a, F, P, NTT, MerkleProver, MerkleScheme, H>
where
    F: BinaryField,
    P: PackedField<Scalar = F>,
    NTT: AdditiveNTT<Field = F> + Sync,
    MerkleProver: MerkleTreeProver<F, Scheme = MerkleScheme>,
    MerkleScheme: MerkleTreeScheme<F>,
    H: PseudoCompressionFunction<Digest, 2>,
{
    /// Underlying FRI folder
    fri_folder: FRIFoldProver<'a, F, P, NTT, MerkleProver>,
    /// Hash function for state chain H^↑
    state_hasher: H,
    /// Challenge hasher H
    challenge_hasher: H,
    /// Current state chain being built
    state_chain: Option<FridaState<F>>,
}

/// FRIDA verifier with full enforcement
pub struct FridaVerifier<'a, F, VCS, H>
where
    F: BinaryField,
    VCS: MerkleTreeScheme<F>,
    H: PseudoCompressionFunction<VCS::Digest, 2>,
{
    /// FRI parameters
    params: &'a FRIParams<F>,
    /// Merkle tree scheme for verification
    vcs: &'a VCS,
    /// Hash function for state chain
    state_hasher: H,
    /// Challenge hasher
    challenge_hasher: H,
}
```

**Core Functions:**

```rust
/// Derive challenge from state
/// ϑ_i = H(hst_{i-1})
pub fn derive_challenge<F: Field, H: PseudoCompressionFunction<F, 2>>(
    hst_prev: F,
    hasher: &H,
) -> F {
    // Hash the previous state value
    // In practice: serialize F, hash, deserialize
    todo!("Implement challenge derivation")
}

/// Update state chain
/// hst_i = H^↑(root_i, hst_{i-1}, i)
pub fn update_state<F: Field, H: PseudoCompressionFunction<Digest, 2>>(
    root_i: Digest,
    hst_prev: F,
    index: usize,
    hasher: &H,
) -> F {
    // Combine root, previous state, and index
    // In practice: hash(root || hst_prev || index)
    todo!("Implement state update")
}

/// QSelect: Deterministic query position derivation
/// j = hash(ϑ_1 || ... || ϑ_r || ϑ_{r+1}) mod |C|
pub fn qselect<F: Field>(
    challenges: &[F],
    query_challenge: F,
    codeword_len: usize,
) -> usize {
    // Combine all challenges and query challenge
    // Hash to get deterministic index
    // Modulo by codeword length
    todo!("Implement QSelect")
}

/// OpenAuth: Generate multi-layer authentication
/// auth = OpenAuth(c, (ω_i), (ϑ_i), ϑ_{r+1})
pub fn open_auth<F: Field, D: Clone>(
    codeword: &[F],
    layers: &[Vec<F>], // ω_1, ..., ω_r
    challenges: &[F],  // ϑ_1, ..., ϑ_r
    query_challenge: F, // ϑ_{r+1}
    merkle_prover: &impl MerkleTreeProver<F>,
) -> FridaAuth<F, D> {
    // 1. Derive query position
    // 2. Get Merkle path in initial codeword
    // 3. For each layer, compute folded position and get path
    // 4. Return auth structure
    todo!("Implement OpenAuth")
}

/// CheckAuth: Verify with strict enforcement
/// Returns 1 if all checks pass, 0 otherwise
pub fn check_auth<F: Field, D: Clone, VCS: MerkleTreeScheme<F, Digest = D>>(
    roots: &[D],              // (root_i)_{i=0}^r
    challenges: &[F],        // (ϑ_i)_{i=1}^r
    query_challenge: F,      // ϑ_{r+1}
    auth: &FridaAuth<F, D>,
    vcs: &VCS,
    state_hasher: &impl PseudoCompressionFunction<D, 2>,
    challenge_hasher: &impl PseudoCompressionFunction<F, 2>,
) -> bool {
    // 1. Reconstruct state chain
    // 2. Verify challenges match derived values
    // 3. Verify query_challenge derivation
    // 4. Parse auth paths
    // 5. Verify all paths authenticate to roots
    // 6. ENFORCE: j ∈ Q_0
    // 7. ENFORCE: values fold consistently
    // 8. Return result
    todo!("Implement CheckAuth")
}
```

## Implementation Steps

### Step 1: Core Infrastructure

**New File: `crates/iop-prover/src/fri/frida_full.rs`**

```rust
// Module structure:
pub mod state;      // State chain management
pub mod qselect;    // Query selection
pub mod auth;       // OpenAuth and CheckAuth
pub mod prover;     // FridaProver
pub mod verifier;   // FridaVerifier
pub mod types;      // Core types (FridaState, FridaCommitment, etc.)
```

**Implementation Order:**
1. Define all types (FridaState, FridaCommitment, FridaAuth)
2. Implement state chain operations
3. Implement QSelect
4. Implement OpenAuth
5. Implement CheckAuth
6. Implement FridaProver
7. Implement FridaVerifier
8. Add comprehensive tests

### Step 2: State Chain Module

```rust
// crates/iop-prover/src/fri/frida_full/state.rs

pub struct StateChain<F: Field> {
    initial_state: F,
    states: Vec<F>,
    challenges: Vec<F>,
}

impl<F: Field> StateChain<F> {
    /// Create new state chain with initial value
    pub fn new(initial: F) -> Self {
        Self {
            initial_state: initial,
            states: vec![initial],
            challenges: Vec::new(),
        }
    }
    
    /// Add new commitment and update chain
    /// hst_i = H^↑(root_i, hst_{i-1}, i)
    pub fn add_commitment<D: Clone>(
        &mut self,
        root: D,
        index: usize,
        hasher: &impl PseudoCompressionFunction<D, 2>,
    ) {
        // Compute new state
        let hst_prev = self.states.last().unwrap();
        let hst_new = self.compute_state(root, *hst_prev, index, hasher);
        
        // Derive challenge
        let challenge = self.derive_challenge(hst_new);
        
        self.states.push(hst_new);
        self.challenges.push(challenge);
    }
    
    /// Get challenge at index i (1-indexed)
    pub fn challenge(&self, i: usize) -> Option<F> {
        self.challenges.get(i - 1).copied()
    }
    
    /// Get state at index i
    pub fn state(&self, i: isize) -> Option<F> {
        // i = -1 returns initial_state
        // i = 0, 1, ... returns states[i + 1]
        if i == -1 {
            Some(self.initial_state)
        } else {
            self.states.get((i + 1) as usize).copied()
        }
    }
}
```

### Step 3: QSelect Module

```rust
// crates/iop-prover/src/fri/frida_full/qselect.rs

use binius_field::Field;
use binius_hash::PseudoCompressionFunction;

/// Deterministically derive query position from challenges
pub fn qselect<F: Field>(
    challenges: &[F],
    query_challenge: F,
    codeword_len: usize,
    hasher: &impl PseudoCompressionFunction<F, 2>,
) -> usize {
    // Combine all challenges
    let mut combined = Vec::with_capacity(challenges.len() + 1);
    combined.extend_from_slice(challenges);
    combined.push(query_challenge);
    
    // Hash to get deterministic value
    let hash_result = hash_field_elements(&combined, hasher);
    
    // Convert to index
    let index = field_to_index(hash_result, codeword_len);
    
    index
}

/// Hash a slice of field elements
fn hash_field_elements<F: Field, H: PseudoCompressionFunction<F, 2>>(
    elements: &[F],
    hasher: &H,
) -> F {
    // Fold elements using compression function
    // For 2 elements: hasher.compress([a, b])
    // For >2: fold iteratively
    let mut result = elements[0];
    for &elem in &elements[1..] {
        result = hasher.compress([result, elem]);
    }
    result
}

/// Convert field element to index in range [0, len)
fn field_to_index<F: Field>(field: F, len: usize) -> usize {
    // Extract bits from field representation
    // Convert to usize and take modulo
    let bytes = field.to_bytes(); // Need to implement
    let mut index: usize = 0;
    for (i, &byte) in bytes.iter().enumerate() {
        index |= (byte as usize) << (i * 8);
    }
    index % len
}
```

### Step 4: Auth Module (OpenAuth/CheckAuth)

```rust
// crates/iop-prover/src/fri/frida_full/auth.rs

use super::qselect::qselect;
use super::types::FridaAuth;

/// Generate multi-layer authentication
pub fn open_auth<F: Field, D: Clone, P: PackedField<Scalar = F>>(
    codeword: &FieldBuffer<P>,           // c
    layers: &[FieldBuffer<P>],           // ω_1, ..., ω_r
    challenges: &[F],                    // ϑ_1, ..., ϑ_r
    query_challenge: F,                // ϑ_{r+1}
    merkle_prover: &impl MerkleTreeProver<F, Scheme = impl MerkleTreeScheme<F, Digest = D>>,
    merkle_committed: &[impl HasCommittedData<F>],
) -> Result<FridaAuth<F, D>, Error> {
    // 1. Derive query position from challenges
    let codeword_len = 1 << codeword.log_len();
    let query_position = qselect(challenges, query_challenge, codeword_len);
    
    // 2. Get Merkle path in initial codeword
    let path_0 = merkle_prover.prove_opening(
        &merkle_committed[0],
        0, // layer_depth
        query_position,
        &mut transcript.decommitment(),
    )?;
    
    // 3. For each layer, compute folded position and get path
    let mut paths = vec![path_0];
    let mut current_index = query_position;
    
    for (i, (layer, committed)) in layers.iter().zip(&merkle_committed[1..]).enumerate() {
        // Compute folded index
        let arity = challenges[i]; // Simplified - actual folding uses challenge
        current_index = fold_index(current_index, arity);
        
        // Get Merkle path at folded position
        let path_i = merkle_prover.prove_opening(
            committed,
            i + 1, // layer_depth
            current_index,
            &mut transcript.decommitment(),
        )?;
        
        paths.push(path_i);
    }
    
    Ok(FridaAuth {
        query_challenge,
        query_position,
        paths,
    })
}

/// Verify multi-layer authentication with strict enforcement
pub fn check_auth<F: Field, D: Clone, VCS: MerkleTreeScheme<F, Digest = D>>(
    roots: &[D],                          // (root_i)_{i=0}^r
    challenges: &[F],                     // (ϑ_i)_{i=1}^r
    query_challenge: F,                  // ϑ_{r+1}
    auth: &FridaAuth<F, D>,
    vcs: &VCS,
    codeword_len: usize,
) -> Result<bool, Error> {
    // 1. Reconstruct state chain (simplified - full version would recompute)
    
    // 2. Verify query position matches QSelect
    let expected_position = qselect(challenges, query_challenge, codeword_len);
    if auth.query_position != expected_position {
        return Ok(false); // ENFORCE: position must match
    }
    
    // 3. Verify paths authenticate to roots
    for (i, (path, root)) in auth.paths.iter().zip(roots).enumerate() {
        // Compute folded index for this layer
        let index = if i == 0 {
            auth.query_position
        } else {
            fold_index(auth.query_position, &challenges[..i])
        };
        
        // Verify Merkle path
        let valid = vcs.verify_opening(
            index,
            &get_values_from_path(path),
            i, // layer_depth
            roots.len().trailing_zeros() as usize, // tree_depth
            &[root.clone()], // layer_digests (simplified)
            &mut TranscriptReader::new(path),
        )?;
        
        if !valid {
            return Ok(false); // Path doesn't authenticate
        }
    }
    
    // 4. ENFORCE: Verify folding consistency
    // This ensures values at auth.query_position fold correctly through all layers
    
    Ok(true)
}
```

### Step 5: Prover Implementation

```rust
// crates/iop-prover/src/fri/frida_full/prover.rs

impl<'a, F, P, NTT, MerkleProver, MerkleScheme, H> 
    FridaProver<'a, F, P, NTT, MerkleProver, MerkleScheme, H>
where
    F: BinaryField,
    P: PackedField<Scalar = F>,
    NTT: AdditiveNTT<Field = F> + Sync,
    MerkleProver: MerkleTreeProver<F, Scheme = MerkleScheme>,
    MerkleScheme: MerkleTreeScheme<F, Digest: SerializeBytes>,
    H: PseudoCompressionFunction<MerkleScheme::Digest, 2>,
{
    /// Commit to message and initialize FRIDA state
    pub fn commit<Challenger_>(
        &mut self,
        message: FieldSlice<P>,
        transcript: &mut ProverTranscript<Challenger_>,
    ) -> Result<MerkleScheme::Digest, Error>
    where
        Challenger_: Challenger,
    {
        // 1. Encode and commit
        let (commit_output, committed) = fri::commit_interleaved(
            self.fri_folder.params,
            &self.ntt,
            &self.merkle_prover,
            message,
        )?;
        
        // 2. Initialize state chain
        let initial_state = F::ONE; // 1^ε
        let mut state_chain = StateChain::new(initial_state);
        
        // 3. Add root_0 to state
        state_chain.add_commitment(
            commit_output.root.clone(),
            0,
            &self.state_hasher,
        );
        
        self.state_chain = Some(state_chain);
        self.committed.push(committed);
        
        Ok(commit_output.root)
    }
    
    /// Execute fold round with FRIDA state updates
    pub fn execute_fold_round<Challenger_>(
        &mut self,
        transcript: &mut ProverTranscript<Challenger_>,
    ) -> Result<FoldRoundOutput<MerkleScheme::Digest>, Error>
    where
        Challenger_: Challenger,
    {
        // 1. Execute FRI fold round
        let output = self.fri_folder.execute_fold_round()?;
        
        // 2. If commitment produced, update FRIDA state
        if let FoldRoundOutput::Commitment(root) = &output {
            if let Some(state) = &mut self.state_chain {
                let index = state.challenges.len();
                state.add_commitment(
                    root.clone(),
                    index,
                    &self.state_hasher,
                );
            }
        }
        
        Ok(output)
    }
    
    /// Finish with FRIDA authentications
    pub fn finish<Challenger_, R>(
        &mut self,
        transcript: &mut ProverTranscript<Challenger_>,
        prover_rng: &mut R,
        num_queries: usize, // L queries
    ) -> Result<FridaCommitment<F, MerkleScheme::Digest>, Error>
    where
        Challenger_: Challenger,
        R: RngCore + CryptoRng,
    {
        // 1. Finalize FRI
        let (terminate_codeword, query_prover) = self.fri_folder.finalize()?;
        
        // 2. Get state chain
        let state = self.state_chain.take()
            .ok_or(Error::InvalidArgs("State chain not initialized".into()))?;
        
        // 3. Generate L query challenges
        // In formal FRIDA: ϑ^{(l)}_{r+1} = H(hst_r, l)
        let mut query_challenges = Vec::with_capacity(num_queries);
        let hst_r = state.state(state.challenges.len() as isize)
            .ok_or(Error::InvalidArgs("Invalid state index".into()))?;
        
        for l in 0..num_queries {
            let query_challenge = self.derive_query_challenge(hst_r, l);
            query_challenges.push(query_challenge);
        }
        
        // 4. Generate authentications for each query
        let mut auths = Vec::with_capacity(num_queries);
        for &query_challenge in &query_challenges {
            let auth = auth::open_auth(
                &self.codeword,
                &self.layers,
                &state.challenges,
                query_challenge,
                &self.merkle_prover,
                &self.committed,
            )?;
            auths.push(auth);
        }
        
        // 5. Build and return commitment
        Ok(FridaCommitment {
            state,
            query_challenges,
            auths,
        })
    }
}
```

### Step 6: Verifier Implementation

```rust
// crates/iop-prover/src/fri/frida_full/verifier.rs

impl<'a, F, VCS, H> FridaVerifier<'a, F, VCS, H>
where
    F: BinaryField,
    VCS: MerkleTreeScheme<F, Digest: DeserializeBytes + Clone>,
    H: PseudoCompressionFunction<VCS::Digest, 2>,
{
    /// Verify FRIDA commitment
    pub fn verify<Challenger_>(
        &self,
        commitment: &FridaCommitment<F, VCS::Digest>,
        transcript: &mut VerifierTranscript<Challenger_>,
    ) -> Result<bool, Error>
    where
        Challenger_: Challenger,
    {
        // 1. Reconstruct state chain and verify challenges
        let roots = &commitment.state.roots;
        let challenges = &commitment.state.challenges;
        
        // Verify each challenge was correctly derived
        for (i, challenge) in challenges.iter().enumerate() {
            let expected = self.derive_challenge_from_state(
                commitment.state.state(i as isize - 1).unwrap()
            );
            if *challenge != expected {
                return Ok(false);
            }
        }
        
        // 2. Verify each authentication
        for (l, (query_challenge, auth)) in commitment.query_challenges.iter()
            .zip(&commitment.auths)
            .enumerate()
        {
            // Verify query challenge derivation
            let hst_r = commitment.state.state(challenges.len() as isize - 1)
                .unwrap();
            let expected_challenge = self.derive_query_challenge(hst_r, l);
            if *query_challenge != expected_challenge {
                return Ok(false);
            }
            
            // CheckAuth with strict enforcement
            let valid = auth::check_auth(
                roots,
                challenges,
                *query_challenge,
                auth,
                self.vcs,
                1 << self.params.index_bits(),
            )?;
            
            if !valid {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}
```

### Step 7: Tests

```rust
// Tests for full FRIDA implementation

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_state_chain_initialization() {
        // Test state chain starts correctly
    }
    
    #[test]
    fn test_state_chain_commitment() {
        // Test adding commitment updates state
    }
    
    #[test]
    fn test_challenge_derivation() {
        // Test ϑ_i = H(hst_{i-1})
    }
    
    #[test]
    fn test_qselect_determinism() {
        // Test QSelect is deterministic
    }
    
    #[test]
    fn test_qselect_distribution() {
        // Test QSelect covers space uniformly
    }
    
    #[test]
    fn test_open_auth_structure() {
        // Test OpenAuth generates correct paths
    }
    
    #[test]
    fn test_check_auth_valid() {
        // Test CheckAuth accepts valid auth
    }
    
    #[test]
    fn test_check_auth_invalid_position() {
        // Test CheckAuth rejects wrong position
    }
    
    #[test]
    fn test_check_auth_invalid_path() {
        // Test CheckAuth rejects invalid path
    }
    
    #[test]
    fn test_check_auth_inconsistent_folding() {
        // Test CheckAuth rejects inconsistent values
    }
    
    #[test]
    fn test_frida_full_prove_verify() {
        // Full prove/verify roundtrip
    }
    
    #[test]
    fn test_frida_security_vs_retry_attack() {
        // Verify prover cannot retry
    }
    
    #[test]
    fn test_frida_security_vs_selective_error() {
        // Verify selective errors are caught
    }
}
```

## Dependencies and Imports Required

```rust
// Required imports for frida_full.rs
use binius_field::{BinaryField, Field, PackedField};
use binius_hash::PseudoCompressionFunction;
use binius_iop::fri::FRIParams;
use binius_iop::merkle_tree::MerkleTreeScheme;
use binius_math::{ntt::AdditiveNTT, reed_solomon::ReedSolomonCode};
use binius_math::{FieldBuffer, FieldSlice};
use binius_transcript::{Challenger, ProverTranscript, VerifierTranscript};
use binius_utils::{DeserializeBytes, SerializeBytes};
use rand::{CryptoRng, RngCore};
use std::marker::PhantomData;
```

## Success Criteria

1. ✅ State chain correctly binds all commitments
2. ✅ Challenges derived deterministically from state
3. ✅ QSelect generates deterministic query positions
4. ✅ OpenAuth generates multi-layer Merkle paths
5. ✅ CheckAuth enforces strict verification
6. ✅ Prover cannot predict queries before committing
7. ✅ Prover cannot retry with different queries
8. ✅ All L queries verified with enforcement
9. ✅ Full prove/verify roundtrip works
10. ✅ All tests pass
11. ✅ No existing files modified
12. ✅ Code compiles without errors

## Risks and Considerations

| Risk | Mitigation |
|------|-----------|
| **Complexity** | Break into submodules (state, qselect, auth, prover, verifier) |
| **Performance** | Batch operations where possible, use efficient hash functions |
| **Correctness** | Extensive property-based testing for QSelect and folding |
| **Integration** | Keep compatible with existing FRI infrastructure |
| **Hash Functions** | Need to define H (challenge) and H^↑ (state) precisely |
| **Field Serialization** | Need to_bytes/from_bytes for field elements |

## Timeline Estimate

| Component | Estimated Time |
|-----------|---------------|
| Types and basic structures | 30 min |
| State chain module | 45 min |
| QSelect module | 30 min |
| OpenAuth | 1 hour |
| CheckAuth | 1 hour |
| FridaProver | 1.5 hours |
| FridaVerifier | 1.5 hours |
| Tests | 1.5 hours |
| **Total** | **~8 hours** |

## Next Steps

1. Run `/start-work` to begin implementation
2. Implement in order: types → state → qselect → auth → prover → verifier → tests
3. Verify each component before moving to next
4. Run full test suite after completion

**Recommendation:** This is a substantial implementation. Consider breaking into smaller work units if needed.
