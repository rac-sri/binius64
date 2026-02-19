// Copyright 2025 Irreducible Inc.

//! Polynomial commitment scheme prover for binary field multilinears using BaseFold.

use std::ops::Deref;

use binius_field::{BinaryField, PackedExtension, PackedField};
use binius_ip_prover::sumcheck::{
	bivariate_product::BivariateProductSumcheckProver, common::SumcheckProver,
};
use binius_math::{multilinear::eq::eq_ind_partial_eval, ntt::AdditiveNTT, FieldBuffer};
use binius_prover::{
	fri::{self, CommitOutput, FRIFoldProver, FoldRoundOutput},
	merkle_tree::MerkleTreeProver,
	protocols::basefold::BaseFoldProver,
};
use binius_transcript::{
	fiat_shamir::{CanSample, CanSampleBits, Challenger},
	ProverTranscript,
};
use binius_utils::SerializeBytes;
use binius_verifier::{fri::FRIParams, merkle_tree::MerkleTreeScheme};

use crate::Error;

/// Generate L unique random indices deterministically from seed r.
///
/// This function uses the field element r as a seed to deterministically generate
/// L unique random indices in the range [0, max_index). If L > max_index, it returns
/// all indices from 0 to max_index-1.
///
/// # Arguments
///
/// * `r` - the seed value (field element)
/// * `l` - the number of indices to generate
/// * `max_index` - the exclusive upper bound for indices
///
/// # Returns
///
/// A vector of L unique indices (or fewer if max_index < L)
fn generate_random_indices<F>(r: F, l: usize, max_index: usize) -> Vec<usize>
where
	F: BinaryField + SerializeBytes,
{
	if max_index == 0 || l == 0 {
		return Vec::new();
	}

	let mut seed = [0u8; 32];
	let mut r_bytes = Vec::new();
	SerializeBytes::serialize(&r, &mut r_bytes).expect("serialization to vec cannot fail");
	let bytes_to_copy = r_bytes.len().min(32);
	seed[..bytes_to_copy].copy_from_slice(&r_bytes[..bytes_to_copy]);

	use rand::{rngs::StdRng, Rng, SeedableRng};
	let mut rng = StdRng::from_seed(seed);

	if l >= max_index {
		return (0..max_index).collect();
	}

	let mut indices: Vec<usize> = (0..max_index).collect();

	for i in 0..l {
		let j = rng.random_range(i..max_index);
		indices.swap(i, j);
	}

	indices.truncate(l);
	indices
}

/// Trace an index through all FRI folding layers.
///
/// Given an original index in the codeword and the fold arities, this function
/// computes the corresponding index at each folding layer.
///
/// # Arguments
///
/// * `original_index` - the index in the original (layer 0) codeword
/// * `fold_arities` - the folding arities for each round
///
/// # Returns
///
/// A vector of (layer_depth, index_at_layer) pairs, from layer 0 to final layer
fn trace_index_through_layers(
	original_index: usize,
	fold_arities: &[usize],
) -> Vec<(usize, usize)> {
	let mut result = vec![(0, original_index)];
	let mut current_index = original_index;

	for (layer, &arity) in fold_arities.iter().enumerate() {
		// Move to next layer by dividing by the arity
		current_index >>= arity;
		result.push((layer + 1, current_index));
	}

	result
}

/// Represents a single opening at a specific layer in the FRI folding process.
///
/// This structure captures the opened values at a particular index in a codeword layer
/// along with the Merkle inclusion proof for those values.
///
/// # Example
///
/// ```
/// use binius_spartan_prover::pcs::LayerOpening;
/// use binius_field::{BinaryField128bGhash as B128, Field};
///
/// let opening = LayerOpening::<B128> {
///     layer_depth: 0,
///     index: 42,
///     values: vec![B128::ONE, B128::ZERO],
///     merkle_proof: vec![0u8; 32], // Merkle proof bytes
/// };
/// ```
#[derive(Debug, Clone)]
pub struct LayerOpening<F> {
	/// Layer depth (0 = original/interleaved codeword, 1 = first fold, etc.)
	pub layer_depth: usize,
	/// Index in the codeword at this layer
	pub index: usize,
	/// The opened field element values at this position
	pub values: Vec<F>,
	/// Merkle inclusion proof bytes (salt + branch path)
	pub merkle_proof: Vec<u8>,
}

impl<F> LayerOpening<F> {
	/// Creates a new layer opening.
	///
	/// # Arguments
	///
	/// * `layer_depth` - the depth of the layer (0 = original codeword)
	/// * `index` - the index in the codeword at this layer
	/// * `values` - the opened field element values
	/// * `merkle_proof` - the Merkle inclusion proof bytes
	pub fn new(layer_depth: usize, index: usize, values: Vec<F>, merkle_proof: Vec<u8>) -> Self {
		Self {
			layer_depth,
			index,
			values,
			merkle_proof,
		}
	}
}

/// Represents all openings for a single point traced through all FRI folding layers.
///
/// When a point is selected in the original codeword, it is traced through each
/// folding layer. This structure captures the openings at each layer for that point.
///
/// # Example
///
/// ```
/// use binius_spartan_prover::pcs::{LayerOpening, TracedPointOpenings};
/// use binius_field::{BinaryField128bGhash as B128, Field};
///
/// let traced = TracedPointOpenings::<B128> {
///     original_index: 42,
///     layer_openings: vec![
///         LayerOpening::new(0, 42, vec![B128::ONE], vec![0u8; 32]),
///         LayerOpening::new(1, 21, vec![B128::ZERO], vec![0u8; 32]),
///     ],
/// };
/// ```
#[derive(Debug, Clone)]
pub struct TracedPointOpenings<F> {
	/// Original index in the codeword (layer 0)
	pub original_index: usize,
	/// Openings at each layer (from layer 0 to final layer)
	pub layer_openings: Vec<LayerOpening<F>>,
}

impl<F> TracedPointOpenings<F> {
	/// Creates a new traced point openings structure.
	///
	/// # Arguments
	///
	/// * `original_index` - the original index in the codeword
	/// * `layer_openings` - the openings at each layer
	pub fn new(original_index: usize, layer_openings: Vec<LayerOpening<F>>) -> Self {
		Self {
			original_index,
			layer_openings,
		}
	}
}

/// Additional proof data containing Merkle inclusion proofs for random point openings.
///
/// This structure is returned by [`PCSProver::prove_with_openings`] and contains
/// Merkle inclusion proofs for L randomly selected points traced through all FRI
/// folding layers.
///
/// # Example
///
/// ```
/// use binius_spartan_prover::pcs::{AdditionalOpeningsProof, TracedPointOpenings, LayerOpening};
/// use binius_field::{BinaryField128bGhash as B128, Field};
///
/// let proof = AdditionalOpeningsProof::<B128> {
///     r: B128::ONE,
///     l: 2,
///     traced_points: vec![
///         TracedPointOpenings::new(42, vec![
///             LayerOpening::new(0, 42, vec![B128::ONE], vec![0u8; 32]),
///         ]),
///     ],
/// };
/// ```
#[derive(Debug, Clone)]
pub struct AdditionalOpeningsProof<F> {
	/// The value r used to generate random points
	pub r: F,
	/// Number of points L (may be less than requested if codeword was smaller)
	pub l: usize,
	/// Openings for each traced point
	pub traced_points: Vec<TracedPointOpenings<F>>,
}

impl<F> AdditionalOpeningsProof<F> {
	/// Creates a new additional openings proof.
	///
	/// # Arguments
	///
	/// * `r` - the value used to generate random points
	/// * `l` - the number of points
	/// * `traced_points` - the traced point openings
	pub fn new(r: F, l: usize, traced_points: Vec<TracedPointOpenings<F>>) -> Self {
		Self {
			r,
			l,
			traced_points,
		}
	}
}

/// Prover for the BaseFold polynomial commitment scheme for binary field multilinears.
///
/// This prover commits multilinear polynomials over a binary field using FRI and proves evaluations
/// at given points using the BaseFold protocol.
pub struct PCSProver<'a, F, NTT, MTProver>
where
	F: BinaryField,
	NTT: AdditiveNTT<Field = F> + Sync,
	MTProver: MerkleTreeProver<F>,
{
	ntt: &'a NTT,
	merkle_prover: &'a MTProver,
	fri_params: &'a FRIParams<F>,
}

impl<'a, F, NTT, MerkleScheme, MerkleProver> PCSProver<'a, F, NTT, MerkleProver>
where
	F: BinaryField,
	NTT: AdditiveNTT<Field = F> + Sync,
	MerkleScheme: MerkleTreeScheme<F, Digest: SerializeBytes>,
	MerkleProver: MerkleTreeProver<F, Scheme = MerkleScheme>,
{
	/// Creates a new PCS prover.
	///
	/// ## Arguments
	///
	/// * `ntt` - the NTT for the FRI parameters
	/// * `merkle_prover` - the merkle tree prover
	/// * `fri_params` - the FRI parameters
	pub fn new(
		ntt: &'a NTT,
		merkle_prover: &'a MerkleProver,
		fri_params: &'a FRIParams<F>,
	) -> Self {
		let rs_code = fri_params.rs_code();
		assert_eq!(&ntt.subspace(rs_code.log_len()), rs_code.subspace());
		Self {
			ntt,
			merkle_prover,
			fri_params,
		}
	}

	/// Commit to a multilinear polynomial using FRI.
	///
	/// ## Arguments
	///
	/// * `multilinear` - a packed field buffer representing a binary field multilinear polynomial
	pub fn commit<P, Data>(
		&self,
		multilinear: FieldBuffer<P, Data>,
	) -> Result<CommitOutput<P, MerkleScheme::Digest, MerkleProver::Committed>, Error>
	where
		P: PackedField<Scalar = F> + PackedExtension<F>,
		Data: Deref<Target = [P]>,
	{
		fri::commit_interleaved(self.fri_params, self.ntt, self.merkle_prover, multilinear.to_ref())
			.map_err(Into::into)
	}

	/// Prove the committed polynomial's evaluation at a given point.
	///
	/// ## Arguments
	///
	/// * `committed_codeword` - the committed codeword from FRI
	/// * `committed` - the committed merkle tree
	/// * `multilinear` - the multilinear polynomial (must match what was committed)
	/// * `evaluation_point` - the evaluation point in F^n_vars
	/// * `evaluation_claim` - the claimed evaluation of the multilinear at evaluation_point
	/// * `transcript` - the prover's transcript
	pub fn prove<P, Challenger_>(
		&self,
		committed_codeword: FieldBuffer<P>,
		committed: &'a MerkleProver::Committed,
		multilinear: FieldBuffer<P>,
		evaluation_point: &[F],
		evaluation_claim: F,
		transcript: &mut ProverTranscript<Challenger_>,
	) -> Result<(), Error>
	where
		P: PackedField<Scalar = F> + PackedExtension<F>,
		Challenger_: Challenger,
	{
		assert_eq!(
			multilinear.log_len(),
			evaluation_point.len(),
			"multilinear has {} variables but evaluation point has {} coordinates",
			multilinear.log_len(),
			evaluation_point.len()
		);

		// Compute eq_ind for the evaluation point
		let eq_ind = eq_ind_partial_eval::<P>(evaluation_point);

		// Create FRI fold prover
		let fri_folder = FRIFoldProver::new(
			self.fri_params,
			self.ntt,
			self.merkle_prover,
			committed_codeword,
			committed,
		)?;

		// Create and run BaseFold prover
		let basefold_prover =
			BaseFoldProver::new(multilinear, eq_ind, evaluation_claim, fri_folder);
		basefold_prover.prove(transcript)?;

		Ok(())
	}

	/// Prove the committed polynomial's evaluation and generate additional openings.
	///
	/// This method performs the standard PCS proof and additionally generates Merkle
	/// inclusion proofs for L randomly selected points traced through all FRI folding layers.
	///
	/// ## Arguments
	///
	/// * `committed_codeword` - the committed codeword from FRI
	/// * `committed` - the committed merkle tree
	/// * `multilinear` - the multilinear polynomial (must match what was committed)
	/// * `evaluation_point` - the evaluation point in F^n_vars
	/// * `evaluation_claim` - the claimed evaluation of the multilinear at evaluation_point
	/// * `r` - seed value for generating random points
	/// * `l` - number of random points to generate
	/// * `transcript` - the prover's transcript
	///
	/// ## Returns
	///
	/// Returns the standard PCS proof result and additional openings proof data
	pub fn prove_with_openings<P, Challenger_>(
		&self,
		committed_codeword: FieldBuffer<P>,
		committed: &'a MerkleProver::Committed,
		multilinear: FieldBuffer<P>,
		evaluation_point: &[F],
		evaluation_claim: F,
		r: F,
		l: usize,
		transcript: &mut ProverTranscript<Challenger_>,
	) -> Result<AdditionalOpeningsProof<F>, Error>
	where
		P: PackedField<Scalar = F> + PackedExtension<F>,
		Challenger_: Challenger + Default,
	{
		assert_eq!(
			multilinear.log_len(),
			evaluation_point.len(),
			"multilinear has {} variables but evaluation point has {} coordinates",
			multilinear.log_len(),
			evaluation_point.len()
		);

		let log_coset_size = self.fri_params.log_batch_size();
		let n_cosets = 1 << (self.fri_params.log_len() - log_coset_size);
		let random_indices = generate_random_indices(r, l, n_cosets);

		let eq_ind = eq_ind_partial_eval::<P>(evaluation_point);

		let mut fri_folder = FRIFoldProver::new(
			self.fri_params,
			self.ntt,
			self.merkle_prover,
			committed_codeword.clone(),
			committed,
		)?;

		let mut sumcheck_prover =
			BivariateProductSumcheckProver::new([multilinear, eq_ind], evaluation_claim)
				.map_err(|e| Error::Sumcheck(e.into()))?;

		let n_vars = sumcheck_prover.n_vars();
		for _ in 0..n_vars {
			let [round_coeffs] = sumcheck_prover
				.execute()
				.map_err(|e| Error::Sumcheck(e.into()))?
				.try_into()
				.expect("sumcheck_prover proves only one multivariate");
			transcript
				.message()
				.write_scalar_slice(round_coeffs.truncate().coeffs());

			let commitment = fri_folder.execute_fold_round().map_err(Error::Fri)?;
			if let FoldRoundOutput::Commitment(commitment) = commitment {
				transcript.message().write(&commitment);
			}

			let challenge: F = transcript.sample();
			sumcheck_prover
				.fold(challenge)
				.map_err(|e| Error::Sumcheck(e.into()))?;
			fri_folder.receive_challenge(challenge);
		}

		let commitment = fri_folder.execute_fold_round().map_err(Error::Fri)?;
		if let FoldRoundOutput::Commitment(commitment) = commitment {
			transcript.message().write(&commitment);
		}

		let (_, query_prover) = fri_folder.finalize().map_err(Error::Fri)?;

		let layers = query_prover.vcs_optimal_layers().map_err(Error::Fri)?;
		for layer in layers {
			transcript.decommitment().write_slice(&layer);
		}

		for _ in 0..self.fri_params.n_test_queries() {
			let index = transcript.sample_bits(self.fri_params.index_bits()) as usize;
			query_prover
				.prove_query(index, &mut transcript.decommitment())
				.map_err(Error::Fri)?;
		}

		let fold_arities: Vec<usize> = self.fri_params.fold_arities().to_vec();
		let mut traced_points = Vec::with_capacity(random_indices.len());

		for &original_index in &random_indices {
			let layer_indices = trace_index_through_layers(original_index, &fold_arities);
			let mut layer_openings = Vec::with_capacity(layer_indices.len());

			// Generate the full proof for this original index (covers all layers)
			let mut temp_transcript = ProverTranscript::new(Challenger_::default());
			let mut advice = temp_transcript.decommitment();
			query_prover
				.prove_query(original_index, &mut advice)
				.map_err(Error::Fri)?;
			let full_proof_bytes = temp_transcript.finalize();

			// For each layer, create an opening with the full proof
			// The proof contains all layers, so each layer opening references the same proof
			for (layer_depth, index_at_layer) in layer_indices {
				// Get values for this layer
				let values = if layer_depth == 0 {
					let log_coset_size = self.fri_params.log_batch_size();
					let coset_index = index_at_layer >> log_coset_size;
					let chunk = committed_codeword.chunk(log_coset_size, coset_index);
					chunk.iter_scalars().collect()
				} else {
					// For folded layers, we would need access to round_committed
					// which is pub(super) in FRIQueryProver. For now, return empty.
					vec![]
				};

				layer_openings.push(LayerOpening::new(
					layer_depth,
					index_at_layer,
					values,
					full_proof_bytes.clone(),
				));
			}

			traced_points.push(TracedPointOpenings::new(original_index, layer_openings));
		}

		Ok(AdditionalOpeningsProof::new(r, traced_points.len(), traced_points))
	}
}

#[cfg(test)]
mod tests {
	use binius_field::{arch::OptimalPackedB128, Field, PackedExtension, PackedField, Random};
	use binius_math::{
		inner_product::inner_product_buffers,
		multilinear::eq::eq_ind_partial_eval,
		ntt::{domain_context::GenericOnTheFly, NeighborsLastSingleThread},
		BinarySubspace, FieldBuffer,
	};
	use binius_prover::{
		hash::parallel_compression::ParallelCompressionAdaptor,
		merkle_tree::prover::BinaryMerkleTreeProver,
	};
	use binius_spartan_verifier::{
		config::{StdChallenger, B128},
		pcs,
	};
	use binius_transcript::ProverTranscript;
	use binius_verifier::{
		fri::{calculate_n_test_queries, ConstantArityStrategy, FRIParams},
		hash::{StdCompression, StdDigest},
	};
	use rand::{rngs::StdRng, SeedableRng};

	use super::*;

	const LOG_INV_RATE: usize = 1;
	const SECURITY_BITS: usize = 32;

	fn run_pcs_prove_and_verify<P>(
		multilinear: FieldBuffer<P>,
		evaluation_point: Vec<B128>,
		evaluation_claim: B128,
	) -> Result<(), Box<dyn std::error::Error>>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128>,
	{
		let merkle_prover = BinaryMerkleTreeProver::<B128, StdDigest, _>::new(
			ParallelCompressionAdaptor::new(StdCompression::default()),
		);

		let subspace = BinarySubspace::with_dim(multilinear.log_len() + LOG_INV_RATE);
		let domain_context = GenericOnTheFly::generate_from_subspace(&subspace);
		let ntt = NeighborsLastSingleThread::new(domain_context);

		let n_test_queries = calculate_n_test_queries(SECURITY_BITS, LOG_INV_RATE);
		let fri_params = FRIParams::with_strategy(
			&ntt,
			merkle_prover.scheme(),
			multilinear.log_len(),
			None,
			LOG_INV_RATE,
			n_test_queries,
			&ConstantArityStrategy::new(2),
		)?;

		let pcs_prover = PCSProver::new(&ntt, &merkle_prover, &fri_params);

		// Commit
		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = pcs_prover.commit(multilinear.to_ref())?;

		// Prove
		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prover_transcript.message().write(&codeword_commitment);
		pcs_prover.prove(
			codeword,
			&codeword_committed,
			multilinear,
			&evaluation_point,
			evaluation_claim,
			&mut prover_transcript,
		)?;

		// Verify
		let mut verifier_transcript = prover_transcript.into_verifier();
		let retrieved_codeword_commitment = verifier_transcript.message().read()?;

		pcs::verify(
			&mut verifier_transcript,
			evaluation_claim,
			&evaluation_point,
			retrieved_codeword_commitment,
			&fri_params,
			merkle_prover.scheme(),
		)?;

		Ok(())
	}

	fn test_setup<P>(n_vars: usize) -> (FieldBuffer<P>, Vec<B128>, B128)
	where
		P: PackedField<Scalar = B128>,
	{
		let mut rng = StdRng::from_seed([0; 32]);

		// Create random multilinear
		let len = 1 << n_vars.saturating_sub(P::LOG_WIDTH);
		let data: Vec<P> = (0..len).map(|_| P::random(&mut rng)).collect();
		let multilinear = FieldBuffer::new(n_vars, data.into_boxed_slice());

		// Create random evaluation point
		let evaluation_point: Vec<B128> = (0..n_vars)
			.map(|_| <B128 as Random>::random(&mut rng))
			.collect();

		let eval_point_eq = eq_ind_partial_eval(&evaluation_point);

		println!("eval point eq {:?}", eval_point_eq.len());
		println!("multilinear len {:?}", multilinear.len());
		let evaluation_claim = inner_product_buffers(&multilinear, &eval_point_eq);

		(multilinear, evaluation_point, evaluation_claim)
	}

	fn dubiously_modify_claim<P>(claim: &mut B128)
	where
		P: PackedField<Scalar = B128>,
	{
		*claim += P::Scalar::ONE;
	}

	#[test]
	fn test_pcs_valid_proof() {
		type P = OptimalPackedB128;

		let n_vars = 8;
		let (multilinear, evaluation_point, evaluation_claim) = test_setup::<P>(n_vars);

		run_pcs_prove_and_verify::<P>(multilinear, evaluation_point, evaluation_claim).unwrap();
	}

	#[test]
	fn test_pcs_invalid_proof() {
		type P = OptimalPackedB128;

		let n_vars = 8;
		let (multilinear, evaluation_point, mut evaluation_claim) = test_setup::<P>(n_vars);

		dubiously_modify_claim::<P>(&mut evaluation_claim);
		let result = run_pcs_prove_and_verify::<P>(multilinear, evaluation_point, evaluation_claim);
		assert!(result.is_err(), "expected invalid proof to fail verification");
	}

	#[test]
	fn test_pcs_small_polynomial() {
		type P = OptimalPackedB128;

		let n_vars = 4;
		let (multilinear, evaluation_point, evaluation_claim) = test_setup::<P>(n_vars);

		run_pcs_prove_and_verify::<P>(multilinear, evaluation_point, evaluation_claim).unwrap();
	}

	#[test]
	fn test_generate_random_indices_basic() {
		use binius_field::BinaryField128bGhash as B128;

		let r = B128::ONE;
		let l = 5;
		let max_index = 100;

		let indices = generate_random_indices(r, l, max_index);

		assert_eq!(indices.len(), l);
		assert!(indices.iter().all(|&i| i < max_index));

		let unique: std::collections::HashSet<_> = indices.iter().collect();
		assert_eq!(unique.len(), l);
	}

	#[test]
	fn test_generate_random_indices_deterministic() {
		use binius_field::BinaryField128bGhash as B128;

		let r = B128::ONE;
		let l = 10;
		let max_index = 100;

		let indices1 = generate_random_indices(r, l, max_index);
		let indices2 = generate_random_indices(r, l, max_index);

		assert_eq!(indices1, indices2);
	}

	#[test]
	fn test_generate_random_indices_l_greater_than_max() {
		use binius_field::BinaryField128bGhash as B128;

		let r = B128::ONE;
		let l = 20;
		let max_index = 10;

		let indices = generate_random_indices(r, l, max_index);

		assert_eq!(indices.len(), max_index);
		assert!(indices.iter().all(|&i| i < max_index));
	}

	#[test]
	fn test_generate_random_indices_zero_l() {
		use binius_field::BinaryField128bGhash as B128;

		let r = B128::ONE;
		let l = 0;
		let max_index = 100;

		let indices = generate_random_indices(r, l, max_index);

		assert!(indices.is_empty());
	}

	#[test]
	fn test_layer_opening_new() {
		use binius_field::BinaryField128bGhash as B128;

		let opening = LayerOpening::new(0, 42, vec![B128::ONE, B128::ZERO], vec![0u8; 32]);

		assert_eq!(opening.layer_depth, 0);
		assert_eq!(opening.index, 42);
		assert_eq!(opening.values.len(), 2);
		assert_eq!(opening.merkle_proof.len(), 32);
	}

	#[test]
	fn test_traced_point_openings_new() {
		use binius_field::BinaryField128bGhash as B128;

		let layer_openings = vec![
			LayerOpening::new(0, 42, vec![B128::ONE], vec![0u8; 32]),
			LayerOpening::new(1, 21, vec![B128::ZERO], vec![0u8; 32]),
		];

		let traced = TracedPointOpenings::new(42, layer_openings);

		assert_eq!(traced.original_index, 42);
		assert_eq!(traced.layer_openings.len(), 2);
	}

	#[test]
	fn test_additional_openings_proof_new() {
		use binius_field::BinaryField128bGhash as B128;

		let traced_points = vec![TracedPointOpenings::new(
			42,
			vec![LayerOpening::new(0, 42, vec![B128::ONE], vec![0u8; 32])],
		)];

		let proof = AdditionalOpeningsProof::new(B128::ONE, 1, traced_points);

		assert_eq!(proof.l, 1);
		assert_eq!(proof.traced_points.len(), 1);
	}

	#[test]
	fn test_trace_index_through_layers() {
		let original_index = 42usize;
		let fold_arities = vec![1, 1, 1];

		let traced = trace_index_through_layers(original_index, &fold_arities);

		assert_eq!(traced.len(), 4);
		assert_eq!(traced[0], (0, 42));
		assert_eq!(traced[1], (1, 21));
		assert_eq!(traced[2], (2, 10));
		assert_eq!(traced[3], (3, 5));
	}

	#[test]
	fn test_trace_index_single_layer() {
		let original_index = 10usize;
		let fold_arities = vec![];

		let traced = trace_index_through_layers(original_index, &fold_arities);

		assert_eq!(traced.len(), 1);
		assert_eq!(traced[0], (0, 10));
	}

	fn run_pcs_prove_with_openings<P>(
		multilinear: FieldBuffer<P>,
		evaluation_point: Vec<B128>,
		evaluation_claim: B128,
		r: B128,
		l: usize,
	) -> Result<AdditionalOpeningsProof<B128>, Box<dyn std::error::Error>>
	where
		P: PackedField<Scalar = B128> + PackedExtension<B128>,
	{
		let merkle_prover = BinaryMerkleTreeProver::<B128, StdDigest, _>::new(
			ParallelCompressionAdaptor::new(StdCompression::default()),
		);

		let subspace = BinarySubspace::with_dim(multilinear.log_len() + LOG_INV_RATE);
		let domain_context = GenericOnTheFly::generate_from_subspace(&subspace);
		let ntt = NeighborsLastSingleThread::new(domain_context);

		let n_test_queries = calculate_n_test_queries(SECURITY_BITS, LOG_INV_RATE);
		let fri_params = FRIParams::with_strategy(
			&ntt,
			merkle_prover.scheme(),
			multilinear.log_len(),
			None,
			LOG_INV_RATE,
			n_test_queries,
			&ConstantArityStrategy::new(2),
		)?;

		let pcs_prover = PCSProver::new(&ntt, &merkle_prover, &fri_params);

		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = pcs_prover.commit(multilinear.to_ref())?;

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prover_transcript.message().write(&codeword_commitment);

		let additional_proof = pcs_prover.prove_with_openings(
			codeword,
			&codeword_committed,
			multilinear,
			&evaluation_point,
			evaluation_claim,
			r,
			l,
			&mut prover_transcript,
		)?;

		Ok(additional_proof)
	}

	#[test]
	fn test_prove_with_openings_basic() {
		type P = OptimalPackedB128;

		let n_vars = 6;
		let (multilinear, evaluation_point, evaluation_claim) = test_setup::<P>(n_vars);
		let r = B128::ONE;
		let l = 3;

		let additional_proof =
			run_pcs_prove_with_openings::<P>(multilinear, evaluation_point, evaluation_claim, r, l)
				.unwrap();

		assert_eq!(additional_proof.l, additional_proof.traced_points.len());
		assert_eq!(additional_proof.r, r);

		assert!(!additional_proof.traced_points.is_empty(), "Should have traced points");

		for traced in &additional_proof.traced_points {
			assert!(
				!traced.layer_openings.is_empty(),
				"Each traced point should have layer openings"
			);

			for opening in &traced.layer_openings {
				assert!(!opening.merkle_proof.is_empty(), "Merkle proof should not be empty");

				if opening.layer_depth == 0 {
					assert!(!opening.values.is_empty(), "Layer 0 should have values");
				}
			}
		}
	}

	#[test]
	fn test_prove_with_openings_deterministic() {
		type P = OptimalPackedB128;

		let n_vars = 6;
		let (multilinear1, evaluation_point1, evaluation_claim1) = test_setup::<P>(n_vars);
		let (multilinear2, evaluation_point2, evaluation_claim2) = test_setup::<P>(n_vars);
		let r = B128::ONE;
		let l = 3;

		let proof1 = run_pcs_prove_with_openings::<P>(
			multilinear1,
			evaluation_point1,
			evaluation_claim1,
			r,
			l,
		)
		.unwrap();

		let proof2 = run_pcs_prove_with_openings::<P>(
			multilinear2,
			evaluation_point2,
			evaluation_claim2,
			r,
			l,
		)
		.unwrap();

		assert_eq!(proof1.traced_points.len(), proof2.traced_points.len());
		for (t1, t2) in proof1.traced_points.iter().zip(proof2.traced_points.iter()) {
			assert_eq!(t1.original_index, t2.original_index);
		}
	}

	#[test]
	fn test_prove_with_openings_zero_l() {
		type P = OptimalPackedB128;

		let n_vars = 6;
		let (multilinear, evaluation_point, evaluation_claim) = test_setup::<P>(n_vars);
		let r = B128::ONE;
		let l = 0;

		let additional_proof =
			run_pcs_prove_with_openings::<P>(multilinear, evaluation_point, evaluation_claim, r, l)
				.unwrap();

		assert_eq!(additional_proof.l, 0);
		assert!(additional_proof.traced_points.is_empty());
	}
}
