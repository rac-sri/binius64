// Copyright 2025 Irreducible Inc.

//! Polynomial commitment scheme prover for binary field multilinears using BaseFold.

use std::ops::Deref;

use binius_field::{BinaryField, PackedExtension, PackedField};
use binius_math::{multilinear::eq::eq_ind_partial_eval, ntt::AdditiveNTT, FieldBuffer};
use binius_prover::{
	fri::{self, CommitOutput, FRIFoldProver, FRIQueryProver},
	merkle_tree::MerkleTreeProver,
	protocols::basefold::BaseFoldProver,
};
use binius_transcript::{fiat_shamir::Challenger, ProverTranscript};
use binius_utils::SerializeBytes;
use binius_verifier::{fri::FRIParams, merkle_tree::MerkleTreeScheme};

use crate::Error;

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
		transcript: &mut ProverTranscript<Challenger_>,
	) -> Result<FRIQueryProver<'a, F, P, MerkleProver, MerkleScheme>, Error>
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
		let result = basefold_prover.prove(transcript)?;

		Ok(result)
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
		and_reduction::verifier,
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

	fn run_pcs_prove_with_openings<P>(
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

		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = pcs_prover.commit(multilinear.to_ref())?;

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prover_transcript.message().write(&codeword_commitment);

		// Call prove_with_openings to get the FRIQueryProver
		let query_prover = pcs_prover.prove_with_openings(
			codeword.clone(),
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

	#[test]
	fn test_prove_with_openings_basic() {
		type P = OptimalPackedB128;

		let n_vars = 6;
		let (multilinear, evaluation_point, evaluation_claim) = test_setup::<P>(n_vars);

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
		)
		.unwrap();

		let pcs_prover = PCSProver::new(&ntt, &merkle_prover, &fri_params);

		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = pcs_prover.commit(multilinear.to_ref()).unwrap();

		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prover_transcript.message().write(&codeword_commitment);

		// Call prove_with_openings to get the FRIQueryProver
		let query_prover = pcs_prover
			.prove_with_openings(
				codeword,
				&codeword_committed,
				multilinear,
				&evaluation_point,
				evaluation_claim,
				&mut prover_transcript,
			)
			.unwrap();

		// Verify that query_prover can generate proofs
		let mut temp_transcript = ProverTranscript::new(StdChallenger::default());
		let mut advice = temp_transcript.decommitment();
		query_prover.prove_query(0, &mut advice).unwrap();
		let proof_bytes = temp_transcript.finalize();

		assert!(!proof_bytes.is_empty(), "Proof should not be empty");
	}

	#[test]
	fn test_run_pcs_prove_with_openings() {
		type P = OptimalPackedB128;

		let n_vars = 6;
		let (multilinear, evaluation_point, evaluation_claim) = test_setup::<P>(n_vars);

		// Call the helper function
		run_pcs_prove_with_openings::<P>(multilinear, evaluation_point, evaluation_claim).unwrap();
	}

	#[test]
	fn test_e2e_prove_with_openings_extra_query() {
		type P = OptimalPackedB128;
		use binius_spartan_verifier::pcs;

		let n_vars = 6;
		let (multilinear, evaluation_point, evaluation_claim) = test_setup::<P>(n_vars);

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
		)
		.unwrap();

		let pcs_prover = PCSProver::new(&ntt, &merkle_prover, &fri_params);

		// Commit
		let CommitOutput {
			commitment: codeword_commitment,
			committed: codeword_committed,
			codeword,
		} = pcs_prover.commit(multilinear.to_ref()).unwrap();

		// Prove
		let mut prover_transcript = ProverTranscript::new(StdChallenger::default());
		prover_transcript.message().write(&codeword_commitment);

		// Get query prover for additional queries
		let query_prover = pcs_prover
			.prove_with_openings(
				codeword.clone(),
				&codeword_committed,
				multilinear,
				&evaluation_point,
				evaluation_claim,
				&mut prover_transcript,
			)
			.unwrap();

			// Verify the main proof and get verifier with arena for extra query verification
		let mut verifier_transcript = prover_transcript.into_verifier();
		let retrieved_codeword_commitment = verifier_transcript.message().read().unwrap();

		let (output, verifier_with_arena) = binius_iop::basefold::verify_with_verifier(
			&fri_params,
			merkle_prover.scheme(),
			retrieved_codeword_commitment,
			evaluation_claim,
			&mut verifier_transcript,
		)
		.unwrap();

		// Verify consistency between sumcheck and FRI final values
		assert!(
			binius_iop::basefold::sumcheck_fri_consistency(
				output.final_fri_value,
				output.final_sumcheck_value,
				&evaluation_point,
				output.challenges,
			),
			"Sumcheck and FRI final values should be consistent"
		);

	// Generate 1 extra query proof at a valid index
		let extra_index = 0usize;
		let mut extra_transcript = ProverTranscript::new(StdChallenger::default());
		let mut extra_advice = extra_transcript.decommitment();
		query_prover
			.prove_query(extra_index, &mut extra_advice)
			.unwrap();
		let extra_proof_bytes = extra_transcript.finalize();

		assert!(!extra_proof_bytes.is_empty(), "Extra proof should not be empty");


		// The verifier_with_arena holds the FRIQueryVerifier which can be used
		// to verify additional queries. The extra_proof_bytes contains the proof
		// for the additional query at index 0.
		let _verifier = verifier_with_arena.verifier();

		// Verify that the extra proof bytes are valid by parsing them
		let mut extra_proof_reader = binius_transcript::VerifierTranscript::new(
			binius_spartan_verifier::config::StdChallenger::default(),
			extra_proof_bytes.into(),
		);

		// Read the coset values from the extra proof
		let log_coset_size = fri_params.log_batch_size();
		let coset_values: Vec<B128> = extra_proof_reader
			.decommitment()
			.read_scalar_slice(1 << log_coset_size)
			.unwrap();

		assert!(!coset_values.is_empty(), "Coset values should not be empty");
	}
}
