#![allow(unused, unreachable_code)]
use ark_ed_on_bls12_381::Fr;
use ark_ff::{Field, UniformRand};
use strong_adaptivity::{Instance, Proof, ProofCommitment, ProofResponse, data::puzzle_data};
use strong_adaptivity::verify;
use strong_adaptivity::PUZZLE_DESCRIPTION;
use prompt::{puzzle, welcome};

use strong_adaptivity::utils::b2s_hash_to_field;

fn main() {
    welcome();
    puzzle(PUZZLE_DESCRIPTION);
    let ck = puzzle_data();

    let (instance, witness, proof): (Instance, (Fr, Fr, Fr, Fr), Proof) = {
        let rng = &mut rand::thread_rng();

        // === CHANGE: DEFER OFFLINE PHASE ===

        // === ONLINE PHASE ===
        // Step 1: Prover samples random elements r_ρ, r_τ
        let r_rho = Fr::rand(rng);
        let r_tau = Fr::rand(rng);

        // Step 2: Prover commits to random values ρ and τ using r_ρ and r_τ
        let (comm_rho, rho) = ck.commit_with_rng(r_rho, rng);
        let (comm_tau, tau) = ck.commit_with_rng(r_tau, rng);
        let commitment = ProofCommitment { comm_rho, comm_tau };

        // Step 3: Verifier derives challenge e from commitments using Fiat–Shamir
        let challenge = b2s_hash_to_field(&(ck, commitment));

        // === BEGIN REORDERED OFFLINE PHASE PART 1 ===
        // Generate first message a_1 and commit
        let a_1 = Fr::rand(rng);
        let (comm_1, r_1) = ck.commit_with_rng(a_1, rng);

        // Generate independent randomness for second commitment
        let r_2 = Fr::rand(rng);
        // === END REORDERED OFFLINE PHASE PART 1 ===

        // Step 4: Compute responses
        let s = r_rho + challenge * a_1;
        let u = rho + challenge * r_1;
        let t = tau + challenge * r_2;
        let response = ProofResponse { s, u, t };

        // === BEGIN REORDERED OFFLINE PHASE PART 2 ===
        // Derive a_2 such that s = r_τ + e · a_2
        let r_diff = r_tau - r_rho;
        let a_2 = a_1 - r_diff / challenge;
        let comm_2 = ck.commit_with_explicit_randomness(a_2, r_2);
        // === END REORDERED OFFLINE PHASE PART 2 ===

        let instance = Instance { comm_1, comm_2 };
        let witness = (a_1, r_1, a_2, r_2);
        let proof = Proof { commitment, response };

        (instance, witness, proof)
    };

    let (a_1, r_1, a_2, r_2) = witness;

    assert!(verify(&ck, &instance, &proof));
    assert_eq!(ck.commit_with_explicit_randomness(a_1, r_1), instance.comm_1);
    assert_eq!(ck.commit_with_explicit_randomness(a_2, r_2), instance.comm_2);
    assert_ne!(a_1, a_2);
}
