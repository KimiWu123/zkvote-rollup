
const {stringifyBigInts} = require('snarkjs/src/stringifybigint.js');

const chai = require('chai');
const assert = chai.assert;

const snarkjs = require('snarkjs');
const bigInt = snarkjs.bigInt;

const circomlib = require('circomlib');
const eddsa = circomlib.eddsa;
const mimc7 = circomlib.mimc7;

const ethers = require('ethers');


function rollup(private_key, proofs, proof_path, ballots) {
    // console.log(`proof_path: ${proof_path}`);
    const prvKey = Buffer.from(private_key, 'hex');
    const pubKey = eddsa.prv2pub(prvKey);
    
    let sig_R8 = []
    let sig_S = []
    let external_proofs = []
    let opinions = []
    let roots = []
    let pf_path_elements = []
    let pf_path_index = []
    for (var i=0; i<proofs.length; i++) {
      const hash_proof = hashKeccak(proofs[i].proof.trim())
      const hash_opinion = hashKeccak(proofs[i].opinion)

      const proof_leaf = get_proof_leaf(hash_proof, hash_opinion)
      const signature = eddsa.signMiMCSponge(prvKey, proof_leaf);
      assert(eddsa.verifyMiMCSponge(proof_leaf, signature, pubKey));

      sig_R8.push([signature.R8[0], signature.R8[1]])
      sig_S.push(signature.S)

      external_proofs.push(hash_proof)
      opinions.push(hash_opinion)

      pf_path_index.push(proof_path[i].path_index)
      pf_path_elements.push(proof_path[i].path_elements)
      roots.push(proof_path[i].root)
    }

    
    return {
        'node_pk[0]': pubKey[0],
        'node_pk[1]': pubKey[1],
        'sig_r': sig_R8,
        'sig_s': sig_S,

        'proof_root': roots, 
        'proof_external_proof': external_proofs,
        'proof_opinion': opinions,
        'pf_path_elements': pf_path_elements,
        'pf_path_paths': pf_path_index,

        // 'new_proof_root': roots[roots.length-1], 
        'ballots': ballots,
        fake_zero: bigInt(0),
    };
}

function hashKeccak(msgStr) {
  const hash_hex = ethers.utils.solidityKeccak256(
    ['string'],
    [msgStr],
  );
  return bigInt.beBuff2int(Buffer.from(hash_hex.slice(2), 'hex'))/bigInt(8);
}

function get_proof_leaf(hashedProof, hashedOpinion) {
  return mimc7.multiHash([hashedProof/bigInt(8), hashedOpinion/bigInt(8)])
}

function get_proof_hash(proof, opinion) {

  // serialize proof
  const serialized_proof = proof.trim()

  const proof_hash = hashKeccak(serialized_proof)
  const opinion_hash = hashKeccak(opinion)

  return get_proof_leaf(proof_hash, opinion_hash)
}

module.exports = {
  rollup,
  get_proof_hash,
};
