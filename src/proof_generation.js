const rollup = require('./zkvote_rollup.js')
const snarkjs = require("snarkjs");
const snarkjsStringify = require('snarkjs/src/stringifybigint.js');
const websnarkStringify =  require('websnark/tools/stringifybigint.js');
const chai = require('chai');
const assert = chai.assert;
const converter = require('./witness_conversion.js')
const websnark = require('websnark')

const generateWitness = async function(cir_def, prvKey, proofs, proof_path, ballots) {
    try {
        let now = Date.now();
        const inputs = rollup.rollup(prvKey, proofs, proof_path, ballots)
        console.log(`inputs:`, inputs);

        // 
        // calculating witness
        //
        now = Date.now();
        const circuit = new snarkjs.Circuit(cir_def);
        console.log("Witness calculating...")
        const w = circuit.calculateWitness(inputs);
        console.log(`calculating witness (took ${Date.now() - now} msecs)`);
        assert(circuit.checkWitness(w));

        const wtmp = websnarkStringify.unstringifyBigInts(JSON.parse(JSON.stringify(snarkjsStringify.stringifyBigInts(w))))
        const wb = converter.convert_witness(wtmp)
        
        //
        // verify witness content
        //
        const root = w[circuit.getSignalIdx('main.new_proof_root')];
        // console.log(`root from proof:`, root);
        assert.equal(root.toString(), proof_path[proof_path.length-1].root);
    
        let publicSignals = w.slice(1,  circuit.nPubInputs+circuit.nOutputs+1);
        
        return {
            "witness":wb,
            // "witness":w,
            "signals":publicSignals, 
            "root": root,
            "ballot_YES": w[circuit.getSignalIdx('main.out_final_Yes')],
            "ballot_NO": w[circuit.getSignalIdx('main.out_final_No')]
        }
    }
    catch(e) {
        console.log(e)
    }
}

const generateProof = async function(cir_def, proving_key, verification_key, prvKey, proofs, proof_path, ballots) {

    try {
        const w = await generateWitness(cir_def, prvKey, proofs, proof_path, ballots)
        if(typeof w === "undefined") {
            console.log("generate witness error !!")
            return w
        }

        //
        // generating proof
        //
        const bn128 = await websnark.buildBn128()
        now = Date.now()
        console.log("Proof generating...")
        const proof = await bn128.groth16GenProof(w.witness, proving_key)
        // const {proof, publicSignals} = snarkjs.groth.genProof(snarkjsStringify.unstringifyBigInts(proving_key), w.witness);
        console.log(`generating proof (took ${Date.now()-now} msecs)`);
    
        // assert(snarkjs.groth.isValid(snarkjsStringify.unstringifyBigInts(verification_key), proof, publicSignals));
        assert.isTrue(
            snarkjs.groth.isValid(
                snarkjsStringify.unstringifyBigInts(verification_key), snarkjsStringify.unstringifyBigInts(proof), w.signals
        ));

        return {
            "root": w.root.toString(),
            "ballots" : [w.ballot_YES, w.ballot_NO],
            "proof": snarkjsStringify.stringifyBigInts(proof),
            "public_signal": snarkjsStringify.stringifyBigInts(w.signals)
        }
    }
    catch(e) {
        console.log(e)
    }
}

exports.generateProof = generateProof
exports.generateWitness = generateWitness