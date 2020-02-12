
include "../node_modules/circomlib/circuits/mimc.circom"
include "../node_modules/circomlib/circuits/bitify.circom";
include "../node_modules/circomlib/circuits/eddsamimcsponge.circom";

template ShiftRight(n, shf) {
    signal input in;
    signal output out;

    component bits = Num2Bits(n);
    bits.in <== in;
    component num = Bits2Num(n);
    for (var i=0; i<n-shf; i++) {
        num.in[i] <== bits.out[i+shf];
    }
    for (var i=n-shf; i<n; i++) {
        num.in[i] <== 0;
    }
    out <== num.out;
}

template HashLeftRight() {
  signal input left;
  signal input right;

  signal output hash;

  component left_shift = ShiftRight(256, 3);
  left_shift.in <== left;
  component right_shift = ShiftRight(256, 3);
  right_shift.in <== right;

  component hasher = MultiMiMC7(2, 91);
  left_shift.out ==> hasher.in[0];
  right_shift.out ==> hasher.in[1];
  hasher.k <== 0;

  hash <== hasher.out;
}


template Selector() {
  signal input input_elem;
  signal input path_elem;
  signal input path_index;

  signal output left;
  signal output right;

  signal left_selector_1;
  signal left_selector_2;
  signal right_selector_1;
  signal right_selector_2;

  path_index * (1-path_index) === 0

  left_selector_1 <== (1 - path_index)*input_elem;
  left_selector_2 <== (path_index)*path_elem;
  right_selector_1 <== (path_index)*input_elem;
  right_selector_2 <== (1 - path_index)*path_elem;

  left <== left_selector_1 + left_selector_2;
  right <== right_selector_1 + right_selector_2;
}

template GetMerkleRoot(levels) {

    signal input leaf;
    signal input path_index[levels];
    signal input path_elements[levels];

    signal output out;

    component selectors[levels];
    component hashers[levels];

    for (var i = 0; i < levels; i++) {
      selectors[i] = Selector();
      hashers[i] = HashLeftRight();

      path_index[i] ==> selectors[i].path_index;
      path_elements[i] ==> selectors[i].path_elem;

      selectors[i].left ==> hashers[i].left;
      selectors[i].right ==> hashers[i].right;
    }

    leaf ==> selectors[0].input_elem;

    for (var i = 1; i < levels; i++) {
      hashers[i-1].hash ==> selectors[i].input_elem;
    }

    out <== hashers[levels - 1].hash;
}

template HashMultiInputs(n) {

    signal input ins[n];
    signal output out;

    component shifted_ins[n];
    for (var i=0; i<n; i++) {
        shifted_ins[i] = ShiftRight(256, 3);
        shifted_ins[i].in <== ins[0]
    }

    component hasher = MultiMiMC7(n, 91);
    for (var i=0; i<n; i++) {
        hasher.in[i] <== shifted_ins[i].out;
    }
    hasher.k <== 0;

    out <== hasher.out;
}

template calcBallot() {
    var OPINIONS = [
        43379584054787486383572605962602545002668015983485933488536749112829893476306,  // YES
        85131057757245807317576516368191972321038229705283732634690444270750521936266   // NO
    ];

    signal input opinion;
    signal output yes;
    signal output no;
    
    component compYes = IsEqual()
    compYes.in[0] <== opinion;
    compYes.in[1] <== OPINIONS[0];
    yes <== compYes.out;

    component compNo = IsEqual()
    compNo.in[0] <== opinion;
    compNo.in[1] <== OPINIONS[1];
    no <== compNo.out;
}

//"proof":{
    // "pi_a":[ "13862018769176408654557878303258422977372570156005950906750594914905072002550",
    //          "4683975830196691695306757075679551580096470187515470380016494066127874235242",
    //          "1"],
    // "pi_b":[
        // ["13453527910197148610782466478305274651058561032671752335650864014243061704434",
        //  "18645189788145486135271375816065576109987315148200112683784638537012650254313"],
        // ["7734517262166638900371489950583935871298182578768415897690240336787394743748",
        //  "17921050622246768150421692105356526988744674913910765693395209944024270764742"],
        // ["1","0"]
        // ],
    // "pi_c":[ "10453716040370598269972525081195272028544145906517562336151947320924833345260",
    //          "5790724294985261956879165436587583053935971877177314513395693636995449909160",
    //          "1"]
    // }
template zkVoteRollup(nTx, nLevels) {

    signal input new_proof_root;
    signal input ballot_Yes;     // TODO: to weak..., try to binding with other state
    signal input ballot_No;
    signal input fake_zero;

    // content of proof tree
    signal private input proof_root[nTx];
    signal private input proof_external_proof[nTx];  // hash of semaphore proof
    signal private input proof_opinion[nTx];         // hash of "YES" or "NO"

    signal private input pf_path_elements[nTx][nLevels];
    signal private input pf_path_paths[nTx][nLevels];

    // signature on hash(proof) with node_pk
    signal private input sig_r[2];
    signal private input sig_s;
    signal private input node_pk[2];

    // output
    // signal output out_final_proof_root // pf_root[nTx-1]
    signal output out_final_Yes;
    signal output out_final_No;

    out_final_Yes <== ballot_Yes;
    out_final_No <== ballot_No;

    component hashedLeaf[nTx];
    component sig_verifier[nTx];
    component intermTree[nTx];
    component ballot[nTx];
    for (var i=0; i<nTx; i++) {
        
        // 0. get merkle leaf
        hashedLeaf[i] = HashMultiInputs(2);
        hashedLeaf[i].ins[0] <== proof_external_proof[i]
        hashedLeaf[i].ins[0] <== proof_opinion[i]

        // 1. verify signature
        sig_verifier[i] = EdDSAMiMCSpongeVerifier();
        sig_verifier[i].Ax <== node_pk[0];
        sig_verifier[i].Ay <== node_pk[1];
        sig_verifier[i].R8x <== sig_r[0];
        sig_verifier[i].R8y <== sig_r[1];
        sig_verifier[i].S <== sig_s;
        sig_verifier[i].M <== hashedLeaf[i].out;
        sig_verifier[i].enabled <== (1 - fake_zero);

        // 2. check each tx(proof)
        intermTree[i] = GetMerkleRoot(nLevels);
        intermTree[i].leaf <== hashedLeaf[i].out;
        for (var j=0; j<nLevels; j++) {
            intermTree[i].path_index[j] <== pf_path_paths[i][j];
            intermTree[i].path_elements[j] <== pf_path_elements[i][j];
        }
        intermTree[i].out === proof_root[i];

        // 3. update ballot
        ballot[i] = calcBallot();
        ballot[i].opinion <== proof_opinion[i];
        out_final_Yes <== out_final_Yes + ballot[i].yes;
        out_final_No <== out_final_No + ballot[i].no;
    }

    new_proof_root === proof_root[nTx - 1];
}

component main = zkVoteRollup(3, 4);