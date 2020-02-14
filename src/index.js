const rollup = require('./zkvote_rollup.js')
const proof = require('./proof_generation.js');
// const tool = require('./witness_conversion.js')
const fs = require('fs');

const snarkjs = require('snarkjs');
const bigInt = snarkjs.bigInt;

const circomlib = require('circomlib');
const mimcsponge = circomlib.mimcsponge;
const mimc7 = circomlib.mimc7;

// const {unstringifyBigInts, stringifyBigInts} = require('websnark/tools/stringifybigint.js');

const proofA = `
"proof":{
  "pi_a":[ "13862018769176408654557878303258422977372570156005950906750594914905072002550",
           "4683975830196691695306757075679551580096470187515470380016494066127874235242",
           "1"],
  "pi_b":[
      ["13453527910197148610782466478305274651058561032671752335650864014243061704434",
       "18645189788145486135271375816065576109987315148200112683784638537012650254313"],
      ["7734517262166638900371489950583935871298182578768415897690240336787394743748",
       "17921050622246768150421692105356526988744674913910765693395209944024270764742"],
      ["1","0"]
      ],
  "pi_c":[ "10453716040370598269972525081195272028544145906517562336151947320924833345260",
           "5790724294985261956879165436587583053935971877177314513395693636995449909160",
           "1"]
  }`

const proofB = `
"proof":{
    "pi_a":["5130864991510516020589301482816385045114505165388788331277364659354435182810",
            "14624787538719710071561135714681794820435278427338354053426473370895245586473",
            "1"],
    "pi_b":[
      ["2519751358858314680632043259616681530636461459914595622833863468231886154181",
       "14851006424341806526548437698456612289914012850227010536650813352300674130470"],
      ["19829824757938655441339463777969715228589298658301180511998154963361744586767",
       "20709947025569446219123821817494267516151918988747204458454289801481828597513"],
      ["1","0"]
    ],
    "pi_c":["15724995963652449382424287839617233008320513085948692491849187549005477915174",
            "19274913245849688437675507118686581038440252759771900156316348927882003233743",
            "1"]
  }`

let tree_level0 = []
let build_full_merkle_tree_example = (n_levels, index, content) => {
    let tree = [];
    let current_index = index;
    let path_index = [];
    let path_elements = [];
    for (let i = 0; i < n_levels; i++) {
      let tree_level = [];
      path_index.push(current_index % 2);
      for (let j = 0; j < Math.pow(2, n_levels - i); j++) {
        if (i == 0) {
          if (j == index) {
            tree_level0[j] = bigInt(content);
          } else if (j > index) {
            tree_level0[j] = bigInt(bigInt(0));
          }
          tree_level[j] = tree_level0[j];
        } else {
        //   tree_level.push(mimcsponge.multiHash([ tree[i-1][2*j], tree[i-1][2*j+1] ]));
            let h = mimc7.multiHash([ tree[i-1][2*j]/bigInt(8), tree[i-1][2*j+1]/bigInt(8) ])
            // let h = privateVote.pedersenHash( [tree[i-1][2*j], tree[i-1][2*j+1]] );
            tree_level.push(h);
            // console.log(h)
        }
      }
      // if (i !=0)
      //   console.log(tree_level)

      if (current_index % 2 == 0) {
        path_elements.push(tree_level[current_index + 1]);
      } else {
        path_elements.push(tree_level[current_index - 1]);
      }

      tree.push(tree_level);
      current_index = Math.floor(current_index / 2);
    }

    // const root = mimcsponge.multiHash([ tree[n_levels - 1][0], tree[n_levels - 1][1] ]);
    const root = mimc7.multiHash([ tree[n_levels - 1][0]/bigInt(8), tree[n_levels - 1][1]/bigInt(8) ]);
    // let root = privateVote.pedersenHash([ tree[n_levels - 1][0], tree[n_levels - 1][1] ]);
    console.log("root", root)
    // console.log("tree 0 ", tree_level0)

    return [root,  path_elements, path_index];
};

let merkle_tree_test = (initValue) => {

  initValue = mimc7.multiHash([
    bigInt("2712799187491703030545327092023188527282581638717183267978071744305068724021")/bigInt(8), 
    bigInt("5049852429172545234685423733264756719186878340966653445126005684620919008623")/bigInt(8)
  ])
  const vectors = [
    bigInt(0),
    bigInt("3089049976446759283073903078838002107081160427222305800976141688008169211302"),
    bigInt("3314128016301011542915539277173583244242761185745326814725302780613031871979"),
    bigInt("11256653678364010982051633452980802814987439238877888822347951837402798142953")
  ]
  let currentHash = initValue
  console.log(currentHash)
  for (var i=0; i<vectors.length; i++) {
    currentHash = mimc7.multiHash([currentHash/bigInt(8), vectors[i]/bigInt(8)])
    console.log(currentHash)
  }
  console.log("TEST: ", currentHash)
}

const gen = async () =>{

  const cir_def = JSON.parse(fs.readFileSync('./snark_data/circuit.json', 'utf8'));
  const proving_key = JSON.parse(fs.readFileSync('./snark_data/proving_key.json', 'utf8'));
  // const proving_key = fs.readFileSync('../snark_data/proving_key.bin');
  const verification_key = JSON.parse(fs.readFileSync('./snark_data/verification_key.json', 'utf8'));
  

  // console.log("Proof conversion...")
  // let now = Date.now()
  // var pk = new ArrayBuffer(proving_key.length);
  // var arr = new Uint32Array(pk);
  // for (var i=0; i<proving_key.length/4; i++) {
  //     arr[i] = new Uint32Array(proving_key.buffer.slice(4*i, 4*i+4))
  // }
  // console.log(`proof conversion (took ${Date.now()-now} msecs)`);

  const private_key = "00010203040506070809000102030405060708090001020304050607080900ff"
  let proof_path = []
  let proofs = []
  for (let i=0; i<3; i++) {
    if(i%2 == 0)
      proofs.push({"proof":proofA, "opinion":"YES"})
    else 
      proofs.push({"proof":proofB, "opinion":"NO"})

    const tree = build_full_merkle_tree_example(4, i, rollup.get_proof_hash(String(proofs[i].proof), String(proofs[i].opinion)))
    // console.log(tree)
    // merkle_tree_test(rollup.get_proof_hash(String(proofs[i].proof), String(proofs[i].opinion)))
    proof_path.push({
      "root": tree[0],  
      "path_elements":tree[1], 
      "path_index":   tree[2],   
    })
  }
  // console.log(proof_path)
  const rollup_proof = await proof.generateProof(
      cir_def,
      proving_key,
      verification_key,
      private_key, 
      proofs,
      proof_path, 
      [0, 0]
  )
  // const file = "vote" + i + ".proof"
  // fs.writeFileSync(file, JSON.stringify(rollup_proof), "utf8");
  console.log("output\n", rollup_proof)
};

gen()
