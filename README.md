# zkvote-rollup
Roll up ballots of zkvote

The idea of zkvote-rollup is from zk-rollup. Here, we rollup the ballot results of [zkvote](https://github.com/Unitychain/zkvote-node). 

In zk-rollup, registration is required to insert your account info(balance, public key, nonce... etc.) into a merkle tree and transactions will update the state of the accounts.

In zkvote-rollup, the tree leaves are proofs (zkvote proofs) so we don't 'update' the leaves, we just insert new proofs into the tree (just like registration in zk-rollup). In this PoC, we only aggregate proofs and update ballot results of a single subject.
Operator aggregates new proofs from the network and signs every individual `hash(proof)`. Operators need to deposit first, if any operator is doing anything unexpected, he/she will be punished. The design of deposit/punishment will be in the next phase.

### Data structure
- `proof` : (external_proof, opinion)
  - `external_proof` :  hash of zkvote proof
  - `opinion` : hash of string, "YES" or "NO" 
- `ballot` : [num of Yes, num of No]
