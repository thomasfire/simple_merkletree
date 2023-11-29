# Just simple script for generating correct data for testing the Rust implementation

from pymerkle import InmemoryTree as MerkleTree

tree = MerkleTree.init_from_entries([b'\x00', b'\x01', b'\x02', b'\x03'], algorithm='sha256', disable_security=True)

print(tree.get_state().hex())
print(list(map(lambda x: x.hex(), tree.prove_inclusion(1).path)))
print(list(map(lambda x: x.hex(), tree.prove_inclusion(2).path)))
print(list(map(lambda x: x.hex(), tree.prove_inclusion(3).path)))
print(list(map(lambda x: x.hex(), tree.prove_inclusion(4).path)))

print("-------\n")


tree = MerkleTree.init_from_entries([b'\x00', b'\x01', b'\x02'], algorithm='sha256', disable_security=True)

print(tree.get_state().hex())
print(list(map(lambda x: x.hex(), tree.prove_inclusion(1).path)))
print(list(map(lambda x: x.hex(), tree.prove_inclusion(2).path)))
print(list(map(lambda x: x.hex(), tree.prove_inclusion(3).path)))