# TODOs

 - PVSS transcript needs to contain a PoK of the dealt secret. Otherwise, last dealer can decide the randomness.
 - PVSS transcript needs to contain a signature from the dealer on $g^s$, such that we can tell where an aggregated transcript was aggregated from.
   + Ideally, these two can be combined into one, al a [GJM+21]
 - accumulator_poly uses hard-coded FFT threshold to decide when to switch between slow/fast implementations

# Notes

We (mostly) rely on the `aptos-crypto` `SerializeKey` and `DeserializeKey` derives for safety during deserialization.
Specifically, each cryptographic object (e.g., public key, public parameters, etc) must implement `ValidCryptoMaterial` for serialization and `TryFrom` for deserialization when these derives are used.

The G1/G2 group elements in `blstrs` are deserialized safely via calls to `from_[un]compressed` rather than calls to `from_[un]compressed_unchecked` which does not check prime-order subgroup membership.

Our structs use $(x, y, z)$ projective coordinates, for faster arithmetic operations.
During serialization, we convert to more succinct $(x, y)$ affine coordinates.

# Cargo flamegraphs

Example: You indicate the benchmark group with `--bench` and then you append part of the benchmark name at the end (e.g., `accumulator_poly/` so as to exclude `accumulator_poly_slow/`)
```
sudo cargo flamegraph --bench 'crypto' -- --bench accumulator_poly/
```
