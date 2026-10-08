# kno-org localnet branch

This branch starts at Agave v3.1.7 and is used by the four-validator solK test cluster.
Its patched Crossbeam dependency is compiled from the sibling `../crossbeam`
checkout of `https://github.com/kno-org/crossbeam`, branch `solk-localnet`.
Clone both repositories beside one another, or use the solK source build workflow.
The dependency lock keeps the original crates.io resolutions while using that local source.

The Docker build sets `CI_COMMIT` to this checkout's exact commit. CLI version
output and gossip metadata therefore identify the fork revision rather than a
random source identifier. Local uncommitted edits are recorded separately by
the solK source digest. Standard Rust and Solana SBF toolchains remain external
build tools; this branch does not modify consensus or protocol versions.
