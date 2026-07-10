# Protocol Closure Check Matrix

This matrix records the safe Phase 0 commands for local and CI-style protocol
work. Commands use the vendored dependency tree and must not require live network
access.

## Required baseline

```bash
CARGO_NET_OFFLINE=true cargo metadata --locked --offline --no-deps --format-version 1
CARGO_NET_OFFLINE=true cargo check --workspace --locked
```

## Safe default tests

```bash
CARGO_NET_OFFLINE=true cargo test -p aetheris-core --locked
CARGO_NET_OFFLINE=true cargo test -p aetheris-crypto --locked
CARGO_NET_OFFLINE=true cargo test -p aetheris-zkp --locked
CARGO_NET_OFFLINE=true cargo test -p aetheris-ffi --lib --locked -- --test-threads=1
CARGO_NET_OFFLINE=true cargo test -p aetheris-recursive --lib --locked -- --test-threads=1
```

Do not run the whole workspace test suite as the default safety check. Recursive
K=17/K=18 circuit tests are marked `#[ignore]` and must be selected explicitly
by name when a phase needs them.

## Heavy recursive tests

Run ignored recursive circuit tests only with a name filter and limited
parallelism, for example:

```bash
CARGO_NET_OFFLINE=true cargo test -p aetheris-recursive --lib --locked test_ecc_scalar_mul -- --ignored --test-threads=1
```

Never run all ignored recursive tests at once on memory-constrained machines.
