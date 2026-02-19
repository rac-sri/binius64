# PROJECT KNOWLEDGE BASE

**Generated:** Mon, Feb 9, 2026
**Commit:** 2fdae0f
**Branch:** main

## OVERVIEW
Binius64 is a zero-knowledge succinct argument system (zk-SNARK) implemented in Rust, optimizing for CPU performance with 64-bit word arithmetic and SIMD instructions.

## STRUCTURE
```
binius64/
├── crates/          # 21 workspace crates
│   ├── field/       # Core tower field arithmetic
│   ├── prover/      # Proof generation
│   ├── verifier/    # Proof verification
│   ├── frontend/    # Circuit building DSL
│   ├── circuits/    # Pre-built circuits
│   └── math/        # Mathematical primitives
├── tools/
└── examples/
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Proving | `crates/prover/` | Core proving logic |
| Verification | `crates/verifier/` | Verifier entry points |
| Field operations | `crates/field/` | Tower fields T_i |
| Circuit building | `crates/frontend/` | `CircuitBuilder` API |
| Sumcheck protocol | `crates/ip-prover/src/sumcheck/` | Interactive proof |
| Standard circuits | `crates/circuits/src/` | Hash functions, bigint |
| Examples | `crates/examples/examples/` | CLI demos |

## CODE MAP
| Symbol | Type | Location | Role |
|--------|------|----------|------|
| `binius_prover` | Crate | `crates/prover/` | Main proving API |
| `binius_verifier` | Crate | `crates/verifier/` | Main verifying API |
| `binius_field` | Crate | `crates/field/` | Tower field arithmetic |
| `binius_frontend` | Crate | `crates/frontend/` | Circuit DSL |
| `CircuitBuilder` | Struct | `crates/frontend/src/` | Entry for circuit construction |

## CONVENTIONS

### Error Handling
- **Prover**: May assume witness is satisfying; panics on invalid witness are acceptable
- **Verifier**: Must return `VerificationError` for invalid proofs; never panic on untrusted input

### Type Parameters
- `F`: Field parameter
- `P`: PackedField parameter
- `FSub`, `FDomain`, `FEncode`: Subfield variants for prover optimizations

### Build
- Use nightly rustfmt: `cargo +nightly fmt`
- Performance: `export RUSTFLAGS="-C target-cpu=native"`
- Clippy strict: `-D warnings`
- CI uses GitHub Actions (see `.github/workflows/`)

## ANTI-PATTERNS
- **DO NOT** use `unwrap` in verifier code
- **DO NOT** use Rayon in verifier; **DO** use in prover for performance
- **DO NOT** suppress type errors with `as any` or `@ts-ignore` (TypeScript projects only)

## COMMANDS
```bash
cargo build --release        # Optimized build with native CPU features
cargo test -p <crate>        # Test specific crate
cargo bench                  # Run benchmarks
pre-commit run --all-files   # CI checks locally
```

## NOTES
- Workspace organized by architectural layer (prover/verifier/frontend)
- `examples/` contains CLI executables and benchmarks
- Protocol spec lives in separate repo: `../binius.xyz` or https://www.binius.xyz/blueprint
- Well-documented crates: `binius-field`, `binius-frontend`, `binius-spartan-frontend`
