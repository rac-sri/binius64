# MATH CRATE

**Location:** `crates/math/`

## OVERVIEW
Foundational mathematical primitives for Binius64: finite field arithmetic, polynomial algebra, and linear algebra. Underpins cryptographic primitives and protocol implementations with focus on correctness and performance.

## STRUCTURE
```
crates/math/
└── src/
    ├── field/             # Finite field operations
    ├── polynomials/       # Univariate/multivariate polynomials
    ├── linear_algebra/    # Vectors, matrices, solvers
    ├── fft_ntt/          # Fast transforms
    └── interpolation/     # Lagrange/barycentric interpolation
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Polynomial operations | `src/polynomials/` | Arithmetic, evaluation, root-finding |
| Linear algebra | `src/linear_algebra/` | Matrix operations, solvers |
| Field operations | `src/field/` | Finite field arithmetic |
| Protocol math | `src/` | Sumcheck, consistency checks |

## CONVENTIONS
- **Naming**: Coefficients ordered ascending; domain conventions documented per module
- **Invariants**: Precondition contracts (asserts) for zero-division, domain validity, dimension checks
- **Performance**: Zero-allocation paths; FFT/NTT-based algorithms where possible
- **API design**: Trait-based abstractions over Field/Num with clear, minimal public surfaces
- **Testing**: Algebraic laws and cryptographic primitive correctness tests

## ANTI-PATTERNS
- Avoid floating-point arithmetic in core math; rely on exact finite-field operations
- Do not implement cryptographic primitives without constant-time considerations
- Avoid exposing internal field representations; prefer abstract traits
- No unsafe blocks in public math APIs; limit unsafe to performance-critical kernels
- Do not duplicate algorithms across modules; factor common patterns into utilities
- Do not bypass invariants with panics in verifier paths; prefer Result/Error propagation
