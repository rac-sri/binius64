# CIRCUITS CRATE

**Location:** `crates/circuits/`

## OVERVIEW
Pre-built circuits for common cryptographic operations: hash functions, bigint arithmetic, and hash-based signatures. These circuits provide reusable building blocks for constructing larger proof systems.

## STRUCTURE
```
crates/circuits/
├── src/
│   ├── hash_based_sig/  # Hash-based signature circuits
│   ├── bignum/          # Big integer arithmetic
│   └── lib.rs          # Public API
└── tests/               # Circuit tests
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Hash circuits | `src/hash_based_sig/` | Circuit implementations |
| Bigint ops | `src/bignum/` | Arithmetic circuits |
| Circuit composition | `src/lib.rs` | Builder patterns |

## CONVENTIONS
- Circuits use `CircuitBuilder` API from frontend
- Each circuit module documents input/output constraints
- Tests verify circuit correctness against reference implementations
- Generic, field-parameterized components for maximum reuse

## ANTI-PATTERNS
- Monolithic gadgets: avoid one-off, large circuits that choke reuse
- Non-circuit logic: keep IO, crypto wallet wiring, and external systems out of gadget internals
- Divergent interfaces: maintain consistent gadget APIs to ease composition and testing
- Premature optimization: validate correctness first; benchmark after correctness proofs
- Over-abstracting: guard against creating too many tiny primitives that hinder understandability
