# FIELD CRATE

**Location:** `crates/field/`

## OVERVIEW
Implements binary tower fields T_i = F_{2^{2^i}} for efficient arithmetic in Binius64. Provides scalar fields (`Field`) and SIMD-packed fields (`PackedField`) with hardware-specific optimizations (x86_64, portable).

## STRUCTURE
```
crates/field/
├── src/
│   ├── arch/
│   │   ├── x86_64/       # AVX2/AVX512 optimizations
│   │   └── portable/     # Fallback implementations
│   ├── underlier/        # Underlying storage types
│   └── lib.rs           # Public API
└── benches/             # Performance benchmarks
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| Field traits | `src/lib.rs` | `Field`, `PackedField` definitions |
| x86_64 optimizations | `src/arch/x86_64/` | SIMD implementations |
| Portable fallbacks | `src/arch/portable/` | Cross-platform code |
| Tower field ops | `src/` | T_i arithmetic implementations |
| Type parameters | Throughout | `F: Field`, `P: PackedField` |

## CONVENTIONS
- Hardware-specific code isolated in `arch/` modules
- Use `PackedField` for prover performance, `Field` for verifier
- Tower field indices: T_7 = F_{2^128}, T_8 = F_{2^256}, etc.
- Underlier types abstract over `[u64; N]`, `u128`, etc.

## ANTI-PATTERNS
- Do not mix scalar and packed field operations without explicit conversion
- Do not bypass `arch` module - always go through public API
