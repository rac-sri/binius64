# FRONTEND CRATE

**Location:** `crates/frontend/`

## OVERVIEW
Provides the Circuit DSL for Binius64, enabling circuit construction via `CircuitBuilder` API. Handles gate compilation, constraint generation, and circuit optimization through a compilation pipeline.

## STRUCTURE
```
crates/frontend/
├── src/                    # Core DSL types, CircuitBuilder, wiring primitives
├── ceck/                   # Lightweight validation checks during circuit construction
└── src/compiler/
    └── gate/               # Concrete gate implementations (AND, OR, XOR, etc.)
```

## WHERE TO LOOK
| Task | Location | Notes |
|------|----------|-------|
| CircuitBuilder API | `src/lib.rs` | Main entry point for constructing circuits |
| Gate implementations | `src/compiler/gate/` | Individual gate modules and traits |
| Compilation pipeline | `src/compiler/` | Lowering circuits to constraint systems |

## CONVENTIONS
- DSL patterns use builder-style workflow: declare wires, instantiate gates, chain constraints
- Circuit composition: small primitives that compose into larger components
- Compilation passes: normalization, gate fusion, constraint generation
- Clear separation between frontend construction and backend constraint logic

## ANTI-PATTERNS
- Over-abstracting DSL with excessive macro gymnastics that hinder readability
- Mixing frontend construction logic with backend constraint details
- Ignoring validation checks during construction; rely on ceck validation early
- Duplicating gate definitions across modules
