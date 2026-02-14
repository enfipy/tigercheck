# tigercheck

> WARNING: tigercheck is in the early stages of development, expect interface changes, rules modification, feature additions/removals/modifications.

**Deterministic safety and conformance enforcement for Zig.**

The goal of tigercheck is to turn NASA Power of 10, TigerStyle, and TigerBeetle guidance into repeatable static checks with stable rule IDs and CI-friendly output.

## Why tigercheck

- Deterministic checks: every rule maps to an explicit enforcement mechanism.
- Strict-by-default behavior: warnings and critical diagnostics fail CI.
- Policy-aware profiles: run strict core or TigerBeetle repository mode.
- Precision gates: track FP/FN deltas per rule against a committed baseline.

## Quick Start

Requires Zig `0.16.0-dev`.

```bash
./zig/zig build
./zig/zig build run -- src/
```

Common commands:

```bash
# Explain policy suppressions/downgrades
./zig/zig build run -- --profile tigerbeetle_repo --explain-policy ./tigerbeetle/src

# Explain strict-core rewrites
./zig/zig build run -- --profile strict_core --explain-strict ./src

# Dump call graph
./zig/zig build run -- --dump-graph ./src
```

Diagnostic shape:

```text
[CRITICAL] src/foo.zig:88:17 [N02_BOUNDED_LOOPS] all loops must have static bounds; loop bound depends on runtime input
        rewrite: clamp bound with explicit max and assert the cap
```

## Unified Rule Catalog

CLI diagnostics use the IDs below. This is the canonical catalog for NASA, TigerStyle, and TigerBeetle checks.

| Family | Rules | Status |
| --- | ---: | --- |
| NASA | 10 | Enforced |
| TigerStyle | 26 | Enforced |
| TigerBeetle | 5 | Enforced |

<details>
<summary><strong>NASA Rules (N01-N10)</strong></summary>

| ID | Enforcement Mechanism | Status |
| --- | --- | --- |
| `N01_CONTROL_FLOW` | AST ban list (`goto`/`setjmp`/`longjmp`) + whole-program cycle detection | Enforced |
| `N02_BOUNDED_LOOPS` | Interprocedural loop-bound proof with taint propagation | Enforced |
| `N03_STATIC_MEMORY` | Phase-colored allocation analysis (`INIT=green`, `RUN=red`, `MIXED=amber`) | Enforced |
| `N04_FUNCTION_SIZE` | Normalized logical-line counter with hard function-length ceiling | Enforced |
| `N05_ASSERTION_DENSITY` | Per-function assertion density and side-effect safety checks | Enforced |
| `N06_SCOPE_MINIMIZATION` | Scope-width analysis, global audit, declaration-locality checks | Enforced |
| `N07_RETURN_AND_PARAM_CHECKS` | Unchecked non-void return detection + parameter-guard coverage | Enforced |
| `N08_PREPROCESSOR_OR_COMPTIME_BUDGET` | Comptime complexity budget + hidden-control-flow pattern bans | Enforced |
| `N09_POINTER_DISCIPLINE` | Pointer dereference-depth limits + function-pointer policy checks | Enforced |
| `N10_PEDANTIC_PIPELINE` | Strict compiler-warning gate plus analyzer integration | Enforced |

</details>

<details>
<summary><strong>TigerStyle Rules (TS01-TS26)</strong></summary>

| ID | Enforcement Mechanism | Status |
| --- | --- | --- |
| `TS01_SIMPLE_FLOW` | Reuse `N01_CONTROL_FLOW` + explicit-flow style checks | Enforced |
| `TS02_EXPLICIT_BOUNDS` | Reuse `N02_BOUNDED_LOOPS` + bounded-queue checks | Enforced |
| `TS03_FIXED_WIDTH_TYPES` | Detect architecture-sized integer leakage (`usize/isize`) at boundaries | Enforced |
| `TS04_ASSERTIONS` | Assertion presence for argument/return/invariant contracts | Enforced |
| `TS05_PAIR_ASSERT` | Pair-invariant enforcement across independent paths | Enforced |
| `TS06_POS_NEG_ASSERT` | Positive-space and negative-space assertion coverage | Enforced |
| `TS07_MEMORY_PHASE` | Reuse `N03_STATIC_MEMORY` startup-only allocation policy | Enforced |
| `TS08_SCOPE` | Reuse `N06_SCOPE_MINIMIZATION` for smallest declaration scope | Enforced |
| `TS09_FUNCTION_SHAPE` | TigerStyle hard limit function-size policy (70-line default profile) | Enforced |
| `TS10_PEDANTIC` | Zero-warning compiler policy gate | Enforced |
| `TS11_PACED_CONTROL` | Reject direct external-event mutation without batching boundary | Enforced |
| `TS12_PLANE_BOUNDARY` | Control-plane/data-plane boundary checks and complexity ceilings | Enforced |
| `TS13_BOOLEAN_SPLIT` | Reject compound boolean density in critical branches | Enforced |
| `TS14_POSITIVE_INVARIANTS` | Prefer positive invariant forms in boundary checks | Enforced |
| `TS15_ERROR_HANDLING` | Detect silent catch suppression and discarded fallible results | Enforced |
| `TS16_EXPLICIT_OPTIONS` | Detect default-option reliance in sensitive call sites | Enforced |
| `TS17_SNAKE_CASE` | Function/variable/file naming policy + structural naming checks | Enforced |
| `TS18_ACRONYM_CASE` | Acronym capitalization policy | Enforced |
| `TS19_UNIT_SUFFIX_ORDER` | Units/qualifiers suffix-order policy | Enforced |
| `TS20_NO_ABBREVIATION` | Abbreviation denylist with domain exceptions | Enforced |
| `TS21_CALLBACK_LAST` | Callback-last signature policy | Enforced |
| `TS22_STRUCT_ORDER` | Struct declaration order policy (fields, types, methods) | Enforced |
| `TS23_LARGE_ARG_POINTER` | By-value large-argument enforcement (`*const` preference) | Enforced |
| `TS24_IN_PLACE_INIT` | Large-struct return-by-value detection + out-pointer recommendation | Enforced |
| `TS25_IF_BRACES` | If-brace safety policy (single-line exception) | Enforced |
| `TS26_LINE_LENGTH` | 100-column line-length ceiling after normalization | Enforced |

</details>

<details>
<summary><strong>TigerBeetle Rules (TB01-TB05)</strong></summary>

| ID | Enforcement Mechanism | Status |
| --- | --- | --- |
| `TB01_ALIASING` | Pointer-parameter overlap risk detector | Enforced |
| `TB02_ASSERT_ALIAS` | Ban qualified `std.debug.assert`; require local `assert` alias | Enforced |
| `TB03_COPY_API` | Ban raw copy APIs; require explicit `stdx` copy helpers | Enforced |
| `TB04_CONTEXT_BUNDLE` | Require context bundling for repeated walker plumbing signatures | Enforced |
| `TB05_TAG_DISPATCH` | Prefer direct tag dispatch over repeated tag-set guards | Enforced |

</details>

## Profiles and Build Steps

- Profiles:
  - `strict_core` (default)
  - `tigerbeetle_repo`
- Build steps:
  - `./zig/zig build check`
  - `./zig/zig build check-strict`
  - `./zig/zig build bench`
- Build options:
  - `-Dstyle-path=<path>`
  - `-Dstyle-profile=strict_core|tigerbeetle_repo`
  - `-Dperf-budget-ms=<ms>` (default: `30000` in Debug, `200` in Release*)

## CI and Quality Gates

```yaml
name: safety
on: [push, pull_request]

jobs:
  tigercheck:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: mlugg/setup-zig@v1
        with:
          version: 0.16.0-dev
      - name: Build checker
        run: ./zig/zig build
      - name: Safety analysis
        run: ./zig/zig build run -- .
```

Core gates:

- `./zig/zig build test` validates unit coverage + corpus pass/fail contracts.
- `./zig/zig build precision-check` enforces rule-level FP/FN deltas vs `tests/corpus/precision-baseline.json`.
- `./zig/zig build check-strict` enforces strict-core conformance plus perf budget checks.

If you see stdlib errors like `invalid builtin function: '@Type'`, your Zig binary and lib directory are out of sync. Use `./zig/zig ...` to force a matched toolchain.

## Conformance Roadmap

tigercheck is focused on one outcome: strict, deterministic Zig conformance in CI.

- Rule contracts: make each rule's violation semantics explicit and testable.
- Corpus discipline: maintain pass/fail/edge coverage per rule prefix.
- Precision tracking: keep baseline-driven FP/FN regression gates for every rule.
- Determinism and performance: hold strict and bench lanes stable with release headroom.
- CI UX: keep local and CI gates identical, concise, and reproducible.
