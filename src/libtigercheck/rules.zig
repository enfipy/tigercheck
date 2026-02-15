const std = @import("std");

pub const Id = enum {
    N01_CONTROL_FLOW,
    N02_BOUNDED_LOOPS,
    N03_STATIC_MEMORY,
    N04_FUNCTION_SIZE,
    N05_ASSERTION_DENSITY,
    N06_SCOPE_MINIMIZATION,
    N07_RETURN_AND_PARAM_CHECKS,
    N08_PREPROCESSOR_OR_COMPTIME_BUDGET,
    N09_POINTER_DISCIPLINE,
    N10_PEDANTIC_PIPELINE,

    TS01_SIMPLE_FLOW,
    TS02_EXPLICIT_BOUNDS,
    TS03_FIXED_WIDTH_TYPES,
    TS04_ASSERTIONS,
    TS05_PAIR_ASSERT,
    TS06_POS_NEG_ASSERT,
    TS07_MEMORY_PHASE,
    TS08_SCOPE,
    TS09_FUNCTION_SHAPE,
    TS10_PEDANTIC,
    TS11_PACED_CONTROL,
    TS12_PLANE_BOUNDARY,
    TS13_BOOLEAN_SPLIT,
    TS14_POSITIVE_INVARIANTS,
    TS15_ERROR_HANDLING,
    TS16_EXPLICIT_OPTIONS,
    TS17_SNAKE_CASE,
    TS18_ACRONYM_CASE,
    TS19_UNIT_SUFFIX_ORDER,
    TS20_NO_ABBREVIATION,
    TS21_CALLBACK_LAST,
    TS22_STRUCT_ORDER,
    TS23_LARGE_ARG_POINTER,
    TS24_IN_PLACE_INIT,
    TS25_IF_BRACES,
    TS26_LINE_LENGTH,

    TB01_ALIASING,
    TB02_ASSERT_ALIAS,
    TB03_COPY_API,
    TB04_CONTEXT_BUNDLE,
    TB05_TAG_DISPATCH,
};

pub fn id_string(id: Id) []const u8 {
    return @tagName(id);
}

pub const Family = enum {
    nasa,
    tigerstyle,
    tigerbeetle,
};

pub const Contract = struct {
    requirement: []const u8,
    rationale: []const u8,
    rewrite: []const u8,
};

pub fn family(id: Id) Family {
    return switch (id) {
        .N01_CONTROL_FLOW,
        .N02_BOUNDED_LOOPS,
        .N03_STATIC_MEMORY,
        .N04_FUNCTION_SIZE,
        .N05_ASSERTION_DENSITY,
        .N06_SCOPE_MINIMIZATION,
        .N07_RETURN_AND_PARAM_CHECKS,
        .N08_PREPROCESSOR_OR_COMPTIME_BUDGET,
        .N09_POINTER_DISCIPLINE,
        .N10_PEDANTIC_PIPELINE,
        => .nasa,

        .TS01_SIMPLE_FLOW,
        .TS02_EXPLICIT_BOUNDS,
        .TS03_FIXED_WIDTH_TYPES,
        .TS04_ASSERTIONS,
        .TS05_PAIR_ASSERT,
        .TS06_POS_NEG_ASSERT,
        .TS07_MEMORY_PHASE,
        .TS08_SCOPE,
        .TS09_FUNCTION_SHAPE,
        .TS10_PEDANTIC,
        .TS11_PACED_CONTROL,
        .TS12_PLANE_BOUNDARY,
        .TS13_BOOLEAN_SPLIT,
        .TS14_POSITIVE_INVARIANTS,
        .TS15_ERROR_HANDLING,
        .TS16_EXPLICIT_OPTIONS,
        .TS17_SNAKE_CASE,
        .TS18_ACRONYM_CASE,
        .TS19_UNIT_SUFFIX_ORDER,
        .TS20_NO_ABBREVIATION,
        .TS21_CALLBACK_LAST,
        .TS22_STRUCT_ORDER,
        .TS23_LARGE_ARG_POINTER,
        .TS24_IN_PLACE_INIT,
        .TS25_IF_BRACES,
        .TS26_LINE_LENGTH,
        => .tigerstyle,

        .TB01_ALIASING,
        .TB02_ASSERT_ALIAS,
        .TB03_COPY_API,
        .TB04_CONTEXT_BUNDLE,
        .TB05_TAG_DISPATCH,
        => .tigerbeetle,
    };
}

pub fn summary(id: Id) []const u8 {
    return switch (id) {
        .N01_CONTROL_FLOW => "simple explicit control flow; no recursion",
        .N02_BOUNDED_LOOPS => "loops need a proven finite bound",
        .N03_STATIC_MEMORY => "runtime allocation is forbidden on execution paths",
        .N04_FUNCTION_SIZE => "functions must stay under configured size limit",
        .N05_ASSERTION_DENSITY => "complex logic needs explicit invariants",
        .N06_SCOPE_MINIMIZATION => "minimize scope and mutable global state",
        .N07_RETURN_AND_PARAM_CHECKS => "check fallible returns and argument contracts",
        .N08_PREPROCESSOR_OR_COMPTIME_BUDGET => "bound preprocessor/comptime complexity",
        .N09_POINTER_DISCIPLINE => "restrict pointer depth and risky pointer forms",
        .N10_PEDANTIC_PIPELINE => "treat all warnings as build failures",
        .TS01_SIMPLE_FLOW => "prefer exhaustive, explicit control-flow forms",
        .TS02_EXPLICIT_BOUNDS => "all loops and queues require explicit bounds",
        .TS03_FIXED_WIDTH_TYPES => "avoid arch-sized integers at protocol boundaries",
        .TS04_ASSERTIONS => "assert preconditions and invariants explicitly",
        .TS05_PAIR_ASSERT => "pair assertions across independent paths",
        .TS06_POS_NEG_ASSERT => "assert both positive and negative spaces",
        .TS07_MEMORY_PHASE => "allocate during startup, not runtime",
        .TS08_SCOPE => "declare variables in the smallest valid scope",
        .TS09_FUNCTION_SHAPE => "keep TigerStyle function shape limits",
        .TS10_PEDANTIC => "zero-warning compiler policy",
        .TS11_PACED_CONTROL => "pace external event handling",
        .TS12_PLANE_BOUNDARY => "enforce control/data-plane boundary and complexity",
        .TS13_BOOLEAN_SPLIT => "split compound boolean checks into explicit branches",
        .TS14_POSITIVE_INVARIANTS => "prefer positive invariant forms",
        .TS15_ERROR_HANDLING => "handle errors explicitly",
        .TS16_EXPLICIT_OPTIONS => "avoid default-option reliance",
        .TS17_SNAKE_CASE => "enforce TigerStyle naming rules",
        .TS18_ACRONYM_CASE => "enforce acronym capitalization policy",
        .TS19_UNIT_SUFFIX_ORDER => "enforce units/qualifier suffix order",
        .TS20_NO_ABBREVIATION => "avoid non-sanctioned abbreviations",
        .TS21_CALLBACK_LAST => "callback parameters should be last",
        .TS22_STRUCT_ORDER => "declare fields before methods",
        .TS23_LARGE_ARG_POINTER => "prefer pointers for large arguments",
        .TS24_IN_PLACE_INIT => "prefer in-place initialization for large structs",
        .TS25_IF_BRACES => "if/else bodies should use braces",
        .TS26_LINE_LENGTH => "line exceeds 100 columns",
        .TB01_ALIASING => "pointer params may alias",
        .TB02_ASSERT_ALIAS => "use local assert alias, not qualified std.debug.assert",
        .TB03_COPY_API => "use explicit copy helper instead of raw copy APIs",
        .TB04_CONTEXT_BUNDLE => "bundle repeated walk plumbing into context objects",
        .TB05_TAG_DISPATCH => "prefer direct tag dispatch over repeated tag-set guards",
    };
}

pub fn contract(id: Id) Contract {
    return .{
        .requirement = summary(id),
        .rationale = rationale(id),
        .rewrite = rewrite_hint(id),
    };
}

pub fn rationale(id: Id) []const u8 {
    return switch (family(id)) {
        .nasa => "deterministic bounded behavior is required for static proof " ++
            "and safety-case review",
        .tigerstyle => "style contracts encode operational safety assumptions " ++
            "and keep review load bounded",
        .tigerbeetle => "repository conventions prevent high-cost regressions " ++
            "in performance-critical code paths",
    };
}

pub fn rewrite_hint(id: Id) []const u8 {
    return switch (id) {
        .N01_CONTROL_FLOW => "remove recursion/back-jumps and use explicit bounded dispatch",
        .N02_BOUNDED_LOOPS => "use constant upper bounds or iterator APIs " ++
            "with proven finite limits",
        .N03_STATIC_MEMORY => "move allocation to init paths and pass " ++
            "preallocated buffers at runtime",
        .N04_FUNCTION_SIZE => "split function into smaller helpers " ++
            "with single-purpose control flow",
        .N05_ASSERTION_DENSITY => "add precondition, postcondition, and invariant " ++
            "assertions at boundaries",
        .N06_SCOPE_MINIMIZATION => "narrow declaration scope and avoid mutable globals",
        .N07_RETURN_AND_PARAM_CHECKS => "check fallible returns and guard incoming " ++
            "parameters explicitly",
        .N08_PREPROCESSOR_OR_COMPTIME_BUDGET => "reduce nested comptime/preprocessor logic " ++
            "and flatten control",
        .N09_POINTER_DISCIPLINE => "reduce pointer depth and remove function-pointer indirection",
        .N10_PEDANTIC_PIPELINE => "resolve all warnings before merge; do not rely on warning debt",
        .TS01_SIMPLE_FLOW => "rewrite control flow into exhaustive and explicit branches",
        .TS02_EXPLICIT_BOUNDS => "declare queue and loop bounds in code, not comments",
        .TS03_FIXED_WIDTH_TYPES => "replace usize/isize with protocol-width integers at boundaries",
        .TS04_ASSERTIONS => "assert argument and state assumptions at function entry",
        .TS05_PAIR_ASSERT => "assert both sides of paired state transitions",
        .TS06_POS_NEG_ASSERT => "cover both allowed and forbidden state spaces with asserts",
        .TS07_MEMORY_PHASE => "allocate only during startup and keep " ++
            "runtime hot paths allocation-free",
        .TS08_SCOPE => "declare values at first use and keep scope minimal",
        .TS09_FUNCTION_SHAPE => "stay under TigerStyle function-size limits via helper extraction",
        .TS10_PEDANTIC => "treat warning-free builds as a hard policy requirement",
        .TS11_PACED_CONTROL => "insert explicit batching or pacing boundary before mutation",
        .TS12_PLANE_BOUNDARY => "separate control and data-plane logic " ++
            "via explicit handoff functions",
        .TS13_BOOLEAN_SPLIT => "split dense boolean expressions into named guard checks",
        .TS14_POSITIVE_INVARIANTS => "express boundary checks in positive invariant form",
        .TS15_ERROR_HANDLING => "handle and surface errors instead of silent discard",
        .TS16_EXPLICIT_OPTIONS => "pass options explicitly at sensitive call sites",
        .TS17_SNAKE_CASE => "rename symbols/files to conform to snake_case policy",
        .TS18_ACRONYM_CASE => "normalize acronym casing to repository convention",
        .TS19_UNIT_SUFFIX_ORDER => "reorder suffixes to unit-before-qualifier canonical form",
        .TS20_NO_ABBREVIATION => "replace non-sanctioned abbreviations with full terms",
        .TS21_CALLBACK_LAST => "move callback parameter to the last argument position",
        .TS22_STRUCT_ORDER => "declare struct fields first, helpers second, methods last",
        .TS23_LARGE_ARG_POINTER => "pass large values by pointer (prefer *const for read-only)",
        .TS24_IN_PLACE_INIT => "return large aggregates via out-parameter initialization",
        .TS25_IF_BRACES => "use braces for if/else bodies except approved single-line form",
        .TS26_LINE_LENGTH => "wrap long lines and extract subexpressions",
        .TB01_ALIASING => "avoid aliased mutable pointer parameters",
        .TB02_ASSERT_ALIAS => "alias assert locally and call the local alias",
        .TB03_COPY_API => "use explicit stdx copy helpers with overlap semantics",
        .TB04_CONTEXT_BUNDLE => "bundle repeated traversal parameters into a context struct",
        .TB05_TAG_DISPATCH => "replace repeated tag-set checks with direct tag dispatch",
    };
}

test "all rules expose executable contracts" {
    inline for (@typeInfo(Id).@"enum".fields) |field| {
        const id: Id = @field(Id, field.name);
        const c = contract(id);
        try std.testing.expect(c.requirement.len > 0);
        try std.testing.expect(c.rationale.len > 0);
        try std.testing.expect(c.rewrite.len > 0);
    }
}
