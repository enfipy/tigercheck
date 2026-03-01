// expect-rule: TS01_SIMPLE_FLOW
const Kind = enum { a, b };

pub fn main() void {
    const k: Kind = .a;
    switch (k) {
        .a => {},
        else => {},
    }
}
