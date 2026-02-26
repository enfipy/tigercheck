// expect-rule: N06_SCOPE_MINIMIZATION
var GlobalState: u32 = 0;

pub fn main() void {
    _ = GlobalState;
}
