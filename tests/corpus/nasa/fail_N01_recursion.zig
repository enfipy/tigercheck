// expect-rule: N01_CONTROL_FLOW
fn a() void {
    b();
}

fn b() void {
    a();
}

pub fn main() void {
    a();
}
