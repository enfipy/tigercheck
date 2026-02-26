// expect-rule: N01_CONTROL_FLOW
fn stage_a() void {
    stage_b();
}

fn stage_b() void {
    stage_a();
}

pub fn main() void {
    stage_a();
}
