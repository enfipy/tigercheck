fn stage_a() void {
    stage_b();
}

fn stage_b() void {
    stage_a();
}

pub fn main() void {
    stage_a();
}
