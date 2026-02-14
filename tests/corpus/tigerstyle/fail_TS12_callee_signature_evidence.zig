const ControlPlane = struct {};
const DataPlane = struct {};

fn alpha(control: *ControlPlane) void {
    _ = control;
}

fn beta(data: *DataPlane, id: u32) void {
    _ = data;
    _ = id;
}

fn handle(control: *ControlPlane, data: *DataPlane) void {
    alpha(control);
    beta(data, 1);
}

pub fn main() void {
    var control = ControlPlane{};
    var data = DataPlane{};
    handle(&control, &data);
}
