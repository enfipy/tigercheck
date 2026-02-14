const ControlPlane = struct {};
const DataPlane = struct {};
const PlaneBoundary = struct {};

fn alpha(control: *ControlPlane) void {
    _ = control;
}

fn bridge(boundary: *PlaneBoundary) void {
    _ = boundary;
}

fn beta(data: *DataPlane, id: u32) void {
    _ = data;
    _ = id;
}

fn handle(control: *ControlPlane, boundary: *PlaneBoundary, data: *DataPlane) void {
    alpha(control);
    bridge(boundary);
    beta(data, 1);
}

pub fn main() void {
    var control = ControlPlane{};
    var boundary = PlaneBoundary{};
    var data = DataPlane{};
    handle(&control, &boundary, &data);
}
