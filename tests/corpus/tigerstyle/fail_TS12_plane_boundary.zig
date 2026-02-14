const ControlPlane = struct {
    fn reload_config(self: *ControlPlane) void {
        _ = self;
    }
};

const DataPlane = struct {
    fn append_request(self: *DataPlane, id: u32) void {
        _ = self;
        _ = id;
    }
};

fn handle_tick(control: *ControlPlane, data: *DataPlane, id: u32) void {
    control.reload_config();
    data.append_request(id);
}

pub fn main() void {
    var control = ControlPlane{};
    var data = DataPlane{};
    handle_tick(&control, &data, 1);
}
