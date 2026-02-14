const User = struct {
    id: u32,
};

fn create(self: *User) void {
    _ = self;
}

pub fn main() void {
    var user = User{ .id = 1 };
    create(&user);
}
