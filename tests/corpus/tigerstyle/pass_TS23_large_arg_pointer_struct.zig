const SmallPacket = struct {
    header: [16]u8,
    body: [16]u8,
};

fn process_packet(packet: SmallPacket) void {
    _ = packet;
}

pub fn main() void {
    const packet = SmallPacket{
        .header = [_]u8{0} ** 16,
        .body = [_]u8{0} ** 16,
    };
    process_packet(packet);
}
