const LargePacket = struct {
    header: [32]u8,
    body: [64]u8,
};

fn process_packet(packet: LargePacket) void {
    _ = packet;
}

pub fn main() void {
    const packet = LargePacket{
        .header = [_]u8{0} ** 32,
        .body = [_]u8{0} ** 64,
    };
    process_packet(packet);
}
