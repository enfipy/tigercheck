fn encode_length_u32(length_u32: u32) u32 {
    return length_u32;
}

pub fn main() void {
    const encoded = encode_length_u32(16);
    if (encoded == 0) {
        unreachable;
    }
}
