/// Null-terminate a Zig slice into a provided buffer.
/// Returns a sentinel-terminated pointer, or null if the buffer is too small.
pub fn nullTerminate(s: []const u8, buf: []u8) ?[*:0]const u8 {
    if (s.len >= buf.len) return null;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return @ptrCast(buf[0..s.len :0]);
}
