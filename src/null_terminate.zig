/// Null-terminate a Zig slice into a provided buffer.
/// Returns a sentinel-terminated pointer, or null if the buffer is too small.
///
/// LIFETIME: The returned pointer points into `buf`. It is only valid for as
/// long as `buf` is live. Do not store the return value past the immediate C
/// call — the typical pattern is:
///   var buf: [N]u8 = undefined;
///   const z = nullTerminate(s, &buf) orelse return error.BufferOverflow;
///   _ = c.some_c_func(z);  // z valid here; do not store z past this scope
pub fn nullTerminate(s: []const u8, buf: []u8) ?[*:0]const u8 {
    if (s.len >= buf.len) return null;
    @memcpy(buf[0..s.len], s);
    buf[s.len] = 0;
    return @ptrCast(buf[0..s.len :0]);
}
