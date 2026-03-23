const std = @import("std");
const c = @import("c.zig").c;

/// Global allocator bridged into wolfSSL's C malloc/free/realloc.
/// wolfSSL_SetAllocators installs process-wide callbacks, so this must be global.
/// Set via setAllocator() before calling wolfSSL_Init(). Once set, the allocator
/// must remain valid for the lifetime of the wolfSSL library usage.
/// Thread safety: the allocator itself must be thread-safe (e.g. std.heap.GeneralPurposeAllocator
/// or std.heap.page_allocator). Setting the allocator is not thread-safe and must
/// be done before any concurrent wolfSSL operations.
// Safety of non-atomic access: `current_allocator` is always written by
// `setAllocator` *before* `init_called` is stored with release ordering
// (in `markInitialized`).  All readers of `current_allocator` (the zig*
// callbacks) only execute after wolfSSL_Init() has been called, which
// observes the `init_called` store via acquire ordering.  This establishes
// a happens-before relationship that prevents data races without requiring
// `current_allocator` itself to be atomic.
var current_allocator: ?std.mem.Allocator = null;

/// Tracks whether wolfSSL_Init() has been called. Used to catch out-of-order
/// setAllocator calls (allocator must be set *before* init).
var init_called: std.atomic.Value(bool) = std.atomic.Value(bool).init(false);

// Header prepended to every allocation so we can reconstruct the slice on free/realloc.
// We store full len so we can pass the correct slice to the Zig allocator.
const AllocHeader = struct {
    len: usize,
};

const header_size = @sizeOf(AllocHeader);
// Alignment for payloads returned to C. Use 16 bytes to match max_align_t on most
// platforms and satisfy AES-NI alignment requirements for wolfSSL key schedules.
const payload_alignment: std.mem.Alignment = .fromByteUnits(16);
const aligned_header_size = std.mem.alignForward(usize, header_size, payload_alignment.toByteUnits());

fn zigMalloc(size: usize) callconv(.c) ?*anyopaque {
    const ally = current_allocator orelse return null;
    const total = aligned_header_size + size;
    const buf = ally.alignedAlloc(u8, payload_alignment, total) catch return null;
    const header: *AllocHeader = @ptrCast(@alignCast(buf.ptr));
    header.* = .{ .len = size };
    return buf.ptr + aligned_header_size;
}

fn zigFree(ptr: ?*anyopaque) callconv(.c) void {
    const p = ptr orelse return;
    const ally = current_allocator orelse return;
    const base: [*]align(payload_alignment.toByteUnits()) u8 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(p)) - aligned_header_size));
    const header: *const AllocHeader = @ptrCast(base);
    const total = aligned_header_size + header.len;
    ally.free(base[0..total]);
}

fn zigRealloc(ptr: ?*anyopaque, size: usize) callconv(.c) ?*anyopaque {
    if (ptr == null) return zigMalloc(size);
    if (size == 0) {
        zigFree(ptr);
        return null;
    }

    const ally = current_allocator orelse return null;
    const old_base: [*]align(payload_alignment.toByteUnits()) u8 = @ptrCast(@alignCast(@as([*]u8, @ptrCast(ptr.?)) - aligned_header_size));
    const old_header: *const AllocHeader = @ptrCast(old_base);
    const old_total = aligned_header_size + old_header.len;

    const new_total = aligned_header_size + size;
    const new_buf = ally.alignedAlloc(u8, payload_alignment, new_total) catch return null;

    // Copy old data
    const copy_len = @min(old_header.len, size);
    const old_data = old_base[aligned_header_size .. aligned_header_size + old_header.len];
    @memcpy(new_buf[aligned_header_size .. aligned_header_size + copy_len], old_data[0..copy_len]);

    // Free old
    ally.free(old_base[0..old_total]);

    const header: *AllocHeader = @ptrCast(@alignCast(new_buf.ptr));
    header.* = .{ .len = size };
    return new_buf.ptr + aligned_header_size;
}

/// Install a Zig allocator as wolfSSL's memory backend.
/// Must be called before wolfSSL_Init().
pub fn setAllocator(ally: std.mem.Allocator) void {
    if (init_called.load(.acquire)) @panic("setAllocator must be called before wolfSSL_Init()");
    current_allocator = ally;
    if (@hasDecl(c, "wolfSSL_SetAllocators")) {
        _ = c.wolfSSL_SetAllocators(zigMalloc, zigFree, zigRealloc);
    }
}

/// Called by root.init() after a successful wolfSSL_Init() to lock out
/// further setAllocator calls.
pub fn markInitialized() void {
    init_called.store(true, .release);
}

/// A wrapper allocator that calls secureZero on memory before freeing.
pub const SecureAllocator = struct {
    backing: std.mem.Allocator,

    pub fn allocator(self: *SecureAllocator) std.mem.Allocator {
        return .{
            .ptr = self,
            .vtable = &vtable,
        };
    }

    const vtable = std.mem.Allocator.VTable{
        .alloc = secureAlloc,
        .free = secureFree,
        .resize = secureResize,
        .remap = secureRemap,
    };

    fn secureAlloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        return self.backing.rawAlloc(len, alignment, ret_addr);
    }

    fn secureFree(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, ret_addr: usize) void {
        // Wipe before freeing
        std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(memory)));
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        self.backing.rawFree(memory, alignment, ret_addr);
    }

    fn secureResize(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        // If shrinking, zero the tail before handing back
        if (new_len < memory.len) {
            std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(memory[new_len..])));
        }
        return self.backing.rawResize(memory, alignment, new_len, ret_addr);
    }

    fn secureRemap(ctx: *anyopaque, memory: []u8, alignment: std.mem.Alignment, new_len: usize, ret_addr: usize) ?[*]u8 {
        const self: *SecureAllocator = @ptrCast(@alignCast(ctx));
        // If shrinking, zero the tail before remapping
        if (new_len < memory.len) {
            std.crypto.secureZero(u8, @as([]volatile u8, @volatileCast(memory[new_len..])));
        }
        return self.backing.rawRemap(memory, alignment, new_len, ret_addr);
    }
};
