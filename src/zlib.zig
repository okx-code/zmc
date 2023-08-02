const std = @import("std");

const c = @cImport({
    @cInclude("zlib.h");
});

// todo fix thread safety (use arena allocator)
var in_buffer: [65536]u8 = undefined;
var out_buffer: [65536]u8 = undefined;

pub const Zlib = struct {
    stream: c.z_stream,
    inflating: bool = false,

    pub fn init(allocator: *const std.mem.Allocator) Zlib {
        var strm: c.z_stream = undefined;
        strm.next_in = c.Z_NULL;
        strm.avail_in = 0;
        strm.zalloc = zalloc;
        strm.zfree = zfree;
        strm.@"opaque" = @constCast(@ptrCast(allocator));

        return .{ .stream = strm };
    }

    pub fn inflate(self: *Zlib, reader: anytype, writer: anytype) !void {
        if (self.inflating) {
            if (c.inflateReset(&self.stream) != c.Z_OK) return error.zerror;
        } else {
            if (c.inflateInit(&self.stream) != c.Z_OK) return error.zerror;
        }
        self.inflating = true;

        outer: while (true) {
            self.stream.avail_in = @intCast(try reader.readAll(&in_buffer));
            if (self.stream.avail_in == 0) {
                break;
            }
            self.stream.next_in = &in_buffer;

            while (true) {
                self.stream.avail_out = out_buffer.len;
                self.stream.next_out = &out_buffer;

                const ret = c.inflate(&self.stream, c.Z_NO_FLUSH);
                switch (ret) {
                    c.Z_NEED_DICT, c.Z_DATA_ERROR, c.Z_MEM_ERROR => {
                        return error.zerror;
                    },
                    else => {},
                }

                try writer.writeAll(out_buffer[0 .. out_buffer.len - self.stream.avail_out]);

                if (ret == c.Z_STREAM_END) {
                    break :outer;
                } else if (self.stream.avail_out == 0) {
                    break;
                }
            }
        }
    }

    pub fn deinit(self: *Zlib) void {
        _ = c.inflateEnd(&self.stream);
    }
};

fn zalloc(allocator_ptr: ?*anyopaque, items: c_uint, size: c_uint) callconv(.C) ?*anyopaque {
    const allocator = @as(*const std.mem.Allocator, @ptrCast(@alignCast(allocator_ptr)));
    var value = allocator.alignedAlloc(u8, @sizeOf(usize), (items * size) + @sizeOf(usize)) catch return null;
    @as(*usize, @ptrCast(value)).* = (items * size) + @sizeOf(usize);

    return @ptrFromInt(@intFromPtr(value.ptr) + @sizeOf(usize));
}

fn zfree(allocator_ptr: ?*anyopaque, ptr: ?*anyopaque) callconv(.C) void {
    if (ptr) |p| {
        const size_ptr: *usize = @ptrFromInt(@intFromPtr(p) - @sizeOf(usize));
        const array_ptr: [*]u8 = @ptrFromInt(@intFromPtr(p) - @sizeOf(usize));

        const allocator = @as(*const std.mem.Allocator, @ptrCast(@alignCast(allocator_ptr)));
        allocator.free(array_ptr[0..size_ptr.*]);
    }
}
