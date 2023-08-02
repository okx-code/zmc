const std = @import("std");
const varint = @import("varint.zig");

pub const PacketBuilder = struct {
    arena_allocator: std.mem.Allocator,
    allocator: std.mem.Allocator,
    buffer: std.ArrayListUnmanaged(u8) = .{},
    output_buffer: std.ArrayListUnmanaged(u8) = .{},

    pub const WriteError = error{OutOfMemory};
    pub const Writer = std.io.Writer(*Self, WriteError, write);

    const Self = @This();

    pub fn writer(self: *Self) Writer {
        return .{ .context = self };
    }

    pub fn write(self: *Self, bytes: []const u8) WriteError!usize {
        return self.buffer.writer(self.arena_allocator).write(bytes);
    }

    pub fn deinit(self: *Self) void {
        self.output_buffer.deinit(self.allocator);
    }

    pub fn finish(self: *Self) !void {
        var lenbuf: [5]u8 = undefined;
        try self.output_buffer.appendSlice(self.allocator, varint.writeVarInt(@intCast(self.buffer.items.len), &lenbuf));
        try self.output_buffer.appendSlice(self.allocator, self.buffer.items);
        self.buffer.clearRetainingCapacity();
    }

    pub fn enqueue(self: *Self, packet_queue: *std.atomic.Queue([]u8)) !void {
        var node = try self.allocator.create(std.atomic.Queue([]u8).Node);
        errdefer self.allocator.destroy(node);
        node.data = try self.output_buffer.toOwnedSlice(self.allocator);
        packet_queue.put(node);
    }
};
