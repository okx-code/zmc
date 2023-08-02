const std = @import("std");
const os = std.os;
const linux = std.os.linux;

const event_loop = @import("event_loop.zig");
const block_states = @import("block_states.zig");
const server = @import("server.zig");

pub const std_options = struct {
    pub const fmt_max_depth = 10000;
    pub const log_level = .debug;
};

var stop = false;

pub fn main() !void {
    try std.os.sigaction(std.os.SIG.INT, &.{ .handler = .{ .handler = stopFunc }, .mask = std.os.empty_sigset, .flags = 0 }, null);
    try std.os.sigaction(std.os.SIG.TERM, &.{ .handler = .{ .handler = stopFunc }, .mask = std.os.empty_sigset, .flags = 0 }, null);

    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = general_purpose_allocator.deinit();

    //var logging = std.heap.LoggingAllocator(std.log.Level.info, std.log.Level.info).init(general_purpose_allocator.allocator());
    const allocator = general_purpose_allocator.allocator();

    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const arena_allocator = arena.allocator();

    var states: block_states.BlockStates = undefined;
    {
        const file = std.fs.File{ .handle = try os.open("src/blocks.json", os.O.RDONLY, 0) };
        defer file.close();
        const slice = try file.readToEndAlloc(allocator, std.math.maxInt(usize));
        defer allocator.free(slice);
        states = try block_states.parse(arena_allocator, arena_allocator, slice);
    }

    var queue: event_loop.ServerQueue = event_loop.ServerQueue.init();
    defer {
        while (queue.get()) |node| {
            allocator.destroy(node);
        }
    }

    var mc_server: server.Server = try server.Server.init(allocator, states);
    defer mc_server.deinit();

    const epfd = try os.epoll_create1(os.SOCK.CLOEXEC);

    const timerfd = try os.timerfd_create(os.CLOCK.MONOTONIC, linux.TFD.NONBLOCK | linux.TFD.CLOEXEC);
    const interval: os.timespec = .{ .tv_sec = 0, .tv_nsec = 50_000_000 };
    try os.timerfd_settime(timerfd, 0, &.{ .it_interval = interval, .it_value = interval }, null);

    var timer_in: linux.epoll_event = .{ .events = linux.EPOLL.IN | linux.EPOLL.ET, .data = .{ .ptr = 0 } };
    try os.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, timerfd, &timer_in);

    var eventfd = try os.eventfd(0, linux.EFD.CLOEXEC | linux.EFD.NONBLOCK);
    var event_in: linux.epoll_event = .{ .events = linux.EPOLL.IN | linux.EPOLL.ET, .data = .{ .ptr = 1 } };
    try os.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, eventfd, &event_in);

    var loop = try event_loop.EventLoop.init(allocator, eventfd, &queue);
    defer loop.deinit();
    var new_event: std.os.linux.epoll_event = .{ .events = linux.EPOLL.IN | linux.EPOLL.ET, .data = .{ .ptr = 2 } };
    try os.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, loop.epfd, &new_event);

    var events: [10]std.os.linux.epoll_event = undefined;
    while (true) {
        var event_count = linux.epoll_pwait(epfd, &events, events.len, -1, null);
        switch (linux.getErrno(event_count)) {
            .SUCCESS => {},
            .INTR => {
                if (stop) {
                    return;
                }
            },
            else => unreachable,
        }

        events: for (0..event_count) |i| {
            if (events[i].data.ptr == 0) {
                while (true) {
                    var buf: [8]u8 = undefined;
                    std.debug.assert(8 == os.read(eventfd, &buf) catch |err| switch (err) {
                        error.WouldBlock => continue :events,
                        else => |e| return e,
                    });

                    for (0..std.mem.readIntNative(u64, &buf)) |_| {
                        if (queue.get()) |node| {
                            defer allocator.destroy(node);
                            try mc_server.handle(node.data);
                        } else {
                            unreachable;
                        }
                    }
                }
            } else if (events[i].data.ptr == 1) {
                while (true) {
                    var buf: [8]u8 = undefined;
                    std.debug.assert(8 == os.read(timerfd, &buf) catch |err| switch (err) {
                        error.WouldBlock => continue :events,
                        else => |e| return e,
                    });

                    for (0..std.mem.readIntNative(u64, &buf)) |_| {
                        try mc_server.tick();
                    }
                }
            } else {
                var loop_events: [10]std.os.linux.epoll_event = undefined;
                while (true) {
                    var loop_event_count = os.epoll_wait(loop.epfd, &loop_events, 0);
                    if (loop_event_count == 0) break;
                    for (0..loop_event_count) |j| {
                        try loop.handle(loop_events[j]);
                    }
                }
            }
        }
    }
}

fn stopFunc(signo: c_int) callconv(.C) void {
    _ = signo;
    stop = true;
}
