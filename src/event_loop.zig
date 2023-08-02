const std = @import("std");
const os = std.os;
const linux = std.os.linux;

const anvil = @import("anvil.zig");
const block_states = @import("block_states.zig");
const chunk_nbt = @import("chunk_nbt.zig");
const packets = @import("packets.zig");
const paletted_container = @import("paletted_container.zig");
const varint = @import("varint.zig");
const zlib = @import("zlib.zig");

const c = @cImport({
    @cInclude("openssl/evp.h");
    @cInclude("openssl/rsa.h");
    @cInclude("openssl/encoder.h");
});

pub const ServerQueue = std.atomic.Queue(packets.ServerboundPacket);

// Handshake -> Status -> End
// HandShake -> Login -> Play -> End
const ProtocolState = union(enum) {
    Handshake: void,
    Status: void,
    Login: ProtocolLoginState,
    Play: void,
};

const ProtocolLoginState = struct {
    verify_token: [4]u8 = undefined,
};

const Client = struct {
    server_address: []u8,
    server_port: u16,
};

const IdState = struct {
    length: u32,
    header_buf: [4]u8 = undefined,
    header_pos: u8 = 0,
};

const LengthState = struct {
    header_buf: [4]u8 = undefined,
    header_pos: u8 = 0,
};

const ContentsState = struct {
    id: u32,
    index: u32,
    array: []u8,
};

const SocketStateEnum = enum {
    length,
    id,
    contents,
};

const Socket = struct {
    stream: std.net.Stream,
    protocol_state: ProtocolState,
    state: SocketState,

    write_encrypt_index: usize,
    write_index: usize,
    // todo fragmented list - std.TailQueue
    write_buf: std.ArrayListUnmanaged(u8),

    aes_encrypt: ?*c.EVP_CIPHER_CTX,
    aes_decrypt: ?*c.EVP_CIPHER_CTX,

    bit_slot: usize,
};

const SocketState = union(SocketStateEnum) {
    length: LengthState,
    id: IdState,
    contents: ContentsState,
};

const EpollType = enum {
    Timer,
    Listen,
    Client,
};

const max_connections = 1024;

const online_mode = false;

pub const EventLoop = struct {
    allocator: std.mem.Allocator,
    arena_allocator: std.heap.ArenaAllocator,
    client_bit_set: std.bit_set.ArrayBitSet(usize, max_connections),
    packet_queues: []std.atomic.Queue([]u8),
    clients: []Client,
    sockets: []Socket,
    epoll_ptrs: []EpollType,
    public_key_len: usize,
    public_key: [162]u8,
    sockfd: os.socket_t,
    timerfd: os.socket_t,
    epfd: i32,
    rsa_ctx: ?*c.EVP_PKEY_CTX,
    server_queue: *ServerQueue,
    eventfd: i32,

    pub fn deinit(self: *EventLoop) void {
        var it = self.client_bit_set.iterator(.{ .kind = .unset });
        while (it.next()) |bit| {
            closeClient(self.allocator, bit, &self.client_bit_set, self.clients, self.sockets, self.epoll_ptrs);
        }

        self.arena_allocator.deinit();
        self.allocator.free(self.clients);
        self.allocator.free(self.sockets);
        self.allocator.free(self.epoll_ptrs);
        self.allocator.free(self.packet_queues);
        os.close(self.epfd);
        os.close(self.timerfd);
        os.close(self.sockfd);
        c.EVP_PKEY_CTX_free(self.rsa_ctx);
    }

    pub fn init(allocator: std.mem.Allocator, eventfd: i32, server_queue: *ServerQueue) !EventLoop {
        var timer = try std.time.Timer.start();

        var rsa_ctx: ?*c.EVP_PKEY_CTX = null;
        errdefer c.EVP_PKEY_CTX_free(rsa_ctx);
        var buffer: [162]u8 = undefined;
        var len: usize = buffer.len;
        if (online_mode) {
            var rsa = EVP_RSA_gen(1024);
            rsa_ctx = c.EVP_PKEY_CTX_new(rsa, null);

            {
                var ctx: ?*c.OSSL_ENCODER_CTX = c.OSSL_ENCODER_CTX_new_for_pkey(rsa, c.EVP_PKEY_PUBLIC_KEY, "DER", "SubjectPublicKeyInfo", null);
                errdefer c.OSSL_ENCODER_CTX_free(ctx);
                if (ctx == null) {
                    return error.RSA_Init;
                }
                if (c.OSSL_ENCODER_CTX_get_num_encoders(ctx) == 0) {
                    return error.RSA_Init;
                }
                if (c.OSSL_ENCODER_to_data(ctx, @ptrCast(&&buffer), &len) == 0) {
                    return error.RSA_Init;
                }
            }
        }

        var loop = std.heap.ArenaAllocator.init(allocator);
        errdefer loop.deinit();
        const loop_allocator = loop.allocator();
        _ = loop_allocator;

        const addr = std.net.Address.initIp4(.{ 127, 0, 0, 1 }, 25565);
        const sock_flags = std.os.SOCK.STREAM | std.os.SOCK.CLOEXEC | std.os.SOCK.NONBLOCK;
        const sockfd = try std.os.socket(addr.any.family, sock_flags, std.os.IPPROTO.TCP);
        errdefer std.os.closeSocket(sockfd);

        var flags = try std.os.fcntl(sockfd, std.os.F.GETFL, 0);
        flags |= std.os.O.NONBLOCK;
        _ = try std.os.fcntl(sockfd, std.os.F.SETFL, flags);

        try std.os.setsockopt(
            sockfd,
            std.os.SOL.SOCKET,
            std.os.SO.REUSEADDR,
            &std.mem.toBytes(@as(c_int, 1)),
        );

        var socklen = addr.getOsSockLen();
        try os.bind(sockfd, &addr.any, socklen);
        try os.listen(sockfd, 128);

        const epfd = try os.epoll_create1(os.SOCK.CLOEXEC);
        errdefer os.close(epfd);
        const listen_type = EpollType.Listen;
        var listen: linux.epoll_event = .{ .events = linux.EPOLL.IN | linux.EPOLL.ET, .data = .{ .ptr = @intFromPtr(&listen_type) } };
        try os.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, sockfd, &listen);

        const timerfd = try os.timerfd_create(os.CLOCK.MONOTONIC, linux.TFD.NONBLOCK | linux.TFD.CLOEXEC);
        errdefer os.close(timerfd);
        const interval: os.timespec = .{ .tv_sec = 10, .tv_nsec = 0 };
        try os.timerfd_settime(timerfd, 0, &.{ .it_interval = interval, .it_value = interval }, null);
        const timerfd_type = EpollType.Timer;
        var timer_in: linux.epoll_event = .{ .events = linux.EPOLL.IN | linux.EPOLL.ET, .data = .{ .ptr = @intFromPtr(&timerfd_type) } }; // todo fix ptr with C epoll
        try os.epoll_ctl(epfd, linux.EPOLL.CTL_ADD, timerfd, &timer_in);

        var client_bit_set = std.bit_set.ArrayBitSet(usize, max_connections).initFull();

        var clients: []Client = try allocator.alloc(Client, max_connections);
        errdefer allocator.free(clients);
        var sockets: []Socket = try allocator.alloc(Socket, max_connections);
        errdefer allocator.free(sockets);
        var epoll_ptrs: []EpollType = try allocator.alloc(EpollType, max_connections);
        errdefer allocator.free(epoll_ptrs);

        var packet_queues: []std.atomic.Queue([]u8) = try allocator.alloc(std.atomic.Queue([]u8), max_connections);
        errdefer allocator.free(packet_queues);
        for (packet_queues) |*queue| {
            queue.* = std.atomic.Queue([]u8).init();
        }

        std.log.info("Ready in {d}μs", .{timer.read() / 1000});

        return .{
            .allocator = allocator,
            .arena_allocator = loop,
            .packet_queues = packet_queues,
            .clients = clients,
            .sockets = sockets,
            .epoll_ptrs = epoll_ptrs,
            .client_bit_set = client_bit_set,
            .public_key_len = buffer.len - len,
            .public_key = buffer,
            .sockfd = sockfd,
            .timerfd = timerfd,
            .epfd = epfd,
            .rsa_ctx = rsa_ctx,
            .server_queue = server_queue,
            .eventfd = eventfd,
        };
    }

    pub fn handle(self: *EventLoop, event: std.os.linux.epoll_event) !void {
        _ = self.arena_allocator.reset(.{ .retain_with_limit = 10_000_000 });
        const epoll_type: *EpollType = @ptrFromInt(event.data.ptr);
        if (epoll_type.* == EpollType.Listen) {
            var accepted_addr: std.net.Address = undefined;
            var adr_len: std.os.socklen_t = @sizeOf(std.net.Address);
            var client_fd = std.os.accept(self.sockfd, &accepted_addr.any, &adr_len, std.os.SOCK.CLOEXEC | std.os.SOCK.NONBLOCK) catch |err| switch (err) {
                error.WouldBlock => return,
                else => |e| return e,
            };

            var bit = self.client_bit_set.toggleFirstSet();
            if (bit == null) {
                os.closeSocket(client_fd);
                return;
            }
            std.log.debug("Accept {d}\n", .{bit.?});
            self.epoll_ptrs[bit.?] = EpollType.Client;
            var new_event: std.os.linux.epoll_event = .{ .events = linux.EPOLL.IN | linux.EPOLL.OUT | linux.EPOLL.ET | linux.EPOLL.RDHUP, .data = .{ .ptr = @intFromPtr(&self.epoll_ptrs[bit.?]) } };

            self.sockets[bit.?] = Socket{ .stream = std.net.Stream{ .handle = client_fd }, .protocol_state = ProtocolState.Handshake, .state = .{ .length = .{} }, .write_buf = std.ArrayListUnmanaged(u8){}, .write_index = 0, .write_encrypt_index = 0, .aes_encrypt = null, .aes_decrypt = null, .bit_slot = bit.? };
            try std.os.epoll_ctl(self.epfd, std.os.linux.EPOLL.CTL_ADD, client_fd, &new_event);
        } else if (epoll_type.* == EpollType.Timer) {
            while (true) {
                var buf: [8]u8 = undefined;
                _ = os.read(self.timerfd, &buf) catch |err| switch (err) {
                    error.WouldBlock => return,
                    else => |e| return e,
                };

                var it = self.client_bit_set.iterator(.{ .kind = .unset });
                while (it.next()) |bit| {
                    try sendKeepAlivePacket(self.allocator, &self.sockets[bit]);
                }
            }
        } else if (epoll_type.* == EpollType.Client) {
            const offset = (@intFromPtr(epoll_type) - @intFromPtr(self.epoll_ptrs.ptr)) / @sizeOf(EpollType);
            if (event.events & linux.EPOLL.RDHUP > 0) {
                closeClient(self.allocator, offset, &self.client_bit_set, self.clients, self.sockets, self.epoll_ptrs);
                return;
            }
            if (event.events & linux.EPOLL.IN > 0) {
                if (online_mode) {
                    // todo make call to mojang in online mode - libcurl
                } else {
                    //
                }
                const pubkey = if (self.public_key_len == 0) null else self.public_key[0..self.public_key_len];
                processPackets(self.allocator, self.arena_allocator.allocator(), pubkey, self.rsa_ctx, &self.clients[offset], &self.sockets[offset], &self.packet_queues[offset], self.server_queue, self.eventfd, offset) catch |err| {
                    std.log.warn("Error handling connection: {any}", .{err});
                    closeClient(self.allocator, offset, &self.client_bit_set, self.clients, self.sockets, self.epoll_ptrs);
                    return;
                };
            }
            if (event.events & linux.EPOLL.OUT > 0) {
                try writeBuffer(self.allocator, &self.packet_queues[offset], &self.sockets[offset]);
            }
        }
    }
};

fn closeClient(allocator: std.mem.Allocator, offset: usize, client_bit_set: anytype, clients: []Client, sockets: []Socket, epoll_ptrs: []EpollType) void {
    client_bit_set.set(offset);

    if (sockets[offset].state == SocketStateEnum.contents) {
        allocator.free(sockets[offset].state.contents.array);
    }
    sockets[offset].write_buf.deinit(allocator);
    sockets[offset] = undefined;
    epoll_ptrs[offset] = undefined;
    clients[offset] = undefined;
}

fn writeBuffer(allocator: std.mem.Allocator, queue: *std.atomic.Queue([]u8), sock: *Socket) !void {
    while (queue.get()) |node| {
        defer allocator.destroy(node);
        defer allocator.free(node.data);
        try sock.write_buf.appendSlice(allocator, node.data);
    }

    if (sock.aes_encrypt != null) {
        while (sock.write_index < sock.write_buf.items.len) {
            var to_write = sock.write_buf.items[sock.write_index..];
            var to_encrypt = sock.write_buf.items[sock.write_encrypt_index..];

            var out: c_int = @intCast(to_encrypt.len);
            if (out > 0) {
                if (c.EVP_EncryptUpdate(sock.aes_encrypt, to_encrypt.ptr, &out, to_encrypt.ptr, out) != 1) return error.EncryptError;
                sock.write_encrypt_index += @intCast(out);
            }

            var bytes_written = sock.stream.write(to_write) catch |err| switch (err) {
                error.WouldBlock => return,
                else => |e| return e,
            };
            sock.write_index += bytes_written;
        }

        sock.write_index = 0;
        sock.write_encrypt_index = 0;
        sock.write_buf.clearAndFree(allocator); // todo revisit this, maybe clear with limit
    } else {
        while (sock.write_index < sock.write_buf.items.len) {
            var to_write = sock.write_buf.items[sock.write_index..];
            var bytes_written = sock.stream.write(to_write) catch |err| switch (err) {
                error.WouldBlock => return,
                else => |e| return e,
            };
            sock.write_index += bytes_written;
        }

        sock.write_index = 0;
        sock.write_buf.clearAndFree(allocator); // todo revisit this, maybe clear with limit
    }
}

fn socketRead(sock: *Socket, buf: []u8) !usize {
    if (sock.aes_decrypt != null) {
        var bytes_read = try sock.stream.read(buf);
        var out: c_int = @intCast(buf.len);
        if (c.EVP_DecryptUpdate(sock.aes_decrypt, buf.ptr, &out, buf.ptr, @intCast(bytes_read)) != 1) return error.EncryptError;

        return @intCast(out);
    } else {
        return sock.stream.read(buf);
    }
}

fn processPackets(allocator: std.mem.Allocator, loop_allocator: std.mem.Allocator, public_key: ?[]u8, rsa_ctx: ?*c.EVP_PKEY_CTX, client: *Client, sock: *Socket, packet_queue: *std.atomic.Queue([]u8), server_queue: *ServerQueue, eventfd: i32, player: usize) !void {
    _ = client;
    event: while (true) {
        switch (sock.state) {
            SocketStateEnum.length => |*ls| {
                var bytes_read = socketRead(sock, ls.header_buf[ls.header_pos .. ls.header_pos + 1]) catch |err| switch (err) {
                    error.WouldBlock => break :event,
                    else => |e| return e,
                };

                var decrypt_buf: [4]u8 = undefined;
                var out: c_int = decrypt_buf.len;
                _ = out;

                ls.header_pos += @intCast(bytes_read);

                const length = varint.readVarInt(ls.header_buf[0..ls.header_pos]) catch |err| switch (err) {
                    error.Eof => continue,
                    else => |e| return e,
                };

                if (length > 16 * 1024 * 1024) return error.LengthTooBig;

                sock.state = .{ .id = IdState{ .length = length } };
            },
            SocketStateEnum.id => |*ls| {
                var bytes_read = socketRead(sock, ls.header_buf[ls.header_pos .. ls.header_pos + 1]) catch |err| switch (err) {
                    error.WouldBlock => break :event,
                    else => |e| return e,
                };
                ls.header_pos += @intCast(bytes_read);

                const packet_id = varint.readVarInt(ls.header_buf[0..ls.header_pos]) catch |err| switch (err) {
                    error.Eof => continue,
                    else => |e| return e,
                };

                var array = try allocator.alloc(u8, ls.length - ls.header_pos);
                sock.state = .{ .contents = ContentsState{ .id = packet_id, .index = 0, .array = array } };
            },
            SocketStateEnum.contents => |*as| {
                var bytes_read = socketRead(sock, as.array[as.index..]) catch |err| switch (err) {
                    error.WouldBlock => break :event,
                    else => |e| return e,
                };
                as.index += @intCast(bytes_read);

                if (as.index < as.array.len) {
                    continue;
                }

                defer sock.state = .{ .length = LengthState{} };
                var free: bool = true;
                defer if (free) allocator.free(as.array);

                std.debug.print("Packet {any}: {d}\n", .{ sock.protocol_state, as.id });
                if (sock.protocol_state == ProtocolState.Handshake) {
                    const state = as.array[as.array.len - 1];
                    if (state == 1) {
                        sock.protocol_state = ProtocolState.Status;
                    } else if (state == 2) {
                        sock.protocol_state = ProtocolState{ .Login = .{} };
                    } else {
                        return error.InvalidState;
                    }
                } else if (sock.protocol_state == ProtocolState.Status) {
                    if (as.id == 0) {
                        const str = @embedFile("json");

                        var lenbuf: [5]u8 = undefined;
                        var lenbuf2: [5]u8 = undefined;
                        var strlen = varint.writeVarInt(str.len, &lenbuf2);

                        try sock.write_buf.appendSlice(allocator, varint.writeVarInt(@intCast(1 + strlen.len + str.len), &lenbuf));
                        try sock.write_buf.append(allocator, 0);
                        try sock.write_buf.appendSlice(allocator, strlen);
                        try sock.write_buf.appendSlice(allocator, str);
                    } else if (as.id == 1) {
                        var lenbuf: [5]u8 = undefined;

                        try sock.write_buf.appendSlice(allocator, varint.writeVarInt(@intCast(1 + 8), &lenbuf));
                        try sock.write_buf.append(allocator, 1);
                        try sock.write_buf.appendSlice(allocator, as.array);
                    }
                } else if (sock.protocol_state == ProtocolState.Login) {
                    if (as.id == 0) {
                        std.debug.print("login\n", .{});

                        if (public_key) |key| {
                            try sendEncryptionRequest(allocator, sock, key);
                        } else {
                            try sendPlaySetup(allocator, loop_allocator, player, sock, packet_queue, server_queue, eventfd);
                            sock.protocol_state = ProtocolState.Play;
                        }
                    } else if (as.id == 1 and public_key != null) {
                        std.debug.print("encryption response\n", .{});

                        var fixed = std.io.fixedBufferStream(as.array);
                        var reader = fixed.reader();
                        var shared_secret_length = try varint.readVarIntReader(reader);
                        if (shared_secret_length != 128) return error.AuthFailure;

                        var shared_secret_encrypted: [128]u8 = undefined;
                        try reader.readNoEof(&shared_secret_encrypted);

                        var verify_token_length = try varint.readVarIntReader(reader);
                        if (verify_token_length != 128) return error.AuthFailure;

                        var verify_token_encrypted: [128]u8 = undefined;
                        try reader.readNoEof(&verify_token_encrypted);

                        var shared_secret: [128]u8 = undefined;
                        var shared_secret_len: usize = shared_secret.len;
                        if (c.EVP_PKEY_decrypt_init(rsa_ctx) != 1) return error.AuthFailure;
                        if (c.EVP_PKEY_decrypt(rsa_ctx, &shared_secret, &shared_secret_len, &shared_secret_encrypted, shared_secret_encrypted.len) != 1) return error.AuthFailure;

                        if (shared_secret_len != 16) {
                            return error.AuthFailure;
                        }

                        var verify_token: [128]u8 = undefined;
                        var verify_token_len: usize = verify_token.len;
                        if (c.EVP_PKEY_decrypt_init(rsa_ctx) != 1) return error.AuthFailure;
                        if (c.EVP_PKEY_decrypt(rsa_ctx, &verify_token, &verify_token_len, &verify_token_encrypted, verify_token_encrypted.len) != 1) return error.AuthFailure;

                        if (!std.mem.eql(u8, verify_token[0..verify_token_len], &sock.protocol_state.Login.verify_token)) {
                            return error.AuthFailure;
                        }

                        const aes_cipher = c.EVP_aes_128_cfb8();

                        if (sock.write_buf.items.len != 0) {
                            unreachable;
                        }

                        sock.aes_encrypt = c.EVP_CIPHER_CTX_new();
                        if (c.EVP_EncryptInit_ex2(sock.aes_encrypt, aes_cipher, &shared_secret, &shared_secret, null) != 1) return error.AuthFailure;

                        sock.aes_decrypt = c.EVP_CIPHER_CTX_new();
                        if (c.EVP_DecryptInit_ex2(sock.aes_decrypt, aes_cipher, &shared_secret, &shared_secret, null) != 1) return error.AuthFailure;

                        try sendPlaySetup(allocator, loop_allocator, player, sock, packet_queue, server_queue, eventfd);
                        sock.protocol_state = ProtocolState.Play;
                    }
                } else if (sock.protocol_state == ProtocolState.Play) {
                    //free = false;
                    try handlePacket(as.id, as.array, allocator, packet_queue, server_queue, eventfd, player);
                    if (as.id == 0x08) {
                        // Client Information
                    } else if (as.id == 0x0C) {
                        // Close Container
                    } else if (as.id == 0x06) {
                        // Player Session
                    }
                    // 20 & 21 player update
                }
            },
        }
    }
}

fn sendEncryptionRequest(allocator: std.mem.Allocator, sock: *Socket, public_key: []u8) !void {
    var lenbuf: [5]u8 = undefined;

    var public_key_lenbuf: [5]u8 = undefined;
    var public_key_len = varint.writeVarInt(@intCast(public_key.len), &public_key_lenbuf);

    try sock.write_buf.appendSlice(allocator, varint.writeVarInt(@intCast(7 + public_key_len.len + public_key.len), &lenbuf));
    try sock.write_buf.append(allocator, 0x01);
    try sock.write_buf.append(allocator, 0);
    try sock.write_buf.appendSlice(allocator, public_key_len);
    try sock.write_buf.appendSlice(allocator, public_key);
    try sock.write_buf.append(allocator, 4);
    std.crypto.random.bytes(&sock.protocol_state.Login.verify_token);
    try sock.write_buf.appendSlice(allocator, &sock.protocol_state.Login.verify_token);
}

fn sendPlaySetup(allocator: std.mem.Allocator, arena_allocator: std.mem.Allocator, player: usize, sock: *Socket, packet_queue: *std.atomic.Queue([]u8), server_queue: *ServerQueue, eventfd: i32) !void {
    _ = arena_allocator;
    var lenbuf: [5]u8 = undefined;
    try sock.write_buf.appendSlice(allocator, varint.writeVarInt(@intCast(16 + 1 + 1 + 1 + 3), &lenbuf));
    try sock.write_buf.append(allocator, 0x02);
    try sock.write_buf.appendSlice(allocator, &[_]u8{ 0x2c, 0x7c, 0x20, 0xf7, 0x84, 0x72, 0x47, 0x80, 0x9b, 0x35, 0x4c, 0xd4, 0xfa, 0xe4, 0x60, 0xc6 });
    try sock.write_buf.append(allocator, 3);
    try sock.write_buf.appendSlice(allocator, "Okx");
    try sock.write_buf.append(allocator, 0);

    const dim = "minecraft:overworld";
    const codec = @embedFile("registry_codec_1.20.dat");
    try sock.write_buf.appendSlice(allocator, varint.writeVarInt(@intCast(1 + 4 + 5 + dim.len + codec.len + 1 + dim.len + 1 + dim.len + 8 + 9), &lenbuf));
    try sock.write_buf.append(allocator, 0x28); // packet id
    try sock.write_buf.appendSlice(allocator, &[_]u8{ 0, 0, 0, 1 }); // entity id
    try sock.write_buf.append(allocator, 0); // is hardcode
    try sock.write_buf.append(allocator, 0); // game mode
    try sock.write_buf.append(allocator, 0); // previous game mode
    try sock.write_buf.append(allocator, 1); // dimension count
    try sock.write_buf.append(allocator, @intCast(dim.len)); // dimension names[0]
    try sock.write_buf.appendSlice(allocator, dim); // dimension name[0]
    try sock.write_buf.appendSlice(allocator, codec);
    try sock.write_buf.append(allocator, @intCast(dim.len)); // dimension type
    try sock.write_buf.appendSlice(allocator, dim); // dimension type
    try sock.write_buf.append(allocator, @intCast(dim.len)); // dimension name
    try sock.write_buf.appendSlice(allocator, dim); // dimension name
    try sock.write_buf.appendSlice(allocator, &[_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 }); // hashed seed
    try sock.write_buf.append(allocator, 0); // max players
    try sock.write_buf.append(allocator, 8); // view distance
    try sock.write_buf.append(allocator, 8); // simulation distance
    try sock.write_buf.append(allocator, 0); // reduced debug info
    try sock.write_buf.append(allocator, 1); // enable respawn screen
    try sock.write_buf.append(allocator, 0); // is debug
    try sock.write_buf.append(allocator, 1); // is flat
    try sock.write_buf.append(allocator, 0); // has death location
    try sock.write_buf.append(allocator, 0); // portal cooldown

    // Chunk Data and Update Light

    var node = try allocator.create(ServerQueue.Node);
    node.data = .{ .queue = packet_queue, .player = player, .type = packets.ServerboundPacketType.Play };
    server_queue.put(node);
    // if it blocks it's hit the maximum value, so the best option is to crash
    std.debug.assert(8 == os.write(eventfd, &std.mem.toBytes(@as(u64, 1))) catch unreachable);
}

fn sendKeepAlivePacket(allocator: std.mem.Allocator, sock: *Socket) !void {
    // TODO check received keep alive
    if (sock.protocol_state == ProtocolState.Play) {
        var lenbuf: [5]u8 = undefined;
        try sock.write_buf.appendSlice(allocator, varint.writeVarInt(@intCast(1 + 8), &lenbuf));
        try sock.write_buf.append(allocator, 0x23); // packet id
        try sock.write_buf.appendSlice(allocator, &std.mem.toBytes(std.mem.nativeToBig(u64, @as(u64, 0))));
    }
}

fn handlePacket(id: u32, pkt: []u8, allocator: std.mem.Allocator, packet_queue: *std.atomic.Queue([]u8), server_queue: *ServerQueue, eventfd: os.socket_t, player: usize) !void {
    var buffer = std.io.fixedBufferStream(pkt);
    const reader = buffer.reader();
    const packet: packets.ServerboundPacketType = switch (id) {
        0x14 => .{ .Pos = .{
            .x = @bitCast(try reader.readIntBig(u64)),
            .y = @bitCast(try reader.readIntBig(u64)),
            .z = @bitCast(try reader.readIntBig(u64)),
        } },
        0x15 => .{
            .Pos = .{ // actually pos rot
                .x = @bitCast(try reader.readIntBig(u64)),
                .y = @bitCast(try reader.readIntBig(u64)),
                .z = @bitCast(try reader.readIntBig(u64)),
            },
        },
        else => return,
    };

    var node = try allocator.create(ServerQueue.Node);
    node.data = .{ .queue = packet_queue, .player = player, .type = packet };
    server_queue.put(node);
    // if it blocks it's hit the maximum value, so the best option is to crash
    std.debug.assert(8 == os.write(eventfd, &std.mem.toBytes(@as(u64, 1))) catch unreachable);
}

// Workaround for Zig not translating macros correctly
pub inline fn EVP_RSA_gen(bits: usize) ?*c.EVP_PKEY {
    return c.EVP_PKEY_Q_keygen(null, null, "RSA", bits);
}
