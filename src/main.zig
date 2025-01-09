const std = @import("std");
const eql = std.mem.eql;
const Address = std.net.Address;
const Ip4Address = std.net.Ip4Address;

const usage = "usage: ipcalc <prefix>\n" ++ "prefix:\n\t\"network/prefix\"\n\t\"network netmask\"\n";

fn print_usage(out: std.fs.File) !void {
    _ = try out.write(usage);
}

const ParsingError = error{
    HelpRequested,
    NoArgumentsSpecified,
    IP4PrefixTooBig,
    IP4PrefixInvalid,
    IP4AddressInvalid,
    IP4NetmaskInvalid,
    IP4CIDRInvalid,
};

const Ip4CIDR = struct {
    const Self = @This();
    address: u32,
    prefix: u6, // we use u6 instead of u5, because we need values from 0 to 32
    netmask: u32,

    fn fromStdIp4Address(address: Ip4Address, prefix: u6) !Self {
        if (prefix > 32) return error.IP4PrefixTooBig;
        const bytes = @as(*const [4]u8, @ptrCast(&address.sa.addr));
        var result_bytes: [4]u8 = [_]u8{0} ** 4;
        result_bytes[3] = bytes[0];
        result_bytes[2] = bytes[1];
        result_bytes[1] = bytes[2];
        result_bytes[0] = bytes[3];
        const result = @as(*const u32, @ptrCast(@alignCast(&result_bytes)));
        const netmask = Self.calculate_netmask_from_prefix(prefix);
        return Self{ .address = result.*, .prefix = prefix, .netmask = netmask };
    }

    fn calculate_netmask_from_prefix(prefix: u6) u32 {
        const host_bits = 32 - prefix;
        var netmask: u32 = 0xffffffff;
        if (host_bits == 32) {
            netmask = 0x00000000;
        } else {
            netmask <<= @as(u5, @intCast(host_bits & 0b11111));
        }
        return netmask;
    }

    fn get_num_possible_hosts(self: Self) u32 {
        return std.math.pow(u32, 2, (32 - self.prefix)) - 2;
    }

    fn print_address(self: Self, writer: anytype) !void {
        try print_u32_as_bytes(self.address, writer);
    }

    fn print_netmask(self: Self, writer: anytype) !void {
        try print_u32_as_bytes(self.netmask, writer);
    }

    fn print_wildcard(self: Self, writer: anytype) !void {
        try print_u32_as_bytes(~self.netmask, writer);
    }

    fn print_network(self: Self, writer: anytype) !void {
        try print_u32_as_bytes(self.address & self.netmask, writer);
    }

    fn print_broadcast(self: Self, writer: anytype) !void {
        try print_u32_as_bytes(self.address | ~self.netmask, writer);
    }

    fn print_first_host(self: Self, writer: anytype) !void {
        try print_u32_as_bytes((self.address & self.netmask) + 1, writer);
    }

    fn print_last_host(self: Self, writer: anytype) !void {
        try print_u32_as_bytes((self.address | ~self.netmask) - 1, writer);
    }

    fn print_u32_as_bytes(value: u32, writer: anytype) !void {
        const bytes = @as(*const [4]u8, @ptrCast(&value));
        try writer.print(
            "{}.{}.{}.{}",
            .{ bytes[3], bytes[2], bytes[1], bytes[0] },
        );
    }

    fn print_info(self: Self, writer: anytype) !void {
        _ = try writer.write("Address:\n");
        try self.print_address(writer);
        _ = try writer.write("\n");
        _ = try writer.write("Netmask:\n");
        try self.print_netmask(writer);
        try writer.print(" = {d}", .{self.prefix});
        _ = try writer.write("\n");
        _ = try writer.write("Wildcard:\n");
        try self.print_wildcard(writer);
        _ = try writer.write("\n");

        if (self.prefix != 32) {
            _ = try writer.write("Network:\n");
            try self.print_network(writer);
            _ = try writer.write("\n");
            _ = try writer.write("Broadcast:\n");
            try self.print_broadcast(writer);
            _ = try writer.write("\n");

            if (self.prefix != 31) {
                _ = try writer.write("First Host:\n");
                try self.print_first_host(writer);
                _ = try writer.write("\n");
                _ = try writer.write("Last Host:\n");
                try self.print_last_host(writer);
                _ = try writer.write("\n");
                try writer.print("Number of possible hosts: {d}\n", .{self.get_num_possible_hosts()});
            }
        }
    }
};

fn parse_args(argv: [][*:0]const u8) !struct { Ip4Address, u6 } {
    // const argv = std.os.argv;
    // if no parameter specified print usage to stderr and exit
    if (argv.len == 1) return error.NoArgumentsSpecified;

    // we need to convert arg to slice with len, because initially it has type [*:0]u8
    const arg = argv[1][0..std.mem.len(argv[1])];
    // if parameter is -h or --help print usage to stdout
    if (eql(u8, arg, "-h") or eql(u8, arg, "--help")) return error.HelpRequested;

    // if user provided "network netmask", we will have argv.len == 3
    // else we try to parse it as "network/prefix"
    var address: Address = undefined;
    var prefix: u6 = undefined;

    if (argv.len == 3) {
        address = Address.parseIp4(arg, 0) catch return error.IP4AddressInvalid;
        const netmask_string = argv[2][0..std.mem.len(argv[2])];
        const netmask = Address.parseIp4(netmask_string, 0) catch return error.IP4NetmaskInvalid;
        _ = netmask;
        // TODO: Finish netmask parsing. How to check netmask validity?
    } else {
        // if we get CIDR notation, split arg to two slices
        const index = std.mem.indexOfScalar(u8, arg, '/') orelse return error.IP4CIDRInvalid;
        address = Address.parseIp4(arg[0..index], 0) catch return error.IP4AddressInvalid;
        prefix = std.fmt.parseInt(u6, arg[index + 1 ..], 10) catch return error.IP4PrefixInvalid;
        if (prefix > 32) return error.IP4PrefixTooBig;
    }

    return .{ address.in, prefix };
}

pub fn main() !void {
    const stderr = std.io.getStdErr();
    const stdout = std.io.getStdOut();
    const argv = std.os.argv;

    const parsed = parse_args(argv) catch |err| {
        switch (err) {
            // if help was requested, write usage to stdout and exit successfully
            error.HelpRequested => {
                try print_usage(stdout);
                std.process.exit(0);
            },
            // if we get parsing error, write usage to stderr and exit with error
            error.IP4CIDRInvalid, error.IP4NetmaskInvalid, error.IP4AddressInvalid, error.NoArgumentsSpecified, error.IP4PrefixInvalid, error.IP4PrefixTooBig => {
                try stderr.writer().print("error: {!}\n", .{err});
                try print_usage(stderr);
                std.process.exit(1);
            },
        }
    };
    const address = parsed[0];
    const prefix = parsed[1];

    const writer = stdout.writer();
    var adr = try Ip4CIDR.fromStdIp4Address(address, prefix);
    try adr.print_info(writer);

    std.process.exit(0);
}

test "address with different prefixes" {
    // Too much code for this type of test, maybe I am doing something wrong?
    const allocator = std.testing.allocator;
    var list = std.ArrayList(u8).init(allocator);
    defer list.deinit();
    const w = list.writer();

    const address = try Ip4Address.parse("10.11.12.13", 0);
    const adr0 = try Ip4CIDR.fromStdIp4Address(address, 0);
    const adr1 = try Ip4CIDR.fromStdIp4Address(address, 8);
    const adr2 = try Ip4CIDR.fromStdIp4Address(address, 12);
    const adr3 = try Ip4CIDR.fromStdIp4Address(address, 16);
    const adr4 = try Ip4CIDR.fromStdIp4Address(address, 24);
    const adr5 = try Ip4CIDR.fromStdIp4Address(address, 32);

    try adr0.print_address(w);
    _ = try w.write("\n");
    try adr0.print_netmask(w);
    _ = try w.write("\n");
    try adr1.print_netmask(w);
    _ = try w.write("\n");
    try adr2.print_netmask(w);
    _ = try w.write("\n");
    try adr3.print_netmask(w);
    _ = try w.write("\n");
    try adr4.print_netmask(w);
    _ = try w.write("\n");
    try adr5.print_netmask(w);

    const captured_output = try list.toOwnedSlice();
    defer allocator.free(captured_output);
    const expect =
        \\10.11.12.13
        \\0.0.0.0
        \\255.0.0.0
        \\255.240.0.0
        \\255.255.0.0
        \\255.255.255.0
        \\255.255.255.255
    ;
    try std.testing.expectEqualStrings(expect, captured_output);
}

test "no args error" {
    // This looks awful, but I don't know a better way to fake std.os.argv type
    const argv0: [][*:0]const u8 = @constCast(@ptrCast(&[_][*:0]const u8{
        "ipcalc",
    }));
    const p = parse_args(argv0);
    try std.testing.expectError(error.NoArgumentsSpecified, p);
}

test "invalid CIDR error" {
    const argv0: [][*:0]const u8 = @constCast(@ptrCast(&[_][*:0]const u8{ "ipcalc", "assdfsdb" }));
    const p = parse_args(argv0);
    try std.testing.expectError(error.IP4CIDRInvalid, p);
}

test "invalid address error" {
    const argv0: [][*:0]const u8 = @constCast(@ptrCast(&[_][*:0]const u8{ "ipcalc", "172.260.40.40/24" }));
    const p = parse_args(argv0);
    try std.testing.expectError(error.IP4AddressInvalid, p);
}

test "invalid prefix error" {
    const argv0: [][*:0]const u8 = @constCast(@ptrCast(&[_][*:0]const u8{ "ipcalc", "172.40.40.40/df" }));
    const p = parse_args(argv0);
    try std.testing.expectError(error.IP4PrefixInvalid, p);
}

test "prefix too big error" {
    const argv0: [][*:0]const u8 = @constCast(@ptrCast(&[_][*:0]const u8{ "ipcalc", "172.40.40.40/33" }));
    const p = parse_args(argv0);
    try std.testing.expectError(error.IP4PrefixTooBig, p);
}
