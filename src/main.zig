const std = @import("std");
const eql = std.mem.eql;
const Address = std.net.Address;
const Writer = std.fs.File.Writer;
const Ip4Address = std.net.Ip4Address;

const usage = "usage: ipcalc <prefix>\n" ++ "prefix:\n\t\"network/prefix\"\n\t\"network netmask\"\n";

fn print_usage(out: std.fs.File) !void {
    _ = try out.write(usage);
}

const ParsingError = error{
    IP4PrefixTooBig,
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

    fn get_num_possible_hosts(self: *Self) u32 {
        return std.math.pow(u32, 2, (32 - self.prefix)) - 2;
    }

    fn print_address(self: *Self, writer: Writer) !void {
        try print_u32_as_bytes(self.address, writer);
    }

    fn print_netmask(self: *Self, writer: Writer) !void {
        try print_u32_as_bytes(self.netmask, writer);
    }

    fn print_wildcard(self: *Self, writer: Writer) !void {
        try print_u32_as_bytes(~self.netmask, writer);
    }

    fn print_network(self: *Self, writer: Writer) !void {
        try print_u32_as_bytes(self.address & self.netmask, writer);
    }

    fn print_broadcast(self: *Self, writer: Writer) !void {
        try print_u32_as_bytes(self.address | ~self.netmask, writer);
    }

    fn print_first_host(self: *Self, writer: Writer) !void {
        try print_u32_as_bytes((self.address & self.netmask) + 1, writer);
    }

    fn print_last_host(self: *Self, writer: Writer) !void {
        try print_u32_as_bytes((self.address | ~self.netmask) - 1, writer);
    }

    fn print_u32_as_bytes(value: u32, writer: Writer) !void {
        const bytes = @as(*const [4]u8, @ptrCast(&value));
        try writer.print(
            "{}.{}.{}.{}",
            .{ bytes[3], bytes[2], bytes[1], bytes[0] },
        );
    }

    fn print_info(self: *Self, writer: Writer) !void {
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

// TODO: use errdefer to print usage in case of error
pub fn main() !u8 {
    const argv = std.os.argv;
    const stderr = std.io.getStdErr();
    const stdout = std.io.getStdOut();

    // if no parameter specified print usage to stderr and exit
    if (argv.len == 1) {
        _ = try stderr.write("ipcalc: no parameter was specified\n");
        try print_usage(stderr);
        return 1;
    }

    // we need to convert arg to slice with len, because initially it has type [*:0]u8
    const arg = argv[1][0..std.mem.len(argv[1])];
    // if parameter is -h or --help print usage to stdout
    if (eql(u8, arg, "-h") or eql(u8, arg, "--help")) {
        try print_usage(stdout);
        return 0;
    }

    // if user provided "network netmask", we will have argv.len == 3
    // else we try to parse it as "network/prefix"
    var address: Address = undefined;
    var prefix: usize = undefined;

    if (argv.len == 3) {
        address = Address.parseIp4(arg, 0) catch {
            std.debug.print("Invalid IP address\n", .{});
            try print_usage(stderr);
            return 1;
        };
        const netmask_string = argv[2][0..std.mem.len(argv[2])];
        const netmask = Address.parseIp4(netmask_string, 0) catch {
            std.debug.print("Invalid IP netmask\n", .{});
            try print_usage(stderr);
            return 1;
        };
        _ = netmask;
        // TODO: Finish netmask parsing. How to check netmask validity?
    } else {
        // if we get CIDR notation, split arg to two slices
        const index = std.mem.indexOfScalar(u8, arg, '/') orelse {
            std.debug.print("Invalid prefix CIDR\n", .{});
            try print_usage(stderr);
            return 1;
        };
        address = Address.parseIp4(arg[0..index], 0) catch {
            std.debug.print("Invalid IP address\n", .{});
            try print_usage(stderr);
            return 1;
        };
        prefix = try std.fmt.parseInt(usize, arg[index + 1 ..], 10);
        if (prefix > 32) {
            std.debug.print("Invalid prefix length\n", .{});
            try print_usage(stderr);
            return 1;
        }
    }

    const writer = stdout.writer();
    const u6_prefix: u6 = @intCast(prefix & 0b111111);
    var adr = try Ip4CIDR.fromStdIp4Address(address.in, u6_prefix);
    try adr.print_info(writer);

    return 0;
}

// TODO: Add tests
