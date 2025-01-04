const std = @import("std");
const eql = std.mem.eql;
const Address = std.net.Address;
const Ip4Address = std.net.Ip4Address;

const ParsingError = error{
    IP4PrefixTooBig,
};

const usage = "usage: ipcalc <prefix>\n" ++ "prefix:\n\t\"network/prefix\"\n\t\"network netmask\"\n";

fn print_usage(out: std.fs.File) !void {
    _ = try out.write(usage);
}

fn print_info_ip4(out: std.fs.File, address: Ip4Address, prefix: usize) !void {
    const writer = out.writer();
    if (prefix > 32) return ParsingError.IP4PrefixTooBig;

    // output address
    _ = try writer.write("Address:\n");
    const bytes = @as(*const [4]u8, @ptrCast(&address.sa.addr));
    try writer.print("{}.{}.{}.{}\n", .{ bytes[0], bytes[1], bytes[2], bytes[3] });

    // calculate and output netmask
    const maxInt: u32 = std.math.maxInt(u32);
    var netmask: u32 = 0;
    if (prefix == 0) {
        netmask = 0;
    } else if (prefix == 32) {
        netmask = maxInt;
    } else {
        netmask = maxInt << (0 -% @as(u5, @intCast(prefix & 0b11111)));
    }
    _ = try writer.write("Netmask (=prefix):\n");
    const netmask_bytes = @as(*const [4]u8, @ptrCast(&netmask));
    try writer.print("{}.{}.{}.{} = {}\n", .{ netmask_bytes[3], netmask_bytes[2], netmask_bytes[1], netmask_bytes[0], prefix });

    // calculate and print wildcard mask
    const wildcard = ~netmask;
    _ = try writer.write("Wildcard:\n");
    const wildcard_bytes = @as(*const [4]u8, @ptrCast(&wildcard));
    try writer.print("{}.{}.{}.{}\n", .{
        wildcard_bytes[3],
        wildcard_bytes[2],
        wildcard_bytes[1],
        wildcard_bytes[0],
    });

    // skip other params if prefix == 32
    if (prefix == 32) {
        return;
    }

    // network
    const network = address.sa.addr; // & @bitReverse(netmask);
    _ = try writer.write("Network:\n");
    const network_bytes = @as(*const [4]u8, @ptrCast(&network));
    try writer.print("{}.{}.{}.{}\n", .{
        network_bytes[0] & netmask_bytes[3],
        network_bytes[1] & netmask_bytes[2],
        network_bytes[2] & netmask_bytes[1],
        network_bytes[3] & netmask_bytes[0],
    });

    // broadcast
    const broadcast = network;
    _ = try writer.write("Broadcast:\n");
    const broadcast_bytes = @as(*const [4]u8, @ptrCast(&broadcast));
    try writer.print("{}.{}.{}.{}\n", .{
        broadcast_bytes[0] | wildcard_bytes[3],
        broadcast_bytes[1] | wildcard_bytes[2],
        broadcast_bytes[2] | wildcard_bytes[1],
        broadcast_bytes[3] | wildcard_bytes[0],
    });

    // skip other params if prefix == 31
    if (prefix == 31) {
        return;
    }

    // first host
    _ = try writer.write("First host:\n");
    try writer.print("{}.{}.{}.{}\n", .{
        network_bytes[0] & netmask_bytes[3],
        network_bytes[1] & netmask_bytes[2],
        network_bytes[2] & netmask_bytes[1],
        network_bytes[3] & netmask_bytes[0] + 1,
    });

    // last host
    _ = try writer.write("Last host:\n");
    try writer.print("{}.{}.{}.{}\n", .{
        broadcast_bytes[0] | wildcard_bytes[3],
        broadcast_bytes[1] | wildcard_bytes[2],
        broadcast_bytes[2] | wildcard_bytes[1],
        broadcast_bytes[3] | wildcard_bytes[0] - 1,
    });

    // number of hosts
    const num_possible_hosts = std.math.pow(usize, 2, (32 - prefix)) - 2;
    _ = try writer.write("Possible hosts:\n");
    try writer.print("{d}\n", .{num_possible_hosts});
}

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

    try print_info_ip4(stdout, address.in, prefix);

    return 0;
}

// TODO: Add tests
