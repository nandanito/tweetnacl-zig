const std = @import("std");
const nacl = @import("tweetnacl-zig"); // Import your library

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();

    // Example configuration
    const key = [32]u8{ 0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4, 0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7, 0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2, 0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89 };
    const nonce = [16]u8{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    // Buffers
    var salsa_out: [64]u8 = undefined;
    var hsalsa_out: [32]u8 = undefined;

    // Core operations
    nacl.salsa20.salsa20(&salsa_out, &nonce, &key);
    nacl.salsa20.hsalsa20(&hsalsa_out, &nonce, &key);

    // Print results
    try stdout.print("Salsa20 output:\n{s}\n", .{std.fmt.fmtSliceHexLower(&salsa_out)});
    try stdout.print("HSalsa20 output:\n{s}\n", .{std.fmt.fmtSliceHexLower(&hsalsa_out)});
}
