//! Demonstrates the low-level Salsa20 / HSalsa20 core permutation.
//!
//! `core` produces one 64-byte keystream block; `hsalsa20` derives the 32-byte
//! subkey that XSalsa20 uses to support a 24-byte nonce. Most applications
//! should not call these directly — see xsalsa20_demo for the stream cipher,
//! and prefer `secretbox` (roadmap) for authenticated encryption.
const std = @import("std");
const nacl = @import("tweetnacl_zig");

pub fn main() void {
    // All-zero key and input block so the output is reproducible.
    const key = [_]u8{0} ** 32;
    const input = [_]u8{0} ** 16; // 8-byte nonce ++ 8-byte block counter

    var block: [64]u8 = undefined;
    nacl.lowlevel.salsa20.core(&block, &input, &key);
    const block_hex = std.fmt.bytesToHex(block, .lower);
    std.debug.print("Salsa20 keystream block:\n  {s}\n", .{block_hex[0..]});

    var subkey: [32]u8 = undefined;
    nacl.lowlevel.salsa20.hsalsa20(&subkey, &input, &key);
    const subkey_hex = std.fmt.bytesToHex(subkey, .lower);
    std.debug.print("HSalsa20 subkey:\n  {s}\n", .{subkey_hex[0..]});
}
