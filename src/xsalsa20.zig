const std = @import("std");
const salsa20 = @import("salsa20.zig");
const mem = std.mem;
const crypto = std.crypto;

/// XSalsa20 constants
const sigma = [_]u8{ 101, 120, 112, 97, 110, 100, 32, 51, 50, 45, 98, 121, 116, 101, 32, 107 };

/// XSalsa20 stream cipher (24-byte nonce version)
pub fn xsalsa20Xor(
    out: []u8,
    msg: []const u8,
    nonce: []const u8,
    key: []const u8,
) void {
    std.debug.assert(nonce.len == 24); // xsalsa20 requires 24-byte nonce
    std.debug.assert(key.len == 32); // 256-bit key
    std.debug.assert(out.len == msg.len); // Output must match message size

    // HSalsa20 for subkey generation
    var subkey: [32]u8 = undefined;
    salsa20.hsalsa20(
        subkey[0..], // out
        nonce[0..16], // input (first 16 bytes of nonce)
        key, // key
    );

    // Salsa20 for actual encryption
    salsa20.salsa20Xor(
        out,
        msg,
        nonce[16..24], // Last 8 bytes as Salsa20 nonce
        &subkey,
    );
}

// Test vector from NaCl's tests/stream2.c
test "XSalsa20 Known Answer Test" {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 24;
    const msg = [_]u8{0} ** 128;
    var cipher: [128]u8 = undefined;

    xsalsa20Xor(&cipher, &msg, &nonce, &key);

    // Expected output from first 32 bytes of 128-zero-byte encryption
    const expected = [_]u8{
        0x21, 0xa7, 0x60, 0xf7, 0xd5, 0xbf, 0xec, 0x7a,
        0x3f, 0x3f, 0x0a, 0x6a, 0xdc, 0x1f, 0x1d, 0xab,
        0xee, 0x1c, 0x46, 0x8a, 0x2d, 0x53, 0xae, 0x16,
        0x4a, 0x18, 0xcc, 0x02, 0x7c, 0xbf, 0xe0, 0xdb,
    };

    try std.testing.expectEqualSlices(
        u8,
        &expected,
        cipher[0..32],
    );
}

test "XSalsa20 Round Trip" {
    const allocator = std.testing.allocator;
    const msg = "Test message for XSalsa20";
    const nonce = [_]u8{0} ** 24;
    const key = [_]u8{0x42} ** 32;

    const cipher = try allocator.alloc(u8, msg.len);
    defer allocator.free(cipher);
    const plain = try allocator.alloc(u8, msg.len);
    defer allocator.free(plain);

    // Encrypt
    xsalsa20Xor(cipher, msg, &nonce, &key);

    // Decrypt (XSalsa20 is symmetric)
    xsalsa20Xor(plain, cipher, &nonce, &key);

    try std.testing.expectEqualStrings(msg, plain);
}
