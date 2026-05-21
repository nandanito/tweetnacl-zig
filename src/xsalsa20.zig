//! XSalsa20 stream cipher — Salsa20 extended to a 192-bit (24-byte) nonce.
//!
//! Low-level building block; provides confidentiality only. For authenticated
//! encryption use `secretbox`.
const std = @import("std");
const salsa20 = @import("salsa20.zig");

/// XSalsa20 stream cipher: XORs `msg` with the keystream produced from a
/// 24-byte nonce and a 32-byte key, writing `msg.len` bytes to `out`.
///
/// The same call decrypts. Provides confidentiality only — no authentication.
pub fn stream(out: []u8, msg: []const u8, nonce: *const [24]u8, key: *const [32]u8) void {
    std.debug.assert(out.len == msg.len);

    // Derive a subkey from the first 16 nonce bytes via HSalsa20...
    var subkey: [32]u8 = undefined;
    defer std.crypto.secureZero(u8, &subkey);
    salsa20.hsalsa20(&subkey, nonce[0..16], key);

    // ...then run Salsa20 with that subkey and the remaining 8 nonce bytes.
    salsa20.stream(out, msg, nonce[16..24], &subkey);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "XSalsa20 stream matches std.crypto across sizes (incl. multi-block)" {
    var prng = std.Random.DefaultPrng.init(0xfeedface00c0ffee);
    const rand = prng.random();
    const sizes = [_]usize{ 0, 1, 63, 64, 65, 128, 192, 777 };
    for (sizes) |len| {
        var iter: usize = 0;
        while (iter < 32) : (iter += 1) {
            var key: [32]u8 = undefined;
            var nonce: [24]u8 = undefined;
            var msg: [777]u8 = undefined;
            rand.bytes(&key);
            rand.bytes(&nonce);
            rand.bytes(msg[0..len]);

            var mine: [777]u8 = undefined;
            var reference: [777]u8 = undefined;
            stream(mine[0..len], msg[0..len], &nonce, &key);
            std.crypto.stream.salsa.XSalsa20.xor(reference[0..len], msg[0..len], 0, key, nonce);
            try testing.expectEqualSlices(u8, reference[0..len], mine[0..len]);
        }
    }
}

test "XSalsa20 stream round-trips" {
    var prng = std.Random.DefaultPrng.init(0x99aabbccddeeff00);
    const rand = prng.random();
    var key: [32]u8 = undefined;
    var nonce: [24]u8 = undefined;
    var msg: [250]u8 = undefined;
    rand.bytes(&key);
    rand.bytes(&nonce);
    rand.bytes(&msg);

    var ciphertext: [250]u8 = undefined;
    var plaintext: [250]u8 = undefined;
    stream(&ciphertext, &msg, &nonce, &key);
    stream(&plaintext, &ciphertext, &nonce, &key);
    try testing.expectEqualSlices(u8, &msg, &plaintext);
}
