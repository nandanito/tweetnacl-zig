//! Authenticated encryption with secretbox (XSalsa20-Poly1305).
//!
//! secretbox both encrypts a message and attaches an authentication tag, so
//! any tampering with the sealed box is detected when it is opened. This is
//! the API most applications should use.
const std = @import("std");
const nacl = @import("tweetnacl_zig");

pub fn main() void {
    // Fixed key and nonce so this demo prints reproducible output.
    // In production: draw both from a CSPRNG, and NEVER reuse a (key, nonce).
    const key = [_]u8{
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
        0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78,
        0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0,
    };
    const nonce = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const message = "secretbox: encrypted and authenticated.";

    // Seal: the sealed box is the message plus a 16-byte tag.
    var boxed: [message.len + nacl.secretbox.overhead]u8 = undefined;
    nacl.secretbox.seal(&boxed, message, &nonce, &key);

    const boxed_hex = std.fmt.bytesToHex(boxed, .lower);
    std.debug.print("message:      {s}\n", .{message});
    std.debug.print("sealed box:   {s}\n", .{boxed_hex[0..]});

    // Open: verifies the tag, then decrypts.
    var opened: [message.len]u8 = undefined;
    nacl.secretbox.open(&opened, &boxed, &nonce, &key) catch {
        std.debug.print("open:         authentication FAILED\n", .{});
        return;
    };
    std.debug.print("opened:       {s}\n", .{opened[0..]});

    // Tamper detection: flip a single byte of the sealed box.
    var tampered = boxed;
    tampered[20] ^= 0x01;
    if (nacl.secretbox.open(&opened, &tampered, &nonce, &key)) |_| {
        std.debug.print("tampered box: opened (UNEXPECTED)\n", .{});
    } else |_| {
        std.debug.print("tampered box: rejected with AuthFailed (as expected)\n", .{});
    }
}
