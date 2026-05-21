//! Encrypts and decrypts a message with the XSalsa20 stream cipher.
//!
//! XSalsa20 provides confidentiality but NOT integrity: a tampered ciphertext
//! decrypts to garbage with no error. For authenticated encryption, use
//! `secretbox` (XSalsa20-Poly1305) once it lands — see the roadmap.
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
    const message = "XSalsa20 keeps this message confidential.";

    // Encrypt.
    var ciphertext: [message.len]u8 = undefined;
    nacl.lowlevel.xsalsa20.stream(&ciphertext, message, &nonce, &key);

    // Decrypt — the stream cipher is its own inverse.
    var decrypted: [message.len]u8 = undefined;
    nacl.lowlevel.xsalsa20.stream(&decrypted, &ciphertext, &nonce, &key);

    const ciphertext_hex = std.fmt.bytesToHex(ciphertext, .lower);
    std.debug.print("message:    {s}\n", .{message});
    std.debug.print("ciphertext: {s}\n", .{ciphertext_hex[0..]});
    std.debug.print("decrypted:  {s}\n", .{decrypted[0..]});
    std.debug.print("round-trip: {s}\n", .{
        if (std.mem.eql(u8, message, &decrypted)) "OK" else "FAILED",
    });
}
