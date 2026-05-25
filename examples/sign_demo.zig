//! Ed25519 digital signatures with sign.
//!
//! sign lets a holder of a secret key attach a 64-byte signature to a message;
//! anyone who knows the corresponding public key can then verify that the
//! message came from the signer and was not modified in flight. Signatures
//! are deterministic — the same `(secret_key, message)` always produces the
//! same 64 bytes, so signing is reproducible without any random source.
const std = @import("std");
const nacl = @import("tweetnacl_zig");

pub fn main() void {
    // Fixed seed so this demo prints reproducible output. In production
    // generate each key pair with `sign.keyPair(io)`, which draws the seed
    // from the operating system's CSPRNG. This seed is RFC 8032 §7.1 vector 2.
    const seed = [_]u8{
        0x4c, 0xcd, 0x08, 0x9b, 0x28, 0xff, 0x96, 0xda,
        0x9d, 0xb6, 0xc3, 0x46, 0xec, 0x11, 0x4e, 0x0f,
        0x5b, 0x8a, 0x31, 0x9f, 0x35, 0xab, 0xa6, 0x24,
        0xda, 0x8c, 0xf6, 0xed, 0x4f, 0xb8, 0xa6, 0xfb,
    };
    const kp = nacl.sign.keyPairFromSeed(&seed);

    const message = "sign: anyone with the public key can verify this came from me.";

    // Detached signature — 64 bytes, independent of the message.
    var sig: [nacl.sign.signature_length]u8 = undefined;
    nacl.sign.signDetached(&sig, message, &kp.secret_key);

    const pk_hex = std.fmt.bytesToHex(kp.public_key, .lower);
    const sig_hex = std.fmt.bytesToHex(sig, .lower);
    std.debug.print("message:      {s}\n", .{message});
    std.debug.print("public key:   {s}\n", .{pk_hex[0..]});
    std.debug.print("signature:    {s}\n", .{sig_hex[0..]});

    // Anyone with the public key can verify.
    nacl.sign.verifyDetached(&sig, message, &kp.public_key) catch {
        std.debug.print("verify:       authentication FAILED\n", .{});
        return;
    };
    std.debug.print("verify:       OK\n", .{});

    // Tamper detection: flip a single byte of the message and re-verify.
    var tampered: [message.len]u8 = undefined;
    @memcpy(&tampered, message);
    tampered[7] ^= 0x01;
    if (nacl.sign.verifyDetached(&sig, &tampered, &kp.public_key)) |_| {
        std.debug.print("tampered msg: verified (UNEXPECTED)\n", .{});
    } else |_| {
        std.debug.print("tampered msg: rejected with AuthFailed (as expected)\n", .{});
    }
}
