//! Public-key authenticated encryption with box (Curve25519-XSalsa20-Poly1305).
//!
//! box lets two parties exchange a message using only each other's *public*
//! keys: Alice seals a message for Bob with her secret key and his public key;
//! Bob opens it with his secret key and her public key. The box is both
//! encrypted and authenticated, so Bob knows it came from Alice untampered.
const std = @import("std");
const nacl = @import("tweetnacl_zig");

pub fn main() void {
    // Fixed secret keys so this demo prints reproducible output. In production
    // generate each key pair with `box.keyPair(io)`, which draws the secret
    // key from the operating system's CSPRNG.
    const alice_secret = [_]u8{
        0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
        0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
        0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
        0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
    };
    const bob_secret = [_]u8{
        0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
        0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
        0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
        0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
    };

    // Each party derives a public key to share. The secret key stays private.
    const alice = nacl.box.keyPairFromSecretKey(&alice_secret);
    const bob = nacl.box.keyPairFromSecretKey(&bob_secret);

    // A nonce must be unique per (key pair, message) — never reuse one.
    const nonce = [_]u8{
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    };
    const message = "box: only Bob can read this, and he knows Alice sent it.";

    // Alice seals for Bob: his public key, her secret key. `seal` returns
    // error.WeakPublicKey if the recipient key is a low-order point.
    var boxed: [message.len + nacl.box.overhead]u8 = undefined;
    nacl.box.seal(&boxed, message, &nonce, &bob.public_key, &alice.secret_key) catch {
        std.debug.print("seal:         recipient public key is weak\n", .{});
        return;
    };

    const boxed_hex = std.fmt.bytesToHex(boxed, .lower);
    std.debug.print("message:      {s}\n", .{message});
    std.debug.print("sealed box:   {s}\n", .{boxed_hex[0..]});

    // Bob opens it: Alice's public key, his secret key.
    var opened: [message.len]u8 = undefined;
    nacl.box.open(&opened, &boxed, &nonce, &alice.public_key, &bob.secret_key) catch {
        std.debug.print("open:         authentication FAILED\n", .{});
        return;
    };
    std.debug.print("opened:       {s}\n", .{opened[0..]});

    // Tamper detection: flip a single byte of the sealed box.
    var tampered = boxed;
    tampered[30] ^= 0x01;
    if (nacl.box.open(&opened, &tampered, &nonce, &alice.public_key, &bob.secret_key)) |_| {
        std.debug.print("tampered box: opened (UNEXPECTED)\n", .{});
    } else |_| {
        std.debug.print("tampered box: rejected with AuthFailed (as expected)\n", .{});
    }
}
