const std = @import("std");
const nacl = @import("tweetnacl-zig"); // Import your library
const print = std.debug.print;
const crypto = std.crypto;

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    // --- Configuration ---
    const message = "Zig Cryptography Demo: Securing Data with XSalsa20!";
    print("\n=== XSalsa20 Stream Cipher Demo ===\n\n", .{});
    print("Original Message: {s}\n", .{message});

    // --- Key & Nonce Generation ---
    var key: [32]u8 = undefined; // 256-bit key
    var nonce: [24]u8 = undefined; // 192-bit nonce

    // Generate secure random values
    crypto.random.bytes(&key);
    crypto.random.bytes(&nonce);

    print("\nGenerated Key (hex):    {s}\n", .{std.fmt.fmtSliceHexLower(&key)});
    print("Generated Nonce (hex):  {s}\n", .{std.fmt.fmtSliceHexLower(&nonce)});

    // --- Encryption ---
    const ciphertext = try allocator.alloc(u8, message.len);
    defer allocator.free(ciphertext);

    nacl.xsalsa20.xsalsa20Xor(ciphertext, message, &nonce, &key);
    print("\nEncrypted Ciphertext (hex):\n{s}\n", .{
        std.fmt.fmtSliceHexLower(ciphertext),
    });

    // --- Decryption ---
    const plaintext = try allocator.alloc(u8, ciphertext.len);
    defer allocator.free(plaintext);

    nacl.xsalsa20.xsalsa20Xor(plaintext, ciphertext, &nonce, &key);
    print("\nDecrypted Message: {s}\n", .{plaintext});

    // --- Verification ---
    print("\nVerification: ", .{});
    if (std.mem.eql(u8, message, plaintext)) {
        print("Success! Decrypted text matches original.\n", .{});
    } else {
        print("ERROR: Decryption failed!\n", .{});
    }

    print("\n=== Demo Complete ===\n\n", .{});
}
