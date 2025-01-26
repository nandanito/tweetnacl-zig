# TweetNaCl-Zig

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Zig Version](https://img.shields.io/badge/Zig-0.12.0+-orange)](https://ziglang.org/)

**Early Stage Project**: ⚠️ This package is under active development. The library may change as we improve the implementation. ⚠️

A Zig implementation of [TweetNaCl](https://tweetnacl.cr.yp.to/), maintaining **API compatibility** with [TweetNaCl.js](https://github.com/dchest/tweetnacl-js). A minimal cryptographic library for modern applications, providing essential cryptographic primitives in a compact, auditable form.

## Features

- **Authenticated Encryption**: `crypto_secretbox` (XSalsa20+Poly1305)
- **Public-Key Cryptography**: `crypto_box` (Curve25519+XSalsa20+Poly1305)
- **Cryptographic Primitives**:
  - Salsa20 stream cipher
  - Poly1305 MAC
  - Curve25519 elliptic curve
- **Zero Dependencies**: Pure Zig implementation
- **Memory Safe**: Designed with Zig's memory safety features

## Installation

Add to your `build.zig.zon`:

```zig
.dependencies = .{
    .tweetnacl = .{
        .url = "https://github.com/nandanito/tweetnacl-zig/archive/[COMMIT_HASH].tar.gz",
        .hash = "[PACKAGE_HASH]",
    },
},
```

Then in your `build.zig`:

```zig
const tweetnacl = b.dependency("tweetnacl-zig", .{
    .target = target,
    .optimize = optimize,
});
exe.addModule("tweetnacl-zig", tweetnacl.module("tweetnacl"));
```

## Usage

### Secret Box (Authenticated Encryption)

```zig
const nacl = @import("tweetnacl-zig");

pub fn demo() !void {
    const key = [_]u8{0} ** 32;
    const nonce = [_]u8{0} ** 24;
    const msg = "Hello, Secure World!";

    var ciphertext: [msg.len + 32]u8 = undefined;
    var plaintext: [msg.len]u8 = undefined;

    // Encrypt
    try nacl.secretbox.secretbox(
        &ciphertext,
        msg,
        &nonce,
        &key
    );

    // Decrypt
    try nacl.secretbox.open(
        &plaintext,
        ciphertext[32..],
        &nonce,
        &key
    );
}
```

### Public-Key Encryption (Box)

```zig
const nacl = @import("tweetnacl-zig");

pub fn key_exchange() !void {
    // Generate key pair
    const alice = try nacl.box.keyPair();
    const bob = try nacl.box.keyPair();

    // Encrypt message
    var ciphertext: [256]u8 = undefined;
    try nacl.box.seal(
        &ciphertext,
        "Secret Message",
        &bob.publicKey,
        &alice.secretKey
    );

    // Decrypt message
    var plaintext: [256]u8 = undefined;
    try nacl.box.open(
        &plaintext,
        &ciphertext,
        &alice.publicKey,
        &bob.secretKey
    );
}
```

## Current Status

- [x] Salsa20 core functions
- [ ] Poly1305 MAC
- [ ] SecretBox API (XSalsa20+Poly1305)
- [ ] Box API (Curve25519 key exchange)
- [ ] Signatures (Ed25519)
- [ ] SHA-512 hashing
- [ ] Complete test vectors
- [ ] Performance optimizations

## Contributing

Contributions are welcome! Please:

1. Open an issue to discuss major changes
2. Ensure all tests pass (`zig build test`)
3. Maintain the cryptographic safety properties
4. Follow Zig's standard style guidelines

Special consideration given to:

1. Security-critical code reviews
2. Performance improvements
3. Additional test vectors

## License

MIT License - See [LICENSE](LICENSE) for details
