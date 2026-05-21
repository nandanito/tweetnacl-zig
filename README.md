# TweetNaCl-Zig

[![CI](https://github.com/nandanito/tweetnacl-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/nandanito/tweetnacl-zig/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Zig](https://img.shields.io/badge/Zig-0.16.0-orange)](https://ziglang.org/)

A minimal, auditable Zig port of [TweetNaCl](https://tweetnacl.cr.yp.to/) — Bernstein's compact cryptographic library — targeting **wire compatibility** with [tweetnacl-js](https://github.com/dchest/tweetnacl-js).

> ⚠️ **Early stage.** Authenticated encryption (`secretbox`), the Salsa20 family and Poly1305 are implemented and verified; public-key encryption, signatures and hashing are still to come. The API will change as more primitives land, and the library has not been audited — do not use it in production yet.

## Why this exists

Zig's standard library already ships production-grade NaCl (`std.crypto.nacl`). This project is **not** a replacement for it — it is a small, readable, self-contained TweetNaCl port for learning and auditing, where every line of the cryptographic core is meant to be read. `std.crypto` serves as the differential-test oracle (see [CONTRIBUTING.md](CONTRIBUTING.md)).

If you need vetted cryptography in production today, reach for `std.crypto`.

## Requirements

- Zig **0.16.0** — the project tracks the latest stable Zig release.

## What works today

| API | Kind | Status |
|---|---|---|
| `secretbox` — XSalsa20-Poly1305 | High-level authenticated encryption | ✅ |
| `lowlevel.salsa20` — core / HSalsa20 / stream | Low-level building block | ✅ |
| `lowlevel.xsalsa20` — stream | Low-level building block | ✅ |
| `lowlevel.poly1305` — one-time MAC | Low-level building block | ✅ |

`secretbox` is the API most applications should use. The `lowlevel` primitives are building blocks; everything is verified against `std.crypto` and published test vectors. Public-key encryption (`box`), signatures (`sign`) and hashing (`hash`) are on the [roadmap](#roadmap).

## Installation

```sh
zig fetch --save git+https://github.com/nandanito/tweetnacl-zig.git
```

Then wire it into your `build.zig`:

```zig
const tweetnacl = b.dependency("tweetnacl_zig", .{
    .target = target,
    .optimize = optimize,
});
exe.root_module.addImport("tweetnacl_zig", tweetnacl.module("tweetnacl_zig"));
```

## Usage

The library is imported as `tweetnacl_zig`:

```zig
const nacl = @import("tweetnacl_zig");
```

### secretbox — authenticated encryption

`secretbox` is the recommended API: it encrypts a message **and** attaches an authentication tag, so any tampering is detected when the box is opened. It is XSalsa20 for confidentiality plus Poly1305 for integrity.

```zig
const key: [32]u8 = ...;   // secret, shared by sender and recipient
const nonce: [24]u8 = ...; // unique per message — never reuse one with a key

const message = "attack at dawn";

// Seal: the sealed box is the message plus a 16-byte tag (`secretbox.overhead`).
var boxed: [message.len + nacl.secretbox.overhead]u8 = undefined;
nacl.secretbox.seal(&boxed, message, &nonce, &key);

// Open: verifies the tag, then decrypts. Returns error.AuthFailed — without
// writing any plaintext — if the box was tampered with or the key is wrong.
var opened: [message.len]u8 = undefined;
try nacl.secretbox.open(&opened, &boxed, &nonce, &key);
// opened now equals message
```

Output buffers are caller-allocated: `seal` needs `msg.len + 16` bytes, `open` needs `boxed.len - 16`. Fixed-size inputs — the key and nonce — are passed as array pointers (`&key`, `&nonce`), so a wrong-sized key is a *compile error*, not a runtime surprise. The 24-byte nonce is large enough to be chosen at random.

The output is byte-for-byte identical to TweetNaCl / tweetnacl-js, so a sealed box can be opened by any NaCl implementation.

### lowlevel — stream cipher and MAC

When you need the raw primitives, they live under `nacl.lowlevel`. The XSalsa20 stream cipher XORs a message with a keystream; it is symmetric, so the *same call* encrypts and decrypts:

```zig
var ciphertext: [message.len]u8 = undefined;
nacl.lowlevel.xsalsa20.stream(&ciphertext, message, &nonce, &key);
```

> ⚠️ **A stream cipher gives you confidentiality, not integrity.** Anyone can flip bits in the ciphertext and the tampering is invisible at decryption. Use `secretbox` unless you are authenticating the data by some other means.

Also available: `lowlevel.salsa20.core` (the raw 64-byte block function), `lowlevel.salsa20.hsalsa20` (subkey derivation), `lowlevel.salsa20.stream`, and `lowlevel.poly1305.auth` / `.verify` (the one-time MAC). See [ARCHITECTURE.md](ARCHITECTURE.md) for how they compose.

### Runnable examples

The [`examples/`](examples/) directory has complete, commented programs:

| Example | Run it | Demonstrates |
|---|---|---|
| `secretbox_demo` | `zig build secretbox_demo` | Authenticated encryption: seal, open, and tamper detection |
| `xsalsa20_demo` | `zig build xsalsa20_demo` | XSalsa20 stream-cipher encrypt → decrypt round-trip |
| `salsa20_demo` | `zig build salsa20_demo` | Salsa20 core block + HSalsa20 subkey derivation |

## Building and testing

```sh
zig build                              # build the static library
zig build test                         # run the unit-test suite
zig build test -Doptimize=ReleaseFast  # run the suite in a release mode
zig build secretbox_demo               # build and run an example
```

Run a single test file, or filter by test name:

```sh
zig test src/secretbox.zig
zig test src/salsa20.zig --test-filter "round-trip"
```

## Roadmap

- [x] Zig 0.16 toolchain and CI
- [x] Salsa20 / HSalsa20 core
- [x] Salsa20 and XSalsa20 stream ciphers
- [x] Poly1305 one-time MAC
- [x] `secretbox` — XSalsa20-Poly1305 authenticated encryption
- [ ] Curve25519 (X25519) scalar multiplication
- [ ] `box` — Curve25519-XSalsa20-Poly1305 public-key encryption
- [ ] SHA-512 hashing
- [ ] `sign` — Ed25519 signatures
- [ ] First tagged release

## Design and contributing

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — module layering, API conventions, the wire-compatibility contract, security properties.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — how to build, test, and add a primitive, including the test-coverage bar.

## Compatibility note

The goal is **wire compatibility** — byte-for-byte identical ciphertext, tags, keys and nonces versus TweetNaCl / tweetnacl-js — **not** signature-level API compatibility. The API is idiomatic Zig (comptime-sized buffers, caller-owned output), not a transliteration of the JavaScript API.

## License

MIT — see [LICENSE](LICENSE).
