# TweetNaCl-Zig

[![CI](https://github.com/nandanito/tweetnacl-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/nandanito/tweetnacl-zig/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Zig](https://img.shields.io/badge/Zig-0.16.0-orange)](https://ziglang.org/)

A minimal, auditable Zig port of [TweetNaCl](https://tweetnacl.cr.yp.to/) — Bernstein's compact cryptographic library — targeting **wire compatibility** with [tweetnacl-js](https://github.com/dchest/tweetnacl-js).

> ⚠️ **Early stage.** Only the Salsa20 family is implemented and verified so far. The API will change as more primitives land, and the library has not been audited — do not use it in production yet.

## Why this exists

Zig's standard library already ships production-grade NaCl (`std.crypto.nacl`). This project is **not** a replacement for it — it is a small, readable, self-contained TweetNaCl port for learning and auditing, where every line of the cryptographic core is meant to be read. `std.crypto` serves as the differential-test oracle (see [CONTRIBUTING.md](CONTRIBUTING.md)).

If you need authenticated encryption in production today, reach for `std.crypto.nacl` or `std.crypto.aead`.

## Requirements

- Zig **0.16.0** — the project tracks the latest stable Zig release.

## What works today

| Primitive | Status |
|---|---|
| Salsa20 core / HSalsa20 | ✅ implemented, verified against `std.crypto` and a NaCl vector |
| Salsa20 stream cipher | ✅ |
| XSalsa20 stream cipher | ✅ |

These are **low-level, confidentiality-only** primitives, exposed under `lowlevel`. The high-level authenticated APIs (`secretbox`, `box`, `sign`, `hash`) are on the [roadmap](#roadmap).

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

### XSalsa20 stream cipher

`xsalsa20.stream` XORs a message with a keystream derived from a 32-byte key and a 24-byte nonce. A 24-byte nonce is large enough to be picked at random. The cipher is symmetric — the *same call* encrypts and decrypts:

```zig
const key: [32]u8 = ...;   // secret
const nonce: [24]u8 = ...; // unique per message — never reuse one with a given key

const message = "attack at dawn";

// Encrypt. The output buffer is caller-allocated and must match the message length.
var ciphertext: [message.len]u8 = undefined;
nacl.lowlevel.xsalsa20.stream(&ciphertext, message, &nonce, &key);

// Decrypt — running the same function again recovers the plaintext.
var plaintext: [message.len]u8 = undefined;
nacl.lowlevel.xsalsa20.stream(&plaintext, &ciphertext, &nonce, &key);
// plaintext now equals message
```

Note how fixed-size inputs — the key and nonce — are passed as array pointers (`&key`, `&nonce`). The compiler checks their sizes: a wrong-sized key is a *compile error*, not a runtime surprise.

> ⚠️ **A stream cipher gives you confidentiality, not integrity.** Anyone can flip bits in the ciphertext and the tampering is invisible at decryption. Never use `xsalsa20.stream` alone to protect data you do not separately authenticate. Authenticated encryption (`secretbox`) is on the roadmap; until then, use `std.crypto`.

### Salsa20 core

`salsa20.core` is the raw 64-byte block function, and `salsa20.hsalsa20` derives the 32-byte subkey that XSalsa20 uses internally to support its longer nonce. These are building blocks — most code should not call them directly:

```zig
// input is *const [16]u8: an 8-byte nonce followed by an 8-byte block counter.
var block: [64]u8 = undefined;
nacl.lowlevel.salsa20.core(&block, &input, &key);
```

### Runnable examples

The [`examples/`](examples/) directory has complete, commented programs:

| Example | Run it | Demonstrates |
|---|---|---|
| `salsa20_demo` | `zig build salsa20_demo` | Salsa20 core block + HSalsa20 subkey derivation |
| `xsalsa20_demo` | `zig build xsalsa20_demo` | XSalsa20 encrypt → ciphertext → decrypt round-trip |

## Building and testing

```sh
zig build                              # build the static library
zig build test                         # run the unit-test suite
zig build test -Doptimize=ReleaseFast  # run the suite in a release mode
zig build salsa20_demo                 # build and run an example
```

Run a single test file, or filter by test name:

```sh
zig test src/salsa20.zig
zig test src/salsa20.zig --test-filter "round-trip"
```

## Roadmap

- [x] Zig 0.16 toolchain and CI
- [x] Salsa20 / HSalsa20 core
- [x] Salsa20 and XSalsa20 stream ciphers
- [ ] Poly1305 one-time MAC
- [ ] `secretbox` — XSalsa20-Poly1305 authenticated encryption
- [ ] Curve25519 (X25519) scalar multiplication
- [ ] `box` — Curve25519-XSalsa20-Poly1305 public-key encryption
- [ ] SHA-512 hashing
- [ ] `sign` — Ed25519 signatures
- [ ] First tagged release

## Design and contributing

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — module layering, API conventions, the wire-compatibility contract, security properties.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — how to build, test, and add a primitive, including the test-coverage bar.

## Compatibility note

The goal is **wire compatibility** — byte-for-byte identical ciphertext, keys, and nonces versus TweetNaCl / tweetnacl-js — **not** signature-level API compatibility. The API is idiomatic Zig (comptime-sized buffers, caller-owned output), not a transliteration of the JavaScript API.

## License

MIT — see [LICENSE](LICENSE).
