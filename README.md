# TweetNaCl-Zig

[![CI](https://github.com/nandanito/tweetnacl-zig/actions/workflows/ci.yml/badge.svg)](https://github.com/nandanito/tweetnacl-zig/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Zig](https://img.shields.io/badge/Zig-0.16.0-orange)](https://ziglang.org/)

A minimal, auditable Zig port of [TweetNaCl](https://tweetnacl.cr.yp.to/) — Bernstein's compact cryptographic library — targeting **wire compatibility** with [tweetnacl-js](https://github.com/dchest/tweetnacl-js).

> ⚠️ **Early stage.** Authenticated encryption (`secretbox` and `box`), SHA-512 hashing, the Salsa20 family, Poly1305 and X25519 are implemented and verified; signatures are still to come. The API will change as more primitives land, and the library has not been audited — do not use it in production yet.

## Why this exists

Zig's standard library already ships production-grade NaCl (`std.crypto.nacl`). This project is **not** a replacement for it — it is a small, readable, self-contained TweetNaCl port for learning and auditing, where every line of the cryptographic core is meant to be read. `std.crypto` serves as the differential-test oracle (see [CONTRIBUTING.md](CONTRIBUTING.md)).

If you need vetted cryptography in production today, reach for `std.crypto`.

## Requirements

- Zig **0.16.0** — the project tracks the latest stable Zig release.

## What works today

| API | Kind | Status |
|---|---|---|
| `secretbox` — XSalsa20-Poly1305 | High-level authenticated encryption | ✅ |
| `box` — Curve25519-XSalsa20-Poly1305 | High-level public-key authenticated encryption | ✅ |
| `hash` — SHA-512 | High-level hash function | ✅ |
| `lowlevel.salsa20` — core / HSalsa20 / stream | Low-level building block | ✅ |
| `lowlevel.xsalsa20` — stream | Low-level building block | ✅ |
| `lowlevel.poly1305` — one-time MAC | Low-level building block | ✅ |
| `lowlevel.scalarmult` — Curve25519 / X25519 | Low-level building block | ✅ |

`secretbox` and `box` are the APIs most applications should use. The `lowlevel` primitives are building blocks; everything is verified against `std.crypto` and published test vectors. Signatures (`sign`) are on the [roadmap](#roadmap).

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

### box — public-key authenticated encryption

`box` is `secretbox` for two parties who each hold a key pair: the sender seals a message with the recipient's **public** key and their own **secret** key; the recipient opens it with their own secret key and the sender's public key. The result is encrypted *and* authenticated, so the recipient knows the message is genuine and untampered — without the two ever sharing a secret key.

```zig
// Each party holds a key pair and shares only its public key.
const alice = nacl.box.keyPair(io);
const bob = nacl.box.keyPair(io);

const nonce: [24]u8 = ...; // unique per message — never reuse one
const message = "attack at dawn";

// Alice seals for Bob: his public key, her secret key.
var boxed: [message.len + nacl.box.overhead]u8 = undefined;
try nacl.box.seal(&boxed, message, &nonce, &bob.public_key, &alice.secret_key);

// Bob opens it: Alice's public key, his secret key. Returns error.AuthFailed
// — without writing any plaintext — if the box was tampered with.
var opened: [message.len]u8 = undefined;
try nacl.box.open(&opened, &boxed, &nonce, &alice.public_key, &bob.secret_key);
// opened now equals message
```

`box.keyPair(io)` draws a fresh secret key from `io`'s CSPRNG (`io` is a `std.Io`); `box.keyPairFromSecretKey(&sk)` derives a key pair deterministically from an existing 32-byte secret key. When several messages travel between the same pair of keys, derive the shared key once with `box.beforenm` and reuse it via `box.sealAfternm` / `box.openAfternm` — this skips the X25519 scalar multiplication on every message. `beforenm`, `seal` and `open` return `error.WeakPublicKey` if a supplied public key is a low-order Curve25519 point (which would collapse the shared key to a fixed, publicly-known value). Output is byte-for-byte identical to TweetNaCl / tweetnacl-js.

### hash — SHA-512

`hash` computes a 64-byte SHA-512 digest of a message. It takes no key, so there is nothing to verify and no round-trip — just a one-shot digest.

```zig
const message = "attack at dawn";

var digest: [nacl.hash.digest_length]u8 = undefined; // digest_length == 64
nacl.hash.hash(&digest, message);
```

The message is a slice of any length; the digest is a caller-allocated 64-byte array. Output is byte-for-byte identical to TweetNaCl / tweetnacl-js (`crypto_hash`) and to any other SHA-512 implementation.

### lowlevel — stream cipher and MAC

When you need the raw primitives, they live under `nacl.lowlevel`. The XSalsa20 stream cipher XORs a message with a keystream; it is symmetric, so the *same call* encrypts and decrypts:

```zig
var ciphertext: [message.len]u8 = undefined;
nacl.lowlevel.xsalsa20.stream(&ciphertext, message, &nonce, &key);
```

> ⚠️ **A stream cipher gives you confidentiality, not integrity.** Anyone can flip bits in the ciphertext and the tampering is invisible at decryption. Use `secretbox` unless you are authenticating the data by some other means.

Also available: `lowlevel.salsa20.core` (the raw 64-byte block function), `lowlevel.salsa20.hsalsa20` (subkey derivation), `lowlevel.salsa20.stream`, `lowlevel.poly1305.auth` / `.verify` (the one-time MAC), and `lowlevel.scalarmult` (Curve25519 / X25519 scalar multiplication). See [ARCHITECTURE.md](ARCHITECTURE.md) for how they compose.

### Runnable examples

The [`examples/`](examples/) directory has complete, commented programs:

| Example | Run it | Demonstrates |
|---|---|---|
| `secretbox_demo` | `zig build secretbox_demo` | Authenticated encryption: seal, open, and tamper detection |
| `box_demo` | `zig build box_demo` | Public-key authenticated encryption between two key pairs |
| `hash_demo` | `zig build hash_demo` | SHA-512 digest of a message |
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
- [x] Curve25519 (X25519) scalar multiplication
- [x] `box` — Curve25519-XSalsa20-Poly1305 public-key encryption
- [x] `hash` — SHA-512
- [ ] `sign` — Ed25519 signatures
- [ ] First tagged release

## Design and contributing

- **[ARCHITECTURE.md](ARCHITECTURE.md)** — module layering, API conventions, the wire-compatibility contract, security properties.
- **[CONTRIBUTING.md](CONTRIBUTING.md)** — how to build, test, and add a primitive, including the test-coverage bar.

## Compatibility note

The goal is **wire compatibility** — byte-for-byte identical ciphertext, tags, keys and nonces versus TweetNaCl / tweetnacl-js — **not** signature-level API compatibility. The API is idiomatic Zig (comptime-sized buffers, caller-owned output), not a transliteration of the JavaScript API.

## License

MIT — see [LICENSE](LICENSE).
