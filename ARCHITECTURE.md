# Architecture

tweetnacl-zig is a layered Zig port of TweetNaCl. This document describes the
stable design; the delivery roadmap lives in the [README](README.md).

## Positioning

Zig's standard library already provides audited NaCl (`std.crypto.nacl`).
tweetnacl-zig exists to be a **minimal, self-contained, readable**
implementation suitable for study and audit. Consequently:

- The whole cryptographic core is meant to be readable end to end.
- `std.crypto` is used only as a **differential-test oracle**, never as a
  dependency of the library code.

## Two tiers

**High-level API** (roadmap) — what applications should use:

| Namespace   | Primitive                                              |
|-------------|--------------------------------------------------------|
| `secretbox` | XSalsa20-Poly1305 authenticated encryption (symmetric) |
| `box`       | Curve25519-XSalsa20-Poly1305 authenticated encryption (public-key) |
| `sign`      | Ed25519 signatures                                     |
| `hash`      | SHA-512                                                |

**Low-level API** (`lowlevel`) — building blocks for advanced use:

| Module                | Contents                              |
|-----------------------|---------------------------------------|
| `lowlevel.salsa20`    | `core`, `hsalsa20`, `stream`          |
| `lowlevel.xsalsa20`   | `stream`                              |
| `lowlevel.poly1305`   | one-time MAC *(roadmap)*              |
| `lowlevel.scalarmult` | Curve25519 / X25519 *(roadmap)*       |

Each primitive composes the one below it:

```
xsalsa20.stream = salsa20.hsalsa20 (subkey) + salsa20.stream
secretbox       = xsalsa20.stream + poly1305          (roadmap)
box             = scalarmult + secretbox              (roadmap)
```

Inside `salsa20.zig`, a single `permute` (the 20-round column/row permutation)
is shared by `core` (64-byte block — adds the initial state back) and
`hsalsa20` (32-byte subkey — selects words of the final state, no addition).

## API conventions

These rules are binding for every primitive:

1. **Fixed-size buffers are array pointers** — keys (`*const [32]u8`), nonces
   (`*const [24]u8` / `*const [8]u8`), tags, etc. The compiler enforces the
   size; there is no `InvalidLength` error and no runtime length check.
2. **Variable-length data is slices** — messages and ciphertext are `[]u8` /
   `[]const u8`. Output buffers are caller-allocated; required lengths are
   documented.
3. **Allocation-free** — no primitive takes an allocator.
4. **Authentication failure is an error** — `open` / verify operations return
   `error{AuthFailed}`, never a silent wrong result.
5. **Constant-time** — no secret-dependent branches or memory indexing; tag
   comparison uses `std.crypto.timing_safe`.
6. **Secret hygiene** — stack-resident secret material (subkeys, expanded keys)
   is wiped with `std.crypto.secureZero` before return.
7. **Explicit endianness** — all integer encoding is little-endian via
   `std.mem.readInt` / `writeInt`.
8. **No `assert` for validation** — `std.debug.assert` is only a debug aid (it
   is compiled out in release builds); input contracts are enforced by the type
   system or an error union.

## Wire compatibility

The contract is **byte-for-byte interoperability** with TweetNaCl and
tweetnacl-js: identical ciphertext, signatures, keys, and nonces. The NaCl
zero-padding convention (`ZEROBYTES` / `BOXZEROBYTES`) is an internal
implementation detail and is hidden from callers — `secretbox` output will be a
16-byte authentication tag followed by the ciphertext, exactly as tweetnacl-js
produces it.

This is **not** signature-level API compatibility: the API is idiomatic Zig,
not a transliteration of the JavaScript or C signatures.

## Source layout

```
src/
  root.zig       Public API surface
  lowlevel.zig   Aggregator for the low-level namespace
  salsa20.zig    Salsa20 / HSalsa20 core + Salsa20 stream cipher
  xsalsa20.zig   XSalsa20 stream cipher
build.zig        Zig 0.16 build: static library, test step, example runners
examples/        One runnable, commented program per usable primitive
```

Tests are `test` blocks co-located with each primitive. Zig 0.16 does not
auto-collect tests from imported files, so `root.zig` and `lowlevel.zig` each
contain a `test` block that `@import`s their children — this pulls the whole
graph into `zig build test`.

## Security properties and current limitations

- Salsa20 has no secret-dependent branches or table lookups; it is
  constant-time by construction.
- **The `lowlevel` stream ciphers provide confidentiality only.** They do not
  authenticate; ciphertext malleability is expected and is the caller's
  responsibility until `secretbox` lands.
- The library is early-stage and unaudited. Until a high-level authenticated
  API ships and is reviewed, prefer `std.crypto` for production use.
