---
name: file-sops-core
description: "Architecture and wire-format invariants of File::SOPS — the pure-Perl Mozilla SOPS implementation. AAD/path derivation, MAC computation and its ordering dependency, type detection and Go-compatible value serialization, the metadata section, and why the test suite can be green while the only compliance test never ran."
---

# File::SOPS — core

Pure-Perl implementation of the Mozilla SOPS encrypted-file format, byte-compatible
with the Go reference implementation (`github.com/getsops/sops`). Interop is the whole
product: every design choice here exists because Go does it that way.

## Module map

| Module | Owns |
|---|---|
| `File::SOPS` | public API (`encrypt`/`decrypt`/`encrypt_file`/`decrypt_file`/`extract`/`rotate`), tree walk, path→AAD, MAC |
| `File::SOPS::Encrypted` | one `ENC[...]` value — parse, encrypt, decrypt, type (de)serialization |
| `File::SOPS::Metadata` | the `sops:` section — backends, mac, lastmodified, version, encryption rules |
| `File::SOPS::Backend::Age` | data-key encryption via `Crypt::Age` (the only backend implemented) |
| `File::SOPS::Format::{YAML,JSON}` | parse/serialize, split off and re-attach the `sops:` section |

Everything is `Moo` + `namespace::clean`. The public API is class methods on
`File::SOPS`, not instance methods.

## The wire format

```
ENC[AES256_GCM,data:<b64>,iv:<b64>,tag:<b64>,type:<str|int|float|bool|bytes>]
```

Parsed and matched by one regex in `File::SOPS::Encrypted` (`$ENC_REGEX`, anchored).
`is_encrypted` and `parse` share it — keep them sharing it.

## Invariants that interop depends on

Break any of these and the file still *looks* fine, still round-trips through this
library's own tests, and fails against the real `sops` binary.

1. **AAD is the path, colon-joined, with a trailing colon.** `database:password:` for
   `{database}{password}`. Empty path → empty AAD.
2. **Arrays do not contribute a path component.** Every element of an array shares the
   *parent's* path — no index. `_encrypt_tree`/`_decrypt_tree`/`_build_enc_path_mapping`
   all implement this; they must stay in agreement.
3. **The IV is 32 bytes**, not the AES-GCM-conventional 12. SOPS-Go uses a 32-byte
   nonce. (`=attr iv` in the POD still says 12 bytes — the POD is wrong, the code is
   right.)
4. **Booleans serialize Go-style titlecase**: `True` / `False` — on the wire *and* in
   the bytes fed to the MAC digest. Never `1`/`0`, never lowercase.
5. **Type detection is a fixed ladder** (`_detect_type`): `JSON::PP::Boolean` → bool;
   the literal strings `'true'`/`'false'` → bool; `/^-?\d+$/` → int; `/^-?\d+\.\d+$/` →
   float; else str.

   **This ladder does NOT match Go, and that is a known defect, not a design choice**
   (karr #15). SOPS types a value by what the *parser* produced, never by pattern-
   matching its text. Verified against sops 3.13.3: bare `false` → `type:bool`, but
   quoted `"false"`, `"true"`, `"1"`, `"0"` are all `type:str`. We turn every one of
   those into a bool or an int, so a quoted scalar does not survive a round trip as
   the string it went in as. Perl can tell the two apart — YAML::XS and JSON::MaybeXS
   preserve the SV's string-vs-number distinction — so this is fixable, but the fix
   touches both type ladders and all three conversions and wants an ADR first.
   Until then: treat the ladder as *what the code does*, not as what is correct.
6. **`bool` deserializes to `JSON::PP::Boolean`** (`JSON->true` / `JSON->false`), not to
   `1`/`0`, so that YAML::XS (with `$YAML::XS::Boolean = 'JSON::PP'`) and JSON::MaybeXS
   emit real `true`/`false` on re-serialization. A plain `1` here silently degrades
   every bool in the file to an int on the next write.
7. **Empty and undefined leaf values are not encrypted** — they serialize as `''`.
8. **Everything hashed or encrypted is UTF-8 bytes** — `Digest::SHA` and the GCM
   primitives reject wide characters. But the encode rule is **not the same in both
   places**, and the difference is load-bearing:

   - **The AAD is encoded unconditionally** (`_aad_bytes`). `YAML::XS::Dump` and
     `JSON::MaybeXS(utf8 => 1)` encode a key to UTF-8 **regardless of Perl's UTF-8
     flag** — below U+0100 that flag is storage, not meaning. A flag-guarded AAD
     therefore authenticates against different bytes than the emitter wrote, and the
     document fails *its own* MAC on the next read. The AAD must say what the emitter
     wrote.
   - **Plaintext is encoded only when the flag is set** (`_utf8_bytes`). Nothing
     outside `encrypt_value` has to agree on it — ciphertext and MAC both derive from
     exactly those bytes — so a caller deliberately passing byte strings keeps
     writing the bytes it meant.

   The same emitter-disagreement still exists on the **value** path (karr #27) and is
   not fixed: fixing it moves wire bytes for byte-string callers.

9. **The API boundary is characters, the wire is UTF-8 bytes, and the library encodes
   exactly once.** Keys, values, `extract` paths and everything `decrypt` returns are
   character strings. Two documented exceptions come back as bytes rather than being
   mangled: `type:bytes` (SOPS's binary type) and a `type:str` whose plaintext is not
   valid UTF-8.

## The MAC — and its ordering dependency

The MAC is a SHA-512 over the **plaintext values only** (no keys, no paths), uppercase
hex, then itself AES-GCM-encrypted with **`lastmodified` as AAD** and stored as an
`ENC[...]` string in the `sops:` section.

**Every value goes into the digest, encrypted or not** — matching the Go reference —
unless `mac_only_encrypted` is set, which switches to encrypted values only behind a
32-byte `MACOnlyEncryptedInitialization` prefix that keeps the two settings' digests
apart. That prefix appears nowhere but the reference source.

Both directions funnel through `_mac_digest`. What differs is only how leaves are
collected and where the order comes from:

| Direction | Leaves | Order |
|---|---|---|
| encrypt | the live tree | `sort keys %$node` |
| decrypt | the parsed tree, walked in parallel | an order-preserving reparse (YAML::PP, `PRESERVE_ORDER`) |

Perl hash order is randomized and the MAC is order-dependent, so the decrypt side must
recover order from the document. It used to scrape `ENC[...]` strings out of the raw
text with a regex; that could not see unencrypted values and so could not place them.
**ADR 0001** records why YAML::PP supplies order and nothing else — values still come
from the real tree, and YAML::XS / JSON::MaybeXS remain the parsers and emitters. The
metadata MAC is excluded structurally by dropping the `sops` branch, not by matching
`mac:` in text (which used to swallow any user key ending in `mac`).

**The encrypt side still depends on the emitters sorting keys** — `YAML::XS::Dump`
sorts, `File::SOPS::Format::JSON` sets `canonical => 1`. That is load-bearing and
`t/05-format-key-order.t` pins it: a serializer that emits insertion order breaks
verification for self-produced files, and the failure surfaces as `MAC verification
failed`, nowhere near the cause.

**What a leaf contributes is the authenticated plaintext**, from
`File::SOPS::Encrypted::decrypt_bytes`, with only the bool titlecase rule applied —
never a re-serialization. Hashing a value after Perl's numeric conversion is what made
`'007'` hash as `007` on write and `7` on read.

Verification **fails closed**: a missing, malformed or undecryptable MAC dies. Callers
that need the old lax behaviour pass `ignore_mac => 1` to `decrypt`, `decrypt_file`,
`extract` or `rotate` — that returns data which is decrypted but *not authenticated*,
and exists mainly to rescue files damaged by the pre-0.003 boolean bugs.

## Metadata section

`to_hash` always emits `kms`, `gcp_kms`, `azure_kv`, `hc_vault`, `age`, `pgp` — empty
arrays included, because the Go implementation expects the keys to exist. Optional
fields (`lastmodified`, `mac`, `version`, the four encryption-rule fields) are emitted
only when defined. `version` defaults to `3.7.3`.

Encryption rules: `unencrypted_suffix` (default `_unencrypted`) marks keys that are
**not encrypted but still hashed into the MAC**; `encrypted_suffix`,
`unencrypted_regex` and `encrypted_regex` are parsed and stored but drive only
`should_encrypt_key`. Note the asymmetry in the tree walk: `_encrypt_tree` consults
`should_encrypt_key`, `_decrypt_tree` does not — decryption is driven purely by whether
a leaf matches `ENC[...]`.

## Verification — read this before saying "tests pass"

```bash
prove -lr t/          # recursive; -r matters if subdirs ever appear
dzil test             # recursive by construction
```

**`t/04-interop.t` is the only test that proves compatibility with SOPS** — round-trips
in both directions (Perl→sops, sops→Perl), YAML and JSON, types, unicode, nested
structures. It finds a binary via `$SOPS_BIN`, then `PATH`, then `/tmp/sops`, and only
skips when none of the three yields one. A `$SOPS_BIN` that is set but not executable
is a hard failure, not a fall-through to something nobody chose.

**Check the run, not the summary.** With sops on `PATH` the suite is 122 tests; without
it, 105 and a skip notice. `All tests successful` at 105 means the compatibility
assertions did not execute — that is exactly how two releases shipped a library whose
every YAML file sops rejected. When the test runs it prints the binary and version it
used; quote that when you claim compatibility.

If a binary is missing, `maint/fetch-sops` installs the pinned version (needs a Go
toolchain). A release without a real interop run is a release of untested compatibility
claims.

## Deliberate gaps

`CLAUDE.md` is the original design document and describes more than exists. Not
implemented today: the ENV and INI format handlers, the `.sops.yaml` creation-rules
config, `encrypt_in_place`, `edit`, and every backend other than age (PGP, KMS,
GCP KMS, Azure KV, Vault — the metadata fields for them exist and round-trip, the
encryption does not). Treat that file as a roadmap, not as a description of the code.
