# ADR 0003 — The value's UTF-8 encoding is unconditional, like the AAD; `type:bytes` is the way to say "bytes"

- Status: accepted
- Date: 2026-08-09
- Tags: encoding, mac, interop, wire-format
- Completes the encoding rule begun in commit 11658c3 (AAD) and depends on ADR 0002

## Context

Everything File::SOPS writes to a document has to cross from Perl strings into
bytes exactly once, and every component that crosses has to agree on where the
line is. There were two rules:

```perl
sub _utf8_bytes {            # the VALUE
    utf8::encode($str) if utf8::is_utf8($str);
    return $str;
}

sub _aad_bytes {             # the AAD
    utf8::encode($aad);      # unconditional
    return $aad;
}
```

The AAD became unconditional in 0.003 because a flag-guarded AAD authenticated
against different bytes than the emitter wrote the key as. The value kept the
flag guard, deliberately, because changing it moves wire bytes. This ADR is
that deferred decision.

### What the emitters actually do

Measured, both formats, all four states of the same conceptual string:

| Perl scalar                      | flag | in memory        | YAML::XS::Dump and JSON::MaybeXS(utf8=>1) write |
|----------------------------------|------|------------------|--------------------------------------------------|
| `"caf\x{e9}"` upgraded           | on   | `63 61 66 e9`    | `63 61 66 c3 a9`                                 |
| `"caf\x{e9}"` downgraded         | off  | `63 61 66 e9`    | `63 61 66 c3 a9`                                 |
| UTF-8 bytes of café              | off  | `63 61 66 c3 a9` | `63 61 66 c3 83 c2 a9`                           |
| `"\x{30ad}"`                     | on   | `30ad`           | `e3 82 ad`                                       |

**Both emitters treat every scalar as characters and never consult the flag.**
Row 2 is the bug: Perl considers rows 1 and 2 the same string — below U+0100
the UTF-8 flag is a storage detail, not a statement about meaning — and the
emitters agree, but the value conversion did not.

Row 3 is the other half of the story, and it is the one that decides this ADR:
a caller who passes UTF-8 **bytes** is *already* double-encoded by the
emitters. There is no rule under which both row 2 and row 3 come out right,
because rows 2 and 3 are indistinguishable to Perl as *intent* — they are both
"a string with the flag off". The ambiguity is not resolvable; it can only be
resolved *once*, consistently.

### The two failures, reproduced

Both with a plain unflagged `"caf\x{e9}"`, no configuration:

1. **An unencrypted value fails our own MAC.** `unencrypted_suffix` defaults to
   `_unencrypted`, so such a value is written into the document by the emitter
   *and* hashed into the digest. The emitter wrote `caf\xc3\xa9`; the digest
   covered `caf\xe9`. The next read re-derives `caf\xc3\xa9` from the document
   and the file fails its own MAC. **sops rejects it for the same reason** —
   `MAC mismatch. File has 8CA338E0…, computed 90FB5FD5…` — so this is not a
   Perl-side quirk but a genuinely malformed document.

2. **An encrypted value reaches the wire as Latin-1.** Self-consistent, so
   nothing inside Perl notices, but `\xe9` is not UTF-8 and Go cannot read it
   as text. `sops -d` returns

   ```yaml
   secret: !!binary Y2Fm6Q==
   ```

   instead of `secret: café`. The value is intact but its *type* has silently
   become binary, which is a different thing from the text that was stored.

### Why this has been blocked

Withdrawing the flag guard changes the wire bytes for a caller who passes byte
strings deliberately, and `t/08-encoding.t` pinned that as a guarantee:
"a caller passing UTF-8 bytes produces identical wire bytes".

Measured, that guarantee was never whole. Today, for a caller passing UTF-8
bytes:

- an **encrypted** value round-trips and reaches sops correctly — the plaintext
  never passes an emitter, so nothing has to agree with it;
- an **unencrypted** value is written by the emitter as `caf\xc3\x83\xc2\xa9`
  (double-encoded) while the digest covers `caf\xc3\xa9`, so **the document
  already fails its own MAC**, with no fix applied.

So the choice is not "keep a working guarantee or break it". It is "keep a
guarantee that holds for half the document, or state one rule that holds for
all of it".

### The interaction with ADR 0002

ADR 0002 collapsed the type ladder and the value→bytes conversion into a single
`File::SOPS::Encrypted->value_to_bytes`. The ticket for this defect
(karr #27) was written before that and assumed the fix would have to touch
"both value conversions". **It does not: there is exactly one left**, and
`_utf8_bytes` has exactly one caller. The behavioural change here is one
removed conditional. That is worth stating because it is the direct payoff of
0002's consolidation — the same fix against the pre-0002 code would have had to
land identically in two places and stay byte-identical between them, which is
the failure mode this distribution keeps producing.

## Decision

**`_utf8_bytes` becomes unconditional**, matching `_aad_bytes`, the emitters,
and Go — where a string is UTF-8 by construction.

**`type:bytes` is exempt, on both sides.** It is SOPS's binary type; it is not
text, so there is nothing to encode. The decrypt side already exempted it from
`utf8::decode`; the encrypt side now mirrors that. This is what gives a caller
who genuinely means bytes something to say:

```perl
File::SOPS::Encrypted->encrypt_value(value => $blob, type => 'bytes', …);
```

The resulting rule is symmetric and can be stated in one line: **`type:bytes`
is raw bytes in and raw bytes out; everything else is characters in, UTF-8 on
the wire, characters out.**

### Alternatives rejected

1. **Encode only when the string is not already valid UTF-8.** This is the
   "have it both ways" option and it appears to fix rows 2 and 3 at once. It
   makes the wire format depend on a *content* test: the two-character string
   `Ã©` (U+00C3 U+00A9, flag off) is byte-identical to the UTF-8 encoding of
   `é`, so the same input would be encoded or not depending on what it happens
   to spell. A wire format decided by a validity heuristic is worse than either
   consistent answer, and it would be undebuggable the one time it guessed
   wrong.
2. **Keep the flag guard for encrypted values, make it unconditional only for
   unencrypted ones.** Fixes failure 1 and leaves failure 2. It also makes the
   same value encode differently depending on whether the encryption rules
   happened to cover it — the exact shape of bug this distribution exists to
   avoid, since the two paths are supposed to produce identical bytes.
3. **Croak on an unflagged string containing bytes ≥ 0x80.** Honest about the
   ambiguity and fails loud rather than guessing. Rejected because the ambiguity
   already has an answer everywhere else in the library — the emitters, the
   AAD, and the documented API boundary all say "characters" — so refusing
   would be inventing a third position rather than resolving to the existing
   one. It would also reject perfectly ordinary input read from a file without
   an `:encoding(UTF-8)` layer, which is most callers' first mistake and one
   the "characters" rule handles correctly by accident.
4. **Leave it.** The default configuration produces documents that sops
   rejects, and there is no way for a caller to see it coming.

## Consequences

### Whose bytes move

Only a caller passing a **non-ASCII byte string** to `encrypt`. ASCII is
unaffected — `utf8::encode` is a no-op on it — which is every existing test in
this distribution but `t/08-encoding.t` and most real documents.

| input                                    | plaintext before | plaintext after      |
|------------------------------------------|------------------|----------------------|
| `"caf\x{e9}"` flagged                    | `caf\xc3\xa9`    | `caf\xc3\xa9` (same) |
| `"caf\x{e9}"` unflagged                  | `caf\xe9`        | `caf\xc3\xa9`        |
| UTF-8 bytes `caf\xc3\xa9`                | `caf\xc3\xa9`    | `caf\xc3\x83\xc2\xa9`|
| any ASCII                                | unchanged        | unchanged            |

Row 2 is the fix. Row 3 is the cost: a byte-string caller's encrypted values
now go to the wire double-encoded — the same thing the emitter was already
doing to their unencrypted values. What they do instead is decode once at their
own boundary, which is what the "API boundary is characters" section of
`File::SOPS` has always asked for:

```perl
utf8::decode($value);     # or read the file with an :encoding layer
```

Their round trip through File::SOPS does **not** break either way: `decrypt`
decodes, and Perl considers the decoded result equal to the byte string that
went in. What changes is what a *different* implementation reads out of the
file — which is the whole point, and the reason the old behaviour could not be
detected from inside Perl.

Existing encrypted documents are unaffected; nothing about reading changes.

### A latent trap for karr #30

`File::SOPS::_value_to_bytes` calls `value_to_bytes($value)` with **no type**,
so a leaf reaches the digest as `str` and gets encoded. `type:bytes` can only
be reached today through `File::SOPS::Encrypted->encrypt_value` directly, where
there is no MAC, so the two cannot currently disagree. If karr #30 adds a
per-leaf type override to `File::SOPS->encrypt`, the MAC path must be given the
type as well or a `type:bytes` leaf will be hashed encoded and encrypted raw —
a document that fails its own MAC. Noted on that ticket.

### The POD promise is withdrawn

`File::SOPS`'s "Character encoding" section promised that handing `encrypt`
UTF-8 bytes still produced correct wire output. That is now false by design and
the paragraph is replaced rather than softened.

## Notes

Every table above is measured on this machine against YAML::XS,
Cpanel::JSON::XS and sops 3.13.3, not derived from documentation. The
`!!binary Y2Fm6Q==` and the `MAC mismatch` are verbatim from the binary.

Failure 1 is pinned without a binary in `t/08-encoding.t`, because it is
reachable with the default configuration and must fail on any machine. Failure
2 needs the binary and lives in `t/04-interop.t`, in both directions — it is
the half that no amount of self-consistency can catch, since a document this
library wrote and read back agreed with itself perfectly while sops saw binary.
