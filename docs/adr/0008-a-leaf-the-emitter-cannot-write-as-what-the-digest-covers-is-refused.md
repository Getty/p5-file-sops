# ADR 0008 — A leaf the emitter cannot write as what the digest covers is refused

- Status: accepted
- Date: 2026-08-10
- Tags: yaml, mac, wire-format, guards, interop
- Resolves karr #65
- Depends on ADR 0002 (a value's type comes from the scalar, which is why a
  blessed leaf is `str` to the digest) and ADR 0006 (which built the `reject`
  hook this uses, and applied it to two classes on the JSON side only)

## Context

`File::SOPS::Encrypted::detect_type` calls every blessed reference except a
`JSON::PP::Boolean` a `str`, so `value_to_bytes` digests its **stringification**
— the same rule ADR 0002 fixed for scalars, applied to objects. That is a
defensible answer as long as the emitter writes the same text. `YAML::XS` does
not. It writes a blessed leaf as a Perl-specific tagged structure:

| leaf | `YAML::XS` writes | digest covers | result |
|---|---|---|---|
| `Math::BigFloat->new("1.5")` | `!!perl/hash:Math::BigFloat` + its guts | `1.5` | self-MAC **FAIL**, `sops -d` exit 51 |
| `Math::BigInt->new("42")` | `!!perl/hash:Math::BigInt` + its guts | `42` | self-MAC **FAIL**, exit 51 |
| `bless {a=>1}, 'Foo'` | `!!perl/hash:Foo` + its guts | `Foo=HASH(0x…)` | self-MAC **FAIL**, exit 51 |
| an object overloading `""` | `!!perl/hash:Overloaded` + its guts | `stringified` | self-MAC **FAIL**, exit 51 |
| `bless \$s, 'Bar'` | `!!perl/scalar:Bar x` | `x` | self-MAC **FAIL**, exit 51 |
| `qr/abc/` | `!!perl/regexp (?^:abc)` | `(?^:abc)` | self-MAC **FAIL**, `sops -d` exit 0 |
| `sub { 1 }` | `!!perl/code '{ "DUMMY" }'` | `CODE(0x…)` | self-MAC **FAIL**, exit 51 |
| `\1` (unblessed) | `!!perl/ref` + `=: 1` | `SCALAR(0x…)` | self-MAC **FAIL**, exit 51 |

Measured against sops 3.13.3 with the leaf under `_unencrypted`, one document
per row. The document and its own MAC state different things, so nothing can
read it — not sops, and not this library. It is written **silently**.

`qr//` is the interesting row: sops accepts the file (exit 0) because Go's
yaml.v3 resolves the unknown tag to the scalar text, which happens to be what
we digested — while File::SOPS itself cannot read back what it just wrote,
because `YAML::XS` reconstructs a `Regexp` object from that tag. Both halves of
the same disagreement, one per implementation.

**JSON refuses every one of these already**, and has since before ADR 0006:
`Cpanel::JSON::XS` will not encode a blessed reference without
`allow_blessed`/`convert_blessed`/`allow_tags`, so the caller gets
`encountered object 'Foo=HASH(0x…)', but neither allow_blessed …`. ADR 0006 then
added an explicit refusal for `Math::BigFloat` and `Math::BigInt`, because
turning on `allow_bignum` for our own float carrier had re-opened exactly those
two. So the two formats answer the same question in opposite ways, and the
format that answers it wrong is the default one.

This is not a regression from ADR 0006. `canonical_float_tree` passes a blessed
leaf through untouched, which is precisely what `Dump()` received before it
existed. ADR 0006 only made the asymmetry visible by fixing one side of it.

### What has to keep working

Two measurements decided the shape of the guard, and the second is the one that
could have made this change catastrophic.

**`JSON::PP::Boolean` is the only blessed leaf the library itself produces.**
Instrumented `emit` for both formats over the whole suite (25 files, 573 tests,
`t/04-interop.t` executed): 28 blessed leaves reached a YAML or JSON emit, all
of them `JSON::PP::Boolean`, plus the 4 `Math::BigFloat`/`Math::BigInt` the
JSON guard's own tests hand it on purpose. `_encrypt_tree` replaces every
encrypted leaf with an `ENC[…]` string before emit ever runs, so an object in an
*encrypted* slot never reaches this guard at all.

**`emit` sees the `sops` section.** `serialize` builds one tree — data plus
`$metadata->to_hash` — and hands it to `emit`, and `Metadata::to_hash` writes
`mac_only_encrypted => JSON->true`. A guard that refused blessed leaves without
an exception for booleans would have made **every `mac_only_encrypted`
document unwritable**, and every document with a bare `true`/`false` under
`unencrypted_suffix` with it.

**The exception is the exact class, not `isa`.** `detect_type` accepts any
`JSON::PP::Boolean` subclass as `bool`, but the emitter does not: measured,
`YAML::XS` writes a subclass as `!!perl/scalar:MyBool 1` while digesting as
`True`, i.e. the same defect wearing the whitelist. Cpanel refuses it outright.
The guard therefore tests `ref($node) eq 'JSON::PP::Boolean'`, which is the
class `$YAML::XS::Boolean = 'JSON::PP'` actually knows how to write.

## Decision

**`Format::YAML::emit` passes a `reject` callback to `canonical_float_tree`
that refuses every referenced leaf other than an exact `JSON::PP::Boolean`.**

- The rule is stated in terms of the emitter, not of the class: this leaf is
  refused because `YAML::XS` cannot write it as the text the digest covers.
  `JSON::PP::Boolean` is not an exception to the rule, it is the one leaf that
  satisfies it — `$YAML::XS::Boolean = 'JSON::PP'` writes it as bare
  `true`/`false` while `detect_type` digests it as `True`/`False`, which is what
  sops has.
- **Unblessed references are refused too**, not only objects. `\1` and a coderef
  produce `!!perl/ref` and `!!perl/code` and fail in exactly the same way; the
  callback already runs for them, and excluding them would leave a known-broken
  path unguarded next to a guard.
- Containers are untouched. `canonical_float_tree` recurses into an unblessed
  `HASH` or `ARRAY` before the leaf branch, so `{}` and `[]` never reach the
  callback and empty ones still emit as they do today.
- **The guard is at emit time, not in `assert_representable`.** Measured: a
  blessed leaf in an *encrypted* slot works in both formats today and must keep
  working — it becomes `ENC[…,type:str]` whose plaintext is the same
  stringification the digest covers, and both implementations read it back.
  `assert_representable` runs over every leaf on the encrypt side *and* on the
  verify side, so putting the rule there would refuse those documents and refuse
  to *read* files it can read today. "What this emitter can write" is a property
  of the emitter; ADR 0006 already put that question in the `reject` hook.
- The message names the class and says what to pass instead. It never names the
  value: an error goes into bug reports, and a plaintext secret that lands
  there was not encrypted for any practical purpose.

## Consequences

- **A croak where a document used to be written.** This is a behaviour change
  and it belongs in `Changes`, but nothing that worked stops working: every
  input that now croaks previously produced a file that failed its own MAC. The
  one row that `sops -d` accepted, `qr//`, is a file File::SOPS could not read
  back.
- YAML and JSON now refuse the same set of leaves, for the same stated reason.
  They still refuse it through different machinery — Cpanel's own encoder error
  for most classes, our callback for the two bignum classes and for `\1` on the
  YAML side — so the *messages* differ.
- A caller who wants an object in a document has two answers, both in the
  message: pass a plain scalar, or pass its stringification yourself. The second
  is not a workaround but the honest form of what used to happen implicitly,
  and it is what an *encrypted* slot has always done.
- The `reject` hook is no longer JSON-specific. Its POD said it existed because
  `allow_bignum` widened one emitter; it now documents the general rule and
  names both callers.
- **Known gap, deliberately not closed here:** on the JSON side an unblessed
  `\1` / `\0` is written by `Cpanel::JSON::XS` as bare `true` / `false` while the
  digest covers `SCALAR(0x…)` — self-MAC FAIL, `sops -d` exit 51, silently.
  Same defect class, different trigger, and the fix is one more condition in
  `Format::JSON::_reject_foreign_bignum`. Filed as karr #66 rather than folded
  in, so that this change stays the one the ticket describes.

  **Closed by karr #66 (the edit to `_reject_foreign_bignum` that turns the
  two-name allow_bignum whitelist into the same exact-class rule the YAML side
  uses).** The JSON guard now refuses every referenced leaf except an exact
  `JSON::PP::Boolean`, with the same message naming the class or ref kind and
  never the value, the same exception, the same "encrypted slots are
  unaffected" rule, and the same exact-class-rather-than-`->isa` discipline.
  Measured against sops 3.13.3: `\1` / `\0` / `\$x` croak,
  `JSON->true` / `JSON->false` still write as bare `true` / `false`, and
  `t/26-json-unblessed-ref-guard.t` pins the whole exchange (13 subtests,
  5 of them driven against the binary). No new ADR: the rationale is this
  one's, and a karr #66 ADR would be a "same rule, same exception, same
  rationale, JSON side" of itself.

### What changes for existing callers

Nothing for any tree made of plain scalars, `undef`, hashes, arrays and
`JSON->true`/`JSON->false` — which is every tree this library produces itself,
measured over the whole suite. A caller who passed an object into a slot that
is **not** encrypted now gets an error naming the class instead of a file
nothing can read. A caller who passed one into a slot that **is** encrypted is
unaffected.

## Rejected alternatives

**Refuse only blessed leaves, leaving `\1` and coderefs.** That is the ticket's
literal scope, and it is narrower than the mechanism: the callback sees every
referenced leaf, the failure mode is identical, and `!!perl/ref` is no more
readable than `!!perl/hash:Foo`. Keeping it would mean writing a guard and
stepping around a case it already had in its hand.

**Whitelist by `detect_type($node) eq 'bool'`** instead of by class. Attractive
because it ties the guard to the rule that decides the digest, and wrong for the
same reason: `detect_type` uses `isa`, so it would admit the
`JSON::PP::Boolean` subclass that `YAML::XS` measurably writes as
`!!perl/scalar:MyBool`. The guard's question is what the emitter can write, and
only the exact class answers it.

**Stringify the object instead of refusing it** — call `"$node"` and write that,
which is what the digest covers, so the document would verify. It makes
File::SOPS silently store a `Foo=HASH(0x55…)` — a heap address, different on
every run — and makes the *unencrypted* path quietly agree with the encrypted
one about a conversion the caller never asked for. Refusing is the same answer
JSON has given all along, and it loses no data.

**Teach `YAML::XS` to emit the stringification** via a representer or
`$YAML::XS::…` knob. There is none: `YAML::XS` exposes no per-scalar style or
tag control, which is the same wall ADR 0006 hit and the reason
`_quote_sops_timestamp` is a post-pass over the emitted text. Switching to
`YAML::PP` to get one is ADR 0001's and ADR 0006's rejected option, and it moves
the wire bytes of every multi-line string in every document.

**Put the rule in `assert_representable`, next to the int64 check.** It is
format-blind and runs earlier, which is why it looks like the right place. It
runs on the verify side too, and it does not know whether the leaf it is looking
at is about to become an `ENC[…]` string — so it would refuse documents this
library writes and reads correctly today, in both formats, and refuse to open
files it can currently open. Measured, not assumed: an encrypted
`Math::BigFloat`, an overloaded object and a `qr//` all round-trip through
`encrypt`/`decrypt` today in YAML and in JSON.
