# File::SOPS House Rules

The shared house rules come from skilletor — bundle `getty-cpan-dist@getty`: engineering
discipline, the delegation lock, the publish gate, karr coordination, CPAN release. They load
as `.claude/rules/.local.*.md`; if they are missing, run `skilletor sync` and publish nothing
until they load. This file adds what is true only here, and wins where it differs.

## What this repo is

Perl implementation of the Mozilla SOPS encrypted file format. Read first: the callers and the
twin — value→bytes conversion and the type ladder exist in more than one place; changing one
alone is this distribution's signature bug.

## Agent team

| Task | Agent |
|---|---|
| Value types, encoding, AES-GCM, MAC/AAD, backends | `file-sops-wire` |
| Public API, guards, error behaviour, rule policy | `file-sops-api` |
| Parsers, emitters, quoting, the order-preserving reparse | `file-sops-format` |
| Write/extend tests, reproduce interop bugs | `file-sops-test-writer` |
| Commits, `Changes`, card → done, pre-release audit | `file-sops-release-manager` |
| Read-only research, audit, gap analysis | the lane owning the area ("read-only, change nothing") |

Pick the lane by what the change *moves*, not by which file it starts in: a `Format/YAML.pm`
edit that changes what gets hashed belongs to `file-sops-wire`.

Behavior-relevant = `lib/`, the tests, and any change to the wire format, MAC, AAD derivation,
type detection or serialization; prose docs, `README.md` and `Changes` wording are not.

## Release

After a release the `$VERSION` bump is a separate, deliberate commit.

## Deviations from the house rules

- **Lanes spanning one ticket run in sequence, not in parallel.** Let each report what it
  handed on — parallel workers in the same file overwrite each other.

## Hazards — interop and crypto: the Go implementation is the spec

- **Never report a green suite as evidence for a format-touching change.** `t/04-interop.t` is
  the only compatibility proof and skips without a `sops` binary — say which run you did;
  self-consistency proves nothing about what `sops` accepts. A test that can't fail when the
  wire format changes is no test here.
- **Nonce sizes, tag handling, AAD, key derivation and the MAC follow the reference
  implementation**, not your taste. What looks wrong is more likely a deliberate
  Go-compatibility choice than a bug — verify against the reference before "fixing" it;
  **never weaken a check to make a test pass**.
- **Secrets, age keys and plaintext values** never land in logs, commit messages or ticket
  bodies.

## Perl specifics — reference, don't restate

House Perl style lives in `getty-perl-core`, `getty-perl-moo`, `getty-perl-release-author-getty`;
wire format and invariants in `file-sops-core` (all force-loaded).
