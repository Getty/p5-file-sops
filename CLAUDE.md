# File::SOPS

Perl implementation of Mozilla SOPS (Secrets OPerationS) encrypted file format.

> **Status of this file:** it is the original *design document*, kept as the roadmap.
> What still does not exist: **ENV and INI format handlers** (karr #36, #37) and
> **every backend beyond age** — PGP, AWS KMS, GCP KMS, Azure KV, Vault (karr #39;
> their metadata fields already round-trip, only the wrapping is missing).
> Implemented since: `encrypt_in_place`, `edit`, and `.sops.yaml` creation rules
> (`creation_rules_for`, karr #38 — with one deliberate divergence from sops that
> is still open for confirmation, karr #55).
> The description of what exists lives in skill `file-sops-core`; the POD in
> `lib/File/SOPS.pm` is the contract.

## Delegation

Delegate behavior-relevant code to the right agent instead of touching it yourself —
principle and lane are in `.claude/rules/file-sops-rules.md`.

| Task | Agent | Owns |
|---|---|---|
| Value types, encoding, AES-GCM, MAC/AAD, backends | `file-sops-wire` | `Encrypted.pm`, `Backend/`, the MAC paths in `SOPS.pm` |
| Public API, guards, error behaviour, rule policy | `file-sops-api` | `SOPS.pm`, `Metadata.pm` |
| Parsers, emitters, quoting, the order-preserving reparse | `file-sops-format` | `Format/*.pm` |
| Write/extend tests, reproduce interop bugs | `file-sops-test-writer` | `t/` |
| Pre-release audit (Changes, cpanfile, dist.ini, interop proof) | `file-sops-release-checker` | reports only |

The first three replaced a single `file-sops-worker`. Splitting them let each briefing
carry its own traps instead of one agent holding all of them: the wire lane needs the
ADRs and the SV-flag rules, the API lane needs the compatibility and fail-loud rules,
the format lane needs the parser/emitter specifics.

**The lanes are not equally clean.** `file-sops-format`'s boundary cuts through a
load-bearing coupling — ADR 0001 records that the emitter and the MAC are one mechanism
— so its briefing requires it to hand a change to `file-sops-wire` whenever parsing or
emitting could move the digest. Same rule in the other direction for `file-sops-api`:
an argument is its own, but what that argument makes the document look like is not.

The agents carry their knowledge via `briefing.skills` (see `.claude/agents/`); the main
agent delegates rather than loading them. Skill sources live under `.claude/skills/` —
`file-sops-core` is project-owned, the `perl-*` and `karr` ones are hardlinked from
their shared sources.

Work coordination runs on the local `karr` board (`karr board`).

## Project Goal

Pure Perl implementation of SOPS file handling, compatible with the reference Go implementation (github.com/getsops/sops).

## What SOPS Does

SOPS encrypts **values** in structured files (YAML, JSON, INI, ENV) while keeping **keys** readable. This allows:
- Git-friendly diffs (you see which keys changed)
- Partial file inspection without decryption
- Multiple encryption backends (age, PGP, KMS)

## Encrypted Value Format

```
ENC[AES256_GCM,data:base64==,iv:base64==,tag:base64==,type:str]
```

Components:
- `AES256_GCM` - Encryption algorithm
- `data` - Encrypted value (base64)
- `iv` - Initialization vector (base64)
- `tag` - Authentication tag (base64)
- `type` - Original data type (str, int, float, bool, bytes)

## How SOPS Works

1. Generate random 256-bit **data key**
2. Encrypt data key with each recipient (age/PGP/KMS)
3. Store encrypted data keys in `sops` metadata section
4. Encrypt each value with AES256-GCM using data key
5. Compute MAC over entire structure

## File Structure (YAML example)

```yaml
database:
    password: ENC[AES256_GCM,data:xyz,iv:abc,tag:def,type:str]
    host: ENC[AES256_GCM,data:xyz,iv:abc,tag:def,type:str]
sops:
    kms: []
    gcp_kms: []
    azure_kv: []
    hc_vault: []
    age:
        - recipient: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            <encrypted data key>
            -----END AGE ENCRYPTED FILE-----
    lastmodified: "2025-01-10T12:00:00Z"
    mac: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
    pgp: []
    unencrypted_suffix: _unencrypted
    version: 3.7.3
```

## API Design

Everything below except the `format => 'env' | 'ini'` note exists today, with named
arguments throughout — `encrypt_in_place` and `edit` take `file => ...` like `rotate`
and `extract`, not a leading positional filename as this document first sketched.

```perl
use File::SOPS;

# Encrypt a hash
my $encrypted = File::SOPS->encrypt(
    data       => { password => 'secret', user => 'admin' },
    recipients => ['age1...'],  # age public keys
    format     => 'yaml',       # yaml, json; env and ini are roadmap
);

# Decrypt
my $data = File::SOPS->decrypt(
    encrypted  => $encrypted,
    identities => ['AGE-SECRET-KEY-1...'],
);

# File operations
File::SOPS->encrypt_file(
    input      => 'secrets.yaml',
    output     => 'secrets.enc.yaml',
    recipients => \@recipients,
);

File::SOPS->decrypt_file(
    input      => 'secrets.enc.yaml',
    output     => 'secrets.yaml',
    identities => \@identities,
);

# In-place encryption (atomic: temp file + rename, permissions preserved)
File::SOPS->encrypt_in_place(
    file       => 'secrets.yaml',
    recipients => \@recipients,
);

# Edit (decrypt, $EDITOR, re-encrypt). Returns 0 if nothing changed.
File::SOPS->edit(
    file       => 'secrets.enc.yaml',
    identities => \@identities,
    editor     => 'vim',   # optional, defaults to $ENV{EDITOR}, no vi fallback
);

# Extract single value
my $password = File::SOPS->extract(
    file       => 'secrets.enc.yaml',
    path       => '["database"]["password"]',
    identities => \@identities,
);

# Rotate data key
File::SOPS->rotate(
    file       => 'secrets.enc.yaml',
    identities => \@identities,
);
```

## Config File (.sops.yaml)

Read by `creation_rules_for`, which returns arguments for the encrypt path rather
than encrypting anything itself:

```perl
my %args = File::SOPS->creation_rules_for(file => $file);
File::SOPS->encrypt_in_place(file => $file, %args);
```

```yaml
creation_rules:
  - path_regex: \.enc\.yaml$
    age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  - path_regex: secrets/.*\.yaml$
    age: >-
      age1...,
      age1...
```

First matching rule wins; a rule without `path_regex` is the catch-all. `age`
also takes a YAML list. `path_regex` matches the path **relative to the config
file's directory**, not the absolute one. A rule carrying an encryption rule
(`encrypted_suffix` and friends) has it returned too.

Two things the POD spells out and this sketch cannot: the search runs upward from
the **file's** directory where sops searches from the **working directory** — a
deliberate divergence, still open for confirmation (karr #55) — and `$SOPS_CONFIG`
is not read from the environment. Not supported: `key_groups`, `shamir_threshold`,
and recipients for backends other than age (karr #39); all are refused rather than
ignored.

## Dependencies

Sketch only — `cpanfile` is the truth, and it is longer (YAML::PP for the
order-preserving reparse, the core modules declared explicitly because there is no
AutoPrereqs).

```perl
requires 'Crypt::Age';        # age encryption backend
requires 'CryptX';            # AES-GCM for value encryption
requires 'YAML::XS';          # YAML parsing
requires 'JSON::MaybeXS';     # JSON parsing
```

## Encryption Backends

**age only** — and `File::SOPS::Backend::Age` is the only backend module. HashiCorp Vault
is the only other one on the roadmap (karr #39).

`File::SOPS::Metadata` models the `sops`-section fields for every backend sops supports
(`pgp`, `kms`, `gcp_kms`, `azure_kv`, `hc_vault`) as first-class attributes, and round-trips
unrecognised fields through `extra`. A document shared with such a recipient can therefore
be *read* here through its age entry — MAC and all. Anything that generates a new data
key — `rotate`, `edit` — refuses such a document rather than dropping the entries it
cannot re-wrap.

## Cryptographic Operations

| Operation | Algorithm | Library |
|-----------|-----------|---------|
| Data key encryption | age (X25519 + ChaCha20-Poly1305) | Crypt::Age |
| Value encryption | AES-256-GCM | CryptX |
| MAC | AES-256-GCM over structure | CryptX |

## Special Keys

- `_unencrypted` suffix: Values not encrypted but included in MAC
- `sops` key: Metadata, always unencrypted

## Files

`ENV.pm` and `INI.pm` do not exist (karr #36, #37); everything else under `lib/` does.
The `t/` layout below was the sketch — the real suite is 18 files and is listed by
`ls t/`, with `t/04-interop.t` the only one that talks to the sops binary.

```
lib/
├── File/
│   ├── SOPS.pm                 # Main interface
│   └── SOPS/
│       ├── Encrypted.pm        # Encrypted value parsing/generation
│       ├── Metadata.pm         # SOPS metadata handling
│       ├── Format/
│       │   ├── YAML.pm
│       │   ├── JSON.pm
│       │   ├── ENV.pm          # roadmap
│       │   └── INI.pm          # roadmap
│       └── Backend/
│           └── Age.pm          # age encryption backend
```

## References

- https://github.com/getsops/sops
- https://getsops.io/docs/
- https://blog.gitguardian.com/a-comprehensive-guide-to-sops/
