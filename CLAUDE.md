# File::SOPS

Perl implementation of Mozilla SOPS (Secrets OPerationS) encrypted file format.

> **Status of this file:** it is the original *design document*. Parts of it describe
> intent that is not implemented (ENV/INI formats, `.sops.yaml` creation rules,
> `encrypt_in_place`, `edit`, every backend beyond age). Read it as the roadmap; the
> description of what exists lives in skill `file-sops-core`.

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

```perl
use File::SOPS;

# Encrypt a hash
my $encrypted = File::SOPS->encrypt(
    data       => { password => 'secret', user => 'admin' },
    recipients => ['age1...'],  # age public keys
    format     => 'yaml',       # yaml, json, env, ini
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

# In-place encryption
File::SOPS->encrypt_in_place('secrets.yaml', recipients => \@recipients);

# Edit (decrypt, edit, re-encrypt)
File::SOPS->edit('secrets.enc.yaml', identities => \@identities);

# Extract single value
my $password = File::SOPS->extract(
    file       => 'secrets.enc.yaml',
    path       => '["database"]["password"]',
    identities => \@identities,
);

# Rotate data key
File::SOPS->rotate('secrets.enc.yaml', identities => \@identities);
```

## Config File (.sops.yaml)

```yaml
creation_rules:
  - path_regex: \.enc\.yaml$
    age: age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p
  - path_regex: secrets/.*\.yaml$
    age: >-
      age1...,
      age1...
```

## Dependencies

```perl
requires 'Crypt::Age';        # age encryption backend
requires 'CryptX';            # AES-GCM for value encryption
requires 'YAML::XS';          # YAML parsing
requires 'JSON::MaybeXS';     # JSON parsing
```

## Encryption Backends (Phase 1)

Start with **age only**:
- Uses `Crypt::Age` for data key encryption
- Most common for local/team use

Later phases:
- PGP (via Crypt::OpenPGP or gpg CLI)
- AWS KMS
- GCP KMS
- Azure Key Vault
- HashiCorp Vault

## Cryptographic Operations

| Operation | Algorithm | Library |
|-----------|-----------|---------|
| Data key encryption | age (X25519 + ChaCha20-Poly1305) | Crypt::Age |
| Value encryption | AES-256-GCM | CryptX |
| MAC | AES-256-GCM over structure | CryptX |

## Special Keys

- `_unencrypted` suffix: Values not encrypted but included in MAC
- `sops` key: Metadata, always unencrypted

## Files to Create

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
│       │   ├── ENV.pm
│       │   └── INI.pm
│       └── Backend/
│           └── Age.pm          # age encryption backend
t/
├── 00-load.t
├── 01-encrypt-decrypt.t
├── 02-yaml.t
├── 03-json.t
└── 04-interop.t                # Test with sops CLI
```

## References

- https://github.com/getsops/sops
- https://getsops.io/docs/
- https://blog.gitguardian.com/a-comprehensive-guide-to-sops/
