# File::SOPS

Pure Perl implementation of [Mozilla SOPS](https://github.com/getsops/sops) (Secrets OPerationS) encrypted file format.

## Synopsis

```perl
use File::SOPS;

# Encrypt a data structure
my $encrypted = File::SOPS->encrypt(
    data       => {
        database => {
            password => 'secret123',
            host     => 'db.example.com',
        },
    },
    recipients => ['age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p'],
    format     => 'yaml',  # or 'json'
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
    recipients => ['age1...'],
);

File::SOPS->decrypt_file(
    input      => 'secrets.enc.yaml',
    output     => 'secrets.yaml',
    identities => ['AGE-SECRET-KEY-1...'],
);

# Extract single value without decrypting entire file
my $password = File::SOPS->extract(
    file       => 'secrets.enc.yaml',
    path       => 'database.password',
    identities => ['AGE-SECRET-KEY-1...'],
);

# Rotate data key (re-encrypt with new key)
File::SOPS->rotate(
    file       => 'secrets.enc.yaml',
    identities => ['AGE-SECRET-KEY-1...'],
);
```

## Description

SOPS encrypts **values** in structured files (YAML, JSON) while keeping **keys** readable. This enables:

- Git-friendly diffs - see which keys changed without decrypting
- Partial file inspection without full decryption
- Multiple encryption backends (currently age, with PGP/KMS planned)
- MAC verification to detect tampering

### Encrypted File Format

```yaml
database:
    password: ENC[AES256_GCM,data:xyz==,iv:abc==,tag:def==,type:str]
    host: ENC[AES256_GCM,data:xyz==,iv:abc==,tag:def==,type:str]
sops:
    age:
        - recipient: age1ql3z7hjy...
          enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            <encrypted data key>
            -----END AGE ENCRYPTED FILE-----
    lastmodified: "2025-01-10T12:00:00Z"
    mac: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
    version: 3.7.3
```

## Interoperability

Files encrypted with File::SOPS can be decrypted with the [reference Go implementation](https://github.com/getsops/sops), and vice versa, for YAML and JSON.

Verified against **sops v3.13.3** by `t/04-interop.t`, which drives the real binary in both directions. That test skips unless a binary is present, so a plain `prove -lr t/` does **not** prove compatibility — run it explicitly:

```bash
SOPS_BIN=/path/to/sops prove -lv t/04-interop.t
```

Known limitations:

- **Quoted scalars change type on a round trip.** sops types a value by what the parser produced; File::SOPS infers the type from the scalar's text. A quoted `"true"`, `"false"`, `"1"` or `"0"` therefore comes back as a boolean or an integer rather than the string it went in as. Unquoted values are unaffected.
- **Comments are not preserved.** `YAML::XS` discards them on parse, so they are absent from the output; `sops -d` keeps them.
- **Multi-document YAML is not supported** — only the last document survives.
- Backends other than age (PGP, KMS, GCP KMS, Azure Key Vault, Vault) are parsed and round-tripped in the metadata but cannot be used for encryption.

## Installation

```bash
cpanm File::SOPS
```

Or manually:

```bash
perl Makefile.PL
make
make test
make install
```

## Dependencies

- [Crypt::Age](https://metacpan.org/pod/Crypt::Age) - age encryption
- [CryptX](https://metacpan.org/pod/CryptX) - AES-GCM encryption
- [YAML::XS](https://metacpan.org/pod/YAML::XS) - YAML parsing
- [JSON::MaybeXS](https://metacpan.org/pod/JSON::MaybeXS) - JSON parsing
- [Moo](https://metacpan.org/pod/Moo) - OO framework

## Encryption Backends

Currently supported:

- **age** - Modern encryption using X25519 + ChaCha20-Poly1305

Planned:

- PGP
- AWS KMS
- GCP KMS
- Azure Key Vault
- HashiCorp Vault

## How It Works

1. Generate a random 256-bit **data key**
2. Encrypt the data key for each recipient using age
3. Encrypt each value with AES-256-GCM using the data key
4. Compute MAC over all values for tamper detection
5. Store encrypted data keys in `sops` metadata section

## See Also

- [SOPS](https://github.com/getsops/sops) - Reference implementation
- [Crypt::Age](https://metacpan.org/pod/Crypt::Age) - Perl age encryption
- [age](https://age-encryption.org/) - age encryption specification

## Author

Torsten Raudssus <torsten@raudssus.de>

## License

This is free software; you can redistribute it and/or modify it under the same terms as the Perl 5 programming language system itself.
