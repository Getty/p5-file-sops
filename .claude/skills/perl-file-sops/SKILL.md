---
name: perl-file-sops
description: Use when calling File::SOPS from another project — encrypt/decrypt SOPS files with age recipients, .sops.yaml creation_rules_for, rotate, encrypt_file, extract, decrypt errors.
---

# File::SOPS — calling it

Pure-Perl Mozilla SOPS: reads and writes the files the `sops` binary reads and writes (YAML, JSON, dotenv,
INI). Every method is a **class method**, takes named arguments and `croak`s on failure. The age layer —
recipient (`age1…`) and identity (`AGE-SECRET-KEY-1…`) strings, key generation — is skill `perl-crypt-age`.
Changing File::SOPS itself is `file-sops-core` and `file-sops-hazards`.

Require `File::SOPS 0.005` (and the `Crypt::Age 0.005` it pulls in). 0.005 stops `decrypt` clobbering the
caller's `$_`, so `for (@files) { File::SOPS->decrypt(…) }` is safe; older releases rewrote the list.

## Encrypt and decrypt strings

```perl
use File::SOPS;
use JSON::MaybeXS qw(JSON);            # JSON->true is not exported by File::SOPS

my $doc = File::SOPS->encrypt(         # one string: the encrypted document, UTF-8 BYTES
    data       => { db => { password => 'secret', port => 5432 }, tls => JSON->true },
    recipients => [ $age_pub1, $age_pub2 ],   # ArrayRef of age1… strings, at least one
    format     => 'yaml',                     # yaml (default) | json | env | ini
);

my $data = File::SOPS->decrypt(        # the HashRef, MAC verified
    encrypted  => $doc,                # the document exactly as read from disk: bytes
    identities => [ $age_secret ],     # ArrayRef of AGE-SECRET-KEY-1… strings; ONE match opens it
    format     => 'yaml',              # optional
);
```

- `data` is a HashRef; an ArrayRef of HashRefs writes a multi-document YAML stream, and `decrypt` returns an
  ArrayRef exactly when the document holds more than one (`ref $r eq 'ARRAY' ? @$r : $r`).
- **A leaf's type is the scalar's type**, never its text: `'5432'` is `type:str`, `5432` is `type:int`,
  `JSON->true` (or a comparison result on perl 5.36+) is `type:bool`. Reading a string in numeric context
  (`$h->{port} > 1024`) turns it into an int for the next `encrypt`; re-stringify first (`"$h->{port}"`).
  A document loaded with YAML::XS / JSON::MaybeXS keeps the types its file gave it.
- The default rule leaves keys ending in `_unencrypted` **readable** (still MAC-covered). To encrypt every
  value pass `unencrypted_suffix => undef`; to choose by name pass exactly one of `encrypted_suffix`,
  `unencrypted_regex`, `encrypted_regex`. Two of them die.
- A top-level `sops` key in the data dies for YAML/JSON (that is where the metadata lives); rename the entry.
- `encrypt` and `decrypt` never touch disk. The key order of the output is sorted, YAML comments are not kept.

## Characters in, characters out

Keys, values, `extract` paths and everything `decrypt` returns are **character strings**: decode at your
boundary and pass characters, never UTF-8 bytes (bytes are encoded a second time). The *document* is the
opposite: `encrypt` returns bytes and `decrypt` wants bytes, so write with `:raw` / `spew` and read with
`slurp` (Path::Tiny, File::Slurper `read_binary`) — a character-decoded document with non-ASCII content
dies in the YAML parse. The file methods below handle both ends themselves.

## Format: detected or explicit

- `decrypt` (string) detects from **content**: `{` first → json, a `sops_` key → env, a `[sops]` section → ini,
  else yaml. An explicit `format => 'yaml'` skips the guess and is the right call when the caller knows.
- `encrypt_file`, `decrypt_file`, `extract`, `rotate`, `edit` detect from the **filename**: `.json`, `.yaml`/`.yml`,
  `.env`, `.ini`, anything else is yaml. A file with another name needs `format =>`.
- A wrong explicit format dies in that format's parser; an unknown name dies `Unknown format: …`.
- `env` is flat and `ini` is two levels (section, key); both come back **untyped** for unencrypted leaves.

## Files

```perl
File::SOPS->encrypt_in_place(file => 'secrets.yaml', recipients => \@pub);        # plaintext → encrypted, atomic
File::SOPS->encrypt_file(input => 'p.yaml', output => 's.yaml', recipients => \@pub);   # output defaults to input
File::SOPS->decrypt_file(input => 's.yaml', output => 'p.yaml', identities => \@sec);   # output is required
my $v = File::SOPS->extract(file => 's.yaml', path => '["db"]["password"]', identities => \@sec);  # or db.password
```

All return true (`extract` returns the value, a subtree for a branch; a missing path dies naming the component).
Every write is a temp file plus `rename`: a failure leaves the original intact, the file gets a new inode (hard
links keep the old content), a new file gets the umask default mode — set the mode when plaintext lands there.
An input that already has a `sops` key dies in `encrypt_file`/`encrypt_in_place`; re-key with `rotate`.
`edit(file, identities, editor)` runs `$EDITOR` (dies when unset) and returns 0 when nothing changed.

## `.sops.yaml` — `creation_rules_for`

```perl
my %args = File::SOPS->creation_rules_for(file => "$dir/keys.yaml");   # config => $path skips the search
File::SOPS->encrypt_in_place(file => "$dir/keys.yaml", %args);         # recipients + the rule's encryption rules
```

- Returns a flat list for splatting into the encrypt methods: `recipients` (the rule's `age`, comma list or YAML
  list), `hc_vault_transit_uris`, and whichever encryption rule and `mac_only_encrypted` the rule carries.
- **First matching rule wins**; no `path_regex` matches everything. The regex runs against the file path made
  absolute and taken **relative to the config's directory**, and must read the same in Perl and Go RE2 (a
  lookaround or backreference dies naming the rule).
- **No match is a `croak`, never an empty list**: `No creation rule in '<config>' matches '<path>'…`. No config
  found dies `No .sops.yaml found for '<file>'…`. A caller that treats "no rule" as "no extra recipients"
  catches `/\ANo creation rule in /` and nothing else; every other failure (bad config, a rule naming pgp/kms/
  key_groups, no recipient in the rule) is real.
- The config is searched upward from the **file's** directory (sops searches from the working directory), first
  `.sops.yaml` found wins; `$SOPS_CONFIG` is ignored unless you pass `config => $ENV{SOPS_CONFIG}`.

## `rotate` — changing recipients

```perl
File::SOPS->rotate(file => 'keys.yaml', identities => \@sec, recipients => \@new_list);   # → 1
```

- Always a **new data key**: decrypt, re-encrypt every value, rewrap for `recipients`, atomic write back.
- `recipients` **replaces** the age set (it is the complete new list, not a delta); omit it to keep the
  document's current recipients. Compute the list yourself, e.g. from `my %a = File::SOPS->creation_rules_for(file => $f)` and `$a{recipients}`.
- `identities` must open the **current** file; they need not belong to the new list — leaving yourself out
  locks you out of the result, so put your own recipient in `recipients`.
- The `sops` section's encryption rules, `mac_only_encrypted` and unmodelled fields carry over; value types
  survive. A file with pgp/kms/gcp_kms/azure_kv/key_groups material is **refused** (use the `sops` CLI).
- A removed recipient still opens older copies of the file (git history): rotate the secrets themselves too.

## Errors a caller can match

All are plain strings ending in ` at FILE line N.`; match unanchored on the head:

| Cause | Message head |
|---|---|
| no identity opens the data key (wrong key, or caller not a recipient) | `Could not decrypt data key with any of the provided identities` |
| a value was altered | `<key:path>: Authentication failed - data may be corrupted` |
| value added/removed/moved, MAC differs | `MAC verification failed: …` |
| MAC missing or unreadable | `Cannot decrypt MAC - refusing to return unverified data` |
| not a SOPS document | `No SOPS metadata found` |
| no `identities` (and no Vault token) | `identities required` |

Verification fails closed. `ignore_mac => 1` returns *unauthenticated* data — for salvage only. A document with
more than 64 age entries is refused (`max_stanzas =>` raises it for a trusted file).

## With the `sops` binary

Documents written here decrypt with `sops -d`, and documents written by `sops -e` decrypt here, in YAML, JSON,
dotenv and INI (pinned by `t/04-interop.t`, against sops 3.13.3). `sops` reads age identities from
`SOPS_AGE_KEY` / `SOPS_AGE_KEY_FILE`; File::SOPS takes identities only as the `identities` argument.
Cosmetic: our YAML starts with `---`. `lastmodified` is written quoted, as sops needs it; a document that
carries it bare (written by 0.002) warns on every read until a `rotate` rewrites it. Integers must fit int64.

## Vault Transit (the release after 0.005)

Pass `hc_vault_transit_uris => [...]` (and `vault_token`, default `$ENV{VAULT_TOKEN}`) instead of or beside
`recipients`, to `encrypt`, `encrypt_file`, `encrypt_in_place` and `rotate`; `decrypt` may then omit
`identities`. Pass `vault_allowed_addresses => [...]` whenever the document is not your own: the Vault address
comes from the document being opened, and the list keeps your token to the servers you name.
