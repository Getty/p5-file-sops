#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use File::Temp qw(tempdir);
use YAML::XS ();
use JSON::MaybeXS;
use Crypt::Age;
use Crypt::AuthEnc::GCM qw(gcm_decrypt_verify);

use File::SOPS;
use File::SOPS::Encrypted;
use File::SOPS::Backend::Age;
use File::SOPS::Format::YAML;

# ----------------------------------------------------------------------------
# Regressions for the two character-encoding defects (karr #26, #12).
#
# Both were invisible to the rest of the suite for the same reason: every
# assertion in it is ASCII, and in ASCII a character string and its UTF-8
# encoding are the same bytes. The moment a key or a value leaves ASCII the two
# rules this file pins come apart:
#
#   #26  The AAD reaching AES-GCM must be UTF-8 bytes, because that is what the
#        Go implementation authenticates against. It used to be handed over as a
#        character string, which CryptX either downgraded to Latin-1 (U+0080 to
#        U+00FF -- a file that looks right and authenticates against nothing) or
#        refused outright with "Wide character in subroutine entry" (above
#        U+00FF). Both directions were affected, including the MAC, which
#        re-derives the same AAD to hash each value's plaintext.
#
#   #12  The API boundary is characters. decrypt used to return the UTF-8 bytes
#        straight off the cipher, so a decrypted structure compared unequal to
#        the one that was encrypted, and decrypt_file encoded those bytes a
#        second time and wrote mojibake.
#
# Nothing here shells out. The fixture in section 1 is a real document written
# by sops 3.13.3, checked in with its (throwaway) age identity, so the read
# direction is pinned against the reference implementation without needing the
# binary present -- which is the whole point, since t/04-interop.t skips when it
# is not. The codepoints are written as \x{} escapes rather than literal UTF-8
# so that the test states them exactly and does not depend on how this file is
# itself decoded.
# ----------------------------------------------------------------------------

# A \x{} escape below U+0100 leaves Perl free to store the string as single
# bytes with the UTF-8 flag off, which is byte-for-byte indistinguishable from a
# caller who really did pass bytes. Everything below is meant as CHARACTERS, so
# say so once, here, rather than depending on how Perl chose to hold a literal.
# (For anything above U+00FF the flag is always on and this is a no-op.)
sub chars { my ($s) = @_; utf8::upgrade($s); return $s }

my $K_LATIN1 = chars("caf\x{e9}");         # café  -- was silently encoded as Latin-1
my $K_WIDE   = "\x{30ad}\x{30fc}";         # キー   -- was fatal, above U+00FF
my $K_PASSW  = chars("passw\x{f6}rd");
my $V_UMLAUT = chars("h\x{e4}mlich");
my $V_OFFEN  = chars("\x{f6}ffentlich");   # unencrypted, but still hashed into the MAC
my $V_CJK    = "\x{5024}";
my $V_EMOJI  = "\x{1f510}ok";              # outside the BMP

# ----------------------------------------------------------------------------
# 1. A real sops 3.13.3 document whose keys leave ASCII.
#
# This is the ground truth for #26: the AAD sops used for the value below is
# "caf\xc3\xa9:passw\xc3\xb6rd:" -- UTF-8, not Latin-1 and not a Perl character
# string. Before the fix this died in the U+30AD branch and failed
# authentication in the café branch.
#
# It also covers the read side of #12: the values must come back as characters,
# and "notiz_unencrypted" exercises a non-ASCII value that is hashed into the
# MAC without being encrypted, so the digest and the AAD are both under test.
# ----------------------------------------------------------------------------

my $SOPS_IDENTITY =
    'AGE-SECRET-KEY-1SU0PVPYT46DZXY67SYTYRCPN95D4VSL9EFF6LJ3TQ6APL7WL2HGQYF0LZV';

my $SOPS_FIXTURE = <<'YAML';
café:
    passwörd: ENC[AES256_GCM,data:eIYc2cwPv0E=,iv:JLLV+z1GQtCSTkaYsUUt4yJZD63wbfvKx6HbGRNQdn4=,tag:oG/xfbEDRLpbgWt/WG+98g==,type:str]
    notiz_unencrypted: öffentlich
キー:
    value: ENC[AES256_GCM,data:PXgm,iv:pkzxWR7YtRiWWyOhZZquCYYh9R5gZzXPKlmNsltmAVM=,tag:y3X7HdQlbWJUEVywTDGlwA==,type:str]
    "n": ENC[AES256_GCM,data:2CA=,iv:JTux29FVhMRWN0XvZCzqwmsCVvzs89QCORHCZJ1IwYk=,tag:upJhbV9UloaFesOluCU0rQ==,type:int]
ascii:
    plain: ENC[AES256_GCM,data:moKf/QI=,iv:AbrnGcKxLs8h4EfEdgyIHznlZRTro5nXRkOrB2d4Y44=,tag:ksWaxRO/dZ2fSw1UIoE72w==,type:str]
sops:
    age:
        - enc: |
            -----BEGIN AGE ENCRYPTED FILE-----
            YWdlLWVuY3J5cHRpb24ub3JnL3YxCi0+IFgyNTUxOSA5T0dSRE5VVHVFU0IrZTFj
            OThwdFR4TkJyUjJuY1ExWTRIS24wSkFhZndJCmZIWVFQVkk0NlA3cmNUTVl6Q3F5
            VVVNT2VxYXh3TDNEMnpncWVVcnNnR2sKLS0tIGdINDlqWkE2eFhzdFBwcHdHS1JJ
            S0lwUWpzSG03UU4yc0QySVE2Y2Zod1UKAmfGsJLjDRi/ZWhBGhBw8Tol7XHjgQQx
            /d8Hvqfh188dnCUw8zSz4a/TVINHbNJLIJXAaJ1/Gg7QwRLDUeKK0g==
            -----END AGE ENCRYPTED FILE-----
          recipient: age1e2xuas0wksl0zu40m4wdzvltznqestr34kuua82v5gqzgzhsaqhq067evm
    lastmodified: "2026-08-08T22:25:11Z"
    mac: ENC[AES256_GCM,data:Z2f3wuWLGT/390WnM/TuocoDlUBIcU6LmBknyoIKyAOj9nvY7UFXItr+7WbUL9TO3SWOsImJ+Jm03ZdZxzb+DXBRnWbnwY5SiGYSfQwCM/pL35Z7LBNr+TVzSTg8xDAGS4bD5Pz/L2YEb0XGncnsdkMNxS0X9uY9i52Gt0hwS4k=,iv:H6ETwBMiYqgBdkt5oLnbxvH8g4l4/QMuwI9A5vVRYZA=,tag:iQtSslWK8D3OXQbP3N3aYA==,type:str]
    unencrypted_suffix: _unencrypted
    version: 3.13.3
YAML

subtest 'sops-written document with non-ASCII keys (#26 read side)' => sub {
    my $got = eval {
        File::SOPS->decrypt(
            encrypted  => $SOPS_FIXTURE,
            identities => [$SOPS_IDENTITY],
        );
    };

    ok(defined $got, 'decrypts, MAC included')
        or do { diag("died: $@"); return };

    is_deeply(
        $got,
        {
            $K_LATIN1 => {
                $K_PASSW            => $V_UMLAUT,
                'notiz_unencrypted' => $V_OFFEN,
            },
            $K_WIDE => { value => $V_CJK, n => 42 },
            ascii   => { plain => 'hello' },
        },
        'values come back as characters under keys that are not ASCII',
    );

    ok(utf8::is_utf8($got->{$K_LATIN1}{$K_PASSW}),
        'decrypted non-ASCII value is a character string, not UTF-8 bytes');
};

# ----------------------------------------------------------------------------
# 2. The AAD we WRITE is UTF-8 (#26 write side), asserted without sops.
#
# The document is encrypted through the public API, then the ENC value under a
# non-ASCII path is re-authenticated by hand under each candidate AAD encoding.
# Exactly one of them may work, and it has to be the UTF-8 one -- section 1
# establishes that as what sops uses.
# ----------------------------------------------------------------------------

subtest 'AAD written for a non-ASCII path is UTF-8 (#26 write side)' => sub {
    my ($public, $secret) = Crypt::Age->generate_keypair();

    my $doc = eval {
        File::SOPS->encrypt(
            data       => { $K_LATIN1 => { $K_PASSW => $V_UMLAUT } },
            recipients => [$public],
            format     => 'yaml',
        );
    };
    ok(defined $doc, 'encrypting under a Latin-1-range key succeeds')
        or do { diag("died: $@"); return };

    # The emitter's own encoding of the key, which is what the AAD has to agree
    # with. Note \Q..\E is no use here: it suppresses the \x escapes.
    my $key_on_the_wire = "caf\xc3\xa9:";
    like($doc, qr/\Q$key_on_the_wire\E/,
        'the key itself is written to the document as UTF-8');

    my ($data, $metadata) = File::SOPS::Format::YAML->parse($doc);
    my $data_key = File::SOPS::Backend::Age->decrypt_data_key(
        age_keys   => $metadata->age,
        identities => [$secret],
    );

    my $enc = File::SOPS::Encrypted->parse($data->{$K_LATIN1}{$K_PASSW});
    ok($enc, 'value was encrypted');

    # Straight at the GCM primitive, deliberately bypassing decrypt_bytes: the
    # claim under test is which BYTES were authenticated, and decrypt_bytes
    # takes characters and does the encoding itself, so asking it would only
    # confirm that it agrees with its own twin. sops has nothing but these
    # bytes.
    is(
        gcm_decrypt_verify('AES', $data_key, $enc->iv,
            "caf\xc3\xa9:passw\xc3\xb6rd:", $enc->data, $enc->tag),
        "h\xc3\xa4mlich",
        'the AAD on the wire is UTF-8, and so is the plaintext',
    );

    is(
        gcm_decrypt_verify('AES', $data_key, $enc->iv,
            "caf\xe9:passw\xf6rd:", $enc->data, $enc->tag),
        undef,
        'and it is not Latin-1',
    );
};

# ----------------------------------------------------------------------------
# The AAD rule has to be UNCONDITIONAL, not "encode if the scalar carries the
# UTF-8 flag", and this is the case that shows why.
#
# For a key whose characters are all below U+0100 that flag is an internal
# storage detail: "caf\x{e9}" may be held as one byte or as two, and Perl
# considers both the same string. The emitters do not care either -- YAML::XS
# and JSON::MaybeXS write the key as UTF-8 both ways. So a flag-guarded AAD
# authenticated an unflagged key against caf\xe9: while the emitter wrote
# caf\xc3\xa9, and the very next read of our OWN document re-derived the UTF-8
# form and failed the MAC. sops rejected it for the same reason.
# ----------------------------------------------------------------------------

subtest 'AAD does not depend on Perl\'s internal string representation (#26)' => sub {
    my ($public, $secret) = Crypt::Age->generate_keypair();

    my $downgraded = "caf\x{e9}";
    utf8::downgrade($downgraded);
    ok(!utf8::is_utf8($downgraded), 'the key is held as bytes, flag off');
    ok(utf8::is_utf8($K_LATIN1),    'and the same key is also available flagged');
    is($downgraded, $K_LATIN1,      'Perl considers the two the same string');

    my %doc;
    for my $case (['downgraded', $downgraded], ['upgraded', $K_LATIN1]) {
        my ($name, $key) = @$case;

        $doc{$name} = File::SOPS->encrypt(
            data       => { $key => 'secret' },
            recipients => [$public],
            format     => 'yaml',
        );

        # The whole point: this must verify, and it is our own output.
        my $got = eval {
            File::SOPS->decrypt(encrypted => $doc{$name}, identities => [$secret]);
        };
        is_deeply($got, { $K_LATIN1 => 'secret' },
            "$name: our own document verifies and round-trips")
            or diag("died: $@");
    }
};

subtest 'a key above U+00FF no longer kills the encoder (#26)' => sub {
    my ($public, $secret) = Crypt::Age->generate_keypair();

    my $data = { $K_WIDE => { $K_WIDE => $V_CJK } };
    my $doc  = eval {
        File::SOPS->encrypt(
            data       => $data,
            recipients => [$public],
            format     => 'yaml',
        );
    };

    ok(defined $doc, 'no "Wide character in subroutine entry"')
        or do { diag("died: $@"); return };

    is_deeply(
        File::SOPS->decrypt(encrypted => $doc, identities => [$secret]),
        $data,
        'and the document verifies and round-trips',
    );
};

# ----------------------------------------------------------------------------
# 3. The boundary rule (#12): what goes in as characters comes back as
#    characters, through every entry point.
# ----------------------------------------------------------------------------

subtest 'encrypt/decrypt is an identity for non-ASCII (#12)' => sub {
    my ($public, $secret) = Crypt::Age->generate_keypair();

    my $data = {
        greeting => chars("gr\x{fc}\x{df}e"),
        cjk      => $V_CJK,
        emoji    => $V_EMOJI,
        nested   => { $K_LATIN1 => $V_UMLAUT },
        ascii    => 'plain',
        number   => 42,
    };

    for my $format (qw(yaml json)) {
        my $doc = File::SOPS->encrypt(
            data       => $data,
            recipients => [$public],
            format     => $format,
        );
        my $got = File::SOPS->decrypt(
            encrypted  => $doc,
            identities => [$secret],
        );
        is_deeply($got, $data, "$format: decrypted structure equals the original");
    }
};

subtest 'decrypt_file does not double-encode (#12)' => sub {
    my ($public, $secret) = Crypt::Age->generate_keypair();
    my $dir = tempdir(CLEANUP => 1);

    my $data = { greeting => chars("gr\x{fc}\x{df}e"), nested => { $K_LATIN1 => $V_CJK } };

    for my $format (qw(yaml json)) {
        my $enc_file = "$dir/secrets.$format";
        my $out_file = "$dir/plain.$format";

        open my $fh, '>:raw', $enc_file or die $!;
        print $fh File::SOPS->encrypt(
            data       => $data,
            recipients => [$public],
            format     => $format,
        );
        close $fh;

        File::SOPS->decrypt_file(
            input      => $enc_file,
            output     => $out_file,
            identities => [$secret],
        );

        open my $in, '<:raw', $out_file or die $!;
        my $bytes = do { local $/; <$in> };
        close $in;

        # "gr\xc3\xbc\xc3\x9fe" is UTF-8 for grüße. The double-encoded form the
        # bug produced is "gr\xc3\x83\xc2\xbc..." -- the leading \xc3\x83 is the
        # signature, and it must not appear.
        unlike($bytes, qr/\xc3\x83/,
            "$format: no double-encoded UTF-8 in the decrypted file");

        my $back = $format eq 'json'
            ? JSON::MaybeXS->new(utf8 => 1)->decode($bytes)
            : YAML::XS::Load($bytes);
        is_deeply($back, $data, "$format: file round-trips to the original characters");
    }
};

subtest 'extract returns characters and takes a character path (#12)' => sub {
    my ($public, $secret) = Crypt::Age->generate_keypair();
    my $dir = tempdir(CLEANUP => 1);

    my $file = "$dir/secrets.yaml";
    open my $fh, '>:raw', $file or die $!;
    print $fh File::SOPS->encrypt(
        data       => { $K_LATIN1 => { $K_WIDE => $V_UMLAUT } },
        recipients => [$public],
        format     => 'yaml',
    );
    close $fh;

    my $got = File::SOPS->extract(
        file       => $file,
        path       => "[\"$K_LATIN1\"][\"$K_WIDE\"]",
        identities => [$secret],
    );

    is($got, $V_UMLAUT, 'extracted value is the character string that went in');
    ok(utf8::is_utf8($got), 'and it carries the UTF-8 flag, i.e. it is not bytes');
};

# ----------------------------------------------------------------------------
# 4. The two guarantees that keep the #12 fix from being a break in the other
#    direction: the wire bytes do not move, and a caller who hands us UTF-8
#    bytes instead of characters still writes the same file.
# ----------------------------------------------------------------------------

subtest 'wire bytes are unchanged: characters and UTF-8 bytes encrypt alike' => sub {
    my ($public, $secret) = Crypt::Age->generate_keypair();

    my $chars = chars("gr\x{fc}\x{df}e");
    my $bytes = $chars;
    utf8::encode($bytes);
    ok(!utf8::is_utf8($bytes), 'the byte-string input really is bytes');

    my %plaintext;
    for my $case (['chars', $chars], ['bytes', $bytes]) {
        my ($name, $value) = @$case;

        my $doc = File::SOPS->encrypt(
            data       => { greeting => $value },
            recipients => [$public],
            format     => 'yaml',
        );
        my ($data, $metadata) = File::SOPS::Format::YAML->parse($doc);
        my $data_key = File::SOPS::Backend::Age->decrypt_data_key(
            age_keys   => $metadata->age,
            identities => [$secret],
        );
        $plaintext{$name} = File::SOPS::Encrypted->parse($data->{greeting})
            ->decrypt_bytes(key => $data_key, aad => 'greeting:');
    }

    is($plaintext{chars}, "gr\xc3\xbc\xc3\x9fe",
        'a character string is written to the wire as UTF-8');
    is($plaintext{bytes}, $plaintext{chars},
        'and a caller passing UTF-8 bytes produces identical wire bytes');
};

subtest 'type:bytes is not decoded' => sub {
    my $key = "\x00" x 32;

    # 0x80 alone is not valid UTF-8, so a decode attempt would either mangle it
    # or leave it -- either way the point is that nothing tries.
    my $binary = "\x89PNG\x0d\x0a\x1a\x0a\x80\xff";

    my $enc = File::SOPS::Encrypted->encrypt_value(
        value => $binary,
        key   => $key,
        aad   => 'blob:',
        type  => 'bytes',
    );

    my $got = $enc->decrypt_value(key => $key, aad => 'blob:');
    is($got, $binary, 'binary type comes back byte-for-byte');
    ok(!utf8::is_utf8($got), 'and is not upgraded to characters');
};

done_testing;
