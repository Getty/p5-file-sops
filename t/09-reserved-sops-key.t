#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);

use File::SOPS;
use File::SOPS::Format::YAML;
use File::SOPS::Format::JSON;
use Crypt::Age;

# ----------------------------------------------------------------------------
# The top-level `sops` key is RESERVED (karr #18).
#
# Two failures that looked unrelated are one rule in the reference
# implementation. Measured against sops 3.13.3, all three of these are refused
# identically -- exit code 203, before anything is encrypted:
#
#   * `sops -e` on a plaintext file containing a top-level `sops:` entry
#   * `sops -e` on a file that is already encrypted
#   * `sops -e -i` on a file that is already encrypted
#
#   The file you have provided contains a top-level entry called 'sops', or for
#   flat file formats top-level entries starting with 'sops_'. This is
#   generally due to the file already being encrypted. SOPS uses a top-level
#   entry called 'sops' to store the metadata required to decrypt the file. For
#   this reason, SOPS can not encrypt files that already contain such an entry.
#
# File::SOPS did neither check, and both failures were silent:
#
#   * serialize assigns the metadata into `sops` unconditionally, so a user
#     value under that name was overwritten by the metadata section. The
#     digest, computed before serialization, covered the user's value -- so the
#     document that came out failed its own MAC on the very next read.
#   * encrypt_file parses the input first, and parse SPLITS OFF the sops
#     section. So an already-encrypted file arrived at encrypt as a plain tree
#     of ENC[...] strings with no metadata, and every one of them was encrypted
#     a second time. That succeeded, and produced a file whose values are
#     doubly-wrapped ciphertext -- readable only by decrypting twice, and
#     silently useless to anything expecting the original values.
#
# Both must be loud. Nothing here needs the sops binary; t/04-interop.t pins
# the Go side of the same rule.
# ----------------------------------------------------------------------------

my ($public, $secret) = Crypt::Age->generate_keypair();
my $tempdir = tempdir(CLEANUP => 1);

# ----------------------------------------------------------------------------
# 1. encrypt() must refuse a data structure carrying a top-level `sops` key.
# ----------------------------------------------------------------------------

for my $format (qw(yaml json)) {
    my $err = do {
        local $@;
        eval {
            File::SOPS->encrypt(
                data       => { sops => 'my own value', other => 'kept' },
                recipients => [$public],
                format     => $format,
            );
        };
        $@;
    };

    like(
        $err,
        qr/top-level 'sops' entry/,
        "[$format] encrypt refuses a data structure with a top-level sops key"
    );
}

# The reason it has to be refused rather than merged: the digest is computed
# over the user's value and the serializer then throws that value away, so the
# document contradicts its own MAC. Pin that consequence directly, so a future
# "just merge the two" fix cannot pass this file.
{
    my $data = { sops => 'my own value', other => 'kept' };

    my $metadata = File::SOPS::Metadata->new;
    $metadata->lastmodified('2026-01-10T12:00:00Z');

    my $yaml = do {
        local $@;
        eval {
            File::SOPS::Format::YAML->serialize(data => $data, metadata => $metadata);
        };
    };

    # Whatever the serializer does, it must not silently return a document in
    # which the user's value has been replaced by the metadata section.
    ok(
        !defined $yaml || $yaml !~ /^other: kept$/m || $yaml =~ /my own value/,
        'serialization never silently drops a user value stored under "sops"'
    );
}

# ----------------------------------------------------------------------------
# 2. encrypt_file() must refuse input that is already encrypted.
# ----------------------------------------------------------------------------

for my $format (qw(yaml json)) {
    my $encrypted = File::SOPS->encrypt(
        data       => { secret => 'value', n => 42 },
        recipients => [$public],
        format     => $format,
    );

    my $enc_file = "$tempdir/already.$format";
    open my $fh, '>:raw', $enc_file or die $!;
    print $fh $encrypted;
    close $fh;

    my $err = do {
        local $@;
        eval {
            File::SOPS->encrypt_file(
                input      => $enc_file,
                output     => "$tempdir/twice.$format",
                recipients => [$public],
            );
        };
        $@;
    };

    like(
        $err,
        qr/top-level 'sops' entry/,
        "[$format] encrypt_file refuses an already-encrypted input file"
    );

    ok(
        !-e "$tempdir/twice.$format",
        "[$format] and writes no output file"
    );

    # The specific damage, reproduced through the parts encrypt_file used to
    # chain together. It is not "the file looks odd": parse splits the sops
    # section off and encrypt builds a NEW one, so the doubly-wrapped file
    # carries a new data key and NOT the one its inner ENC[...] strings were
    # encrypted with. Decrypting it returns those strings, and nothing left in
    # the file can decrypt them.
    my $format_class = $format eq 'json'
        ? 'File::SOPS::Format::JSON' : 'File::SOPS::Format::YAML';
    my ($stripped, $dropped_metadata) = $format_class->parse($encrypted);
    ok($dropped_metadata,
        "[$format] parse splits the sops section off, which is why encrypt cannot see it");

    my $twice = File::SOPS->encrypt(
        data => $stripped, recipients => [$public], format => $format,
    );
    my $inner = File::SOPS->decrypt(
        encrypted => $twice, identities => [$secret], format => $format,
    );
    like($inner->{secret}, qr/\AENC\[/,
        "[$format] double encryption yields ciphertext of ciphertext");

    my $keys_in_file = () = $twice =~ /BEGIN AGE ENCRYPTED FILE/g;
    is($keys_in_file, 1,
        "[$format] and only ONE data key survives, so the inner values are lost");
}

# ----------------------------------------------------------------------------
# 3. encrypt_file() must refuse in-place re-encryption too -- the case that
#    destroys the original, because output defaults to input.
# ----------------------------------------------------------------------------

{
    my $encrypted = File::SOPS->encrypt(
        data       => { secret => 'value' },
        recipients => [$public],
        format     => 'yaml',
    );

    my $file = "$tempdir/inplace.yaml";
    open my $fh, '>:raw', $file or die $!;
    print $fh $encrypted;
    close $fh;

    my $err = do {
        local $@;
        eval { File::SOPS->encrypt_file(input => $file, recipients => [$public]) };
        $@;
    };

    like($err, qr/top-level 'sops' entry/,
        'encrypt_file refuses in-place re-encryption of an encrypted file');

    my $after = do { open my $in, '<:raw', $file or die $!; local $/; <$in> };
    is($after, $encrypted, 'and the original file is untouched');
}

# ----------------------------------------------------------------------------
# 4. rotate() is the supported way to re-key an encrypted file, and must keep
#    working -- the guard above must not catch it.
# ----------------------------------------------------------------------------

{
    my $encrypted = File::SOPS->encrypt(
        data       => { secret => 'value' },
        recipients => [$public],
        format     => 'yaml',
    );

    my $file = "$tempdir/rotate.yaml";
    open my $fh, '>:raw', $file or die $!;
    print $fh $encrypted;
    close $fh;

    my $ok = eval { File::SOPS->rotate(file => $file, identities => [$secret]); 1 };
    ok($ok, 'rotate still works on an encrypted file') or diag("died: $@");

    my $after = do { open my $in, '<:raw', $file or die $!; local $/; <$in> };
    is_deeply(
        File::SOPS->decrypt(encrypted => $after, identities => [$secret]),
        { secret => 'value' },
        'and the rotated file still holds the original value'
    );
}

done_testing;
