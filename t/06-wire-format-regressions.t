#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use File::SOPS;
use File::SOPS::Format::YAML;
use File::SOPS::Metadata;
use JSON::MaybeXS;
use Crypt::Age;

# ----------------------------------------------------------------------------
# Regressions for three wire-format bugs that were all invisible to the rest
# of the suite, because each one was self-consistent: File::SOPS produced a
# file that File::SOPS itself was happy with. Only the real `sops` binary
# disagreed -- and t/04-interop.t skips unless SOPS_BIN is set, so for two
# releases the suite reported "All tests successful" while Perl->sops was
# broken in every YAML case.
#
# Everything below therefore runs WITHOUT the sops binary, on purpose. These
# are the tests that had to fail when the binary was absent.
# ----------------------------------------------------------------------------

my ($public, $secret) = Crypt::Age->generate_keypair();

# ----------------------------------------------------------------------------
# 1. lastmodified must be emitted as a QUOTED YAML scalar.
#
# YAML::XS emits plain scalars for anything its resolver does not recognise.
# $YAML::XS::QuoteNumericStrings (on by default) already covers numbers,
# booleans and nulls, but the resolver has no notion of timestamps, so an
# RFC3339 lastmodified came out bare. Go's yaml.v3 resolves a bare RFC3339
# scalar to time.Time, and sops rejects the entire file before decrypting
# anything:
#
#   'lastmodified' expected type 'string', got unconvertible type 'time.Time'
#
# JSON is structurally immune (no timestamp type, strings always quoted),
# which is exactly why JSON interop passed while every YAML case failed.
# ----------------------------------------------------------------------------

{
    my $metadata = File::SOPS::Metadata->new;
    $metadata->lastmodified('2026-01-10T12:00:00Z');

    my $yaml = File::SOPS::Format::YAML->serialize(
        data     => { secret => 'ENC[AES256_GCM,data:x,iv:y,tag:z,type:str]' },
        metadata => $metadata,
    );

    like(
        $yaml,
        qr/^\s+lastmodified: "2026-01-10T12:00:00Z"$/m,
        'lastmodified is emitted as a quoted string (Go would type a bare '
            . 'RFC3339 scalar as time.Time and reject the file)'
    );

    unlike(
        $yaml,
        qr/^\s+lastmodified: 2026-01-10T12:00:00Z\s*$/m,
        'lastmodified is never emitted bare'
    );
}

# The quoting is a post-process on the dumped text, so it must be scoped to
# the sops block. A user key called "lastmodified" in the DATA section must
# not be rewritten -- that would corrupt user data.
{
    my $metadata = File::SOPS::Metadata->new;
    $metadata->lastmodified('2026-01-10T12:00:00Z');

    my $yaml = File::SOPS::Format::YAML->serialize(
        data => {
            lastmodified => 'user-owned-value',
            # sorts after "sops", so it also proves the sops block is
            # correctly closed at the next column-0 key
            zzz_after_sops => 'untouched',
        },
        metadata => $metadata,
    );

    like(
        $yaml,
        qr/^lastmodified: user-owned-value$/m,
        'a user data key named lastmodified is left alone (quoting is scoped '
            . 'to the sops block)'
    );

    like(
        $yaml,
        qr/^zzz_after_sops: untouched$/m,
        'data keys sorting after "sops" are left alone'
    );
}

# ----------------------------------------------------------------------------
# 2. A false boolean must be encrypted, not silently written as plaintext ''.
#
# JSON::PP::Boolean overloads eq, and JSON->false eq '' is TRUE -- even though
# the same object stringifies to '0'. _encrypt_tree's "SOPS doesn't encrypt
# empty values" guard therefore swallowed every false boolean and wrote it to
# the file as a bare '', in plaintext. _compute_mac had already hashed 'False'
# for that node, so the document then failed its OWN MAC check on the next
# read. sops encrypts false as type:bool with plaintext 'False'.
# ----------------------------------------------------------------------------

for my $format (qw(yaml json)) {
    my $encrypted = File::SOPS->encrypt(
        data       => { flag_false => JSON->false, flag_true => JSON->true },
        recipients => [$public],
        format     => $format,
    );

    unlike(
        $encrypted,
        qr/flag_false"?\s*:\s*(''|""|,|\s*$)/m,
        "[$format] false boolean is not written as an empty plaintext value"
    );

    like(
        $encrypted,
        qr/flag_false"?\s*:\s*"?ENC\[AES256_GCM,[^\]]*type:bool\]/,
        "[$format] false boolean is encrypted as type:bool"
    );

    # The real payoff: this is what actually broke. MAC verification of a
    # self-produced file failed whenever the document contained a false.
    my $decrypted = eval {
        File::SOPS->decrypt(
            encrypted  => $encrypted,
            identities => [$secret],
            format     => $format,
        );
    };
    is($@, '', "[$format] document containing a false boolean passes its own MAC");

    isa_ok($decrypted->{flag_false}, 'JSON::PP::Boolean',
        "[$format] decrypted false");
    ok(!$decrypted->{flag_false}, "[$format] false survives the round trip as false");
    ok($decrypted->{flag_true},   "[$format] true survives the round trip as true");
}

# Same bug, one level down: a false inside an array.
{
    my $encrypted = File::SOPS->encrypt(
        data       => { list => [ 'a', JSON->false, 'b' ] },
        recipients => [$public],
        format     => 'yaml',
    );

    my $decrypted = eval {
        File::SOPS->decrypt(
            encrypted => $encrypted, identities => [$secret], format => 'yaml',
        );
    };
    is($@, '', 'array containing a false boolean passes its own MAC');
    ok(!$decrypted->{list}[1], 'false inside an array survives as false');
}

# ----------------------------------------------------------------------------
# 3. The string 'false' must serialize to 'False', not 'True'.
#
# Both bool serializers ended in a bare Perl truthiness fallback:
#
#   ($value eq 'true' || $value eq '1' || $value) ? 'True' : 'False'
#
# The non-empty string 'false' is truthy in Perl, so it fell through to
# 'True'. The bug was present identically in BOTH twins
# (File::SOPS::Encrypted::_serialize_value, which produces the ciphertext, and
# File::SOPS::_value_to_bytes, which produces the MAC digest input), which is
# precisely why it never showed up as a MAC failure: the ciphertext and the
# MAC were consistently wrong together.
#
# The round-trip assertion below covers the ciphertext; the MAC assertion
# covers the twin. If only one twin were fixed, the MAC check would fail.
# ----------------------------------------------------------------------------

{
    my $key = "\x01" x 32;

    my %expected = (
        'true'  => 1,
        'false' => 0,
    );

    for my $literal (sort keys %expected) {
        my $enc = File::SOPS::Encrypted->encrypt_value(
            value => $literal, key => $key, aad => 'a:',
        );
        my $back = $enc->decrypt_value(key => $key, aad => 'a:');

        is(!!$back, !!$expected{$literal},
            "string '$literal' round-trips to $literal, not its opposite");
    }
}

{
    # Exercises both twins at once: _serialize_value builds the ciphertext,
    # _value_to_bytes builds the MAC input. Disagreement => MAC failure.
    my $encrypted = File::SOPS->encrypt(
        data       => { flag => 'false' },
        recipients => [$public],
        format     => 'yaml',
    );

    my $decrypted = eval {
        File::SOPS->decrypt(
            encrypted => $encrypted, identities => [$secret], format => 'yaml',
        );
    };
    is($@, '', "the string 'false' hashes and encrypts consistently (twins agree)");
    ok(!$decrypted->{flag}, "the string 'false' does not become true");
}

done_testing;
