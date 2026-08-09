#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use Config;

use File::SOPS;
use File::SOPS::Encrypted;
use File::SOPS::Metadata;
use JSON::MaybeXS;
use YAML::XS ();
use Crypt::Age;

# ----------------------------------------------------------------------------
# The SOPS int type is Go's int64, and nothing wider (karr #28).
#
# Measured against sops 3.13.3, one key per document, both formats:
#
#   range                         YAML (yaml.v3)              JSON (encoding/json)
#   -----------------------------------------------------------------------------
#   [-2^63, 2^63-1]               type:int, exact             type:int, exact
#   [2^63, 2^64-1]                REFUSED: exit 23,           type:float, truncated
#                                 "Cannot walk value,         to float64
#                                  unknown type: uint64"
#   > 2^64-1 / < -2^63            type:float, truncated       type:float, truncated
#
# So sops NEVER writes type:int outside int64, in either format, and reading one
# fails in Go with "strconv.Atoi: value out of range".
#
# Perl's IV/UV is unsigned-capable, so a Perl integer can sit in [2^63, 2^64-1]
# where Go's int cannot. File::SOPS wrote those as type:int with their exact
# decimal, and the file was then unreadable:
#
#   $ sops -d
#   Error decrypting tree: Error walking tree: Could not decrypt value:
#   strconv.Atoi: parsing "12345678901234567890": value out of range   (exit 25)
#
# Unencrypted leaves are worse, because they reach the document verbatim:
#
#   YAML: Cannot walk value, unknown type: uint64                      (exit 25)
#   JSON: MAC mismatch                                                 (exit 51)
#         (Go re-derives 12345678901234567000 from the float64 it parsed,
#          while we hashed the exact 12345678901234567890)
#
# There is no SOPS wire form that preserves such an integer, so it is refused
# rather than silently truncated to a float64 the way sops's JSON store does.
# A caller who needs the digits passes them as a STRING, which is type:str and
# round-trips exactly through both implementations.
#
# No sops binary needed; t/04-interop.t pins the Go half.
# ----------------------------------------------------------------------------

plan skip_all => "needs a 64-bit-integer Perl (ivsize=$Config{ivsize})"
    unless $Config{ivsize} >= 8;

my ($public, $secret) = Crypt::Age->generate_keypair();

my $INT64_MAX = 9223372036854775807;
my $INT64_MIN = -9223372036854775807 - 1;

# ----------------------------------------------------------------------------
# 1. The boundary itself must still work. These are the widest values sops
#    writes as type:int, so refusing them would be a different bug.
# ----------------------------------------------------------------------------

for my $edge ($INT64_MAX, $INT64_MIN, 0, 42, -1) {
    is(File::SOPS::Encrypted->detect_type($edge), 'int', "detect_type($edge) is int");
    is(File::SOPS::Encrypted->value_to_bytes($edge), "$edge",
        "value_to_bytes($edge) is its exact decimal");

    my $enc = eval {
        File::SOPS->encrypt(
            data => { v => $edge }, recipients => [$public], format => 'yaml',
        );
    };
    ok($enc, "encrypt accepts $edge") or diag("died: $@");
    like($enc, qr/type:int\]/, "and writes it as type:int") if $enc;
}

# ----------------------------------------------------------------------------
# 2. An integer above int64 must be refused, not written.
#
#    Both the encrypted case (which produced a file sops exits 25 on) and the
#    unencrypted one (exit 25 in YAML, MAC mismatch in JSON).
# ----------------------------------------------------------------------------

my $UV_BIG = 12345678901234567890;   # 2^63 < x < 2^64: a Perl UV, not a Go int

is(File::SOPS::Encrypted->detect_type($UV_BIG), 'int',
    'a Perl UV above int64 is still what Perl holds it as');

for my $format (qw(yaml json)) {
    for my $key (qw(v v_unencrypted)) {
        my $err = do {
            local $@;
            eval {
                File::SOPS->encrypt(
                    data       => { $key => $UV_BIG },
                    recipients => [$public],
                    format     => $format,
                );
            };
            $@;
        };

        like($err, qr/int64/,
            "[$format] encrypt refuses an integer above int64 under '$key'");
        unlike($err, qr/\Q$UV_BIG\E/,
            "[$format] and the error does not quote the value back");
    }
}

# The same refusal from the value-level API, which is where a direct caller
# would hit it.
{
    my $err = do {
        local $@;
        eval {
            File::SOPS::Encrypted->encrypt_value(
                value => $UV_BIG, key => "\0" x 32, aad => 'v:',
            );
        };
        $@;
    };
    like($err, qr/int64/, 'encrypt_value refuses an integer above int64');
}

# ----------------------------------------------------------------------------
# 3. A caller who needs the digits passes a string. That is type:str and is
#    written verbatim, which is exactly what sops does with a quoted scalar.
# ----------------------------------------------------------------------------

{
    my $as_string = '12345678901234567890';
    is(File::SOPS::Encrypted->detect_type($as_string), 'str',
        'the same digits as a string are type:str');
    is(File::SOPS::Encrypted->value_to_bytes($as_string), '12345678901234567890',
        'and go to the wire verbatim');

    my $enc = File::SOPS->encrypt(
        data => { v => $as_string }, recipients => [$public], format => 'yaml',
    );
    like($enc, qr/type:str\]/, 'and encrypt writes them');
    is(
        File::SOPS->decrypt(encrypted => $enc, identities => [$secret])->{v},
        $as_string,
        'and they come back with every digit'
    );
}

# ----------------------------------------------------------------------------
# 4. Values ABOVE 2^64 already become NVs in Perl, so they are type:float and
#    take the canonical Go float form. That must not change -- it is what sops
#    writes for the same input.
# ----------------------------------------------------------------------------

{
    my $huge = YAML::XS::Load("v: 123456789012345678901234567890\n")->{v};
    is(File::SOPS::Encrypted->detect_type($huge), 'float',
        'a value above 2^64 is a float, as it is in Go');
    is(File::SOPS::Encrypted->value_to_bytes($huge), '123456789012345680000000000000',
        'and is written in the positional form sops writes');
}

# ----------------------------------------------------------------------------
# 5. READING must not refuse what sops legitimately writes.
#
#    sops's JSON store truncates a big integer to float64 and then writes the
#    RESULT into the document -- 12345678901234567000, which is above int64 but
#    below 2^64, so Perl parses it back as an exact UV. Such a leaf, unencrypted,
#    is part of the digest, and File::SOPS must hash it as those same digits.
#    A blanket range check on value_to_bytes would reject this real sops file.
# ----------------------------------------------------------------------------

{
    my $from_sops = decode_json('{"v": 12345678901234567000}')->{v};
    is(File::SOPS::Encrypted->detect_type($from_sops), 'int',
        'Perl parses a truncated sops float back as an integer');
    is(
        File::SOPS::Encrypted->value_to_bytes($from_sops),
        '12345678901234567000',
        'and value_to_bytes still produces the bytes Go re-derives, without refusing'
    );
}

# ----------------------------------------------------------------------------
# 6. Reading a type:int whose plaintext Go itself refuses must be loud.
#
#    Go stops with "strconv.Atoi: value out of range". File::SOPS ran it through
#    int(), which is exact up to 2^64-1 on this Perl and silently lossy above --
#    so the same document gave one answer here and no answer at all in Go.
#    Hand-built fixtures: no producer writes these, which is the point.
# ----------------------------------------------------------------------------

{
    my $key = "\1" x 32;

    for my $plaintext ('12345678901234567890',
                       '123456789012345678901234567890',
                       '-9223372036854775809') {
        # Built with an explicit type, which overrides the label and not the
        # bytes -- the documented way to reproduce a foreign producer's value.
        my $enc = File::SOPS::Encrypted->encrypt_value(
            value => $plaintext, key => $key, aad => 'v:', type => 'int',
        );
        is($enc->type, 'int', "fixture for $plaintext is labelled int");

        my $err = do {
            local $@;
            eval { $enc->decrypt_value(key => $key, aad => 'v:') };
            $@;
        };
        like($err, qr/int64|out of range/,
            "decrypting type:int with plaintext out of int64 range is refused");

        # The raw plaintext stays reachable, so the value is not lost.
        is($enc->decrypt_bytes(key => $key, aad => 'v:'), $plaintext,
            'and decrypt_bytes still returns the authenticated plaintext');
    }

    # An in-range value through the same fixture path must still decrypt.
    my $ok = File::SOPS::Encrypted->encrypt_value(
        value => '9223372036854775807', key => $key, aad => 'v:', type => 'int',
    );
    is($ok->decrypt_value(key => $key, aad => 'v:'), 9223372036854775807,
        'int64 max still decrypts');
}

done_testing;
