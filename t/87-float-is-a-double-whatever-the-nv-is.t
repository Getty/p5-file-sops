#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;

use File::SOPS::Encrypted;
use File::SOPS::Format::JSON;
use File::SOPS::Format::YAML;

# ----------------------------------------------------------------------------
# A float on the wire is a float64, so what this distribution writes and reads
# for one does not depend on the width of the perl's NV. A perl built with
# -Duselongdouble holds 3.14 and the double nearest 3.14 as two numbers, and
# stringifies the double with 18 digits; GitHub issue 2. On a double perl every
# assertion here holds trivially, which is the point: the answer is the same.
# ----------------------------------------------------------------------------

sub dbl { unpack('d', pack('d', $_[0])) }

subtest 'the shortest digits of the double, not of the NV' => sub {
    for my $row (
        [ 3.14,   '3.14'       ],
        [ 1.5e-7, '0.00000015' ],
        [ 0.1,    '0.1'        ],
        [ 1 / 3,  '0.3333333333333333' ],
    ) {
        my ($literal, $bytes) = @$row;
        is(File::SOPS::Encrypted->value_to_bytes(dbl($literal)), $bytes,
            "[$bytes] from the double");
        is(File::SOPS::Encrypted->value_to_bytes($literal), $bytes,
            "[$bytes] from the NV the literal is");
    }
    is(File::SOPS::Encrypted->value_to_bytes(dbl(dbl(0.1) + dbl(0.2))),
        '0.30000000000000004', 'the 17-digit double');
};

subtest 'a plaintext is read as the double' => sub {
    my $key = "\x02" x 32;
    for my $text ('3.14', '1.5e-07', '0.30000000000000004') {
        my $enc = File::SOPS::Encrypted->encrypt_value(
            value => dbl($text), key => $key, type => 'float');
        my $back = $enc->decrypt_value(key => $key);
        is(unpack('H*', pack('d', $back)), unpack('H*', pack('d', $text)),
            "[$text] bit-identical to the double it spells");
        is($enc->decrypt_bytes(key => $key), $text eq '1.5e-07' ? '0.00000015' : $text,
            "[$text] and its plaintext is the shortest form");
    }
};

subtest 'a plain float is emitted as the shortest digits' => sub {
    my $value = dbl(dbl(0.1) + dbl(0.2));
    my $json  = File::SOPS::Format::JSON->emit({ v => $value });
    like($json, qr/0\.30000000000000004(?!\d)/, 'JSON');
    my $yaml = File::SOPS::Format::YAML->emit({ v => $value });
    like($yaml, qr/^v: 0\.30000000000000004$/m, 'YAML');
};

subtest 'a YAML float literal stays a float' => sub {
    for my $source ('2.0', '0.0', '-0.0', '1.5') {
        my ($data) = File::SOPS::Format::YAML->parse("v: $source\n");
        is(File::SOPS::Encrypted->detect_type($data->{v}), 'float', "[$source] float");
    }
};

subtest 'overflow is the double\'s' => sub {
    my ($data) = File::SOPS::Format::YAML->parse("v: 1e400\nw: 1.5\n");
    is(File::SOPS::Encrypted->detect_type($data->{v}), 'str', '1e400 is a string, as Go keeps it');
    is(File::SOPS::Encrypted->value_to_bytes(dbl(1e400)), '+Inf', 'a wider NV past the double range is +Inf');
};

done_testing;
