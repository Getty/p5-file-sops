#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurper qw(write_binary);
use Scalar::Util qw(dualvar);

use File::SOPS;
use Crypt::Age;
use lib 't/lib';
use SopsBin qw(find_sops_bin);

# docs/adr/0074 (k216), the exception. The string 'Inf', '-Inf' or 'NaN' that
# was then used as a number (`my $x = $s + 0`) is POK+NOK, with a PV equal to
# the text perl writes for that very number: the trace of a numification, not a
# string half of its own. It was refused as "a non-finite float that also
# states a string half", also on perl >= 5.36; it is now written as a float and
# comes back as one. dualvar(Inf, 'banana') -- a PV that differs -- stays refused.
#
# Literal assertions: the type read off the wire, the value read back, and for
# YAML what sops -d prints (.inf, -.inf, .nan). JSON gets no sops -d: sops
# cannot print a non-finite float into JSON (marshal error, bare 9**9**9 too).

my $sops_bin = find_sops_bin();

my ($public, $secret) = Crypt::Age->generate_keypair();
my $tempdir = tempdir(CLEANUP => 1);
write_binary("$tempdir/key.txt", $secret);
$ENV{SOPS_AGE_KEY_FILE} = "$tempdir/key.txt";

my $INF = 9**9**9;

# [ string, check on the value read back, what sops -d prints in YAML ]
my @cases = (
    [ 'Inf',  sub { $_[0] == $INF  },  '.inf'  ],
    [ '-Inf', sub { $_[0] == -$INF },  '-.inf' ],
    [ 'NaN',  sub { $_[0] != $_[0] },  '.nan'  ],
);

sub wire_type_of {
    my ($document, $key) = @_;
    return $document =~ /\Q$key\E"?\s*:\s*"?ENC\[[^\]]*?type:(\w+)\]/ ? $1 : undef;
}

for my $format (qw( yaml json )) {
    subtest "[$format] a used-as-number non-finite string is a float" => sub {
        for my $case (@cases) {
            my ($text, $check, $sops_text) = @$case;
            my $label = "[$format] '$text'";

            my $s = $text;
            my $n = $s + 0;     # POK+NOK now
            my $document = eval {
                File::SOPS->encrypt(data => { v => $s, keep => 'x' },
                    recipients => [$public], format => $format);
            };
            ok(defined $document, "$label: written, no croak") or do { diag($@); next };
            is(wire_type_of($document, 'v'), 'float', "$label: type:float on the wire");

            my $back = eval {
                File::SOPS->decrypt(encrypted => $document,
                    identities => [$secret], format => $format);
            };
            ok($back, "$label: decrypts, the MAC closes") or do { diag($@); next };
            ok($check->($back->{v}), "$label: reads back as the non-finite float (got $back->{v})");
            is($back->{keep}, 'x', "$label: neighbour untouched");

            next unless $format eq 'yaml';
            SKIP: {
                skip 'no sops binary (set SOPS_BIN): the sops side of this case did NOT run', 2
                    unless $sops_bin;
                my $file = "$tempdir/doc.yaml";
                write_binary($file, $document);
                my $out = `$sops_bin -d $file 2>&1`;
                is($? >> 8, 0, "$label: sops -d accepts it, MAC verified") or diag($out);
                like($out, qr/^v: \Q$sops_text\E$/m, "$label: sops -d prints $sops_text");
            }
        }
    };
}

subtest 'a PV that differs from the infinity stays refused' => sub {
    for my $format (qw( yaml json )) {
        my $err = do {
            local $@;
            eval {
                File::SOPS->encrypt(data => { v => dualvar($INF, 'banana') },
                    recipients => [$public], format => $format);
                1;
            } ? '' : "$@";
        };
        like($err, qr/non-finite|string half/i, "[$format] dualvar(Inf, 'banana') is refused");
    }
};

done_testing;
