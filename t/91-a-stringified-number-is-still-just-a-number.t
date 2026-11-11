#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurper qw(write_binary);
use Scalar::Util qw(dualvar);
use B ();

use File::SOPS;
use Crypt::Age;
use lib 't/lib';
use SopsBin qw(find_sops_bin);

# k216 (Perl 5.022 floor). Before Perl 5.36 the mere act of stringifying a
# number -- `my $s = "$n"` -- sets the PUBLIC SVf_POK, so a number that was
# only ever logged looks like one that carries a string half of its own. A
# number has an own string half only when its PV DIFFERS from the text this
# perl writes for exactly that number (the PV a stringify leaves behind IS that
# text); anything else is the bare number and must write the same bytes, with
# the same type, as the bare number: no croak, and the MAC still closes.
#
# Perl >= 5.36 no longer sets the public POK on `"$n"`, so the old-perl state is
# built without asking the interpreter: Scalar::Util::dualvar($n, "$n") is
# NOK/IOK plus the public POK with the number's own text. The real
# `my $s = "$n"` is covered as well. The counter-probes pin the other side:
# a PV that DIFFERS (dualvar(Inf,'banana'), dualvar(5,'007')) stays refused,
# so the fix cannot have loosened into "any PV is fine".
#
# The format assertions are literal: the type read off the wire, and -- when a
# sops binary resolves -- what `sops -d` itself prints, compared with the bare
# number's. Only the sops parts skip without a binary.

my $sops_bin = find_sops_bin();

my ($public, $secret) = Crypt::Age->generate_keypair();
my $tempdir = tempdir(CLEANUP => 1);
write_binary("$tempdir/key.txt", $secret);
$ENV{SOPS_AGE_KEY_FILE} = "$tempdir/key.txt";

my $INF = 9**9**9;
my $NAN = $INF - $INF;

# [ name, number, wire type, unencrypted slot is writable ]
my @numbers = (
    [ 'int 42',   42,    'int',   1 ],
    [ 'int -7',   -7,    'int',   1 ],
    [ 'float 1.5', 1.5,  'float', 1 ],
    [ '+Inf',     $INF,  'float', 0 ],
    [ '-Inf',     -$INF, 'float', 0 ],
    [ 'NaN',      $NAN,  'float', 0 ],
);

# The states a number can be in. Each builder gets a fresh copy of the number.
my @states = (
    [ 'bare'                      => sub { my $n = $_[0] + 0; $n } ],
    [ 'dualvar(n, "$n")'          => sub { my $n = $_[0]; my $text = "$n"; dualvar($n + 0, $text) } ],
    [ 'explicitly stringified'    => sub { my $n = $_[0]; my $s = "$n"; $n } ],
);

# The number half of a leaf, read off the flags: an int case must carry a real
# IV (IOK, no NOK). Before perl 5.36 `dualvar($n, "$n")` takes the NV path for
# an $n the interpolation has just given a PV, so the state it builds would be
# a float 42, not the int 42 the case claims to test.
sub number_half_is_integer {
    my $flags = B::svref_2object(\$_[0])->FLAGS;
    return ($flags & B::SVf_IOK()) && !($flags & B::SVf_NOK()) ? 1 : 0;
}

sub same_number {
    my ($x, $y) = @_;
    return 0 unless defined $x && defined $y;
    return 1 if $x != $x && $y != $y;       # NaN is the one value != itself
    return $x == $y && "$x" eq "$y";
}

sub wire_type_of {
    my ($document, $key) = @_;
    return $document =~ /\Q$key\E"?\s*:\s*"?ENC\[[^\]]*?type:(\w+)\]/ ? $1 : undef;
}

sub sops_decrypt {
    my ($document, $format) = @_;
    my $file = "$tempdir/doc.$format";
    write_binary($file, $document);
    my $out = `$sops_bin -d $file 2>&1`;
    return ($? >> 8, $out);
}

sub refused {
    my ($data, $format) = @_;
    my $ok = eval {
        File::SOPS->encrypt(data => $data, recipients => [$public], format => $format);
        1;
    };
    return $ok ? undef : ($@ || 'refused');
}

for my $format (qw( yaml json )) {
    subtest "[$format] a stringified number writes what the bare number writes" => sub {
        for my $num (@numbers) {
            my ($name, $value, $type) = @$num;

            my $bare_doc = File::SOPS->encrypt(data => { v => $value, keep => 'x' },
                recipients => [$public], format => $format);
            my ($bare_exit, $bare_sops) = $sops_bin ? sops_decrypt($bare_doc, $format) : ();

            for my $state (@states) {
                my ($state_name, $build) = @$state;
                my $label = "[$format] $name, $state_name";

                my $leaf = $build->($value);
                my $document = eval {
                    File::SOPS->encrypt(data => { v => $leaf, keep => 'x' },
                        recipients => [$public], format => $format);
                };
                ok(defined $document, "$label: written, no croak") or do { diag($@); next };

                ok(number_half_is_integer($leaf), "$label: the number half is an integer")
                    if $type eq 'int';
                is(wire_type_of($document, 'v'), $type, "$label: type:$type on the wire");

                # decrypt checks the MAC: a document whose emitted bytes and
                # digest disagree does not come back.
                my $back = eval {
                    File::SOPS->decrypt(encrypted => $document,
                        identities => [$secret], format => $format);
                };
                ok($back, "$label: decrypts, the MAC closes") or do { diag($@); next };
                ok(same_number($back->{v}, $value), "$label: reads back as the same number")
                    or diag("got " . ($back->{v} // 'undef'));
                is($back->{keep}, 'x', "$label: neighbour untouched");

                SKIP: {
                    skip 'no sops binary (set SOPS_BIN): the sops side of this case did NOT run', 2
                        unless $sops_bin;
                    # Compared with the bare number, not with 0: sops itself
                    # cannot print a non-finite float into JSON (measured:
                    # "unsupported value: +Inf"), bare or not.
                    my ($exit, $out) = sops_decrypt($document, $format);
                    is($exit, $bare_exit, "$label: sops -d exits as it does for the bare number")
                        or diag($out);
                    is($out, $bare_sops, "$label: sops -d prints what it prints for the bare number");
                }
            }
        }
    };
}

# The unencrypted slot reaches the document as the number's own text; only the
# finite numbers have one in both formats.
for my $format (qw( yaml json )) {
    subtest "[$format] and so does the unencrypted slot" => sub {
        for my $num (grep { $_->[3] } @numbers) {
            my ($name, $value) = @$num;
            my $bare_doc = File::SOPS->encrypt(data => { v_unencrypted => $value, keep => 'x' },
                recipients => [$public], format => $format);
            (my $bare_line = $bare_doc) =~ s/\A.*?(v_unencrypted[^\n]*).*\z/$1/s;

            for my $state (@states) {
                my ($state_name, $build) = @$state;
                my $label = "[$format] $name, $state_name";
                my $document = eval {
                    File::SOPS->encrypt(data => { v_unencrypted => $build->($value), keep => 'x' },
                        recipients => [$public], format => $format);
                };
                ok(defined $document, "$label: written") or do { diag($@); next };
                (my $line = $document) =~ s/\A.*?(v_unencrypted[^\n]*).*\z/$1/s;
                is($line, $bare_line, "$label: the same bytes on the wire");

                my $back = eval {
                    File::SOPS->decrypt(encrypted => $document,
                        identities => [$secret], format => $format);
                };
                ok($back && same_number($back->{v_unencrypted}, $value),
                    "$label: decrypts, the MAC closes")
                    or diag($@);
                SKIP: {
                    skip 'no sops binary (set SOPS_BIN): the sops side of this case did NOT run', 1
                        unless $sops_bin;
                    my ($exit, $out) = sops_decrypt($document, $format);
                    is($exit, 0, "$label: sops -d accepts it") or diag($out);
                }
            }
        }
    };
}

# The other side (the unencrypted slot, the only one whose wire carries the
# string half; the encrypted slot has only the number to write): a PV that differs from the number's own text is a real string
# half and stays refused. Without this the fix could be "ignore every PV".
subtest 'a PV that differs from the number stays refused' => sub {
    my @counter = (
        [ 'dualvar(Inf, "banana")', dualvar($INF, 'banana') ],
        [ 'dualvar(5, "007")',      dualvar(5, '007') ],
    );
    for my $format (qw( yaml json )) {
        for my $case (@counter) {
            my ($name, $leaf) = @$case;
            # The unencrypted slot is where the string half reaches the wire,
            # so that is where both halves have to agree (ADR 0012). An
            # encrypted slot writes the number alone.
            my $err = refused({ v_unencrypted => $leaf, keep => 'x' }, $format);
            ok($err, "[$format] $name is refused in an unencrypted slot");
            like($err // '', qr/v_unencrypted/, "[$format] $name: naming the leaf");
        }
    }
};

done_testing;
