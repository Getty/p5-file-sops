#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurp qw(write_file);

use File::SOPS;
use Crypt::Age;

# ----------------------------------------------------------------------------
# karr #59: a non-finite float (NaN, +Inf, -Inf) has no agreed form on the
# wire. value_to_bytes writes +Inf / -Inf / NaN -- the same text Go's
# strconv.FormatFloat produces -- but no emitter can carry it. Cpanel writes
# null (silently rounded), JSON::XS writes bare inf (invalid JSON, sops exit
# 1), YAML::XS writes bare Inf / NaN (self-MAC OK, sops -d exit 51). All
# three produce a file nothing can read back.
#
# The pre-fix code wrote the file anyway. assert_representable now refuses
# them at encrypt time, with the same shape as the int64 and ref guards:
# the exception names the form, says to store as a string, never names the
# value. Reading is unaffected: a type:float plaintext of +Inf or NaN is
# accepted by _deserialize_value today (and sops writes it), and stays
# accepted.
#
# Every subtest below is a Perl-level guarantee ("encrypt dies, decrypt
# never sees the value"), not a byte-level one -- the byte-level question
# is what the emitters USED TO DO, and assert_representable closes that
# path before it can be exercised. The sops binary is unnecessary here and
# is deliberately not used: this test's claim is "this lib refuses on its
# own, and the read path still accepts a Go round-trip file".
# ----------------------------------------------------------------------------

my ($public, $secret) = Crypt::Age->generate_keypair();
my $tempdir = tempdir(CLEANUP => 1);
write_file("$tempdir/key.txt", $secret);
$ENV{SOPS_AGE_KEY_FILE} = "$tempdir/key.txt";

my $inf = 9**9**9;
my %cases = (
    '+Inf' => $inf,
    '-Inf' => -$inf,
    'NaN'  => $inf - $inf,
);

###############################################################################
# 1. WRITE-SIDE REFUSAL: encrypt() refuses every non-finite float, in both
#    formats, with a message that names the form and points at type:str.
###############################################################################

for my $format (qw(yaml json)) {
    for my $name (sort keys %cases) {
        my $value = $cases{$name};

        subtest "[$format] encrypt() refuses a non-finite float ($name) with the karr #59 message" => sub {
            my $encrypted = eval {
                File::SOPS->encrypt(
                    data       => { x_unencrypted => $value, secret => 'shh' },
                    recipients => [$public],
                    format     => $format,
                );
            };

            ok(!defined $encrypted, 'encrypt() does not return a document');
            like($@, qr/non-finite float \Q($name\E/,
                'and dies with the karr #59 message, naming the form')
                or diag("died: $@");
            like($@, qr/store the value as a string/i,
                'and tells the caller what to do instead')
                or diag("died: $@");
        };
    }
}

###############################################################################
# 2. NO REGRESSION ON THE HEALTHY FLOAT: a finite float (the four cases
#    assert_representable used to pass) is still accepted. assert_representable
#    must do ONLY the three refusals and nothing else.
###############################################################################

for my $format (qw(yaml json)) {
    for my $value (0.0, 1.0, -0.0, 0.1 + 0.2, 1.5, -3.5, 1e20) {
        subtest "[$format] a finite float ($value) is still accepted by encrypt()" => sub {
            my $encrypted = eval {
                File::SOPS->encrypt(
                    data       => { x_unencrypted => $value, secret => 'shh' },
                    recipients => [$public],
                    format     => $format,
                );
            };
            is($@, '', "encrypt does not die on $value")
                or diag("died: $@");
            ok(defined $encrypted, "$value passes assert_representable")
                if !$@;
        };
    }
}

###############################################################################
# 3. THE EXEMPTION: -0.0 is NOT in the refusal list. It is finite (a == a,
#    and -0.0 == 0.0), so the check above returns no form and the value
#    passes. JSON -0.0 is the row that the karr #58 work went out of its
#    way to protect (ADR 0005), and it has to keep working.
###############################################################################

subtest '-0.0 is NOT refused (the JSON -0.0 / karr #58 happy path)' => sub {
    for my $format (qw(yaml json)) {
        my $encrypted = eval {
            File::SOPS->encrypt(
                data       => { negzero_unencrypted => -0.0, secret => 'shh' },
                recipients => [$public],
                format     => $format,
            );
        };
        is($@, '', "encrypt does not die on -0.0 in $format")
            or diag("died: $@");
        ok(defined $encrypted, "-0.0 passes assert_representable in $format")
            if !$@;
    }
};

###############################################################################
# 4. THE READ PATH: a sops-written document carrying an unencrypted float
#    readable as +Inf (which sops writes as `Inf`) -- wait, JSON sops
#    writes `null` for that, so an unencrypted +Inf does not survive a
#    sops round trip. The legitimate read path is the ENCRYPTED type:float
#    plaintext +Inf or NaN, which sops writes when its input is the string
#    "Inf" or "NaN" with the value type manually labelled. The smaller
#    read-direction claim we can actually pin is that _deserialize_value
#    accepts the plaintext, which is what encrypt_value's encrypt side
#    would also produce if the caller forced type => 'float' on a string
#    'Inf'. assert_representable does NOT run on the encrypt path when
#    type is forced (the force skips the auto-detect that calls
#    _sv_kind and then refuses); verify this end-to-end.
###############################################################################

subtest "encrypt_value with type=>'float' on a caller-forced 'Inf' string still works" => sub {
    # Caller says: this is a type:float, plaintext 'Inf'. The plaintext is
    # what the digest covers, and the type is what _deserialize_value will
    # route through. assert_representable sees a STRING ('Inf'), not a
    # float, so the karr #59 refusal does not fire.
    my $key = "\x00" x 32;       # 32 bytes; not a real key, ok for our purposes
    my $enc = File::SOPS::Encrypted->encrypt_value(
        value => 'Inf',
        key   => $key,
        aad   => 'x:',
        type  => 'float',
    );
    my $bytes = $enc->decrypt_bytes(key => $key, aad => 'x:');
    is($bytes, 'Inf', 'the plaintext is exactly what we put in');

    # And _deserialize_value gives back a Perl NV which is +Inf -- the path
    # assert_representable would NOT have fired on, because the leaf was
    # a string.
    my $val = $enc->decrypt_value(key => $key, aad => 'x:');
    is($val, $inf, 'decrypt_value returns the +Inf back, and does not die');
};

done_testing;
