#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);
use JSON::MaybeXS qw(decode_json);
use YAML::XS qw(Load);
use POSIX qw(signbit);

use File::SOPS;
use Crypt::Age;

# ----------------------------------------------------------------------------
# karr #58: File::SOPS::Encrypted::value_to_bytes hashes a float at Go's full
# precision (strconv.FormatFloat(v, 'f', -1, 64), up to 17 significant
# digits), but every emitter -- YAML::XS via Perl stringification,
# Cpanel::JSON::XS via %.15g -- WRITES it at 15. For a double that genuinely
# needs 16 or 17 digits to round-trip, the document and its own MAC then
# disagree about which number is in it. Measured, both formats: 0.1+0.2
# (needs 17) and 1/3 (needs 16), both self-MAC FAIL, both `sops -d` exit 51.
#
# Every subtest below drives the real sops binary -- required, no SKIP
# fallback if it is missing -- because the defect IS a byte disagreement with
# it; a self-consistency check alone proves half the story at best (a document
# can fail its own MAC without a binary, but a document that WRONGLY passes,
# as karr #58's spike found for edit(), needs the reference to be seen at
# all).
# ----------------------------------------------------------------------------

# Resolution copied from t/04-interop.t's rule (see the header comment
# there), not re-derived: SOPS_BIN wins and dies if it is set to something
# not executable -- silently falling through would prove compatibility
# against a binary nobody chose -- else PATH, else /tmp/sops, else an honest
# skip_all. This file needs its own copy because it runs as a separate
# process from t/04-interop.t.
sub _find_on_path {
    my ($name) = @_;
    for my $dir (split /:/, $ENV{PATH} // '') {
        next unless length $dir;
        my $candidate = "$dir/$name";
        return $candidate if -x $candidate && !-d $candidate;
    }
    return undef;
}

my $sops_bin;
if (defined $ENV{SOPS_BIN} && length $ENV{SOPS_BIN}) {
    die "SOPS_BIN is set to '$ENV{SOPS_BIN}' but that is not executable. "
      . "Fix the path, or unset SOPS_BIN to auto-detect sops on PATH.\n"
        unless -x $ENV{SOPS_BIN};
    $sops_bin = $ENV{SOPS_BIN};
}
else {
    $sops_bin = _find_on_path('sops') || (-x '/tmp/sops' ? '/tmp/sops' : undef);
}

unless ($sops_bin) {
    plan skip_all =>
        "No sops binary found (checked \$SOPS_BIN, PATH, /tmp/sops) -- "
      . "karr #58 is specifically about byte compatibility with sops, so "
      . "without the binary this file proves nothing. Fix: set "
      . "SOPS_BIN=/path/to/sops.";
}

diag("Using sops binary: $sops_bin");

my ($public, $secret) = Crypt::Age->generate_keypair();
my $tempdir = tempdir(CLEANUP => 1);
write_file("$tempdir/key.txt", $secret);
$ENV{SOPS_AGE_KEY_FILE} = "$tempdir/key.txt";

my $serial = 0;
sub scratch_file {
    my ($ext) = @_;
    return "$tempdir/f" . ++$serial . ".$ext";
}

###############################################################################
# 1. THE CORE BUG: an unencrypted float needing 16 or 17 significant digits
#    must pass its own MAC and be accepted by `sops -d` (exit 0), in both
#    formats. The two ticket-measured cases, exactly.
###############################################################################

my @needs_extra_digits = (
    { label => 'point_one_plus_point_two (needs 17 digits)', value => 0.1 + 0.2 },
    { label => 'one_third (needs 16 digits)',                value => 1 / 3 },
);

for my $format (qw(yaml json)) {
    for my $case (@needs_extra_digits) {
        my $value = $case->{value};

        subtest "[$format] $case->{label}: self-MAC holds and sops -d exits 0" => sub {
            my $encrypted = File::SOPS->encrypt(
                data       => { ratio_unencrypted => $value, secret => 'shh' },
                recipients => [$public],
                format     => $format,
            );

            my $self = eval {
                File::SOPS->decrypt(
                    encrypted => $encrypted, identities => [$secret], format => $format,
                );
            };
            is($@, '', 'the document verifies against its own MAC')
                or diag("died: $@");
            cmp_ok($self->{ratio_unencrypted}, '==', $value,
                'and decrypts back to the value at full precision')
                if $self;

            my $file = scratch_file($format);
            write_file($file, $encrypted);

            my $out       = `$sops_bin -d $file 2>&1`;
            my $exit_code = $? >> 8;
            is($exit_code, 0, 'sops -d accepts the document')
                or diag("sops output: $out");

            if ($exit_code == 0) {
                my $decoded = $format eq 'json' ? decode_json($out) : Load($out);
                cmp_ok($decoded->{ratio_unencrypted}, '==', $value,
                    'and sops itself reads back the value at full precision');
            }
        };
    }
}

###############################################################################
# 2. THE ACCEPTANCE CONDITION: a float that already round-trips at 15
#    significant digits must not have its wire bytes touched by the fix.
#    Pinned as literal text rather than a round-trip, because a round-trip
#    cannot distinguish "written exactly as before" from "written
#    differently but still numerically equal" -- and the latter is exactly
#    what a fix that reformats more than it has to would produce.
###############################################################################

subtest 'floats that already round-trip at 15 digits keep their exact wire bytes' => sub {
    my %healthy = (
        a_unencrypted => 0.5,
        b_unencrypted => 1.5,
        c_unencrypted => 3.14159,
        d_unencrypted => 1e20,
        e_unencrypted => 1e-20,
        f_unencrypted => -3.5,
        g_unencrypted => 1.0,
    );

    # Captured from this distribution's own emitters -- what File::SOPS
    # already writes correctly, needing no fix. If a change to the float
    # path starts reformatting any of these, that is a regression this
    # subtest exists to catch.
    my %expected = (
        yaml => {
            a_unencrypted => qr/^a_unencrypted: 0\.5$/m,
            b_unencrypted => qr/^b_unencrypted: 1\.5$/m,
            c_unencrypted => qr/^c_unencrypted: 3\.14159$/m,
            d_unencrypted => qr/^d_unencrypted: 1e\+20$/m,
            e_unencrypted => qr/^e_unencrypted: 1e-20$/m,
            f_unencrypted => qr/^f_unencrypted: -3\.5$/m,
            g_unencrypted => qr/^g_unencrypted: 1$/m,
        },
        json => {
            a_unencrypted => qr/"a_unencrypted"\s*:\s*0\.5,?$/m,
            b_unencrypted => qr/"b_unencrypted"\s*:\s*1\.5,?$/m,
            c_unencrypted => qr/"c_unencrypted"\s*:\s*3\.14159,?$/m,
            d_unencrypted => qr/"d_unencrypted"\s*:\s*1e\+20,?$/m,
            e_unencrypted => qr/"e_unencrypted"\s*:\s*1e-20,?$/m,
            f_unencrypted => qr/"f_unencrypted"\s*:\s*-3\.5,?$/m,
            g_unencrypted => qr/"g_unencrypted"\s*:\s*1\.0,?$/m,
        },
    );

    for my $format (qw(yaml json)) {
        my $encrypted = File::SOPS->encrypt(
            data       => { %healthy, secret => 'shh' },
            recipients => [$public],
            format     => $format,
        );

        for my $key (sort keys %healthy) {
            like($encrypted, $expected{$format}{$key},
                "[$format] $key is written exactly as it is today")
                or diag("document:\n$encrypted");
        }

        my $file = scratch_file($format);
        write_file($file, $encrypted);
        my $out = `$sops_bin -d $file 2>&1`;
        is($? >> 8, 0, "[$format] sops -d still accepts the unmoved document")
            or diag("sops output: $out");
    }
};

###############################################################################
# 3. THE SPECIFIC SHORTCUT THIS GUARDS AGAINST: JSON -0.0 already round-trips
#    correctly today (Cpanel writes "-0.0", which reparses to the same
#    negative zero) -- exit 0, no bug here. The measurement spike found that
#    the NAIVE fix (route every float through Math::BigFloat unconditionally,
#    rather than only the ones that need it) breaks this case, because
#    Math::BigFloat->new('-0') loses the sign. This subtest is expected to be
#    GREEN already; it exists to stay green through the fix, not to
#    reproduce a bug of its own. (-0.0 beyond this exact case -- e.g. the
#    YAML side, which is broken today for unrelated reasons -- is karr #62,
#    out of scope here.)
###############################################################################

subtest 'JSON -0.0 keeps its sign at exit 0 (guards against the naive fix)' => sub {
    my $encrypted = File::SOPS->encrypt(
        data       => { negzero_unencrypted => -0.0, secret => 'shh' },
        recipients => [$public],
        format     => 'json',
    );

    like($encrypted, qr/"negzero_unencrypted"\s*:\s*-0\.0,?$/m,
        'the written bytes keep the negative sign');

    my $self = eval {
        File::SOPS->decrypt(
            encrypted => $encrypted, identities => [$secret], format => 'json',
        );
    };
    is($@, '', 'self-MAC holds') or diag("died: $@");
    ok(signbit($self->{negzero_unencrypted}), 'and the value decrypts back negative')
        if $self;

    my $file = scratch_file('json');
    write_file($file, $encrypted);
    my $out = `$sops_bin -d $file 2>&1`;
    is($? >> 8, 0, 'sops -d accepts it') or diag("sops output: $out");
};

###############################################################################
# 4. THE READ DIRECTION: a document the REAL sops wrote, carrying an
#    unencrypted float that needs full precision (0.1+0.2, exactly what sops
#    itself writes for that value). Two separate corruptions, both measured,
#    both JSON-specific (YAML::XS retains a parsed float's original text and
#    survives this by accident -- karr #58's spike, section 1a):
#
#      * rotate() re-serializes every value; a bare NV loses precision on
#        the way back out, and the ROTATED file failed its own MAC -- sops
#        -d exit 51. Pinned as an exit-code assertion.
#      * edit() writes the plaintext to a temp file for the editor using the
#        SAME lossy emitter, so the value was already wrong before the
#        editor even ran. edit() reported success (return 1, sops -d exit 0
#        on the result) with the WRONG NUMBER on disk -- no error anywhere.
#        An exit-code assertion cannot see this; only a numeric-precision
#        assertion on the value that comes back can.
###############################################################################

# The literal text sops itself writes for 0.1+0.2 -- NOT $value interpolated
# into a string, which would go through Perl's own ~15-digit stringification
# and quietly write the very number this ticket is about instead of the
# fixture the test means to build.
my $full_precision_text = '0.30000000000000004';
my $full_precision_value = 0.1 + 0.2;

subtest 'rotate() on a sops-written JSON document with a 17-digit float' => sub {
    my $plain = scratch_file('json');
    write_file($plain,
        qq({\n  "ratio_unencrypted": $full_precision_text,\n  "secret": "shh"\n}\n));

    my $enc_file = scratch_file('json');
    system("$sops_bin -e --age $public $plain > $enc_file 2>/dev/null");
    is($? >> 8, 0, 'sops -e wrote the fixture') or return;

    # Baseline: reading it (no re-serialization involved) already works.
    my $content = read_file($enc_file);
    my $read = eval {
        File::SOPS->decrypt(encrypted => $content, identities => [$secret], format => 'json')
    };
    is($@, '', 'decrypt reads the sops-written document') or diag("died: $@");
    cmp_ok($read->{ratio_unencrypted}, '==', $full_precision_value,
        'and returns the value at full precision, before any rewrite')
        if $read;

    # The measured corruption: rotate rewrites the document, and the
    # rewritten value no longer matched the MAC that rotate itself computed.
    File::SOPS->rotate(file => $enc_file, identities => [$secret]);

    my $out = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'sops -d still accepts the rotated document')
        or diag("sops output (measured before the fix: MAC mismatch, exit 51): $out");
};

subtest 'edit() on a sops-written JSON document with a 17-digit float' => sub {
    my $plain = scratch_file('json');
    write_file($plain, qq({\n  "ratio_unencrypted": $full_precision_text,\n)
        . qq(  "note_unencrypted": "old",\n  "secret": "shh"\n}\n));

    my $enc_file = scratch_file('json');
    system("$sops_bin -e --age $public $plain > $enc_file 2>/dev/null");
    is($? >> 8, 0, 'sops -e wrote the fixture') or return;

    # An editor that changes an UNRELATED key and leaves ratio_unencrypted
    # untouched -- the exact shape the spike measured. If edit()'s own
    # plaintext round trip already mangled the value before the editor ran,
    # this editor would never see or reintroduce the correct one.
    my $editor_script = "$tempdir/editor-" . ++$serial . '.pl';
    write_file($editor_script, <<'PERL');
my $file = $ARGV[-1];
open my $in, '<', $file or die $!;
my $content = do { local $/; <$in> };
close $in;
$content =~ s/"old"/"new"/;
open my $out, '>', $file or die $!;
print $out $content;
close $out;
PERL

    my $ret = File::SOPS->edit(
        file       => $enc_file,
        identities => [$secret],
        editor     => [ $^X, $editor_script ],
    );
    is($ret, 1, 'edit reports that it rewrote the file');

    my $out       = `$sops_bin -d $enc_file 2>&1`;
    my $exit_code = $? >> 8;
    is($exit_code, 0, 'sops -d accepts the edited document')
        or diag("sops output: $out");

    return unless $exit_code == 0;

    my $decoded = decode_json($out);
    is($decoded->{note_unencrypted}, 'new', 'the edit itself took effect');

    # The actual bug: edit() reported success and sops -d exited 0, but the
    # untouched ratio field had silently been rewritten to a DIFFERENT
    # double -- 0.3, not 0.1+0.2 -- with no error anywhere. == distinguishes
    # them because they are not the same double, even though both stringify
    # by default as "0.3".
    cmp_ok($decoded->{ratio_unencrypted}, '==', $full_precision_value,
        'and the untouched field is still the value it started as, not silently rounded');
};

done_testing;
