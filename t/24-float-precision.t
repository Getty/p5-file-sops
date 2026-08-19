#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);
use JSON::MaybeXS qw(decode_json);
use YAML::XS qw(Load);
use POSIX qw(signbit);
use Math::BigFloat;
use Math::BigInt;

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

###############################################################################
# 5. karr #64 point 1 (the most important gap): THE FOREIGN-BIGNUM GUARD.
#
#    Format::JSON::emit needs allow_bignum so its OWN Math::BigFloat carrier
#    (see _float_carrier) reaches the wire as a bare JSON number instead of a
#    quoted string. But allow_bignum whitelists the class for EVERY value
#    Cpanel::JSON::XS is asked to encode, not just the carrier this module
#    creates -- so a Math::BigFloat or Math::BigInt the CALLER put in the tree,
#    which the encoder used to refuse outright, would now be written as a bare
#    number too. detect_type calls a blessed leaf 'str', so the MAC digest
#    covers the object's stringification while the document would carry it as
#    a JSON number Go reparses as a float64 -- a document that fails its own
#    MAC, produced silently. Measured in karr #58:
#    Math::BigFloat->new('1.00000000000000000000000000001') digests as 29
#    digits and reads back as 1.
#
#    _reject_referenced_leaf -- named _reject_foreign_bignum when karr #58
#    added it -- is the fix: it croaks on any Math::BigFloat or Math::BigInt
#    reaching the emitter that is NOT its own carrier. Entirely new
#    behaviour as of karr #58 -- until now, not one line of test.
#
#    No sops binary needed for these -- the assertion is that File::SOPS
#    refuses to produce a document at all, which is a Perl-level guarantee.
#    Kept in this file anyway (skip_all and all) because the ticket asks for
#    it here, next to the rest of the float-precision coverage it protects.
###############################################################################

subtest 'a caller-supplied Math::BigFloat as an unencrypted JSON leaf is refused' => sub {
    my $poison = Math::BigFloat->new('1.00000000000000000000000000001');

    my $encrypted = eval {
        File::SOPS->encrypt(
            data       => { ratio_unencrypted => $poison, secret => 'shh' },
            recipients => [$public],
            format     => 'json',
        );
    };

    ok(!defined $encrypted, 'encrypt() does not return a document');
    like($@, qr/cannot write a leaf blessed into Math::BigFloat to a SOPS document/,
        'and dies with the foreign-bignum guard message, not a generic JSON encoder error');
};

subtest 'a caller-supplied Math::BigInt as an unencrypted JSON leaf is refused' => sub {
    # allow_bignum whitelists BOTH Math::BigFloat and Math::BigInt (Cpanel::
    # JSON::XS decodes an over-int64 JSON number to the latter), so the guard
    # has to name both classes. Same corruption shape: an integer literal that
    # is not exactly representable in a JSON number digests as its exact
    # decimal string but would be written -- and re-derived by Go -- as a
    # float64.
    my $poison = Math::BigInt->new('123456789012345678901234567890');

    my $encrypted = eval {
        File::SOPS->encrypt(
            data       => { count_unencrypted => $poison, secret => 'shh' },
            recipients => [$public],
            format     => 'json',
        );
    };

    ok(!defined $encrypted, 'encrypt() does not return a document');
    like($@, qr/cannot write a leaf blessed into Math::BigInt to a SOPS document/,
        'and dies with the foreign-bignum guard message');
};

subtest 'the guard reaches a foreign bignum nested inside a hash and inside an array' => sub {
    # canonical_float_tree's walk is recursive (see section 7 below for the
    # legitimate-float side of that), and the reject callback is invoked from
    # the same recursion, at the same leaf branch. A guard that only fired at
    # the top level would let a nested poison leaf straight through.
    my $nested = eval {
        File::SOPS->encrypt(
            data       => {
                outer_unencrypted => {
                    inner_unencrypted => Math::BigFloat->new('1.00000000000000000000000000001'),
                },
                secret => 'shh',
            },
            recipients => [$public],
            format     => 'json',
        );
    };
    ok(!defined $nested, 'a bignum nested inside a hash is refused');
    like($@, qr/cannot write a leaf blessed into Math::BigFloat to a SOPS document/, 'with the guard message');

    my $in_array = eval {
        File::SOPS->encrypt(
            data       => {
                list_unencrypted => [ 1, 2, Math::BigInt->new('123456789012345678901234567890') ],
                secret            => 'shh',
            },
            recipients => [$public],
            format     => 'json',
        );
    };
    ok(!defined $in_array, 'a bignum inside an array is refused');
    like($@, qr/cannot write a leaf blessed into Math::BigInt to a SOPS document/, 'with the guard message');
};

###############################################################################
# 6. karr #64 point 2: a CLASS-GLOBAL Math::BigFloat->accuracy/precision must
#    not corrupt the carrier. _float_carrier calls
#    Math::BigFloat->new($text, undef, undef) -- the explicit undef, undef
#    overriding whatever global setting is in effect -- and asserts the result
#    stringifies back to $text exactly. Without that assertion a global
#    accuracy(5) left set by unrelated code anywhere in the same process would
#    silently truncate a 16/17-digit float to 5 significant digits.
#
#    Restoration is via `local` on the two package variables Math::BigFloat's
#    accuracy()/precision() accessors read and write
#    ($Math::BigFloat::accuracy / ::precision) -- scoped to the subtest's
#    anonymous sub, so it unwinds when that sub returns for ANY reason,
#    including a die from a failed assertion partway through. Checked
#    explicitly below as well, once execution is back outside the subtest, as
#    the belt to local's suspenders the ticket asked for.
###############################################################################

my $accuracy_before_all  = Math::BigFloat->accuracy();
my $precision_before_all = Math::BigFloat->precision();

subtest '[json] a global Math::BigFloat->accuracy/precision does not corrupt the float carrier' => sub {
    local $Math::BigFloat::accuracy  = 5;
    local $Math::BigFloat::precision = -2;

    my $value = 1 / 3;   # needs 16 digits

    my $encrypted = File::SOPS->encrypt(
        data       => { ratio_unencrypted => $value, secret => 'shh' },
        recipients => [$public],
        format     => 'json',
    );

    my $self = eval {
        File::SOPS->decrypt(encrypted => $encrypted, identities => [$secret], format => 'json');
    };
    is($@, '', 'self-MAC holds even with a global BigFloat accuracy/precision set')
        or diag("died: $@");
    cmp_ok($self->{ratio_unencrypted}, '==', $value,
        'and decrypts back to the value at full precision')
        if $self;

    my $file = scratch_file('json');
    write_file($file, $encrypted);
    my $out = `$sops_bin -d $file 2>&1`;
    is($? >> 8, 0, 'sops -d accepts the document despite the global accuracy/precision')
        or diag("sops output: $out");
};

is(Math::BigFloat->accuracy(), $accuracy_before_all,
    'global Math::BigFloat->accuracy is back to what it was before the subtest');
is(Math::BigFloat->precision(), $precision_before_all,
    'global Math::BigFloat->precision is back to what it was before the subtest');

###############################################################################
# 7. karr #64 point 3: NESTED and ARRAY float leaves. canonical_float_tree's
#    walk is recursive, but until now only a top-level key was ever exercised.
#    A mix of values that need the carrier and values that already round-trip,
#    at two levels of hash nesting and inside an array, in both formats.
###############################################################################

for my $format (qw(yaml json)) {
    subtest "[$format] nested and array float leaves also reach full precision" => sub {
        my $needs_digits_1 = 0.1 + 0.2;   # needs 17
        my $needs_digits_2 = 1 / 3;        # needs 16

        my $data = {
            outer_unencrypted => {
                inner_unencrypted => $needs_digits_1,
            },
            list_unencrypted => [ $needs_digits_2, $needs_digits_1, 3.14 ],
            secret           => 'shh',
        };

        my $encrypted = File::SOPS->encrypt(
            data       => $data,
            recipients => [$public],
            format     => $format,
        );

        my $self = eval {
            File::SOPS->decrypt(encrypted => $encrypted, identities => [$secret], format => $format);
        };
        is($@, '', 'self-MAC holds') or diag("died: $@");
        if ($self) {
            cmp_ok($self->{outer_unencrypted}{inner_unencrypted}, '==', $needs_digits_1,
                'nested (two levels deep) value keeps full precision');
            cmp_ok($self->{list_unencrypted}[0], '==', $needs_digits_2,
                'array element 0 keeps full precision');
            cmp_ok($self->{list_unencrypted}[1], '==', $needs_digits_1,
                'array element 1 keeps full precision');
            cmp_ok($self->{list_unencrypted}[2], '==', 3.14,
                'array element 2 (already healthy at 15 digits) is untouched');
        }

        my $file = scratch_file($format);
        write_file($file, $encrypted);
        my $out       = `$sops_bin -d $file 2>&1`;
        my $exit_code = $? >> 8;
        is($exit_code, 0, 'sops -d accepts the document') or diag("sops output: $out");

        if ($exit_code == 0) {
            my $decoded = $format eq 'json' ? decode_json($out) : Load($out);
            cmp_ok($decoded->{outer_unencrypted}{inner_unencrypted}, '==', $needs_digits_1,
                'and sops itself reads the nested value back at full precision');
            cmp_ok($decoded->{list_unencrypted}[0], '==', $needs_digits_2,
                'and the array value at full precision too');
        }
    };
}

###############################################################################
# 8. karr #64 point 4: CROSS-FORMAT conversion, and decrypt_file's plaintext
#    against what `sops -d` itself writes. Both were "fixed as a side effect"
#    per the karr #58 report, and both were, until now, unverified.
#
#    The fixture is a document the REAL sops wrote (not one this module
#    produced), carrying an unencrypted float that needs full precision --
#    exactly the shape where the pre-fix bug bit hardest: Cpanel::JSON::XS
#    hands back a bare NV with no memory of the text it was parsed from
#    (karr #58 section 1a), so JSON is the format where this had to be
#    fixed for the value to survive at all.
###############################################################################

subtest '[json -> yaml] a float that arrived as a bare NV from JSON survives re-emission as YAML' => sub {
    my $plain = scratch_file('json');
    write_file($plain,
        qq({\n  "ratio_unencrypted": $full_precision_text,\n  "secret": "shh"\n}\n));

    my $enc_file = scratch_file('json');
    system("$sops_bin -e --age $public $plain > $enc_file 2>/dev/null");
    is($? >> 8, 0, 'sops -e wrote the fixture') or return;

    # Decrypting via JSON hands back a bare NV for the float -- Cpanel::
    # JSON::XS keeps no parsed text, unlike YAML::XS (karr #58 section 1a).
    my $content = read_file($enc_file);
    my $data = File::SOPS->decrypt(
        encrypted => $content, identities => [$secret], format => 'json',
    );
    cmp_ok($data->{ratio_unencrypted}, '==', $full_precision_value,
        'decrypted value is correct before any re-emission');

    # The cross-format step: the SAME in-memory tree, with its bare NV, is
    # now encrypted as YAML -- a different emitter than the one that produced
    # the bare NV in the first place.
    my $yaml_encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public],
        format     => 'yaml',
    );

    my $yaml_file = scratch_file('yaml');
    write_file($yaml_file, $yaml_encrypted);
    my $out       = `$sops_bin -d $yaml_file 2>&1`;
    my $exit_code = $? >> 8;
    is($exit_code, 0, 'sops -d accepts the cross-format YAML document')
        or diag("sops output (measured before the fix: MAC mismatch, exit 51): $out");

    if ($exit_code == 0) {
        my $decoded = Load($out);
        cmp_ok($decoded->{ratio_unencrypted}, '==', $full_precision_value,
            'and sops reads the cross-format value back at full precision');
    }
};

subtest 'decrypt_file on a sops-written JSON document matches what sops -d itself prints' => sub {
    my $plain = scratch_file('json');
    write_file($plain,
        qq({\n  "ratio_unencrypted": $full_precision_text,\n  "secret": "shh"\n}\n));

    my $enc_file = scratch_file('json');
    system("$sops_bin -e --age $public $plain > $enc_file 2>/dev/null");
    is($? >> 8, 0, 'sops -e wrote the fixture') or return;

    my $sops_plain_out = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'sops -d on the fixture itself exits 0') or return;

    my $our_output = scratch_file('json');
    File::SOPS->decrypt_file(
        input      => $enc_file,
        output     => $our_output,
        identities => [$secret],
        format     => 'json',
    );
    my $our_content = read_file($our_output);

    # Not a byte-for-byte comparison of the two documents: sops's plaintext
    # writer uses tabs and different key spacing (a pretty-printing choice,
    # not a wire-format one), so the two texts differ even for values that
    # were never broken. What must agree is the NUMBER -- both as a decoded
    # value and, since the whole point of karr #58 was which literal digits
    # get written, as the literal text on the wire.
    my $sops_decoded = decode_json($sops_plain_out);
    my $our_decoded  = decode_json($our_content);
    cmp_ok($our_decoded->{ratio_unencrypted}, '==', $sops_decoded->{ratio_unencrypted},
        'decrypt_file and sops -d decode to the same double');
    cmp_ok($our_decoded->{ratio_unencrypted}, '==', $full_precision_value,
        'and that double is the full-precision value, not the 15-digit truncation');
    like($our_content, qr/\Q$full_precision_text\E/,
        'decrypt_file writes the same literal digits sops -d does, not a truncated form')
        or diag("our decrypt_file output:\n$our_content");
};

###############################################################################
# 9. karr #62: YAML -0.0. The last row of the old non-finite matrix, and the
#    one ADR 0006 excluded by canonical text (-0 was on $NO_AGREED_FORM).
#
#    Before: YAML::XS renders an NV -0.0 as `0`, value_to_bytes digests `-0`,
#    so the document and its own MAC state different numbers -- self-MAC FAIL,
#    sops -d exit 51, written silently. The ticket concluded there was no YAML
#    representation, because emitting the canonical `-0` makes Go's yaml.v3
#    resolve an INTEGER zero and digest `0`: still a mismatch.
#
#    Measured against sops 3.13.3, one document per spelling, same digest:
#
#      -0          sops -d exit 51   self-MAC FAIL   (the ticket's premise)
#      !!float -0  sops -d exit 51   self-MAC FAIL
#      -0.0        sops -d exit 0    self-MAC OK     <- a representation exists
#      -0.         sops -d exit 0    self-MAC OK
#
#    So the value is representable and is now carried, with the ONE text in
#    this distribution that is not value_to_bytes's output verbatim. ADR 0006's
#    rule is that the emitted decimal must PARSE BACK to the same double, not
#    that it be spelled canonically, so `-0.0` satisfies it.
#
#    There is deliberately no sops -> us fixture for this value: `sops -e` on a
#    plaintext -0.0 writes `-0` and then rejects its own file with exit 51, in
#    YAML and in JSON alike (measured, 3.13.3). sops cannot write this value,
#    so the only direction that can be pinned is ours -> sops, which is what
#    this subtest does.
#
#    Section 3 above is the other half of this change and must stay green: the
#    JSON -0.0 row worked before it and works after it, byte for byte.
###############################################################################

subtest '[yaml] -0.0 keeps its sign and its MAC (karr #62)' => sub {
    my $encrypted = File::SOPS->encrypt(
        data       => { negzero_unencrypted => -0.0, secret => 'shh' },
        recipients => [$public],
        format     => 'yaml',
    );

    like($encrypted, qr/^negzero_unencrypted: -0\.0$/m,
        'the written bytes are -0.0, not the 0 YAML::XS renders on its own')
        or diag("emitted:\n$encrypted");
    unlike($encrypted, qr/^negzero_unencrypted: -?0$/m,
        'and specifically not the bare -0 / 0 that resolves as an integer');

    my $self = eval {
        File::SOPS->decrypt(
            encrypted => $encrypted, identities => [$secret], format => 'yaml',
        );
    };
    is($@, '', 'self-MAC holds') or diag("died: $@");
    ok(signbit($self->{negzero_unencrypted}), 'the value decrypts back negative')
        if $self;

    my $file = scratch_file('yaml');
    write_file($file, $encrypted);
    my $out = `$sops_bin -d $file 2>&1`;
    is($? >> 8, 0, 'sops -d accepts it') or diag("sops output: $out");
    like($out, qr/^negzero_unencrypted: -0$/m,
        'and sops reads it back as the negative zero, printing its own -0')
        if $? == 0;
};

subtest '[yaml] the -0 carrier does not touch the neighbouring cases' => sub {
    # +0.0 has always emitted `0` and digested `0`: untouched.
    my $pos = File::SOPS->encrypt(
        data       => { zero_unencrypted => 0.0, secret => 'shh' },
        recipients => [$public],
        format     => 'yaml',
    );
    like($pos, qr/^zero_unencrypted: 0$/m, 'a positive zero still emits bare 0');

    # The STRINGS '-0' and '-0.0' are strings, not floats: detect_type reads
    # the SV (ADR 0002), the carrier never sees them, and YAML::XS quotes
    # them. If the carrier ever started rewriting by text rather than by SV
    # flags, this is the assertion that would catch it.
    my $strs = File::SOPS->encrypt(
        data       => {
            dash_zero_unencrypted     => '-0',
            dash_zero_dot_unencrypted => '-0.0',
            secret                    => 'shh',
        },
        recipients => [$public],
        format     => 'yaml',
    );
    like($strs, qr/^dash_zero_unencrypted: '-0'$/m,
        "the STRING '-0' stays a quoted string");
    like($strs, qr/^dash_zero_dot_unencrypted: '-0\.0'$/m,
        "the STRING '-0.0' stays a quoted string");

    my $file = scratch_file('yaml');
    write_file($file, $strs);
    my $out = `$sops_bin -d $file 2>&1`;
    is($? >> 8, 0, 'sops -d accepts the string document') or diag("sops: $out");

    # A -0.0 that came OUT of a YAML document already emitted -0.0 before this
    # change, because YAML::XS retains a parsed float's text. It must still
    # take that path (roundtrips => yes) rather than the carrier.
    my $parsed = Load("v: -0.0\n")->{v};
    my $round  = File::SOPS->encrypt(
        data       => { v_unencrypted => $parsed, secret => 'shh' },
        recipients => [$public],
        format     => 'yaml',
    );
    like($round, qr/^v_unencrypted: -0\.0$/m,
        'a -0.0 parsed from a YAML document keeps its bytes');
};

subtest '[yaml] an ENCRYPTED -0.0 is unaffected by the carrier' => sub {
    # An encrypted leaf is an ENC[...] string by the time emit() runs, so the
    # float never reaches the carrier at all. This worked before karr #62 and
    # has to keep working -- it is the case ADR 0008 refused to break by
    # putting format rules into assert_representable.
    for my $format (qw(yaml json)) {
        my $encrypted = File::SOPS->encrypt(
            data       => { negzero => -0.0, secret => 'shh' },
            recipients => [$public],
            format     => $format,
        );
        my $file = scratch_file($format);
        write_file($file, $encrypted);
        my $out = `$sops_bin -d $file 2>&1`;
        is($? >> 8, 0, "[$format] sops -d accepts an encrypted -0.0")
            or diag("sops output: $out");
        like($out, qr/negzero"?\s*:\s*-0\b/,
            "[$format] and reads the plaintext back as -0");
    }
};

done_testing;
