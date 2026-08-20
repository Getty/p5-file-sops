#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);
use JSON::MaybeXS qw(JSON);
use YAML::XS ();

use File::SOPS;
use File::SOPS::Format::YAML;
use Crypt::Age;

# ----------------------------------------------------------------------------
# karr #92 / docs/adr/0019: a `True` or `False` STRING is a str here and a bool
# to sops, and both digest the same bytes -- so the MAC holds, sops -d exits 0,
# and the guard ADR 0013 built could not see it. What diverges is the TYPE.
#
# Measured, sops 3.13.3, leaf in an unencrypted YAML slot:
#
#   document              we read       sops reads   sops -d
#   x_unencrypted: True   str "True"    bool true    exit 0
#   x_unencrypted: False  str "False"   bool false   exit 0
#
# and it does not survive a sops write-back -- `sops rotate -i`, `sops set` and
# `sops edit` each rewrite the leaf to a bare `true`, after which THIS module
# reads a JSON::PP::Boolean where the caller put a string. Nothing fails at any
# point, which is why it is a carp and not a refusal: refusing it would refuse a
# document sops reads (measured: 0 of 364 corpus rows stop being written, 4 of
# them newly warn, and all four really do diverge).
#
# Most of this file needs no binary. The write-back is the part that is a claim
# about sops, and it is skipped without one.
# ----------------------------------------------------------------------------

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
diag("Using sops binary: $sops_bin") if $sops_bin;

my ($public, $secret) = Crypt::Age->generate_keypair();
my $tempdir = tempdir(CLEANUP => 1);
write_file("$tempdir/key.txt", $secret);
$ENV{SOPS_AGE_KEY_FILE} = "$tempdir/key.txt";

# A leaf exactly as a YAML parse hands it over. libyaml resolves `true` and
# `false` and NOT their titlecase spellings, so `True` arrives as a string --
# which is the whole subject of this file.
sub yaml_leaf {
    my ($source) = @_;
    local $YAML::XS::Boolean = 'JSON::PP';
    return YAML::XS::Load("v: $source\n")->{v};
}

sub encrypt_capturing {
    my (%args) = @_;
    my @warnings;
    my $document = eval {
        local $SIG{__WARN__} = sub { push @warnings, $_[0] };
        File::SOPS->encrypt(recipients => [$public], format => 'yaml', %args);
    };
    return ($document, $@, \@warnings);
}

my $RETYPED = qr/\Qa string here and a boolean to sops\E/;

###############################################################################
# 1. THE WARNING. One per leaf, naming its key path, and the document is
#    written exactly as it was before -- the bare spelling included.
###############################################################################

subtest 'a True string warns and is still written, bare' => sub {
    for my $source (qw( True False )) {
        my ($document, $died, $warnings) = encrypt_capturing(
            data => { flag_unencrypted => yaml_leaf($source), s => 'x' });

        is($died, '', "[$source] nothing is refused");
        like($document, qr/^flag_unencrypted: \Q$source\E$/m,
            "[$source] and the document carries the spelling, bare and unchanged");
        is(scalar @$warnings, 1, "[$source] exactly one warning");
        like($warnings->[0], qr/\Aflag_unencrypted: /,
            "[$source] which names the leaf by key path");
        like($warnings->[0], $RETYPED, "[$source] and says what diverges");
        like($warnings->[0], qr/\Qsops write-back\E/,
            "[$source] and that a sops write-back rewrites it");
    }
};

subtest 'a caller-supplied Perl string is the same leaf' => sub {
    # Nothing here comes from a parser: this is the shape a caller writes.
    my ($document, $died, $warnings) = encrypt_capturing(
        data => { flag_unencrypted => 'True', s => 'x' });
    is($died, '', 'written');
    is(scalar @$warnings, 1, 'and warned about once');
    like($warnings->[0], $RETYPED, 'with the same message');
};

subtest 'it warns in both MAC modes' => sub {
    # The digest covers the same bytes either way, so there is nothing for
    # mac_only_encrypted to change -- unlike ADR 0013's class, where the flag
    # decides between a refusal and a warning.
    my ($document, $died, $warnings) = encrypt_capturing(
        data => { flag_unencrypted => yaml_leaf('True'), s => 'x' },
        mac_only_encrypted => 1);
    is($died, '', 'written with mac_only_encrypted set');
    is(scalar @$warnings, 1, 'and warned about there too');
    like($warnings->[0], $RETYPED, 'with the same message');
};

subtest 'a nested leaf is named by its full key path, one warning each' => sub {
    my ($document, $died, $warnings) = encrypt_capturing(
        data => { db => { a_unencrypted => yaml_leaf('True'),
                          b_unencrypted => yaml_leaf('False') },
                  s  => 'x' });
    is($died, '', 'both are written');
    is(scalar @$warnings, 2, 'and each one warns');
    my $joined = join '', sort @$warnings;
    like($joined, qr/\Qdb:a_unencrypted: \E/, 'the True leaf, by path');
    like($joined, qr/\Qdb:b_unencrypted: \E/, 'the False leaf, by path');
};

subtest 'the warning never carries the value' => sub {
    # A warning goes to logs, and an unencrypted leaf is not a secret -- but
    # the rule is the rule, and the message is written to hold for the
    # type:bytes leaf that reaches this by the same route.
    my ($document, $died, $warnings) = encrypt_capturing(
        data => { flag_unencrypted => yaml_leaf('True'), s => 'x' });
    is(scalar @$warnings, 1, 'warned');
    unlike($warnings->[0], qr/True/, 'and the value is not in the message');

    my (undef, undef, $false) = encrypt_capturing(
        data => { flag_unencrypted => yaml_leaf('False'), s => 'x' });
    unlike($false->[0], qr/False/, 'nor is the other one');
};

###############################################################################
# 2. WHAT MUST NOT WARN. A guard that fired one leaf wider than this would be
#    warning about documents that round-trip through sops unharmed -- measured,
#    each of these does.
###############################################################################

subtest 'a real boolean is silent' => sub {
    for my $leaf (JSON->true, JSON->false, yaml_leaf('true'), yaml_leaf('false')) {
        my ($document, $died, $warnings) = encrypt_capturing(
            data => { flag_unencrypted => $leaf, s => 'x' });
        is($died, '', 'a boolean leaf is written');
        is_deeply($warnings, [], 'and says nothing')
            or diag("warned: @$warnings");
    }
};

subtest "YAML 1.1's other booleans are strings on both sides" => sub {
    # yaml.v3 dropped them and libyaml never resolved them either. Measured
    # through sops 3.13.3: every one of these is a JSON string in `sops -d`
    # output and survives `sops rotate` byte for byte.
    for my $source (qw( Yes No YES NO yes no y n Y N On Off ON OFF on off )) {
        my ($document, $died, $warnings) = encrypt_capturing(
            data => { flag_unencrypted => yaml_leaf($source), s => 'x' });
        is($died, '', "[$source] is written");
        is_deeply($warnings, [], "[$source] and says nothing")
            or diag("warned: @$warnings");
    }
};

subtest 'the same-bytes-different-type leaves that round-trip are silent' => sub {
    # `08` and `1e3` are ints here and floats to Go; an RFC3339 string is a
    # time.Time to Go. All three come back from a sops write-back as the same
    # value, so warning about them would be noise -- ADR 0019 measured 3 such
    # false warnings for every real one under a plain type comparison.
    for my $source (qw( 007 08 09 1e3 0755e0 null ), '2015-01-01T12:00:00Z',
                    '2015-01-01T12:00:00.5Z') {
        my ($document, $died, $warnings) = encrypt_capturing(
            data => { v_unencrypted => yaml_leaf($source), s => 'x' });
        is($died, '', "[$source] is written");
        is_deeply($warnings, [], "[$source] and says nothing")
            or diag("warned: @$warnings");
    }
};

subtest 'an encrypted slot is silent' => sub {
    # By the time the emitter sees the tree the leaf is an ENC[...] string,
    # which no resolver looks twice at -- and sops decrypts it back to a
    # string, measured.
    for my $source (qw( True False )) {
        my ($document, $died, $warnings) = encrypt_capturing(
            data => { flag => yaml_leaf($source) });
        is($died, '', "[$source] an encrypted leaf is written");
        like($document, qr/^flag: ENC\[.*type:str\]$/m, "[$source] as type:str");
        is_deeply($warnings, [], "[$source] and says nothing")
            or diag("warned: @$warnings");
    }
};

subtest 'JSON is silent, in both slots' => sub {
    # Cpanel::JSON::XS quotes every string, so the document says "True" and Go
    # reads a string. Measured: sops -d gives "True" back in both slots.
    for my $slot (qw( flag_unencrypted flag )) {
        my @warnings;
        my $document = eval {
            local $SIG{__WARN__} = sub { push @warnings, $_[0] };
            File::SOPS->encrypt(data => { $slot => 'True', s => 'x' },
                recipients => [$public], format => 'json');
        };
        is($@, '', "[$slot] written as JSON");
        is_deeply(\@warnings, [], "[$slot] and says nothing")
            or diag("warned: @warnings");
    }
};

subtest 'the plaintext emitters stay silent' => sub {
    # A plaintext document has no MAC, no second reader and nothing a caller
    # can act on -- the same line ADR 0013 drew for the refusals.
    my @on_emit;
    {
        local $SIG{__WARN__} = sub { push @on_emit, $_[0] };
        my $out = File::SOPS::Format::YAML->emit({ flag => yaml_leaf('True') });
        like($out, qr/^flag: True$/m, 'emit writes the spelling straight out');
    }
    is_deeply(\@on_emit, [], 'and says nothing');

    my ($document) = encrypt_capturing(
        data => { flag_unencrypted => yaml_leaf('True'), s => 'x' });
    write_file("$tempdir/enc.yaml", $document);
    my @on_read;
    {
        local $SIG{__WARN__} = sub { push @on_read, $_[0] };
        File::SOPS->decrypt_file(input => "$tempdir/enc.yaml",
            output => "$tempdir/plain.yaml", identities => [$secret]);
    }
    is_deeply(\@on_read, [], 'and decrypting such a document says nothing');
};

###############################################################################
# 3. WHAT THE WARNING IS ABOUT. This is the part that is a claim about sops.
###############################################################################

SKIP: {
    skip "no sops binary (\$SOPS_BIN, PATH, /tmp/sops) -- the claim this file "
       . "makes about sops was NOT verified", 1
        unless $sops_bin;

    subtest 'sops reads a boolean, and a write-back makes it one here too' => sub {
        my ($document, $died, $warnings) = encrypt_capturing(
            data => { flag_unencrypted => yaml_leaf('True'), keep => 'v' });
        is(scalar @$warnings, 1, 'the encrypt warned once');

        my $file = "$tempdir/rt.yaml";
        write_file($file, $document);

        my $json = `$sops_bin -d --output-type json $file 2>&1`;
        is($? >> 8, 0, 'sops -d accepts the document') or diag($json);
        like($json, qr/"flag_unencrypted"\s*:\s*true/,
            'and reads a BOOLEAN out of it, where this module reads a string');

        my $before = File::SOPS->decrypt(encrypted => $document,
                                         identities => [$secret]);
        is(ref($before->{flag_unencrypted}), '',
            'this module reads a plain string before the write-back');
        is($before->{flag_unencrypted}, 'True', 'the string the caller passed');

        my $out = `$sops_bin rotate -i $file 2>&1`;
        is($? >> 8, 0, 'sops rotate rewrites the document') or diag($out);
        like(scalar read_file($file), qr/^flag_unencrypted: true$/m,
            'and writes the leaf back as a bare lowercase true');

        my $after = File::SOPS->decrypt(encrypted => scalar read_file($file),
                                        identities => [$secret]);
        is(ref($after->{flag_unencrypted}), 'JSON::PP::Boolean',
            'after which this module reads a BOOLEAN -- the divergence the '
          . 'warning is about');
    };
}

done_testing();
