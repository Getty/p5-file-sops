#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use Crypt::Age;

use File::SOPS;
use File::SOPS::Format::YAML;
use lib 't/lib';
use SopsBin qw(find_sops_bin);

# File::SOPS->has_bare_lastmodified answers, as a public query, the question
# the read side only answers by warning (docs/adr/0050): is the first
# document's root `sops` mapping's `lastmodified` an UNTAGGED PLAIN scalar
# that go-yaml resolves to a time.Time? sops refuses such a document whole;
# `rotate` repairs it. The query decrypts nothing, verifies no MAC, needs no
# identities, and must never itself warn.
#
# The tests drive the real parser for the "same check as the warning" claim
# and the real sops binary (when there is one) for the claim that the bare
# file is the one sops refuses -- a table of expectations written next to the
# implementation would only prove the implementation agrees with itself.

can_ok('File::SOPS', 'has_bare_lastmodified');

# Every call goes through here: nothing the query does may reach
# $SIG{__WARN__}, and a missing method must show up as a failing assertion
# rather than abort the file.
my @LEAKED;
sub ask {
    my (%args) = @_;
    my $result = eval {
        local $SIG{__WARN__} = sub { push @LEAKED, $_[0] };
        File::SOPS->has_bare_lastmodified(%args);
    };
    diag("has_bare_lastmodified died: $@") if $@;
    return $result;
}

# For the refusals: the error must come from the method, not from its absence.
sub refused {
    my ($label, %args) = @_;
    my $error = do {
        local $@;
        local $SIG{__WARN__} = sub { push @LEAKED, $_[0] };
        eval { File::SOPS->has_bare_lastmodified(%args); 1 } ? '' : $@;
    };
    ok $error ne '' && $error !~ /Can't locate object method/, $label
        or diag("error was: '$error'");
}

my $T = '2026-08-21T09:05:08Z';

###############################################################################
# 1. The table. 1 = bare, 0 = not. Expectations are by the specified rule
#    (first document, root sops mapping, untagged plain, timestamp-shaped);
#    the third subtest checks them against the real parser as well.
###############################################################################
my @TABLE = (
    [ "sops:\n    lastmodified: $T\n",                       1, 'bare RFC3339' ],
    [ "sops:\n    lastmodified: 2026-08-21T11:05:08+02:00\n", 1, 'bare, with an offset' ],
    [ "sops:\n    lastmodified: 2026-08-21T09:05:08.123456789Z\n",
                                                              1, 'bare, with a fraction' ],
    [ "sops:\n    lastmodified: 2026-08-21T11:05:08.5+02:00\n",
                                                              1, 'bare, with fraction and offset' ],
    [ "sops:\n    age: []\n    lastmodified: $T\n    mac: x\n",
                                                              1, 'bare, between real siblings' ],
    [ "sops:\n    lastmodified: \"$T\"\n",                    0, 'double-quoted' ],
    [ "sops:\n    lastmodified: '$T'\n",                      0, 'single-quoted' ],
    [ "sops:\n    lastmodified: !!str $T\n",                  0, 'plain but !!str tagged' ],
    [ "sops:\n    lastmodified: hello\n",                     0, 'plain, not a timestamp' ],
    [ "sops:\n    lastmodified: 2026-08-21T09:05:08\n",       0, 'plain, no zone, not a timestamp to go-yaml' ],
    [ "lastmodified: $T\nsops:\n    lastmodified: \"$T\"\n",  0, "a user's bare lastmodified beside a quoted sops one" ],
    [ "a:\n    lastmodified: $T\n",                            0, "a user's lastmodified, no sops section" ],
    [ "lastmodified: $T\n",                                   0, 'only a top-level user lastmodified' ],
    [ "sops:\n    x:\n        lastmodified: $T\n",            0, 'nested one level inside sops' ],
    [ "a: 1\n",                                               0, 'no sops section at all' ],
    [ "x: &t $T\nsops:\n    lastmodified: *t\n",              0, 'an alias' ],
    [ "sops:\n    lastmodified:\n        $T\n",               1, 'bare, on the line below its key' ],
    [ "sops: {lastmodified: $T}\n",                           1, 'bare inside a flow mapping' ],
    [ "sops: {lastmodified: \"$T\"}\n",                       0, 'quoted inside a flow mapping' ],
    [ "sops:\n    ? lastmodified\n    : $T\n",                 1, 'bare behind an explicit ? key' ],
    [ "a: 1\nsops:\n    lastmodified: $T\n---\nb: 2\n",        1, 'multi-document, bare in the first document' ],
    [ "a: 1\nsops:\n    lastmodified: \"$T\"\n---\nb: 2\nsops:\n    lastmodified: $T\n",
                                                              0, 'multi-document, bare only in a later document' ],
    [ "a: 1\n---\nb: 2\nsops:\n    lastmodified: $T\n",         0, 'multi-document, sops section only in a later document' ],
);

subtest 'raw text: every spelling answers exactly 1 or 0' => sub {
    for my $row (@TABLE) {
        my ($doc, $want, $label) = @$row;
        is ask(encrypted => $doc, format => 'yaml'), $want, "$label (format => 'yaml')";
    }
};

subtest 'raw text: the format is detected from the content when not given' => sub {
    is ask(encrypted => "sops:\n    lastmodified: $T\n"), 1, 'bare, YAML detected';
    is ask(encrypted => "sops:\n    lastmodified: \"$T\"\n"), 0, 'quoted, YAML detected';
};

###############################################################################
# 2. The same check as the warning
###############################################################################
subtest 'answers 1 exactly when parse emits the plain-lastmodified warning' => sub {
    my $compared = 0;
    for my $row (@TABLE) {
        my ($doc, undef, $label) = @$row;

        my @warned;
        my $parsed = eval {
            local $SIG{__WARN__} = sub { push @warned, $_[0] };
            File::SOPS::Format::YAML->parse($doc);
            1;
        };
        unless ($parsed) {
            # Only documents parse accepts are comparable (not a verdict).
            note("skipped, parse refuses it: $label");
            next;
        }
        $compared++;

        my @plain = grep {
            /\Asops:lastmodified: this timestamp is written as a PLAIN scalar/
        } @warned;
        is ask(encrypted => $doc, format => 'yaml'), (@plain ? 1 : 0),
            "$label: query agrees with the read-side warning";
    }
    cmp_ok $compared, '>=', 10, 'a meaningful share of the table was comparable';
};

###############################################################################
# 3. File form and argument handling
###############################################################################
my $dir = tempdir(CLEANUP => 1);

sub put {
    my ($path, $bytes) = @_;
    open my $fh, '>:raw', $path or die "open $path: $!";
    print $fh $bytes;
    close $fh or die "close $path: $!";
    return $path;
}

my $BARE   = "a: 1\nsops:\n    lastmodified: $T\n";
my $QUOTED = "a: 1\nsops:\n    lastmodified: \"$T\"\n";

subtest 'file form' => sub {
    is ask(file => put("$dir/bare.yaml",   $BARE)),   1, 'a .yaml file, bare';
    is ask(file => put("$dir/quoted.yaml", $QUOTED)), 0, 'a .yaml file, quoted';
    is ask(file => put("$dir/bare.yml",    $BARE)),   1, 'a .yml file, bare';
    is ask(file => put("$dir/noext",       $BARE)),   1,
        'no extension: filename detection falls back to yaml, as decrypt_file does';
    is ask(file => "$dir/bare.yaml", format => 'yaml'), 1, 'explicit format with the file';
    is ask(file => put("$dir/odd.dat", $BARE), format => 'yaml'), 1,
        'an unrecognised extension plus format => yaml';
    is ask(file => put("$dir/data.json",
            qq({"sops": {"lastmodified": "$T"}}\n))), 0, 'a .json file';
    is ask(file => put("$dir/bare.json", qq({"sops": {"lastmodified": $T}}\n)),
           format => 'json'), 0, 'JSON always answers 0';
    is ask(encrypted => "FOO=1\nsops_lastmodified=$T\n", format => 'env'), 0,
        'dotenv always answers 0';
    is ask(encrypted => "[sops]\nlastmodified = $T\n", format => 'ini'), 0,
        'INI always answers 0';
};

subtest 'bad arguments croak' => sub {
    refused('a nonexistent file', file => "$dir/does-not-exist.yaml");
    refused('neither file nor encrypted');
    refused('both file and encrypted', file => "$dir/bare.yaml", encrypted => $BARE);
    refused('an unknown format (encrypted)', encrypted => $BARE, format => 'toml');
    refused('an unknown format (file)', file => "$dir/bare.yaml", format => 'toml');
};

###############################################################################
# 4. No decryption, no identities
###############################################################################
my ($pub, $sec) = Crypt::Age->generate_keypair();

subtest 'needs no identities and does not look at the MAC' => sub {
    my ($other_pub) = Crypt::Age->generate_keypair();   # secret thrown away
    my $doc = File::SOPS->encrypt(
        data => { secret => 'hunter2' }, recipients => [$other_pub], format => 'yaml',
    );
    (my $bare = $doc) =~ s/^(\s+lastmodified: )"([^"]*)"$/$1$2/m
        or die 'the fixture has no quoted lastmodified';

    is ask(encrypted => $doc),  0, 'a real quoted document, nobody holds the key';
    is ask(encrypted => $bare), 1, 'the same document made bare';

    (my $broken = $bare) =~ s/^(\s+mac: ).*$/${1}ENC[AES256_GCM,data:AAAA,iv:AAAA,tag:AAAA,type:str]/m
        or die 'the fixture has no mac line';
    is ask(encrypted => $broken), 1, 'a corrupted MAC is not looked at';
};

###############################################################################
# 5. The repair: bare -> rotate -> not bare, data unchanged
###############################################################################
my %DATA = (alpha => 'one', beta => 42);

sub decrypt_quietly {
    my ($text) = @_;
    local $SIG{__WARN__} = sub { };
    return File::SOPS->decrypt(
        encrypted => $text, identities => [$sec], format => 'yaml',
    );
}

sub slurp {
    my ($path) = @_;
    open my $fh, '<:raw', $path or die "open $path: $!";
    local $/;
    return scalar <$fh>;
}

my $made = File::SOPS->encrypt(data => { %DATA }, recipients => [$pub], format => 'yaml');
(my $made_bare = $made) =~ s/^(\s+lastmodified: )"([^"]*)"$/$1$2/m
    or die 'the fixture has no quoted lastmodified';

subtest 'rotate repairs a file the query flags' => sub {
    is ask(encrypted => $made), 0, 'a freshly written document is not bare';

    my $path = put("$dir/repair.yaml", $made_bare);
    is ask(file => $path), 1, 'turned bare by text substitution: flagged';
    is_deeply decrypt_quietly($made_bare), { %DATA },
        'and the substituted text still decrypts (the MAC is over the same AAD)';

    {
        local $SIG{__WARN__} = sub { };
        File::SOPS->rotate(file => $path, identities => [$sec], format => 'yaml');
    }

    is ask(file => $path), 0, 'after rotate: not bare';
    is_deeply decrypt_quietly(slurp($path)), { %DATA }, 'and the data is unchanged';
};

SKIP: {
    my $sops_bin = find_sops_bin();
    skip 'No sops binary found -- that sops refuses the bare file and reads '
       . 'the rotated one went unmeasured here', 1
        unless $sops_bin;

    diag("Using sops binary: $sops_bin");
    put("$dir/key.txt", $sec);
    local $ENV{SOPS_AGE_KEY_FILE} = "$dir/key.txt";

    subtest 'sops -d refuses what the query flags and reads what rotate wrote' => sub {
        my $sops = sub {
            my ($path) = @_;
            my $out = `$sops_bin -d --input-type yaml --output-type json '$path' 2>&1`;
            return ($? >> 8, $out);
        };

        my $bare_path = put("$dir/sops-bare.yaml", $made_bare);
        is ask(file => $bare_path), 1, 'flagged';
        my ($rc, $out) = $sops->($bare_path);
        is $rc, 1, 'sops -d exits 1 on it';
        like $out, qr/unconvertible type 'time\.Time'/, 'and it is the resolver that refuses';

        {
            local $SIG{__WARN__} = sub { };
            File::SOPS->rotate(file => $bare_path, identities => [$sec], format => 'yaml');
        }
        is ask(file => $bare_path), 0, 'rotated: not flagged';
        ($rc) = $sops->($bare_path);
        is $rc, 0, 'sops -d exits 0 on the rotated file';
    };
}

###############################################################################
# Nothing above made the query warn
###############################################################################
is scalar @LEAKED, 0, 'has_bare_lastmodified never warned, over every call'
    or diag(explain(\@LEAKED));

done_testing;
