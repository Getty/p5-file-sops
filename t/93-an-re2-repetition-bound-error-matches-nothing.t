#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurper qw(write_binary);
use Crypt::Age;

use File::SOPS;
use File::SOPS::Metadata;
use lib 't/lib';
use SopsBin qw(find_sops_bin);

# docs/adr/0073 (k216), "Repetition bounds RE2 refuses". RE2 refuses a count
# above 1000, a minimum above the maximum, and nested counts whose product is
# above 1000 -- and refuses the WHOLE pattern, a branch that cannot match
# included. sops discards the compile error, so the rule matches NOTHING: an
# unencrypted_regex then encrypts every key, an encrypted_regex leaves every
# key in plaintext. Perl compiles all of these, so without the scan an
# unencrypted_regex of '^a{1001}$' would leave plaintext where sops encrypts.
# The read path reproduces "matches nothing"; every write path refuses (ADR 0051).

my ($PUBLIC, $SECRET) = Crypt::Age->generate_keypair();

# 1 = the key is encrypted, 0 = it stays plaintext
sub encrypts_under {
    my ($field, $pattern, $key) = @_;
    return File::SOPS::Metadata->new($field => $pattern)->should_encrypt_path([ $key ]);
}

my @REFUSED = (
    [ '^a{1001}$',      'count above 1000' ],
    [ '^a{1001,}$',     'open count above 1000' ],
    [ '^.{1001,}$',     'open count above 1000 on a dot' ],
    [ '^a{1,1001}$',    'maximum above 1000' ],
    [ '^a{2,1}$',       'minimum above maximum' ],
    [ '^(a|b{1001})$',  'the bad branch is not the one that matches' ],
    [ '^(a{501}){2}$',  'nested product above 1000' ],
);

subtest 'read path: a pattern RE2 cannot compile matches nothing' => sub {
    for my $case (@REFUSED) {
        my ($pattern, $why) = @$case;
        for my $key ('a', 'aa') {
            is encrypts_under(unencrypted_regex => $pattern, $key), 1,
                "unencrypted_regex $pattern ($why): '$key' is encrypted";
            is encrypts_under(encrypted_regex => $pattern, $key), 0,
                "encrypted_regex $pattern ($why): '$key' stays plaintext";
        }
    }
};

# [ pattern, key ] -- RE2 compiles these and they hit the key
my @ACCEPTED = (
    [ '^a{1000}$',          'a' x 1000 ],
    [ '^(a{100}){10}$',     'a' x 1000 ],
    [ '^(a{1000}){0}b$',    'b' ],
);

subtest 'read path: the last good bounds still repeat' => sub {
    for my $case (@ACCEPTED) {
        my ($pattern, $key) = @$case;
        my $label = length($key) > 10 ? length($key) . ' x ' . substr($key, 0, 1) : $key;
        is encrypts_under(unencrypted_regex => $pattern, $key), 0,
            "unencrypted_regex $pattern selects '$label' (stays plaintext)";
        is encrypts_under(encrypted_regex => $pattern, $key), 1,
            "encrypted_regex $pattern selects '$label' (is encrypted)";
    }
    is encrypts_under(unencrypted_regex => '^a{1000}$', 'a' x 999), 1,
        '^a{1000}$ does not select 999 characters';
};

# The keys 'a' and 'aa' do not tell the buggy answer from the right one for
# every pattern (Perl does not match them against a{1001} either), so these are
# keys Perl WOULD select -- RE2 still matches nothing.
subtest 'read path: a key Perl would select is encrypted all the same' => sub {
    my %witness = (
        '^a{1001}$'     => 'a' x 1001,
        '^a{1001,}$'    => 'a' x 1001,
        '^.{1001,}$'    => 'a' x 1001,
        '^(a{501}){2}$' => 'a' x 1002,
    );
    for my $pattern (sort keys %witness) {
        my $key = $witness{$pattern};
        is encrypts_under(unencrypted_regex => $pattern, $key), 1,
            "unencrypted_regex $pattern: a " . length($key) . "-char key is encrypted";
        is encrypts_under(encrypted_regex => $pattern, $key), 0,
            "encrypted_regex $pattern: a " . length($key) . "-char key stays plaintext";
    }
};

subtest 'write path: every such pattern is refused' => sub {
    for my $case (@REFUSED) {
        my ($pattern) = @$case;
        for my $field (qw( unencrypted_regex encrypted_regex )) {
            my $err = do {
                local $@;
                eval {
                    File::SOPS->encrypt(
                        data       => { a => 'x' },
                        recipients => [ $PUBLIC ],
                        $field     => $pattern,
                    );
                    1;
                } ? '' : "$@";
            };
            like $err, qr/\QCannot use '$pattern' as the $field\E.*does not support/s,
                "$field $pattern: refused";
        }
    }
    for my $case (@ACCEPTED) {
        my ($pattern) = @$case;
        my $ok = eval {
            File::SOPS->encrypt(
                data => { a => 'x' }, recipients => [ $PUBLIC ],
                unencrypted_regex => $pattern,
            );
            1;
        };
        ok $ok, "$pattern is accepted for writing" or diag($@);
    }
};

subtest 'creation_rules_for refuses such a path_regex' => sub {
    for my $pattern ('^a{2,1}$', '^a{1001}$') {
        my $dir = tempdir(CLEANUP => 1);
        write_binary("$dir/.sops.yaml",
            "creation_rules:\n  - path_regex: '$pattern'\n    age: $PUBLIC\n");
        my $err = do {
            local $@;
            eval { File::SOPS->creation_rules_for(file => "$dir/a"); 1 } ? '' : "$@";
        };
        like $err, qr/\Q$pattern\E.*does not support/s, "$pattern is refused";
    }
};

SKIP: {
    my $sops_bin = find_sops_bin();
    skip 'no sops binary (set SOPS_BIN): the live comparison of these patterns '
       . 'with sops did NOT run', 1 unless $sops_bin;

    my $dir = tempdir(CLEANUP => 1);
    write_binary("$dir/key.txt", $SECRET);
    local $ENV{SOPS_AGE_KEY_FILE} = "$dir/key.txt";

    subtest 'sops and this library select the same keys' => sub {
        my $n = 0;
        my @live = ((map { [ $_->[0], 'a' ], [ $_->[0], 'aa' ] } @REFUSED), @ACCEPTED);
        for my $case (@live) {
            my ($pattern, $key) = @$case;
            my $file = "$dir/doc" . ++$n . '.json';
            my $q = $pattern; $q =~ s/'/'\\''/g;
            write_binary($file, qq({"$key": "hunter2"}\n));
            my $out = `'$sops_bin' -e -i --age '$PUBLIC' --input-type json --output-type json --unencrypted-regex '$q' '$file' 2>&1`;
            is $? >> 8, 0, "sops takes $pattern" or diag($out);
            my $plain = do { local $/; open my $fh, '<', $file or die $!; <$fh> } =~ /hunter2/ ? 1 : 0;
            is encrypts_under(unencrypted_regex => $pattern, $key), $plain ? 0 : 1,
                "$pattern over a " . length($key) . "-char key: library agrees with sops";
        }
    };
}

done_testing;
