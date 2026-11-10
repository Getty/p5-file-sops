#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Path qw(make_path);
use File::Slurper qw(write_binary);
use Crypt::Age;

use File::SOPS;
use File::SOPS::Metadata;
use lib 't/lib';
use SopsBin qw(find_sops_bin);

# docs/adr/0073 (k216). Go's RE2 reads `{` as a repetition only as {n}, {n,} or
# {n,m} (numbers without a leading zero); any other brace is literal text.
# Perl reads `a{,3}` as a literal on 5.22-5.28, dies on it on 5.30-5.32 and
# takes it as {0,3} from 5.34. The rule must select the same keys on every
# perl, so the expectations below are RE2's -- measured against sops 3.13.3 and
# re-measured live at the bottom when a binary is present.

sub selects {
    my ($pattern, $key) = @_;
    return File::SOPS::Metadata->new(unencrypted_regex => $pattern)
        ->should_encrypt_path([ $key ]) ? 0 : 1;
}

# [ pattern, [ keys the rule hits ], [ keys it misses ] ]
my @CASES = (
    [ '^a{,3}$',   [ 'a{,3}' ],            [ 'aa', 'a', 'aaa', '' ] ],
    [ '^a{,}$',    [ 'a{,}' ],             [ 'a', 'aa', '' ] ],
    [ '^a{ 1,3}$', [ 'a{ 1,3}' ],          [ 'a', 'aa' ] ],
    [ '^a{a}$',    [ 'a{a}' ],             [ 'a', 'aa' ] ],
    [ '^a{1,$',    [ 'a{1,' ],             [ 'a', 'aa' ] ],
    [ '^a{01}$',   [ 'a{01}' ],            [ 'a' ] ],
    [ '^a{,3}b$',  [ 'a{,3}b' ],           [ 'ab', 'aab' ] ],
    [ '^a\{,3}$',  [ 'a{,3}' ],            [ 'aa', 'a' ] ],
    [ '^[a{]{,2}$', [ '{,2}' ],            [ 'a', 'aa', '{' ] ],
    # Real repetitions stay repetitions.
    [ '^a{1,3}$',  [ 'a', 'aaa' ],         [ 'a{1,3}', '', 'aaaa' ] ],
    [ '^a{3,}$',   [ 'aaa', 'aaaaa' ],     [ 'aa', 'a{3,}' ] ],
    [ '^a{2}$',    [ 'aa' ],               [ 'a', 'aaa', 'a{2}' ] ],
);

subtest 'a brace that is not an RE2 repetition matches itself' => sub {
    for my $case (@CASES) {
        my ($pattern, $hit, $miss) = @$case;
        for my $key (@$hit) {
            is selects($pattern, $key), 1, "$pattern hits '$key'";
        }
        for my $key (@$miss) {
            is selects($pattern, $key), 0, "$pattern misses '$key'";
        }
    }
};

subtest 'the braces of \\x{..} are escape syntax, not repetitions' => sub {
    my $meta = File::SOPS::Metadata->new(unencrypted_regex => '^\x{263a}{2}$');
    my $dies = !eval { $meta->should_encrypt_path([ "\x{263a}\x{263a}" ]); 1 };
    ok !$dies, '\x{263a}{2} compiles without a refusal' or diag($@);
    is selects('^\x{263a}{2}$', "\x{263a}\x{263a}"), 1, '  and repeats the character';
    is selects('^\x{263a}{2}$', "\x{263a}"),         0, '  exactly twice';
};

subtest 'creation_rules_for reads path_regex the same way' => sub {
    my $dir = tempdir(CLEANUP => 1);
    my ($pub) = Crypt::Age->generate_keypair();
    write_binary("$dir/.sops.yaml",
        "creation_rules:\n"
      . "  - path_regex: '^a{,3}\$'\n"
      . "    age: $pub\n");

    my %args = File::SOPS->creation_rules_for(file => "$dir/a{,3}");
    ok scalar(keys %args), "the file 'a{,3}' matches the rule";
    my $recipients = $args{recipients};
    is_deeply $recipients, [ $pub ], '  and gets its recipient';

    my $err = do {
        local $@;
        eval { File::SOPS->creation_rules_for(file => "$dir/aa"); 1 } ? '' : "$@";
    };
    unlike $err, qr/\A\z/, "the file 'aa' does not match (it is {0,3} to old perls)";
    like $err, qr/no creation rule|match/i, '  and no rule applies';
};

SKIP: {
    my $sops_bin = find_sops_bin();
    skip 'no sops binary (set SOPS_BIN): the live comparison of these patterns '
       . 'with sops did NOT run', 1 unless $sops_bin;

    my ($public, $secret) = Crypt::Age->generate_keypair();
    my $dir = tempdir(CLEANUP => 1);
    write_binary("$dir/key.txt", $secret);
    local $ENV{SOPS_AGE_KEY_FILE} = "$dir/key.txt";

    subtest 'sops and this library select the same keys' => sub {
        my $n = 0;
        for my $case (@CASES) {
            my ($pattern, $hit, $miss) = @$case;
            for my $key (grep { length } @$hit, @$miss) {
                my $file = "$dir/doc" . ++$n . '.json';
                my $q = $pattern; $q =~ s/'/'\\''/g;
                write_binary($file, qq({"$key": "hunter2"}\n));
                my $out = `'$sops_bin' -e -i --age '$public' --input-type json `
                        . `--output-type json --unencrypted-regex '$q' '$file' 2>&1`;
                is $? >> 8, 0, "sops takes $pattern over '$key'" or diag($out);
                my $sops_selects = do {
                    local $/; open my $fh, '<', $file or die $!; <$fh>
                } =~ /hunter2/ ? 1 : 0;
                is selects($pattern, $key), $sops_selects,
                    "$pattern over '$key': library agrees with sops";
            }
        }
    };
}

done_testing;
