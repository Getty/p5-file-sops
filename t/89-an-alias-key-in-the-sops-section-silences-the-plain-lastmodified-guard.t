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

# docs/adr/0050: the plain-lastmodified guard speaks only about documents
# sops refuses. A sops section that writes `lastmodified` plain AND again
# through an ALIAS key (`*k : "<quoted>"`) is read by sops -- yaml.v3 does not
# see the alias key as a duplicate and the later, quoted entry wins -- so the
# guard must stay quiet and File::SOPS->has_bare_lastmodified must say false,
# both from the one predicate.

my $dir = tempdir(CLEANUP => 1);
my ($pub, $sec) = Crypt::Age->generate_keypair();
my %DATA = (alpha => 'one', beta => 42);

my $doc = File::SOPS->encrypt(
    data => {%DATA}, recipients => [$pub], format => 'yaml',
);

my ($stamp) = $doc =~ /^\s+lastmodified: "([^"]+)"$/m
    or die 'the fixture has no quoted lastmodified';

# The card's shape: anchor, plain entry first, alias-keyed quoted entry after.
(my $alias = $doc) =~ s/^(\s+)lastmodified: "\Q$stamp\E"$/${1}x_anchor: &k lastmodified\n${1}lastmodified: $stamp\n${1}*k : "$stamp"/m
    or die 'could not rewrite lastmodified';
# Control: an ordinary plain lastmodified, no alias.
(my $plain = $doc) =~ s/^(\s+lastmodified: )"\Q$stamp\E"$/$1$stamp/m
    or die 'could not rewrite lastmodified';

sub read_back {
    my ($text) = @_;
    my @warned;
    my $data = do {
        local $SIG{__WARN__} = sub { push @warned, $_[0] };
        File::SOPS->decrypt(encrypted => $text, identities => [$sec], format => 'yaml');
    };
    my $parse_warned = do {
        my @w;
        local $SIG{__WARN__} = sub { push @w, $_[0] };
        File::SOPS::Format::YAML->parse($text);
        scalar grep { /PLAIN scalar/ } @w;
    };
    return ($data, [grep { /PLAIN scalar/ } @warned], $parse_warned);
}

sub bare { File::SOPS->has_bare_lastmodified(encrypted => $_[0], format => 'yaml') }

subtest 'the alias-keyed duplicate: no warning, query says false' => sub {
    my ($data, $warned, $parse_warned) = read_back($alias);
    is_deeply $data, {%DATA}, 'the values are read';
    is scalar @$warned, 0, 'decrypt does not warn' or diag explain $warned;
    is $parse_warned, 0, 'parse does not warn';
    ok !bare($alias), 'has_bare_lastmodified is false';
};

subtest 'control: an ordinary plain lastmodified still warns and answers true' => sub {
    my ($data, $warned, $parse_warned) = read_back($plain);
    is scalar @$warned, 1, 'decrypt warns once';
    is $parse_warned, 1, 'parse warns';
    ok bare($plain), 'has_bare_lastmodified is true';
};

SKIP: {
    my $sops_bin = find_sops_bin();
    skip 'No sops binary found -- whether sops reads the alias document went unmeasured', 2
        unless $sops_bin;

    open my $kf, '>', "$dir/key.txt" or die $!; print $kf $sec; close $kf;
    local $ENV{SOPS_AGE_KEY_FILE} = "$dir/key.txt";
    sub run_sops {
        my ($text, $name) = @_;
        open my $fh, '>', "$dir/$name" or die $!; print $fh $text; close $fh;
        system("$sops_bin -d --input-type yaml --output-type yaml $dir/$name >/dev/null 2>&1");
        return $? >> 8;
    }
    is run_sops($alias, 'alias.yaml'), 0, 'sops -d reads the alias document (exit 0)';
    is run_sops($plain, 'plain.yaml'), 1, 'and refuses the plain control (exit 1)';
}

done_testing;
