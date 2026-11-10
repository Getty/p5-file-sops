#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);

use File::SOPS;

# A directory opens fine for reading and reads as undef, so it used to travel
# on and fail far from the cause ("content required", "encrypted required")
# without naming the path. Every public method that reads a file must refuse a
# directory up front, in the same words as any other unreadable file, and the
# message must carry the path.

my $dir = tempdir(CLEANUP => 1);
my $out = "$dir/out.yaml";
my $id  = 'AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ';
my $rec = 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p';

my %call = (
    decrypt_file => sub {
        File::SOPS->decrypt_file(input => $dir, output => $out, identities => [$id]);
    },
    encrypt_file => sub {
        File::SOPS->encrypt_file(input => $dir, output => $out, recipients => [$rec],
            format => 'yaml');
    },
    encrypt_in_place => sub {
        File::SOPS->encrypt_in_place(file => $dir, recipients => [$rec], format => 'yaml');
    },
    edit => sub {
        File::SOPS->edit(file => $dir, identities => [$id], editor => 'true',
            format => 'yaml');
    },
    rotate => sub {
        File::SOPS->rotate(file => $dir, identities => [$id], recipients => [$rec],
            format => 'yaml');
    },
    extract => sub {
        File::SOPS->extract(file => $dir, path => '["a"]', identities => [$id],
            format => 'yaml');
    },
    has_bare_lastmodified => sub {
        File::SOPS->has_bare_lastmodified(file => $dir, format => 'yaml');
    },
    'creation_rules_for (config)' => sub {
        File::SOPS->creation_rules_for(file => "$dir/x.yaml", config => $dir);
    },
);

for my $name (sort keys %call) {
    my $ok = eval { $call{$name}->(); 1 };
    my $err = $@;
    ok(!$ok, "$name: a directory is refused");
    like($err, qr/Cannot open .*\Q$dir\E/, "$name: the message names the path");
    unlike($err, qr/content required|encrypted required/,
        "$name: not the misleading downstream error");
}

done_testing;
