#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurper qw(read_binary write_binary);
use YAML::XS qw(Load);
use JSON::MaybeXS ();
use FindBin;
use lib "$FindBin::Bin/../../t/lib";

use File::SOPS;
use SopsBin qw(find_sops_bin);

# A round trip against a REAL Vault (k39). Everything under t/ uses a mock
# transport; this is the file that proves the mock and Vault agree, and that
# the real sops reads what we write and we read what it writes.
#
#   VAULT_ADDR=http://127.0.0.1:18201 VAULT_TOKEN=root \
#       prove -l xt/author/hc-vault-live.t
#
# The transit key is transit/keys/sops-key (VAULT_TRANSIT_KEY overrides the
# name); the encrypt endpoint creates it if missing, as it does for sops.
plan skip_all => 'VAULT_ADDR is not set: this test needs a running Vault '
    . '(dev server) with the transit engine mounted at transit/ and a token in VAULT_TOKEN'
    unless $ENV{VAULT_ADDR};
plan skip_all => 'VAULT_TOKEN is not set (VAULT_ADDR is)'
    unless $ENV{VAULT_TOKEN};

(my $addr = $ENV{VAULT_ADDR}) =~ s{/+\z}{};
my $key   = $ENV{VAULT_TRANSIT_KEY} // 'sops-key';
my $uri   = "$addr/v1/transit/keys/$key";
my $data  = { a => 'secret', b => { c => 3, d => 'x y', e => JSON::MaybeXS->true } };
my $dir   = tempdir(CLEANUP => 1);

my $yaml = File::SOPS->encrypt(data => $data, hc_vault_transit_uris => [$uri], format => 'yaml');
my $sops = Load($yaml)->{sops};
is(scalar @{ $sops->{hc_vault} }, 1, 'Perl encrypt through the real Vault wrote one entry');
like($sops->{hc_vault}[0]{enc}, qr/\Avault:v\d+:/, 'with a real transit ciphertext');
is($sops->{hc_vault}[0]{key_name}, $key, 'for the named key');

is_deeply(File::SOPS->decrypt(encrypted => $yaml, format => 'yaml',
    vault_allowed_addresses => [$addr]), $data, 'Perl decrypt of its own document');

my $rotated = "$dir/rot.yaml";
write_binary($rotated, $yaml);
File::SOPS->rotate(file => $rotated);
is_deeply(File::SOPS->decrypt(encrypted => read_binary($rotated), format => 'yaml'), $data,
    'rotate through the real Vault keeps the document readable');

my $sops_bin = find_sops_bin();
SKIP: {
    skip 'no sops binary (SOPS_BIN, PATH, .sops-bin/sops, /tmp/sops): '
        . 'the sops direction is NOT checked in this run', 4 unless $sops_bin;

    # Perl -> sops
    my $f = "$dir/perl.yaml";
    write_binary($f, $yaml);
    my $out = `$sops_bin decrypt $f 2>&1`;
    is($?, 0, 'sops decrypt accepts the Perl-written document (MAC included)') or diag($out);
    is_deeply(Load($out), $data, '... and returns the same values');

    # sops -> Perl
    my $plain = "$dir/plain.yaml";
    write_binary($plain, "a: secret\nb:\n  c: 3\n  d: x y\n  e: true\n");
    my $enc = `$sops_bin encrypt --hc-vault-transit $uri $plain 2>&1`;
    is($?, 0, 'sops encrypt --hc-vault-transit works') or diag($enc);
    is_deeply(File::SOPS->decrypt(encrypted => $enc, format => 'yaml'), $data,
        'Perl decrypts what sops wrote');
}

done_testing;
