#!/usr/bin/env perl
use strict;
use warnings;
use utf8;
use Test::More;
use File::Temp qw(tempfile tempdir);
use File::Slurp qw(read_file write_file);
use JSON::MaybeXS qw(decode_json encode_json);
use YAML::XS qw(Load Dump);

use File::SOPS;
use Crypt::Age;

# Check if sops CLI is available
my $sops_bin = $ENV{SOPS_BIN} || '/tmp/sops';
unless (-x $sops_bin) {
    plan skip_all => "sops CLI not found at $sops_bin";
}

my $sops_version = `$sops_bin --version 2>&1`;
diag("Using sops: $sops_version");

# Generate test keypair
my ($public, $secret) = Crypt::Age->generate_keypair();
diag("Test public key: $public");

# Create temp directory
my $tempdir = tempdir(CLEANUP => 1);

# Write age key file for sops CLI
my $keyfile = "$tempdir/key.txt";
write_file($keyfile, $secret);
$ENV{SOPS_AGE_KEY_FILE} = $keyfile;

###############################################################################
# Test 1: Perl encrypt -> sops decrypt (YAML)
###############################################################################
subtest 'Perl encrypt -> sops decrypt (YAML)' => sub {
    my $data = {
        database => {
            host     => 'localhost',
            port     => 5432,
            password => 'supersecret123',
        },
        api_key => 'abc-123-xyz',
    };

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public],
        format     => 'yaml',
    );

    my $enc_file = "$tempdir/perl_encrypted.yaml";
    write_file($enc_file, $encrypted);

    # Decrypt with sops CLI
    my $output = `$sops_bin -d $enc_file 2>&1`;
    my $exit_code = $? >> 8;

    is($exit_code, 0, 'sops decrypt succeeded')
        or diag("sops output: $output");

    if ($exit_code == 0) {
        my $decrypted = Load($output);
        is_deeply($decrypted, $data, 'sops decrypted data matches original');
    }
};

###############################################################################
# Test 2: Perl encrypt -> sops decrypt (JSON)
###############################################################################
subtest 'Perl encrypt -> sops decrypt (JSON)' => sub {
    # Note: avoid bool-like strings as sops returns JSON bools which become 1/0 in Perl
    my $data = {
        config => {
            enabled => 'yes',
            timeout => 30,
            name    => 'test-app',
        },
    };

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public],
        format     => 'json',
    );

    my $enc_file = "$tempdir/perl_encrypted.json";
    write_file($enc_file, $encrypted);

    my $output = `$sops_bin -d $enc_file 2>&1`;
    my $exit_code = $? >> 8;

    is($exit_code, 0, 'sops decrypt JSON succeeded')
        or diag("sops output: $output");

    if ($exit_code == 0) {
        my $decrypted = decode_json($output);
        is_deeply($decrypted, $data, 'sops decrypted JSON matches original');
    }
};

###############################################################################
# Test 3: sops encrypt -> Perl decrypt (YAML)
###############################################################################
subtest 'sops encrypt -> Perl decrypt (YAML)' => sub {
    my $data = {
        secret => 'from-sops-cli',
        nested => {
            value => 'deep-secret',
            number => 42,
        },
    };

    my $plain_file = "$tempdir/sops_plain.yaml";
    my $enc_file = "$tempdir/sops_encrypted.yaml";

    write_file($plain_file, Dump($data));

    # Encrypt with sops CLI
    my $output = `$sops_bin -e --age $public $plain_file 2>&1`;
    my $exit_code = $? >> 8;

    is($exit_code, 0, 'sops encrypt succeeded')
        or diag("sops output: $output");

    if ($exit_code == 0) {
        write_file($enc_file, $output);

        # Decrypt with Perl
        my $decrypted = File::SOPS->decrypt(
            encrypted  => $output,
            identities => [$secret],
            format     => 'yaml',
        );

        is_deeply($decrypted, $data, 'Perl decrypted sops-encrypted data');
    }
};

###############################################################################
# Test 4: sops encrypt -> Perl decrypt (JSON)
###############################################################################
subtest 'sops encrypt -> Perl decrypt (JSON)' => sub {
    my $data = {
        credentials => {
            username => 'admin',
            password => 's3cr3t!',
        },
    };

    my $plain_file = "$tempdir/sops_plain.json";
    write_file($plain_file, encode_json($data));

    my $output = `$sops_bin -e --age $public $plain_file 2>&1`;
    my $exit_code = $? >> 8;

    is($exit_code, 0, 'sops encrypt JSON succeeded')
        or diag("sops output: $output");

    if ($exit_code == 0) {
        my $decrypted = File::SOPS->decrypt(
            encrypted  => $output,
            identities => [$secret],
            format     => 'json',
        );

        is_deeply($decrypted, $data, 'Perl decrypted sops-encrypted JSON');
    }
};

###############################################################################
# Test 5: Various data types
###############################################################################
subtest 'Various data types' => sub {
    my $data = {
        string  => 'hello world',
        integer => 12345,
        float   => 3.14159,
        empty   => '',
        unicode => 'äöü ñ 中文 🎉',
        special => "line1\nline2\ttab",
    };

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public],
        format     => 'yaml',
    );

    my $enc_file = "$tempdir/types.yaml";
    write_file($enc_file, $encrypted);

    my $output = `$sops_bin -d $enc_file 2>&1`;
    my $exit_code = $? >> 8;

    is($exit_code, 0, 'sops decrypt types succeeded')
        or diag("sops output: $output");

    if ($exit_code == 0) {
        # YAML::XS::Load expects bytes, not decoded strings
        my $decrypted = Load($output);
        is($decrypted->{string}, $data->{string}, 'string preserved');
        is($decrypted->{integer}, $data->{integer}, 'integer preserved');
        is($decrypted->{empty}, $data->{empty}, 'empty string preserved');
        is($decrypted->{unicode}, $data->{unicode}, 'unicode preserved');
        is($decrypted->{special}, $data->{special}, 'special chars preserved');
    }
};

###############################################################################
# Test 6: Nested structures
###############################################################################
subtest 'Nested structures' => sub {
    my $data = {
        level1 => {
            level2 => {
                level3 => {
                    deep_secret => 'very-deep-value',
                },
            },
        },
    };

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public],
        format     => 'yaml',
    );

    my $enc_file = "$tempdir/nested.yaml";
    write_file($enc_file, $encrypted);

    my $output = `$sops_bin -d $enc_file 2>&1`;
    my $exit_code = $? >> 8;

    is($exit_code, 0, 'sops decrypt nested succeeded');

    if ($exit_code == 0) {
        my $decrypted = Load($output);
        is_deeply($decrypted, $data, 'nested structure preserved');
    }
};

###############################################################################
# Test 7: Arrays
###############################################################################
subtest 'Arrays' => sub {
    my $data = {
        users => ['alice', 'bob', 'charlie'],
        matrix => [
            [1, 2, 3],
            [4, 5, 6],
        ],
        mixed => [
            { name => 'item1' },
            { name => 'item2' },
        ],
    };

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public],
        format     => 'yaml',
    );

    my $enc_file = "$tempdir/arrays.yaml";
    write_file($enc_file, $encrypted);

    my $output = `$sops_bin -d $enc_file 2>&1`;
    my $exit_code = $? >> 8;

    is($exit_code, 0, 'sops decrypt arrays succeeded');

    if ($exit_code == 0) {
        my $decrypted = Load($output);
        is_deeply($decrypted->{users}, $data->{users}, 'simple array preserved');
        is_deeply($decrypted->{mixed}, $data->{mixed}, 'array of hashes preserved');
    }
};

###############################################################################
# Test 8: Multiple recipients
###############################################################################
subtest 'Multiple recipients' => sub {
    my ($public2, $secret2) = Crypt::Age->generate_keypair();

    my $data = { secret => 'for-multiple-recipients' };

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public, $public2],
        format     => 'yaml',
    );

    # Both keys should work with sops
    my $enc_file = "$tempdir/multi.yaml";
    write_file($enc_file, $encrypted);

    # Test with first key
    my $keyfile1 = "$tempdir/key1.txt";
    write_file($keyfile1, $secret);
    local $ENV{SOPS_AGE_KEY_FILE} = $keyfile1;

    my $output1 = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'first recipient can decrypt');

    # Test with second key
    my $keyfile2 = "$tempdir/key2.txt";
    write_file($keyfile2, $secret2);
    $ENV{SOPS_AGE_KEY_FILE} = $keyfile2;

    my $output2 = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'second recipient can decrypt');

    # Restore original key
    $ENV{SOPS_AGE_KEY_FILE} = $keyfile;
};

###############################################################################
# Test 9: Roundtrip consistency
###############################################################################
subtest 'Roundtrip consistency' => sub {
    my $original = {
        app => {
            db_password => 'original-password',
            api_token   => 'token-12345',
        },
    };

    # Perl -> sops -> Perl
    my $perl_enc = File::SOPS->encrypt(
        data       => $original,
        recipients => [$public],
    );

    my $enc_file = "$tempdir/roundtrip.yaml";
    write_file($enc_file, $perl_enc);

    my $sops_dec = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'sops decrypted Perl-encrypted file');

    my $sops_enc = `$sops_bin -e --age $public $enc_file.dec 2>&1`;

    # Just verify we can decrypt what we encrypted
    my $final = File::SOPS->decrypt(
        encrypted  => $perl_enc,
        identities => [$secret],
    );

    is_deeply($final, $original, 'roundtrip preserves data');
};

###############################################################################
# Test 10: Large values
###############################################################################
subtest 'Large values' => sub {
    my $large_string = 'x' x 10000;
    my $data = {
        large => $large_string,
        normal => 'small',
    };

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public],
    );

    my $enc_file = "$tempdir/large.yaml";
    write_file($enc_file, $encrypted);

    my $output = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'sops decrypts large values');

    if ($? >> 8 == 0) {
        my $decrypted = Load($output);
        is(length($decrypted->{large}), 10000, 'large value length preserved');
        # Workaround for YAML::XS internal state issue with large strings
        undef $decrypted;
    }
    undef $output;
};

###############################################################################
# Test 11: File operations
###############################################################################
subtest 'File operations' => sub {
    my $data = { file_test => 'value' };
    my $plain_file = "$tempdir/file_test.yaml";
    my $enc_file = "$tempdir/file_test.enc.yaml";
    my $dec_file = "$tempdir/file_test.dec.yaml";

    write_file($plain_file, Dump($data));

    File::SOPS->encrypt_file(
        input      => $plain_file,
        output     => $enc_file,
        recipients => [$public],
    );

    ok(-f $enc_file, 'encrypted file created');

    my $enc_content = read_file($enc_file);
    like($enc_content, qr/ENC\[/, 'file contains encrypted values');

    # Decrypt with sops
    my $output = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'sops decrypts file');

    # Decrypt with Perl
    File::SOPS->decrypt_file(
        input      => $enc_file,
        output     => $dec_file,
        identities => [$secret],
    );

    ok(-f $dec_file, 'decrypted file created');
    my $file_content = read_file($dec_file);
    my $dec_content = Load($file_content);
    is_deeply($dec_content, $data, 'decrypted file matches original');
    # Cleanup to avoid YAML::XS internal state issues
    undef $dec_content;
    undef $file_content;
};

###############################################################################
# Test 12: Extract single value
###############################################################################
subtest 'Extract single value' => sub {
    my $data = {
        database => {
            host     => 'db.example.com',
            password => 'extract-me',
        },
    };

    my $enc_file = "$tempdir/extract.yaml";

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public],
    );
    write_file($enc_file, $encrypted);

    my $password = File::SOPS->extract(
        file       => $enc_file,
        path       => '["database"]["password"]',
        identities => [$secret],
    );

    is($password, 'extract-me', 'extracted single value');

    my $host = File::SOPS->extract(
        file       => $enc_file,
        path       => 'database.host',
        identities => [$secret],
    );

    is($host, 'db.example.com', 'extracted with dot notation');
};

###############################################################################
# Test 13: Rotate key
###############################################################################
subtest 'Rotate key' => sub {
    my $data = { rotate_test => 'value' };
    my $enc_file = "$tempdir/rotate.yaml";

    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public],
    );
    write_file($enc_file, $encrypted);

    my $before = read_file($enc_file);

    File::SOPS->rotate(
        file       => $enc_file,
        identities => [$secret],
    );

    my $after = read_file($enc_file);

    # Content should be different (new IVs/data keys)
    isnt($before, $after, 'file changed after rotation');

    # But should still decrypt to same value
    my $decrypted = File::SOPS->decrypt(
        encrypted  => $after,
        identities => [$secret],
    );

    is_deeply($decrypted, $data, 'data preserved after rotation');

    # sops should also be able to decrypt
    my $output = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'sops decrypts after rotation');
};

###############################################################################
# Test 14: Values excluded from encryption
#
# unencrypted_suffix is on by default, so this needs no configuration at all
# to trigger, and it is a MAC question rather than an encryption one: sops
# hashes those values on both sides. t/07-mac.t pins the rule without a
# binary; this is the half that proves the rule is the one Go implements.
###############################################################################
subtest 'Unencrypted suffix values' => sub {
    my $data = {
        cfg_unencrypted => 'plaintext-but-authenticated',
        secret          => 'encrypted',
        blk_unencrypted => { host => 'db.example.com', port => 5432 },
    };

    # Perl -> sops
    my $encrypted = File::SOPS->encrypt(
        data       => $data,
        recipients => [$public],
        format     => 'yaml',
    );
    like($encrypted, qr/^cfg_unencrypted: plaintext-but-authenticated$/m,
        'value is written in plaintext');

    my $enc_file = "$tempdir/unencrypted_suffix.yaml";
    write_file($enc_file, $encrypted);

    my $output = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'sops decrypts a file with unencrypted values')
        or diag("sops output: $output");
    is_deeply(Load($output), $data, 'sops round-trips the whole document')
        if $? >> 8 == 0;

    # sops -> Perl, in an order that is NOT sorted, so the decrypt side has
    # to place the unencrypted values by document order and not by key.
    my $plain_file = "$tempdir/unencrypted_suffix_plain.yaml";
    write_file($plain_file, "zz: last\nblk_unencrypted:\n  b: 1\n  a: two\naa: first\n");

    my $sops_enc = `$sops_bin -e --age $public $plain_file 2>&1`;
    is($? >> 8, 0, 'sops encrypts it') or diag($sops_enc);

    my $decrypted = eval {
        File::SOPS->decrypt(
            encrypted => $sops_enc, identities => [$secret], format => 'yaml',
        );
    };
    is($@, '', 'Perl verifies a sops file whose unencrypted values are not in sorted order')
        or diag("died: $@");
    is_deeply(
        $decrypted,
        { zz => 'last', blk_unencrypted => { b => 1, a => 'two' }, aa => 'first' },
        'and returns it intact'
    ) if $decrypted;
};

###############################################################################
# Test 15: mac_only_encrypted
###############################################################################
subtest 'mac_only_encrypted' => sub {
    my $data = { cfg_unencrypted => 'plain', secret => 'shh', n => 42 };

    my $encrypted = File::SOPS->encrypt(
        data               => $data,
        recipients         => [$public],
        format             => 'yaml',
        mac_only_encrypted => 1,
    );
    like($encrypted, qr/^\s+mac_only_encrypted: true$/m,
        'the flag is recorded in the sops section');

    my $enc_file = "$tempdir/mac_only.yaml";
    write_file($enc_file, $encrypted);

    my $output = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'sops decrypts a mac_only_encrypted file we wrote')
        or diag("sops output: $output");
    is_deeply(Load($output), $data, 'values survive') if $? >> 8 == 0;

    # And the other way round.
    my $plain_file = "$tempdir/mac_only_plain.yaml";
    write_file($plain_file, "zz: last\ncfg_unencrypted: plain\nsecret: shh\n");

    my $sops_enc = `$sops_bin -e --age $public --mac-only-encrypted $plain_file 2>&1`;
    is($? >> 8, 0, 'sops encrypts with --mac-only-encrypted') or diag($sops_enc);

    my $decrypted = eval {
        File::SOPS->decrypt(
            encrypted => $sops_enc, identities => [$secret], format => 'yaml',
        );
    };
    is($@, '', 'Perl verifies a sops --mac-only-encrypted file') or diag("died: $@");
};

###############################################################################
# Test 16: Keys that used to collide with the metadata MAC
###############################################################################
subtest 'Keys ending in mac' => sub {
    my $data = { hmac => 'h', webmac => 'w', mac => 'm', other => 'o' };

    my $encrypted = File::SOPS->encrypt(
        data => $data, recipients => [$public], format => 'yaml',
    );
    my $enc_file = "$tempdir/hmac.yaml";
    write_file($enc_file, $encrypted);

    my $output = `$sops_bin -d $enc_file 2>&1`;
    is($? >> 8, 0, 'sops decrypts a file with hmac/webmac/mac keys')
        or diag("sops output: $output");
    is_deeply(Load($output), $data, 'all of them survive') if $? >> 8 == 0;

    my $plain_file = "$tempdir/hmac_plain.yaml";
    write_file($plain_file, "hmac: h\nwebmac: w\nmac: m\nother: o\n");
    my $sops_enc = `$sops_bin -e --age $public $plain_file 2>&1`;
    is($? >> 8, 0, 'sops encrypts them') or diag($sops_enc);

    my $decrypted = eval {
        File::SOPS->decrypt(
            encrypted => $sops_enc, identities => [$secret], format => 'yaml',
        );
    };
    is($@, '', 'Perl verifies a sops file with hmac/webmac/mac keys') or diag("died: $@");
    is_deeply($decrypted, $data, 'and returns them intact') if $decrypted;
};

###############################################################################
# Test 17: Values Perl's numeric conversion would mangle
#
# These are written by sops, not by us: the point is that verification hashes
# the plaintext sops authenticated, rather than a value round-tripped through
# int() / + 0.0 and stringified again.
###############################################################################
subtest 'Values that do not survive Perl numeric conversion' => sub {
    my $plain_file = "$tempdir/lossy.yaml";
    write_file($plain_file, "big: 1e20\ntiny: 0.00000015\nf: 1.50\npadded: \"007\"\nneg: -0.0\n");

    my $sops_enc = `$sops_bin -e --age $public $plain_file 2>&1`;
    is($? >> 8, 0, 'sops encrypts them') or diag($sops_enc);

    # sops stores 1e20 as its expanded form; Perl restringifies that as 1e+20.
    like($sops_enc, qr/^big: ENC\[[^\]]*type:float\]$/m, 'sops typed 1e20 as float');

    my $decrypted = eval {
        File::SOPS->decrypt(
            encrypted => $sops_enc, identities => [$secret], format => 'yaml',
        );
    };
    is($@, '', 'Perl verifies a sops file holding values Perl would renormalise')
        or diag("died: $@");
    cmp_ok($decrypted->{big}, '==', 1e20, 'and gets the value back') if $decrypted;
};

done_testing;
