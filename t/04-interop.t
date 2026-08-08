#!/usr/bin/env perl
use strict;
use warnings;
use utf8;
use Test::More;
use File::Temp qw(tempfile tempdir);
use File::Slurp qw(read_file write_file);
use JSON::MaybeXS qw(decode_json encode_json JSON);
use YAML::XS qw(Load Dump);

use File::SOPS;
use Crypt::Age;

# Resolve which sops binary to use for interop testing, in order:
#   1. $SOPS_BIN, if set -- an explicit choice always wins. If it is set to
#      something that is not executable, that is a misconfiguration worth
#      failing loudly on, not silently falling through to another binary:
#      falling through would prove compatibility against a binary the
#      caller did not choose, and nobody would notice.
#   2. A `sops` found on PATH -- so a normal install (e.g. ~/bin/sops) is
#      picked up with zero configuration.
#   3. /tmp/sops, kept for backwards compatibility with the old hardcoded
#      location.
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
    die "SOPS_BIN is set to '$ENV{SOPS_BIN}' but that is not executable. ".
        "Fix the path, or unset SOPS_BIN to auto-detect sops on PATH.\n"
        unless -x $ENV{SOPS_BIN};
    $sops_bin = $ENV{SOPS_BIN};
}
else {
    $sops_bin = _find_on_path('sops') || (-x '/tmp/sops' ? '/tmp/sops' : undef);
}

unless ($sops_bin) {
    plan skip_all =>
        "No sops binary found (checked \$SOPS_BIN, PATH, /tmp/sops) -- ".
        "the ONLY sops-compatibility proof in this suite did NOT run. ".
        "Fix: run maint/fetch-sops (needs a Go toolchain) to install a ".
        "pinned sops onto PATH, or set SOPS_BIN=/path/to/sops.";
}

my $sops_version = `$sops_bin --version 2>&1`;
diag("Using sops binary: $sops_bin");
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

###############################################################################
# Test 18: Quoted scalars, us -> sops
#
# The hole that hid karr #15 for two releases: nothing in this file used a
# string that looks like a number or a boolean. sops types a value by what the
# parser returned, so a quoted "false" is type:str and a bare false is
# type:bool -- and a numeric value's plaintext is Go's canonical form, so 007
# is stored as 7 and 1.50 as 1.5. Writing the source spelling instead does not
# merely look odd: Go recomputes the MAC from the canonical form, so `sops -d`
# rejects the whole file. Before the fix these two assertions failed with
# "Failed to verify data integrity".
###############################################################################
subtest 'Quoted scalars: Perl encrypt -> sops decrypt' => sub {
    # Strings on the left, real numbers/booleans on the right. The numbers
    # come from a YAML parse rather than Perl literals so that 007 and 1.50
    # keep a source spelling that is not their canonical form.
    my $numbers = Load("n_pad: 007\nn_float: 1.50\nn_int: 5432\nn_e: 1e20\nn_one: 1.0\n");

    my $data = {
        %$numbers,
        s_true  => 'true',
        s_false => 'false',
        s_one   => '1',
        s_zero  => '0',
        s_pad   => '007',
        s_float => '1.50',
        b_true  => JSON->true,
        b_false => JSON->false,
    };

    for my $format (qw(yaml json)) {
        my $encrypted = File::SOPS->encrypt(
            data       => $data,
            recipients => [$public],
            format     => $format,
        );

        # The wire types, before sops sees the file.
        for my $key (qw(s_true s_false s_one s_zero s_pad s_float)) {
            like($encrypted, qr{\Q$key\E"?\s*:\s*"?ENC\[[^\]]*type:str\]},
                "[$format] $key is written as type:str");
        }
        like($encrypted, qr{b_false"?\s*:\s*"?ENC\[[^\]]*type:bool\]},
            "[$format] a real false is written as type:bool");
        like($encrypted, qr{n_pad"?\s*:\s*"?ENC\[[^\]]*type:int\]},
            "[$format] a bare 007 is written as type:int");

        my $enc_file = "$tempdir/quoted.$format";
        write_file($enc_file, $encrypted);

        my $output = `$sops_bin -d $enc_file 2>&1`;
        my $exit_code = $? >> 8;
        is($exit_code, 0, "[$format] sops decrypts a document of quoted scalars")
            or diag("sops output: $output");
        next unless $exit_code == 0;

        # sops re-emits a string quoted and a number bare, so its own output
        # says which type it read back. This is the assertion that cannot be
        # satisfied by File::SOPS agreeing with itself.
        if ($format eq 'yaml') {
            like($output, qr/^s_pad: "007"$/m,     'sops read s_pad back as the string 007');
            like($output, qr/^s_float: "1\.50"$/m, 'sops read s_float back as the string 1.50');
            like($output, qr/^s_false: "false"$/m, 'sops read s_false back as the string false');
            like($output, qr/^s_one: "1"$/m,       'sops read s_one back as the string 1');
            like($output, qr/^n_pad: 7$/m,         'sops read a bare 007 back as the number 7');
            like($output, qr/^n_float: 1\.5$/m,    'sops read a bare 1.50 back as the number 1.5');
            like($output, qr/^b_false: false$/m,   'sops read a real false back as a boolean');
        }
        else {
            like($output, qr/"s_pad":\s*"007"/,     'sops read s_pad back as the string 007');
            like($output, qr/"s_false":\s*"false"/, 'sops read s_false back as the string false');
            like($output, qr/"n_pad":\s*7\b/,       'sops read a bare 007 back as the number 7');
            like($output, qr/"b_false":\s*false/,   'sops read a real false back as a boolean');
        }

        my $back = $format eq 'json' ? decode_json($output) : Load($output);
        is($back->{$_}, $data->{$_}, "[$format] $_ survives the trip through sops")
            for qw(s_true s_false s_one s_zero s_pad s_float);
    }
};

###############################################################################
# Test 19: Quoted scalars, sops -> us
#
# The other direction of the same defect: a quoted "false" written by sops
# came back from File::SOPS as a boolean and "007" as the integer 7, so the
# library silently changed values it exists to preserve.
#
# The unencrypted key is the MAC half of it. Go hashes an unencrypted value
# through the same ToBytes, so a plaintext "true" that the parser returned as
# a STRING contributes 'true' to the digest -- not the 'True' the old ladder
# produced for it. That one is a MAC failure, not a wrong value.
###############################################################################
subtest 'Quoted scalars: sops encrypt -> Perl decrypt' => sub {
    # Written by hand rather than dumped from a Perl structure: the quoting is
    # the input to the test, and going through an emitter would make it depend
    # on the same Perl flags that are under test.
    my %source;

    $source{yaml} = <<'YAML';
q_false: "false"
q_true: "true"
q_one: "1"
q_zero: "0"
q_pad: "007"
q_float: "1.50"
b_false: false
b_true: true
b_int: 5432
b_float: 1.50
b_pad: 007
flag_unencrypted: "true"
pad_unencrypted: "007"
YAML

    $source{json} = <<'JSON';
{
  "q_false": "false",
  "q_true": "true",
  "q_one": "1",
  "q_zero": "0",
  "q_pad": "007",
  "q_float": "1.50",
  "b_false": false,
  "b_true": true,
  "b_int": 5432,
  "b_float": 1.50,
  "flag_unencrypted": "true",
  "pad_unencrypted": "007"
}
JSON

    for my $format (qw(yaml json)) {
        my $plain_file = "$tempdir/quoted_src.$format";
        write_file($plain_file, $source{$format});

        my $sops_enc = `$sops_bin -e --age $public $plain_file 2>&1`;
        is($? >> 8, 0, "[$format] sops encrypts the source document")
            or diag($sops_enc);

        # What sops decided the types are -- the specification this test is
        # written against, restated as an assertion so a change in sops shows
        # up here rather than as a mysterious failure below.
        like($sops_enc, qr{q_false"?\s*:\s*"?ENC\[[^\]]*type:str\]},
            "[$format] sops typed a quoted false as str");
        like($sops_enc, qr{b_false"?\s*:\s*"?ENC\[[^\]]*type:bool\]},
            "[$format] sops typed a bare false as bool");

        my $got = eval {
            File::SOPS->decrypt(
                encrypted => $sops_enc, identities => [$secret], format => $format,
            );
        };
        is($@, '', "[$format] Perl verifies the MAC of a document with quoted scalars")
            or diag("died: $@");
        next unless $got;

        is($got->{q_false}, 'false', "[$format] quoted false comes back as the string");
        is($got->{q_true},  'true',  "[$format] quoted true comes back as the string");
        is($got->{q_one},   '1',     "[$format] quoted 1 comes back as the string");
        is($got->{q_pad},   '007',   "[$format] quoted 007 keeps its padding");
        is($got->{q_float}, '1.50',  "[$format] quoted 1.50 keeps its trailing zero");

        ok(!ref $got->{q_false}, "[$format] quoted false is not a boolean object");
        ok(!ref $got->{q_true},  "[$format] quoted true is not a boolean object");

        isa_ok($got->{b_false}, 'JSON::PP::Boolean', "[$format] bare false");
        isa_ok($got->{b_true},  'JSON::PP::Boolean', "[$format] bare true");
        ok(!$got->{b_false}, "[$format] and bare false is false");

        cmp_ok($got->{b_int},   '==', 5432, "[$format] bare integer survives");
        cmp_ok($got->{b_float}, '==', 1.5,  "[$format] bare float survives");

        # The MAC half. These are never encrypted, so their plaintext IS the
        # document text and both implementations hash it through the same
        # ToBytes. The old ladder hashed the string "true" as 'True' -- which
        # is what Go writes for a real boolean, not for a quoted one -- so
        # this document failed verification outright rather than returning a
        # wrong value.
        is($got->{flag_unencrypted}, 'true',
            "[$format] an unencrypted quoted true stays a string");
        is($got->{pad_unencrypted}, '007',
            "[$format] an unencrypted quoted 007 keeps its padding");
    }
};

###############################################################################
# Test 20: Latin-1-range VALUES, both directions (karr #27, ADR 0003)
#
# Below U+0100 Perl's UTF-8 flag is a storage detail, not meaning: "caf\x{e9}"
# may be held as one byte or as two and Perl considers both the same string.
# The value conversion used to consult that flag, so an unflagged café reached
# the wire as the single byte \xe9 -- which is not UTF-8, and sops therefore
# could not read it as text at all. Measured before the fix:
#
#     secret: !!binary Y2Fm6Q==      (base64 of caf\xe9)
#
# instead of `secret: café`. The encrypted case was self-consistent, so only
# the real binary could see it; the unencrypted case failed our own MAC and is
# pinned without a binary in t/08-encoding.t.
#
# \x{} escapes rather than literal UTF-8 so the test states the codepoints
# exactly and does not depend on how this file is itself decoded.
###############################################################################
subtest 'Latin-1-range values survive in both directions' => sub {
    my $cafe_up   = do { my $s = "caf\x{e9}";       utf8::upgrade($s);   $s };
    my $cafe_down = do { my $s = "caf\x{e9}";       utf8::downgrade($s); $s };
    my $offen     = do { my $s = "\x{f6}ffentlich"; utf8::downgrade($s); $s };

    for my $format (qw(yaml json)) {
        # --- we write, sops reads ------------------------------------------
        my $encrypted = File::SOPS->encrypt(
            data       => {
                flagged          => $cafe_up,
                unflagged        => $cafe_down,
                note_unencrypted => $offen,
            },
            recipients => [$public],
            format     => $format,
        );

        my $enc_file = "$tempdir/latin1.$format";
        write_file($enc_file, $encrypted);

        my $output = `$sops_bin -d $enc_file 2>&1`;
        my $exit_code = $? >> 8;
        is($exit_code, 0, "[$format] sops decrypts a Latin-1-range document")
            or diag("sops output: $output");
        next unless $exit_code == 0;

        # The assertion that actually failed before the fix. sops emits a
        # scalar it cannot read as UTF-8 as `!!binary <base64>`, so the tag is
        # the signature of the bug -- and it appeared for the unflagged copy
        # only, which is what made this invisible from inside Perl.
        unlike($output, qr/!!binary/,
            "[$format] sops reads every value as text, none as binary");
        like($output, qr/caf\xc3\xa9/,
            "[$format] and the encrypted value arrives as UTF-8 café");
        like($output, qr/\xc3\xb6ffentlich/,
            "[$format] and so does the unencrypted one");

        my $back = $format eq 'json' ? decode_json($output) : Load($output);
        is($back->{flagged},   $cafe_up, "[$format] flagged value survives sops");
        is($back->{unflagged}, $cafe_up, "[$format] unflagged value survives sops too");
        is($back->{note_unencrypted}, "\x{f6}ffentlich",
            "[$format] unencrypted Latin-1-range value survives sops");

        # --- sops writes, we read ------------------------------------------
        my $plain = $format eq 'json'
            ? qq({"pass":"passw\x{f6}rd","note_unencrypted":"\x{f6}ffentlich"}\n)
            : qq(pass: "passw\x{f6}rd"\nnote_unencrypted: "\x{f6}ffentlich"\n);
        utf8::encode($plain);   # the FILE is UTF-8; that is what sops reads

        my $plain_file = "$tempdir/latin1_src.$format";
        write_file($plain_file, $plain);

        my $sops_enc = `$sops_bin -e --age $public $plain_file 2>&1`;
        is($? >> 8, 0, "[$format] sops encrypts a Latin-1-range document")
            or diag($sops_enc);

        my $got = eval {
            File::SOPS->decrypt(
                encrypted => $sops_enc, identities => [$secret], format => $format,
            );
        };
        is($@, '', "[$format] Perl verifies the MAC of a sops Latin-1-range document")
            or diag("died: $@");
        next unless $got;

        is($got->{pass}, "passw\x{f6}rd",
            "[$format] the encrypted value comes back as characters");
        is($got->{note_unencrypted}, "\x{f6}ffentlich",
            "[$format] and so does the unencrypted one");
        ok(utf8::is_utf8($got->{pass}),
            "[$format] and it really is a character string, not UTF-8 bytes");
    }
};

done_testing;
