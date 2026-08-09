#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);

use File::SOPS;
use File::SOPS::Format::YAML;

# Multi-document YAML used to be accepted and silently reduced to its LAST
# document, because YAML::XS::Load in scalar context returns only that one.
# Encrypting a two-document file therefore wrote one document back and threw
# the other away, with no error and nothing in the output to show it had
# happened. These tests pin the loud failure that replaced it.
#
# When multi-document support lands, most of this file becomes the wrong
# assertion and should be rewritten to check the round trip -- not deleted.
# The measured sops model is recorded in File::SOPS::Format::YAML.

my $TWO_DOCS = "alpha: one\nshared: first\n---\nbeta: two\nshared: second\n";

###############################################################################
subtest 'parse refuses a two-document stream instead of truncating it' => sub {
    my @got = eval { File::SOPS::Format::YAML->parse($TWO_DOCS) };
    my $err = $@;

    ok($err, 'parse died')
        or diag("parse returned instead of dying -- this is the data loss bug");

    # The regression, stated as the value it must never be again: the old code
    # returned exactly the last document here.
    is_deeply(\@got, [], 'nothing was returned');

    like($err, qr/2 documents/,
        'error names how many documents were found');
    like($err, qr/multi-document/i,
        'error names the unsupported feature');
};

###############################################################################
subtest 'a document count above two is reported as such' => sub {
    # An empty document in the middle is a real document to both YAML::XS and
    # sops, which gives it its own metadata block and reads it back as {}.
    my $err = do {
        eval { File::SOPS::Format::YAML->parse("a: 1\n---\n---\nb: 2\n") };
        $@;
    };
    like($err, qr/3 documents/, 'the empty middle document is counted');

    # A trailing separator opens a second, empty document. sops agrees -- it
    # writes two metadata blocks for this input -- so refusing it is correct
    # rather than over-strict.
    $err = do { eval { File::SOPS::Format::YAML->parse("a: 1\n---\n") }; $@ };
    like($err, qr/2 documents/, 'a trailing --- is a second document');
};

###############################################################################
subtest 'single-document streams are unaffected' => sub {
    my ($data) = File::SOPS::Format::YAML->parse("a: 1\nb: two\n");
    is_deeply($data, { a => 1, b => 'two' }, 'plain single document');

    # A leading separator is legal single-document YAML. sops drops it on
    # write; either way it must not be miscounted as an extra document.
    ($data) = File::SOPS::Format::YAML->parse("---\na: 1\n");
    is_deeply($data, { a => 1 }, 'leading --- is not a second document');

    # The document count comes from a real parser, never from splitting the
    # text on /^---$/. A value that CONTAINS a separator-looking line must not
    # be mistaken for one -- PEM blocks are the obvious real-world case.
    my $pem = "cert: |\n  -----BEGIN CERTIFICATE-----\n  abc\n"
            . "  -----END CERTIFICATE-----\ndashes: \"x --- y\"\n";
    ($data) = File::SOPS::Format::YAML->parse($pem);
    like($data->{cert}, qr/BEGIN CERTIFICATE/, 'block scalar survives intact');
    is($data->{dashes}, 'x --- y', 'a --- inside a value is just text');

    # Unchanged pre-existing behaviour, re-pinned because the empty stream now
    # takes a different route through parse (0 documents, not undef).
    like(do { eval { File::SOPS::Format::YAML->parse("") }; $@ },
        qr/did not parse to a hash/, 'empty input still reports no hash');
    like(do { eval { File::SOPS::Format::YAML->parse("- a\n- b\n") }; $@ },
        qr/did not parse to a hash/, 'a top-level sequence is still refused');
};

###############################################################################
subtest 'encrypt_file refuses rather than writing a truncated file' => sub {
    my $dir = tempdir(CLEANUP => 1);

    my $in = "$dir/two.yaml";
    write_file($in, $TWO_DOCS);
    my $out = "$dir/two.enc.yaml";

    my $ok = eval {
        File::SOPS->encrypt_file(
            input      => $in,
            output     => $out,
            recipients => ['age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p'],
        );
        1;
    };
    ok(!$ok, 'encrypt_file died');
    like($@, qr/multi-document/i, 'and died for the right reason');
    ok(!-e $out, 'no output file was written');

    # The in-place form is where the loss was unrecoverable: the source file
    # was overwritten with the single surviving document.
    my $inplace = "$dir/inplace.yaml";
    write_file($inplace, $TWO_DOCS);
    eval { File::SOPS->encrypt_file(
        input      => $inplace,
        recipients => ['age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p'],
    ) };
    is(scalar read_file($inplace), $TWO_DOCS,
        'in-place encrypt left the source file untouched');
};

###############################################################################
subtest 'decrypt reports the real problem, not a MAC mismatch' => sub {
    # A sops-shaped two-document file. It never reaches the age backend or the
    # MAC: parse rejects it first. Before the fix this path reported
    # "MAC verification failed", because only the last document's leaves were
    # hashed while the stored MAC covered both -- a misleading error for what
    # is actually an unsupported input.
    my $doc = <<'YAML';
alpha: ENC[AES256_GCM,data:GJx8,iv:UviTVNZsDhJiAqmdlzPo4w==,tag:AVtDgfBZYXqXxTfAdVR/dg==,type:str]
sops:
    lastmodified: "2026-08-08T23:38:52Z"
    mac: ENC[AES256_GCM,data:IUoe,iv:hvGgd6z/nbAmyUMtTkWf3Q==,tag:JK/b2t4PFxlus6NiQ4mB4A==,type:str]
    version: 3.13.3
---
beta: ENC[AES256_GCM,data:+6I2,iv:CG1b+tUlZIexygqHqNDyKQ==,tag:AWnPwk+HEGGk0ejcgh9dcA==,type:str]
sops:
    lastmodified: "2026-08-08T23:38:52Z"
    mac: ENC[AES256_GCM,data:IUoe,iv:hvGgd6z/nbAmyUMtTkWf3Q==,tag:JK/b2t4PFxlus6NiQ4mB4A==,type:str]
    version: 3.13.3
YAML

    eval {
        File::SOPS->decrypt(
            encrypted  => $doc,
            identities => ['AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ'],
        );
    };
    like($@, qr/multi-document/i, 'decrypt names the multi-document input');
    unlike($@, qr/MAC verification failed/,
        'and does not blame the MAC for it');
};

###############################################################################
subtest 'the MAC reparse holds the one-document rule independently' => sub {
    # _parse_in_document_order supplies the key ORDER for MAC verification
    # while the values come from the main parse. The two parsers disagree in
    # scalar context on a multi-document stream -- YAML::PP yields the FIRST
    # document, YAML::XS the LAST -- so a reparse that quietly accepted such a
    # stream would pair one document's order with another's values. Format
    # handlers reject the input before this is reached; the guard is here so
    # the pairing cannot silently go wrong if that ever changes.
    is(File::SOPS::_parse_in_document_order($TWO_DOCS), undef,
        'reparse declines a multi-document stream');

    my $single = File::SOPS::_parse_in_document_order("a: 1\nb: 2\n");
    is_deeply($single, { a => 1, b => 2 },
        'and still recovers a single document');

    # The sops branch is dropped structurally, as before.
    my $with_meta = File::SOPS::_parse_in_document_order(
        "a: 1\nsops:\n    version: 3.13.3\n");
    is_deeply($with_meta, { a => 1 }, 'sops branch still removed');
};

###############################################################################
# Interop: does the refusal actually cover what sops produces?
#
# Deliberately not in t/04-interop.t -- this asserts the CURRENT boundary
# (we refuse), and it belongs next to the tests that will be rewritten when
# multi-document support lands.
###############################################################################
subtest 'a real sops multi-document file is refused, not misread' => sub {
    my $sops_bin;
    if (defined $ENV{SOPS_BIN} && length $ENV{SOPS_BIN}) {
        die "SOPS_BIN is set to '$ENV{SOPS_BIN}' but that is not executable.\n"
            unless -x $ENV{SOPS_BIN};
        $sops_bin = $ENV{SOPS_BIN};
    }
    else {
        for my $dir (split /:/, $ENV{PATH} // '') {
            next unless length $dir;
            next unless -x "$dir/sops" && !-d "$dir/sops";
            $sops_bin = "$dir/sops";
            last;
        }
        $sops_bin ||= (-x '/tmp/sops' ? '/tmp/sops' : undef);
    }

    plan skip_all => "No sops binary found (checked \$SOPS_BIN, PATH, /tmp/sops)"
        unless $sops_bin;

    require Crypt::Age;
    my ($public, $secret) = Crypt::Age->generate_keypair();

    my $dir = tempdir(CLEANUP => 1);
    write_file("$dir/key.txt", $secret);
    local $ENV{SOPS_AGE_KEY_FILE} = "$dir/key.txt";

    write_file("$dir/two.yaml", $TWO_DOCS);
    my $enc = `$sops_bin --age $public -e $dir/two.yaml 2>&1`;
    is($? >> 8, 0, 'sops encrypted a two-document file') or do {
        diag("sops output: $enc");
        return;
    };

    # What sops produced really is multi-document, with one metadata block per
    # document and the same MAC in each -- the model recorded in the POD.
    my @macs = ($enc =~ /^    mac: (\S+)$/mg);
    is(scalar @macs, 2, 'sops wrote one metadata block per document');
    is($macs[0], $macs[1], 'both carry the same MAC (one digest, whole stream)');

    eval {
        File::SOPS->decrypt(encrypted => $enc, identities => [$secret]);
    };
    like($@, qr/multi-document/i,
        'File::SOPS refuses it with the multi-document error');

    # The point of the whole ticket: whatever we do with such a file, we must
    # never hand back a partial document as though it were the file.
    my $data = eval {
        File::SOPS->decrypt(
            encrypted => $enc, identities => [$secret], ignore_mac => 1);
    };
    is($data, undef, 'not even ignore_mac yields a silently truncated document');
};

done_testing;
