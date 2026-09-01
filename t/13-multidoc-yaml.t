#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);
use Crypt::Age;

use lib 't/lib';
use SopsBin qw(find_sops_bin);

use File::SOPS;
use File::SOPS::Format::YAML;

# Multi-document YAML used to be accepted and silently reduced to its LAST
# document, because YAML::XS::Load in scalar context returns only that one.
# Encrypting a two-document file therefore wrote one document back and threw
# the other away, with no error and nothing in the output to show it had
# happened. karr #31 / docs/adr/0033 replaces that with real support, in
# stages. WIRE (File::SOPS::Format::YAML->parse, _parse_in_document_order, the
# MAC over all documents) and now the public API's READ path -- decrypt
# returns an ArrayRef of HashRefs for a real stream and a bare HashRef for a
# single document, extract takes a document => $n argument, and converting a
# stream to a format with no document axis (JSON) is refused (Decision 3) --
# are all in place and pinned below. The WRITE path
# (encrypt/encrypt_file/encrypt_in_place/edit/decrypt_file to a YAML target)
# still refuses a multi-document stream at its own boundary
# (_refuse_multidoc_pending) until the emitter's document separators land
# (karr #31 step 5, format lane) -- that is what the write-refusal subtests
# below pin, and they are regressions, not throwaways: when step 5 lands they
# become round-trip tests, not deletions.
#
# The measured sops model is recorded in docs/adr/0033 and in
# File::SOPS::Format::YAML.

my $TWO_DOCS = "alpha: one\nshared: first\n---\nbeta: two\nshared: second\n";

# Encrypts $content with the real sops binary using $sops_bin, on a fresh age
# keypair, and returns ($enc, $secret) -- the encrypted bytes and the secret
# key that can decrypt them. Records whether sops itself exited 0 as a test
# belonging to whichever subtest is currently running; returns nothing if it
# did not, so callers write
# `my (...) = sops_encrypt(...); return unless defined $enc;`.
sub sops_encrypt {
    my ($sops_bin, $content, $name) = @_;
    $name //= 'doc.yaml';

    my ($public, $secret) = Crypt::Age->generate_keypair();
    my $tempdir = tempdir(CLEANUP => 1);
    write_file("$tempdir/key.txt", $secret);
    local $ENV{SOPS_AGE_KEY_FILE} = "$tempdir/key.txt";

    write_file("$tempdir/$name", $content);
    my $enc = `$sops_bin --age $public -e $tempdir/$name 2>&1`;
    is($? >> 8, 0, "sops encrypted $name") or do {
        diag("sops output: $enc");
        return;
    };

    return ($enc, $secret);
}

# A fixed-output stand-in for the CSPRNG, used only to prove Decision 1's
# byte-identity promise (see the subtest below). File::SOPS::Encrypted's
# shared _random_bytes calls through to Crypt::PRNG::random_bytes for both the
# data key and every per-value GCM nonce, and _encrypt_tree walks a hash with
# `for my $k (keys %$node)` -- UNSORTED, and NOT guaranteed to visit two
# structurally-identical-but-separately-built hashes in the same order:
# measured, `{ %doc }` evaluated twice in the same process gives `keys` two
# different orders. A call-order-based deterministic mock (a counter) would
# therefore hand the wrong nonce to the wrong leaf between the two encrypt()
# calls being compared. A single FIXED return sidesteps that: ciphertext is a
# pure function of (key, iv, aad, plaintext), and aad/plaintext are identical
# for the same leaf regardless of which order the walk reached it in, so a
# constant key and a constant nonce make every leaf's ciphertext depend only
# on its own path and value -- not on when it was visited.
sub fixed_random_bytes {
    return sub {
        my ($n) = @_;
        return substr('K' x 64, 0, $n);
    };
}

###############################################################################
subtest 'parse returns a document list for a two-document stream' => sub {
    my ($first, $metadata, $documents) = eval {
        File::SOPS::Format::YAML->parse($TWO_DOCS) };
    ok(!$@, 'parse no longer dies on a multi-document stream') or diag($@);

    is(scalar @$documents, 2, 'both documents came back');
    is_deeply($documents,
        [ { alpha => 'one', shared => 'first' },
          { beta  => 'two', shared => 'second' } ],
        'each document keeps its own values, in document order');
    is_deeply($first, $documents->[0],
        'the first return value mirrors document 0');
    is($metadata, undef,
        'neither document in this fixture has a sops section, so no metadata');

    # Metadata comes from the FIRST document only, and is stripped from every
    # document's value tree wherever a sops section appears (docs/adr/0033
    # point 2).
    my ($first2, $metadata2, $documents2) = eval { File::SOPS::Format::YAML->parse(
        "alpha: one\nsops:\n    version: 3.13.3\n---\nbeta: two\n"
    ) };
    ok(!$@, 'a stream carrying metadata only in its first document parses')
        or diag($@);
    isa_ok($metadata2, 'File::SOPS::Metadata', 'metadata built from the first document');
    is($metadata2->version, '3.13.3', 'metadata is taken from the first document');
    is_deeply($documents2,
        [ { alpha => 'one' }, { beta => 'two' } ],
        'sops is stripped from document 0, and document 1 is unaffected');
};

###############################################################################
subtest 'an empty document is a real document and reads back as {}' => sub {
    # An empty document in the middle is a real document to both YAML::XS and
    # sops, which gives it its own metadata block and reads it back as {}
    # (docs/adr/0033 point 6).
    my (undef, undef, $documents) = eval {
        File::SOPS::Format::YAML->parse("a: 1\n---\n---\nb: 2\n") };
    ok(!$@, 'three documents, one empty, parse without dying') or diag($@);
    is(scalar @$documents, 3, 'the empty middle document is counted');
    is_deeply($documents, [ { a => 1 }, {}, { b => 2 } ],
        'and it reads back as {}, not as dropped or merged');

    # A trailing separator opens a second, empty document. sops agrees -- it
    # writes two metadata blocks for this input.
    (undef, undef, $documents) = eval {
        File::SOPS::Format::YAML->parse("a: 1\n---\n") };
    ok(!$@, 'a trailing --- parses without dying') or diag($@);
    is(scalar @$documents, 2, 'a trailing --- is a second document');
    is_deeply($documents, [ { a => 1 }, {} ],
        'and it too reads back as {}');
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
    like($@, qr/multi-document YAML \(2 documents\) cannot be WRITTEN yet/,
        'and died for the right reason -- the narrowed karr #31 step 5 message');
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
subtest 'encrypt(data => arrayref) refuses a multi-document write too' => sub {
    # The write path is refused wherever it is reached, not only through
    # encrypt_file. Before docs/adr/0033 an ArrayRef died with "data must be a
    # hash ref"; since Decision 1 it is a legitimate multi-document argument,
    # so what stops it now is the SAME karr #31 step 5 refusal encrypt_file
    # hits, not the old input-shape guard.
    my $ok = eval {
        File::SOPS->encrypt(
            data       => [ { a => 1 }, { b => 2 } ],
            recipients => ['age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p'],
        );
        1;
    };
    ok(!$ok, 'encrypt(data => arrayref) with two documents dies');
    unlike($@, qr/data must be a hash ref/,
        'not the old input-shape guard -- an ArrayRef is legitimate now');
    like($@, qr/multi-document YAML \(2 documents\) cannot be WRITTEN yet/,
        'but the narrowed karr #31 step 5 refusal');
};

###############################################################################
subtest 'a one-element ArrayRef is byte-identical to the same HashRef (docs/adr/0033 Decision 1)' => sub {
    # "encrypt given a one-element ArrayRef writes a one-document file,
    # byte-identical to what the same HashRef would produce" -- ADR 0033
    # Decision 1. Two irreducible sources of non-determinism stand between
    # this and a plain string eq: the age `enc:` blob (Crypt::Age's own
    # ephemeral key and nonce, generated inside Crypt::Age and invisible from
    # here -- see t/21-random-bytes.t) and `lastmodified` (real wall-clock
    # seconds). Both are normalised out before comparing; the mac: line is
    # normalised too, because its own ciphertext is authenticated over
    # lastmodified as AAD and so inherits that same variance whenever the two
    # calls straddle a second boundary. Everything else -- key order, quoting,
    # every leaf's own ENC[...] -- is compared byte for byte, with a fixed
    # CSPRNG stand-in (fixed_random_bytes, above) making that possible despite
    # _encrypt_tree's unsorted, order-varying hash walk.
    my ($public, $secret) = Crypt::Age->generate_keypair();
    my %doc = ( alpha => 'one', nested => { x => 1, y => 2.5, z => 'hello world' } );

    my ($enc_hash, $enc_array);
    {
        no warnings 'redefine';
        local *Crypt::PRNG::random_bytes = fixed_random_bytes();
        $enc_hash  = File::SOPS->encrypt(
            data => { %doc }, recipients => [$public], format => 'yaml');
        $enc_array = File::SOPS->encrypt(
            data => [ { %doc } ], recipients => [$public], format => 'yaml');
    }

    for my $enc ($enc_hash, $enc_array) {
        $enc =~ s/-----BEGIN AGE ENCRYPTED FILE-----.*?-----END AGE ENCRYPTED FILE-----/<AGE-BLOB>/s;
        $enc =~ s/lastmodified: "[^"]*"/lastmodified: "<TIME>"/;
        $enc =~ s/mac: ENC\[[^\]]*\]/mac: <MAC>/;
    }

    is($enc_array, $enc_hash,
        'encrypt(data => [\%doc]) writes the same document as encrypt(data => \%doc), '
      . 'byte for byte apart from the age blob and the timestamp');

    # The round-trip half of Decision 1: what comes back OUT is a bare
    # HashRef, not a one-element ArrayRef -- what round-trips is the FILE, not
    # the Perl container that built it.
    my $enc = File::SOPS->encrypt(
        data => [ { alpha => 'one' } ], recipients => [$public], format => 'yaml');
    my $data = File::SOPS->decrypt(encrypted => $enc, identities => [$secret]);
    is(ref($data), 'HASH',
        'decrypt reads a one-document file back as a bare HashRef, not an ArrayRef');
    is_deeply($data, { alpha => 'one' }, 'holding what was encrypted');
};

###############################################################################
subtest 'rotate and edit also refuse to re-encrypt a multi-document file' => sub {
    # rotate re-encrypts through encrypt() after a full decrypt; edit refuses
    # before decrypting anything at all. Either way, proving the refusal needs
    # a REAL multi-document encrypted file -- this library cannot write one
    # yet, so borrow the real sops binary the way the read-path tests below do.
    my $sops_bin = find_sops_bin();
    plan skip_all =>
        "No sops binary found (checked \$SOPS_BIN, PATH, .sops-bin/sops, /tmp/sops) -- "
      . "rotate and edit only reach their own multi-document refusal from a "
      . "genuinely encrypted stream, and this library cannot write one yet "
      . "(karr #31 step 5). Fix: run maint/fetch-sops .sops-bin to install the "
      . "pinned binary where the suite finds it automatically, or set "
      . "SOPS_BIN=/path/to/sops."
        unless $sops_bin;
    diag("Using sops binary: $sops_bin");

    my ($enc, $secret) = sops_encrypt($sops_bin, $TWO_DOCS, 'two.yaml');
    return unless defined $enc;

    my $dir  = tempdir(CLEANUP => 1);
    my $file = "$dir/two.enc.yaml";
    write_file($file, $enc);

    my $ok = eval { File::SOPS->rotate(file => $file, identities => [$secret]); 1 };
    ok(!$ok, 'rotate dies rather than re-keying a multi-document file');
    like($@, qr/multi-document YAML \(2 documents\) cannot be WRITTEN yet/,
        'with the same narrowed message encrypt_file and encrypt use');
    is(read_file($file), $enc, 'and the file on disk is untouched');

    $ok = eval {
        File::SOPS->edit(
            file       => $file,
            identities => [$secret],
            editor     => 'true',   # never runs -- edit refuses before it would
        );
        1;
    };
    ok(!$ok, 'edit dies rather than opening a multi-document file for editing');
    like($@, qr/multi-document YAML \(2 documents\) cannot be WRITTEN yet/,
        'with the same narrowed message');
    is(read_file($file), $enc, 'and the file on disk is still untouched');
};

###############################################################################
subtest 'a multi-document stream cannot become JSON (docs/adr/0033 Decision 3)' => sub {
    # JSON has no document stream. sops converts it silently and loses every
    # document past the first, on read AND write (N1) -- exactly the karr #14
    # defect class. This library refuses instead. _serialize_plaintext is the
    # one place a decrypted stream meets an output format; there is currently
    # no PUBLIC path that reaches it with more than one document and a JSON
    # target, because decrypt_file uses the SAME format for reading and
    # writing (a real multi-document input auto-detects as YAML from its own
    # filename), so this is exercised directly.
    my $documents = [ { alpha => 'one' }, { beta => 'two' } ];

    my $err = do { eval { File::SOPS::_serialize_plaintext($documents, 'json') }; $@ };
    like($err, qr/cannot convert a multi-document stream \(2 documents\) to json/,
        'names the document count and the target format');
    like($err, qr/all but the first document would be lost/,
        'and says what would happen, not just that it refuses');
    like($err, qr/sops drops them silently here; this library refuses instead/,
        'stating the deviation from sops, per the house rule');

    # A single document is not a stream at all, and converts as always.
    my $json = File::SOPS::_serialize_plaintext({ alpha => 'one' }, 'json');
    like($json, qr/"alpha"/, 'a single document still converts to JSON');
    like($json, qr/"one"/, 'and carries its value');

    # YAML CAN hold a stream in principle (point 5), but the emitter's own
    # separators are not built yet (karr #31 step 5) -- refused for that
    # reason, not the JSON-specific one.
    $err = do { eval { File::SOPS::_serialize_plaintext($documents, 'yaml') }; $@ };
    like($err, qr/cannot be WRITTEN yet/,
        'a YAML target refuses too, but with the write-pending reason');
    unlike($err, qr/has no document stream/,
        'not the JSON-specific reason -- YAML really can hold a stream');
};

###############################################################################
subtest 'metadata only in a later document is refused (docs/adr/0033 point 2)' => sub {
    # Measured against sops 3.13.3: a stream carrying sops only in the FIRST
    # document decrypts fine (see subtest 1 above). One carrying it only in a
    # LATER document is refused with "sops metadata not found". The ENC[...]
    # values below need not decrypt to anything real -- decrypt croaks before
    # the data key is even looked up, because $metadata comes from document 0
    # alone (File::SOPS::Format::YAML's _parse_multidoc).
    my $doc = <<'YAML';
alpha: ENC[AES256_GCM,data:GJx8,iv:UviTVNZsDhJiAqmdlzPo4w==,tag:AVtDgfBZYXqXxTfAdVR/dg==,type:str]
---
beta: ENC[AES256_GCM,data:+6I2,iv:CG1b+tUlZIexygqHqNDyKQ==,tag:AWnPwk+HEGGk0ejcgh9dcA==,type:str]
sops:
    lastmodified: "2026-08-08T23:38:52Z"
    mac: ENC[AES256_GCM,data:IUoe,iv:hvGgd6z/nbAmyUMtTkWf3Q==,tag:JK/b2t4PFxlus6NiQ4mB4A==,type:str]
    version: 3.13.3
YAML

    my (undef, $metadata, $documents) = File::SOPS::Format::YAML->parse($doc);
    is($metadata, undef, 'no metadata is recognised from a document that is not the first');
    is(scalar @$documents, 2, 'both documents still came back');
    is_deeply(
        [ sort keys %{ $documents->[1] } ],
        [ 'beta' ],
        'and the sops section is stripped from document 1 regardless, so the '
      . 'walks never see it as an ordinary key');

    eval {
        File::SOPS->decrypt(
            encrypted  => $doc,
            identities => ['AGE-SECRET-KEY-1QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ'],
        );
    };
    like($@, qr/No SOPS metadata found/,
        q{decrypt refuses with the message that maps to sops's own "sops metadata not found"});
};

###############################################################################
subtest 'decrypt returns an ArrayRef for a real multi-document sops file, MAC verified' => sub {
    my $sops_bin = find_sops_bin();
    plan skip_all =>
        "No sops binary found (checked \$SOPS_BIN, PATH, .sops-bin/sops, /tmp/sops) -- "
      . "this proves decrypt's ArrayRef return against a stream sops itself "
      . "wrote, not just against this library's own parser. Fix: run "
      . "maint/fetch-sops .sops-bin to install the pinned binary where the "
      . "suite finds it automatically, or set SOPS_BIN=/path/to/sops."
        unless $sops_bin;
    diag("Using sops binary: $sops_bin");

    my ($enc, $secret) = sops_encrypt($sops_bin, $TWO_DOCS, 'two.yaml');
    return unless defined $enc;

    # What sops wrote really is multi-document, with one metadata block per
    # document and the same MAC in each (docs/adr/0033 point 1).
    my @macs = ($enc =~ /^    mac: (\S+)$/mg);
    is(scalar @macs, 2, 'sops wrote one metadata block per document');
    is($macs[0], $macs[1], 'both carry the same MAC (one digest, whole stream)');

    my $data = File::SOPS->decrypt(encrypted => $enc, identities => [$secret]);
    is(ref($data), 'ARRAY', 'a real multi-document stream decrypts to an ArrayRef')
        or diag(explain($data));
    is(scalar @$data, 2, 'both documents came back');
    is_deeply($data,
        [ { alpha => 'one', shared => 'first' },
          { beta  => 'two', shared => 'second' } ],
        'each document holds exactly what sops encrypted -- with the MAC '
      . 'verified, not ignore_mac');

    # What round-trips is the FILE, not the Perl container (Decision 1): a
    # genuinely single-document sops file still comes back as a bare HashRef.
    my ($enc1, $secret1) = sops_encrypt($sops_bin, "alpha: one\n", 'one.yaml');
    return unless defined $enc1;
    my $data1 = File::SOPS->decrypt(encrypted => $enc1, identities => [$secret1]);
    is(ref($data1), 'HASH', 'a real single-document sops file decrypts to a bare HashRef');
    is_deeply($data1, { alpha => 'one' }, 'holding what sops encrypted');
};

###############################################################################
subtest 'the MAC reparse pairs a multi-document stream by index' => sub {
    # _parse_in_document_order supplies the key ORDER for MAC verification
    # while the values come from the main parse. The two parsers disagree in
    # SCALAR context on a multi-document stream -- YAML::PP yields the FIRST
    # document, YAML::XS the LAST -- so a reparse that read either side in
    # scalar context would pair one document's order with another's values.
    # docs/adr/0033 closes this by reading BOTH sides in list context, so
    # document i's order now pairs with document i's values structurally.
    my $ordered = File::SOPS::_parse_in_document_order($TWO_DOCS);
    is(ref($ordered), 'ARRAY', 'reparse returns a document list for a stream');
    is_deeply($ordered,
        [ { alpha => 'one', shared => 'first' },
          { beta  => 'two', shared => 'second' } ],
        'each document keeps its own key/value pairs');

    my $single = File::SOPS::_parse_in_document_order("a: 1\nb: 2\n");
    is_deeply($single, { a => 1, b => 2 },
        'and still recovers a single document');

    # The sops branch is dropped structurally, as before.
    my $with_meta = File::SOPS::_parse_in_document_order(
        "a: 1\nsops:\n    version: 3.13.3\n");
    is_deeply($with_meta, { a => 1 }, 'sops branch still removed');
};

###############################################################################
# Interop: does the read path actually work against what sops produces, not
# just against this library's own writer? Deliberately real per-document
# values (not "a"/"b") so a wrong pairing (docs/adr/0033's trap) would show up
# as a wrong VALUE, not just a wrong count.
###############################################################################
subtest 'extract addresses one document at a time, and never falls through' => sub {
    my $sops_bin = find_sops_bin();
    plan skip_all =>
        "No sops binary found (checked \$SOPS_BIN, PATH, .sops-bin/sops, /tmp/sops) -- "
      . "extract's document argument can only be proven against a real "
      . "multi-document file, which this library cannot write yet (karr #31 "
      . "step 5). Fix: run maint/fetch-sops .sops-bin to install the pinned "
      . "binary where the suite finds it automatically, or set "
      . "SOPS_BIN=/path/to/sops."
        unless $sops_bin;
    diag("Using sops binary: $sops_bin");

    my ($enc, $secret) = sops_encrypt($sops_bin, $TWO_DOCS, 'two.yaml');
    return unless defined $enc;

    my $dir  = tempdir(CLEANUP => 1);
    my $file = "$dir/two.enc.yaml";
    write_file($file, $enc);

    is(File::SOPS->extract(file => $file, path => '["alpha"]', identities => [$secret]),
        'one', 'document is 0 by default, reaching document 0');
    is(File::SOPS->extract(file => $file, path => '["alpha"]', document => 0, identities => [$secret]),
        'one', 'document => 0 explicitly is the same document');
    is(File::SOPS->extract(file => $file, path => '["beta"]', document => 1, identities => [$secret]),
        'two', 'document => 1 reaches the second document');
    is(File::SOPS->extract(file => $file, path => '["shared"]', document => 0, identities => [$secret]),
        'first', "document 0's own \"shared\" value");
    is(File::SOPS->extract(file => $file, path => '["shared"]', document => 1, identities => [$secret]),
        'second', "document 1's own value, not document 0's");

    my $err = do { eval {
        File::SOPS->extract(file => $file, path => '["alpha"]', document => 2, identities => [$secret]);
    }; $@ };
    like($err, qr/document => 2 is beyond the last document/,
        'document => 2 errors naming that it is out of range');
    like($err, qr/\b2 documents\b/, 'and names how many documents the file has');

    # beta exists in document 1, not document 0 -- extract must not fall
    # through looking for it there (docs/adr/0033 Decision 2).
    $err = do { eval {
        File::SOPS->extract(file => $file, path => '["beta"]', document => 0, identities => [$secret]);
    }; $@ };
    like($err, qr/component 'beta' not found/, 'beta really is not in document 0');
    like($err, qr/\bdocument 0\b/, 'and the error names WHICH document was searched');
    unlike($err, qr/document 1/, 'never document 1, even though beta is right there');
};

###############################################################################
subtest 'document => 1 on a single-document file is out of range' => sub {
    my ($public, $secret) = Crypt::Age->generate_keypair();
    my $dir  = tempdir(CLEANUP => 1);
    my $file = "$dir/one.enc.yaml";
    write_file($file, File::SOPS->encrypt(
        data       => { alpha => 'one' },
        recipients => [$public],
    ));

    is(File::SOPS->extract(file => $file, path => '["alpha"]', identities => [$secret]),
        'one', 'document => 0 (the default) works as always');

    my $err = do { eval {
        File::SOPS->extract(file => $file, path => '["alpha"]', document => 1, identities => [$secret]);
    }; $@ };
    like($err, qr/document => 1 is beyond the last document/,
        'document => 1 is refused; there is no document 1');
    like($err, qr/\b1 document\b/,
        'the message says the file has one document, singular, not "1 documents"');
};

done_testing;
