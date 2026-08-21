#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);

use File::SOPS;
use File::SOPS::Encrypted;
use File::SOPS::Format::YAML;
use Crypt::Age;

# ----------------------------------------------------------------------------
# karr #108 / docs/adr/0024: a sops comment leaf is refused, not read as a value.
#
# sops attaches a YAML comment to the node that FOLLOWS it. Above a mapping key
# that stays a `#ENC[...,type:comment]` line, which YAML::XS discards and sops
# does not hash -- both sides agree by accident, and such a document has always
# read correctly here. Above a SEQUENCE entry there is no comment line to write,
# so sops emits the comment as a real element:
#
#     list:
#         - ENC[AES256_GCM,...,type:comment]
#         - ENC[AES256_GCM,...,type:str]
#
# Measured against sops 3.13.3 on three lines of plaintext
# (`list:` / `  # only a sequence comment` / `  - one`):
#
#   sops -d                                exit 0
#   File::SOPS->decrypt                    MAC verification failed
#   File::SOPS->decrypt(ignore_mac => 1)   { list => [' only a sequence comment',
#                                                     'one'] }
#
# The last line is the defect: the comment is a silent extra string, and a
# decrypt+encrypt cycle made it PERMANENT with `sops -d` exit 0 at every step.
# Comments are not in sops's MAC in any format, so there is no digest fix that
# also removes the phantom element -- and there is no place in this tree model
# for a leaf without a key. Parse therefore refuses, naming the path.
#
# Sections 1 to 5 need no binary: the guard is textual and structural, it fires
# before anything is decrypted, so a comment leaf can be constructed here.
# Section 6 is the compatibility claim -- that sops really writes this shape and
# that a document whose comments are all in mapping position still reads -- and
# is skipped without a binary.
# ----------------------------------------------------------------------------

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
    die "SOPS_BIN is set to '$ENV{SOPS_BIN}' but that is not executable. "
      . "Fix the path, or unset SOPS_BIN to auto-detect sops on PATH.\n"
        unless -x $ENV{SOPS_BIN};
    $sops_bin = $ENV{SOPS_BIN};
}
else {
    $sops_bin = _find_on_path('sops') || (-x '/tmp/sops' ? '/tmp/sops' : undef);
}
diag("Using sops binary: $sops_bin") if $sops_bin;

my ($public, $secret) = Crypt::Age->generate_keypair();
my $tempdir = tempdir(CLEANUP => 1);
write_file("$tempdir/key.txt", $secret);
$ENV{SOPS_AGE_KEY_FILE} = "$tempdir/key.txt";

# A well-formed ENC[...] string carrying an arbitrary type label. Built through
# encrypt_value rather than typed out, so the base64 is real and the only thing
# synthetic about it is the label -- which is exactly what sops varies.
sub enc_string {
    my ($type, $plaintext) = @_;
    my $enc = File::SOPS::Encrypted->encrypt_value(
        value => $plaintext,
        key   => "\0" x 32,
        aad   => '',
    );
    (my $s = $enc->to_string) =~ s/,type:\w+\]\z/,type:$type]/;
    return $s;
}

my $COMMENT_LEAF = enc_string('comment', ' only a sequence comment');
my $STR_LEAF     = enc_string('str',     'one');

###############################################################################
# 1. THE REFUSAL. A comment leaf in a parsed tree is not a value, and parse
#    says so at the path it sits at rather than handing it on.
###############################################################################

subtest 'a comment leaf in a sequence is refused, naming the path' => sub {
    my $doc = "list:\n    - $COMMENT_LEAF\n    - $STR_LEAF\n";

    my $data = eval { scalar File::SOPS::Format::YAML->parse($doc) };
    ok(!defined $data, 'parse refuses the document');
    like($@, qr/\Alist:0: /,
        'the message names the element, not just the list');
    like($@, qr/type:comment/, 'and says what the leaf is');
    like($@, qr/adr\/0024/, 'and points at the decision');

    unlike($@, qr/only a sequence comment/,
        'the comment text is never decrypted and never printed');
};

subtest 'the path is the full path, at any depth' => sub {
    my %at = (
        'a:b:1'         => "a:\n    b:\n        - $STR_LEAF\n        - $COMMENT_LEAF\n",
        'k'             => "k: $COMMENT_LEAF\n",
        'outer:0:inner' => "outer:\n    - inner: $COMMENT_LEAF\n",
    );

    for my $where (sort keys %at) {
        eval { File::SOPS::Format::YAML->parse($at{$where}) };
        like($@, qr/\A\Q$where\E: /, "refused at $where");
    }
};

subtest 'a damaged comment leaf is still recognised as a comment' => sub {
    # sops tolerates a comment whose ciphertext will not decrypt -- measured, it
    # warns and leaves the text alone. So the guard has to answer from the label
    # alone, without decoding anything, or a damaged comment would be reported
    # as a base64 problem and the real shape would stay hidden.
    my $damaged = 'ENC[AES256_GCM,data:!!!!,iv:!!!!,tag:!!!!,type:comment]';

    eval { File::SOPS::Encrypted->parse($damaged) };
    like($@, qr/Invalid base64/, 'parse of the value itself still croaks');

    eval { File::SOPS::Format::YAML->parse("list:\n    - $damaged\n") };
    like($@, qr/\Alist:0: .*type:comment/s,
        'but the document is refused as a comment leaf, not as bad base64');
};

###############################################################################
# 2. WHAT MUST NOT MOVE. The mapping position has always read correctly, and
#    the guard must not reach it -- there the comment is a real YAML comment
#    line that YAML::XS discards before parse ever gets a tree.
###############################################################################

subtest 'mapping-position comment lines still parse away silently' => sub {
    my $doc = "#$COMMENT_LEAF\n"
            . "database:\n"
            . "    #$COMMENT_LEAF\n"
            . "    host: $STR_LEAF\n";

    my ($data) = File::SOPS::Format::YAML->parse($doc);
    is_deeply($data, { database => { host => $STR_LEAF } },
        'the tree is the values, with no trace of the comments');
};

subtest 'documents without a comment leaf are untouched' => sub {
    my ($data) = File::SOPS::Format::YAML->parse(
        "a: $STR_LEAF\nb:\n    - 1\n    - 2\nc: plain\n");
    is_deeply($data, { a => $STR_LEAF, b => [1, 2], c => 'plain' },
        'an ordinary encrypted document parses as it always did');

    # Plaintext input has no ENC[...] strings in it, so nothing on the encrypt
    # side can trip the guard -- including a plaintext file full of comments.
    my ($plain) = File::SOPS::Format::YAML->parse(
        "# a comment\nlist:\n  # and one in a list\n  - one\n");
    is_deeply($plain, { list => ['one'] }, 'and plaintext with comments parses');

    my $out = File::SOPS->encrypt(
        data => { list => ['one'] }, recipients => [$public], format => 'yaml');
    like($out, qr/type:str/, 'encrypt is unaffected');
};

###############################################################################
# 3. THE LABEL READER. encrypted_type is the third sharer of the one anchored
#    ENC regex, and it answers without decoding -- which is what lets the guard
#    above see a damaged comment.
###############################################################################

subtest 'encrypted_type reads the label and nothing else' => sub {
    is(File::SOPS::Encrypted->encrypted_type($COMMENT_LEAF), 'comment',
        'comment');
    is(File::SOPS::Encrypted->encrypted_type($STR_LEAF), 'str', 'str');
    is(File::SOPS::Encrypted->encrypted_type(enc_string('int', '5')), 'int',
        'int');
    is(File::SOPS::Encrypted->encrypted_type(
        'ENC[AES256_GCM,data:!!!!,iv:!!!!,tag:!!!!,type:comment]'), 'comment',
        'and answers for a value parse() would refuse to decode');

    is(File::SOPS::Encrypted->encrypted_type('not encrypted'), undef,
        'undef for a plain string');
    is(File::SOPS::Encrypted->encrypted_type(undef), undef, 'undef for undef');
    is(File::SOPS::Encrypted->encrypted_type("x\n$STR_LEAF"), undef,
        'undef for an unanchored match -- the same regex is_encrypted uses');
};

###############################################################################
# 4. THE PUBLIC API. Every read path goes through parse, so every read path
#    refuses -- including ignore_mac, which is the one that used to produce the
#    corrupted tree.
###############################################################################

# The document this section reads is a CONSTRUCTION, and knowing that is part of
# reading the failures it produces. File::SOPS encrypts
# [' only a sequence comment', 'one'], and the first element is then relabelled
# type:comment. The leaf is a genuine one -- same data key, and the same AAD,
# because SOPS gives every element of an array its parent's path and adds no
# index -- so it decrypts exactly as a sops-written comment does, and before this
# change it came back as an ordinary string.
#
# Its MAC is not sops's, though. Relabelling does not move the stored digest (it
# covers the authenticated plaintext, and only a bool is normalised by type), so
# here the MAC covers the comment: the unpatched library VERIFIES this document
# and hands back the phantom element from the strict path. A sops-written
# document is the other way round -- sops leaves comments out of the digest, so
# the unpatched library fails MAC verification and only ignore_mac => 1 reaches
# the corrupted tree. That is what karr #108 reports, and it holds for every sops
# document measured: the minimal reproducer, the flow-sequence one, and comments
# of `#x`, `#   ` and a bare tab, all five dead on the MAC. The two shapes that
# could make the two digests agree are both closed -- a bare `#` in a list makes
# sops write an empty string ELEMENT and no comment leaf at all, and in an
# unencrypted subtree, with or without mac_only_encrypted, sops keeps the comment
# as a real comment line that YAML::XS discards.
#
# The construction earns its place by what it isolates: with the MAC agreeing,
# the refusal below can only be the guard firing at PARSE time, and not a side
# effect of a digest mismatch. Subtest 9 asks the binary for the other half.
sub document_with_comment_leaf {
    my $doc = File::SOPS->encrypt(
        data       => { list => [' only a sequence comment', 'one'] },
        recipients => [$public],
        format     => 'yaml',
    );
    # The first `- ENC[` line in the file: `list` sorts before `sops`, and the
    # age entries are `- enc: |`, not ENC values.
    $doc =~ s/^(\s*- ENC\[[^\]]*),type:str\]/$1,type:comment]/m
        or die "test fixture: no encrypted list element found to relabel";
    return $doc;
}

subtest 'decrypt refuses, in both MAC modes' => sub {
    my $doc = document_with_comment_leaf();

    # THE CORRUPTION PATH. Both of these used to return
    # { list => [' only a sequence comment', 'one'] } -- the comment as a silent
    # extra string, which a re-encrypt then made permanent with `sops -d` exit 0
    # on the result. Neither returns anything now.
    my $strict = eval { File::SOPS->decrypt(
        encrypted => $doc, identities => [$secret], format => 'yaml') };
    ok(!defined $strict, 'strict decrypt refuses');
    like($@, qr/\Alist:0: .*type:comment/s, 'at the element, as a comment leaf');
    unlike($@, qr/MAC verification failed/,
        'and not as a MAC failure blaming the file for being altered');

    my $lax = eval { File::SOPS->decrypt(
        encrypted => $doc, identities => [$secret], format => 'yaml',
        ignore_mac => 1) };
    ok(!defined $lax, 'ignore_mac refuses too -- the corruption path is closed');
    like($@, qr/\Alist:0: .*type:comment/s, 'with the same message');

    # And nothing survived to be re-encrypted: there is no longer a route from
    # this document to one holding the comment as a value.
    ok(!defined(eval { File::SOPS->encrypt(
        data => $lax, recipients => [$public], format => 'yaml') }),
        'and there is nothing to hand back to encrypt');
};

subtest 'the file-based read paths refuse as well' => sub {
    my $file = "$tempdir/comment.enc.yaml";
    my $before = document_with_comment_leaf();
    write_file($file, $before);

    for my $case (
        ['decrypt_file' => sub { File::SOPS->decrypt_file(
            input => $file, output => "$tempdir/out.yaml",
            identities => [$secret]) }],
        ['extract'      => sub { File::SOPS->extract(
            file => $file, path => '["list"][1]',
            identities => [$secret]) }],
        ['rotate'       => sub { File::SOPS->rotate(
            file => $file, identities => [$secret]) }],
    ) {
        my ($name, $code) = @$case;
        eval { $code->() };
        like($@, qr/\Alist:0: .*type:comment/s, "$name refuses");
    }

    ok(!-e "$tempdir/out.yaml", 'and decrypt_file wrote nothing');
    is(scalar read_file($file), $before,
        'and rotate left the document on disk untouched');
};

###############################################################################
# 5. THE SHAPE IS SOPS'S, NOT OURS. Without a binary the sections above prove
#    the guard; they cannot prove that sops writes this shape. That is section 6.
###############################################################################

SKIP: {
    skip "no sops binary (\$SOPS_BIN, PATH, /tmp/sops) -- the compatibility "
       . "claim this file makes was NOT verified", 3
        unless $sops_bin;

    subtest 'sops really writes a list comment as a list element' => sub {
        # The three-line minimal reproducer from karr #108, verbatim.
        write_file("$tempdir/seq.plain.yaml", "list:\n  # only a sequence comment\n  - one\n");
        my $out = `$sops_bin -e --age $public --input-type yaml --output-type yaml $tempdir/seq.plain.yaml 2>&1`;
        is($? >> 8, 0, 'sops -e writes the document') or diag($out);

        like($out, qr/^\s+- ENC\[AES256_GCM,.*,type:comment\]$/m,
            'the comment is a SEQUENCE ELEMENT, not a comment line');
        like($out, qr/^\s+- ENC\[AES256_GCM,.*,type:str\]$/m,
            'followed by the value it was written above');

        write_file("$tempdir/seq.enc.yaml", $out);
        my $back = `$sops_bin -d --input-type yaml --output-type yaml $tempdir/seq.enc.yaml 2>&1`;
        is($? >> 8, 0, 'and sops -d reads it back') or diag($back);
        like($back, qr/# only a sequence comment/,
            'with the comment restored as a comment');

        my $got = eval { File::SOPS->decrypt(
            encrypted => scalar read_file("$tempdir/seq.enc.yaml"),
            identities => [$secret]) };
        ok(!defined $got, 'File::SOPS refuses the document sops just wrote');
        like($@, qr/\Alist:0: .*type:comment/s, 'naming the element');

        my $lax = eval { File::SOPS->decrypt(
            encrypted  => scalar read_file("$tempdir/seq.enc.yaml"),
            identities => [$secret], ignore_mac => 1) };
        ok(!defined $lax, 'and refuses it with ignore_mac as well');
    };

    subtest 'a flow sequence with a trailing comment is the same defect' => sub {
        # sops rewrites `flow: [1, 2]  # after` into a BLOCK sequence with the
        # comment as element 0, so a list of integers gains a leading string:
        # sops reads [1, 2], File::SOPS read [' after a flow seq', 1, 2].
        write_file("$tempdir/flow.plain.yaml", "flow: [1, 2]  # after a flow seq\n");
        my $out = `$sops_bin -e --age $public --input-type yaml --output-type yaml $tempdir/flow.plain.yaml 2>&1`;
        is($? >> 8, 0, 'sops -e writes the document') or diag($out);
        like($out, qr/^flow:\n\s+- ENC\[AES256_GCM,.*,type:comment\]$/m,
            'the flow sequence became a block sequence led by the comment');

        write_file("$tempdir/flow.enc.yaml", $out);
        my $got = eval { File::SOPS->decrypt(
            encrypted => scalar read_file("$tempdir/flow.enc.yaml"),
            identities => [$secret]) };
        ok(!defined $got, 'File::SOPS refuses it');
        like($@, qr/\Aflow:0: .*type:comment/s, 'at flow:0');
    };

    subtest 'a document whose comments are all in mapping position still reads' => sub {
        # The control, and the thing this change must not break. Every comment
        # position sops turns into a `#ENC[...]` LINE rather than an element.
        write_file("$tempdir/map.plain.yaml", <<'YAML');
# first line
database:
  # above a key
  host: localhost
  port: 5432  # trailing
api:
  key: secret
YAML
        my $out = `$sops_bin -e --age $public --input-type yaml --output-type yaml $tempdir/map.plain.yaml 2>&1`;
        is($? >> 8, 0, 'sops -e writes the document') or diag($out);
        like($out, qr/^#ENC\[AES256_GCM,.*,type:comment\]$/m,
            'the comments are comment LINES');
        unlike($out, qr/^\s*- ENC\[AES256_GCM,.*,type:comment\]$/m,
            'and not one of them is a sequence element');

        write_file("$tempdir/map.enc.yaml", $out);
        my $got = eval { File::SOPS->decrypt(
            encrypted => scalar read_file("$tempdir/map.enc.yaml"),
            identities => [$secret]) };
        ok(defined $got, 'File::SOPS reads it, MAC and all') or diag($@);
        is_deeply($got, {
            database => { host => 'localhost', port => 5432 },
            api      => { key  => 'secret' },
        }, 'with the comments simply absent, as they always were');
    };
}

done_testing();
