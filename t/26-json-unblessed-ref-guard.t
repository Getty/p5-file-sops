#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurp qw(read_file write_file);
use JSON::MaybeXS qw(decode_json JSON);
use Scalar::Util qw(blessed);
use Digest::SHA ();

use File::SOPS;
use File::SOPS::Encrypted;
use File::SOPS::Metadata;
use File::SOPS::Format::JSON;
use File::SOPS::Backend::Age;
use Crypt::Age;

# ----------------------------------------------------------------------------
# karr #66 / docs/adr/0008 close-the-known-gap: Format::JSON::emit now refuses
# every referenced leaf except an EXACT JSON::PP::Boolean, mirroring the YAML
# guard from karr #65. The unblessed-ref half is the bug this file pins down.
#
# The Cpanel::JSON::XS convention is to write \1 as bare `true` and \0 as bare
# `false` (documented JSON::XS behaviour, not a Cpanel bug). detect_type calls
# an unblessed SCALAR ref `str`, so the digest covers its stringification --
# `SCALAR(0x...)`, a heap address -- while the document carries `true` or
# `false`. The two sides of the document disagree, and the file is unreadable
# to sops and to this module alike. Exit 51 in sops -d, measured against sops
# 3.13.3.
#
# The pre-fix _reject_foreign_bignum only named Math::BigFloat and Math::BigInt,
# because those were the two classes allow_bignum whitelists wide of our own
# carrier. Cpanel itself catches every other blessed reference (Foo=HASH(0x...),
# qr//) with its own error, and unblessed SCALAR refs fell through silently.
# The expanded guard catches every referenced leaf with one message naming the
# class or ref kind, never the value.
#
# The five ADR 0008 rows for the JSON side collapse to one rule under the new
# guard. YAML's behaviour is unchanged by this ticket; cases 1 and 2 below are
# JSON-only.
#
# Interop is required: a green perl-only suite proves the library agrees with
# itself, which is the failure mode here. The cases that would otherwise be
# silent bugs only fail against sops, so a missing sops binary is a skip, not
# a pass.
# ----------------------------------------------------------------------------

# Copied from t/04-interop.t and t/25-blessed-leaf-guard.t's resolution rule.
# SOPS_BIN wins and dies if set to something not executable; falling through
# would silently prove compatibility against a binary nobody chose.
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

unless ($sops_bin) {
    plan skip_all =>
        "No sops binary found (checked \$SOPS_BIN, PATH, /tmp/sops) -- "
      . "karr #66 is a wire-format guard, and interop is how a mistake in it "
      . "(refusing too much, or too little) would actually be seen. Fix: set "
      . "SOPS_BIN=/path/to/sops.";
}

diag("Using sops binary: $sops_bin");

# ----------------------------------------------------------------------------
# One test-only class. A JSON::PP::Boolean subclass: detect_type accepts it as
# bool via ->isa, but neither the cargo-culted Cpanel path nor the carrier
# pipeline writes it as bare true/false. The guard's exact-class rule
# refuses it; case 5 is the regression for that.
# ----------------------------------------------------------------------------
package File::SOPS::Test::JsonUnblessedRefGuard::MyBool;
our @ISA = ('JSON::PP::Boolean');

package main;

my ($public, $secret) = Crypt::Age->generate_keypair();
my $tempdir = tempdir(CLEANUP => 1);
write_file("$tempdir/key.txt", $secret);
$ENV{SOPS_AGE_KEY_FILE} = "$tempdir/key.txt";

my $serial = 0;
sub scratch_file {
    my ($ext) = @_;
    return "$tempdir/f" . ++$serial . ".$ext";
}

###############################################################################
# 1. THE REGESSION: \1 / \0 are now caught, by the same callback that the
#    YAML guard uses. The Cpanel output the pre-fix code wrote (`true`/`false`)
#    is the silent half of the documented defect; the message names the ref
#    kind, never the value.
###############################################################################

subtest 'JSON::emit refuses \1 (unblessed SCALAR ref) -- the karr #66 case' => sub {
    my $result = eval { File::SOPS::Format::JSON->emit({ leaf_unencrypted => \1 }) };
    ok(!defined $result, 'emit() does not return a document');
    like($@, qr/unblessed SCALAR reference/, 'the message names the ref kind');
};

subtest 'JSON::emit refuses \0 (unblessed SCALAR ref) -- the karr #66 case' => sub {
    my $result = eval { File::SOPS::Format::JSON->emit({ leaf_unencrypted => \0 }) };
    ok(!defined $result, 'emit() does not return a document');
    like($@, qr/unblessed SCALAR reference/, 'the message names the ref kind');
};

subtest 'JSON::emit refuses \$x for an arbitrary unblessed SCALAR ref' => sub {
    # The pre-fix code wrote \1 as `true` and \0 as `false`, but ANY unblessed
    # SCALAR ref would have hit the same Cpanel convention; the guard catches
    # the whole class, not just the two end-points.
    my $x = 42;
    my $r = \$x;
    my $result = eval { File::SOPS::Format::JSON->emit({ leaf_unencrypted => $r }) };
    ok(!defined $result, 'emit() does not return a document');
    like($@, qr/unblessed SCALAR reference/, 'the message names the ref kind');
};

subtest 'JSON::emit refuses an unblessed CODE reference' => sub {
    # Cpanel already rejected this with its own error (`JSON can only represent
    # references to arrays or hashes`), so the failure was visible but with a
    # different message than the YAML side. The new guard funnels it through
    # the same message as the other ref kinds.
    my $result = eval { File::SOPS::Format::JSON->emit({ leaf_unencrypted => sub { 1 } }) };
    ok(!defined $result, 'emit() does not return a document');
    like($@, qr/unblessed CODE reference/, 'the message names the ref kind');
};

###############################################################################
# 2. The guard catches the karr #66 case through the PUBLIC API too, not only
#    through Format::JSON->emit directly. This is the path the caller uses, and
#    the one that previously wrote a self-broken file under a user's `secret`
#    key without a word.
###############################################################################

subtest 'File::SOPS->encrypt refuses \1 as an unencrypted JSON leaf' => sub {
    my $encrypted = eval {
        File::SOPS->encrypt(
            data       => { x_unencrypted => \1, secret => 'shh' },
            recipients => [$public],
            format     => 'json',
        );
    };
    ok(!defined $encrypted, 'encrypt() does not return a document');
    like($@, qr/unblessed SCALAR reference/,
        'with the guard message, not a silent `true` and exit 51');
};

subtest 'File::SOPS->encrypt refuses \0 as an unencrypted JSON leaf' => sub {
    my $encrypted = eval {
        File::SOPS->encrypt(
            data       => { x_unencrypted => \0, secret => 'shh' },
            recipients => [$public],
            format     => 'json',
        );
    };
    ok(!defined $encrypted, 'encrypt() does not return a document');
    like($@, qr/unblessed SCALAR reference/, 'with the guard message');
};

###############################################################################
# 3. The guard reaches a rejected leaf nested inside a hash and inside an
#    array, exactly as t/25-blessed-leaf-guard.t does for the YAML side.
#    canonical_float_tree walks every leaf through the same reject callback,
#    so a top-level-only guard would be a narrower guard than the one shipped.
###############################################################################

subtest 'the guard reaches a rejected leaf nested inside a hash (JSON)' => sub {
    my $nested = eval {
        File::SOPS::Format::JSON->emit({
            outer_unencrypted => { inner_unencrypted => \1 },
        });
    };
    ok(!defined $nested, 'a \1 nested inside a hash is refused');
    like($@, qr/unblessed SCALAR reference/, 'with the guard message');
};

subtest 'the guard reaches a rejected leaf nested inside an array (JSON)' => sub {
    my $in_array = eval {
        File::SOPS::Format::JSON->emit({
            list_unencrypted => [ 1, 2, \0 ],
        });
    };
    ok(!defined $in_array, 'a \0 inside an array is refused');
    like($@, qr/unblessed SCALAR reference/, 'with the guard message');
};

###############################################################################
# 4. The exception still works: JSON->true / JSON->false reach the document as
#    bare true/false, and the mac_only_encrypted case (Metadata::to_hash emits
#    JSON->true) keeps writing. Measured on the same docs the YAML side uses
#    in t/25.
#
#    Empty {} / [] as leaves are unaffected for the same reason -- they were
#    never reachable from the reject callback.
# ----------------------------------------------------------------------------
#    This is the test that would have been catastrophic had the guard refused
#    every reference without an exception: Metadata::to_hash writes a JSON-true
#    into every mac_only_encrypted document, so a guard without the boolean
#    exception would have made every such document unwritable.
###############################################################################

subtest 'JSON->true / JSON->false as unencrypted leaves round-trip' => sub {
    my $data = {
        flag_unencrypted  => JSON->true,
        off_unencrypted   => JSON->false,
        block_unencrypted => {
            nested => JSON->true,
            list   => [ JSON->false, JSON->true ],
        },
        secret => 'shh',
    };

    my $encrypted = eval {
        File::SOPS->encrypt(data => $data, recipients => [$public], format => 'json');
    };
    is($@, '', 'encrypt() does not croak on the guard') or return;

    my $self = eval {
        File::SOPS->decrypt(encrypted => $encrypted, identities => [$secret], format => 'json');
    };
    is($@, '', 'self-MAC holds') or diag("died: $@");
    if ($self) {
        ok($self->{flag_unencrypted}, 'top-level true');
        ok(!$self->{off_unencrypted}, 'top-level false');
        ok($self->{block_unencrypted}{nested}, 'nested in a hash');
        ok(!$self->{block_unencrypted}{list}[0], 'nested in an array, false');
        ok($self->{block_unencrypted}{list}[1], 'nested in an array, true');
    }

    my $file = scratch_file('json');
    write_file($file, $encrypted);
    my $out       = `$sops_bin -d $file 2>&1`;
    my $exit_code = $? >> 8;
    is($exit_code, 0, 'sops -d accepts the document') or diag("sops output: $out");
    if ($exit_code == 0) {
        my $decoded = decode_json($out);
        ok($decoded->{flag_unencrypted}, 'sops itself reads the top-level true back');
        ok(!$decoded->{off_unencrypted}, 'and the top-level false');
    }
};

subtest 'mac_only_encrypted still writes and reads (JSON)' => sub {
    my $data = { cfg_unencrypted => 'plain', secret => 'shh', n => 42 };

    my $encrypted = eval {
        File::SOPS->encrypt(
            data               => $data,
            recipients         => [$public],
            format             => 'json',
            mac_only_encrypted => 1,
        );
    };
    is($@, '', 'encrypt() does not croak on the guard') or return;
    like($encrypted, qr/"mac_only_encrypted"\s*:\s*true/,
        'the sops section carries a bare true, not a {{...}} tag');

    my $self = eval {
        File::SOPS->decrypt(encrypted => $encrypted, identities => [$secret], format => 'json');
    };
    is($@, '', 'self-MAC holds') or diag("died: $@");
    is_deeply($self, $data, 'and the data round-trips') if $self;

    my $file = scratch_file('json');
    write_file($file, $encrypted);
    my $out = `$sops_bin -d $file 2>&1`;
    is($? >> 8, 0, 'sops -d accepts the mac_only_encrypted document')
        or diag("sops output: $out");
};

subtest 'empty {} and [] as leaves are unaffected (JSON)' => sub {
    my $data = { empty_hash_unencrypted => {}, empty_arr_unencrypted => [], secret => 'shh' };

    my $encrypted = eval {
        File::SOPS->encrypt(data => $data, recipients => [$public], format => 'json');
    };
    is($@, '', 'encrypt() does not croak') or return;

    my $self = eval {
        File::SOPS->decrypt(encrypted => $encrypted, identities => [$secret], format => 'json');
    };
    is($@, '', 'self-MAC holds') or diag("died: $@");
    is_deeply($self->{empty_hash_unencrypted}, {}, 'empty hash round-trips') if $self;
    is_deeply($self->{empty_arr_unencrypted}, [], 'empty array round-trips') if $self;
};

###############################################################################
# 5. The trap in the trap: a SUBCLASS of JSON::PP::Boolean is refused too.
#    detect_type accepts it via ->isa, but the JSON side has nothing that
#    writes it as bare true/false -- and the guard tests the exact class, not
#    ->isa. Mirrors the YAML test in t/25.
# ----------------------------------------------------------------------------
#    The pre-fix code's allow_bignum whitelist matched Bignum by name, and its
#    whitelist for JSON::PP::Boolean (implicit, in `Metadata::to_hash`) was not
#    what was filtering subclasses. The new guard's exact-class rule is what
#    closes the door here.
###############################################################################

subtest 'a JSON::PP::Boolean subclass is refused too (JSON)' => sub {
    my $subclass_bool = bless(\(my $v = 1), 'File::SOPS::Test::JsonUnblessedRefGuard::MyBool');

    ok(blessed($subclass_bool) && $subclass_bool->isa('JSON::PP::Boolean'),
        'sanity: detect_type would call this leaf bool via ->isa');

    my $result = eval {
        File::SOPS::Format::JSON->emit({ leaf_unencrypted => $subclass_bool });
    };
    ok(!defined $result, 'emit() does not return a document');
    like($@, qr/\bFile::SOPS::Test::JsonUnblessedRefGuard::MyBool\b/,
        'the message names the subclass, not just "JSON::PP::Boolean"');

    my $encrypted = eval {
        File::SOPS->encrypt(
            data       => { flag_unencrypted => $subclass_bool, secret => 'shh' },
            recipients => [$public],
            format     => 'json',
        );
    };
    ok(!defined $encrypted, 'and File::SOPS->encrypt refuses it too');
};

###############################################################################
# 6. A \1 in an ENCRYPTED slot is unaffected: _encrypt_tree replaces every
#    encrypted leaf with an ENC[...] string before emit ever sees it, so the
#    leaf's stringification is what the digest covers AND what the ENC string
#    carries. The guard never sees a value that got encrypted.
###############################################################################

subtest 'a \1 in an ENCRYPTED JSON slot is unaffected (the pre-existing happy path)' => sub {
    # value_to_bytes of an unblessed SCALAR ref is its stringified address,
    # 'SCALAR(0x...)' (measured, length 22 -- even \1 / \0, whose PV slot is
    # empty, stringify the same way because the SvROK branch beats the PV
    # branch). The MAC and the ENC[...] plaintext both cover that text, so
    # the file verifies -- but the address differs per run, which is the
    # problem karr #67 files separately. The test asserts the SHAPE
    # (non-empty stringification, type:str), not the value: the pre-fix code
    # already worked for this case and the new guard must not break it.
    my $encrypted = eval {
        File::SOPS->encrypt(
            data       => { secret => \1, other => 'x' },
            recipients => [$public],
            format     => 'json',
        );
    };
    is($@, '', 'encrypt() does not croak: the guard never sees this leaf') or return;
    like($encrypted, qr/type:str/, 'written as type:str');

    my $self = eval {
        File::SOPS->decrypt(encrypted => $encrypted, identities => [$secret], format => 'json');
    };
    is($@, '', 'self-MAC holds') or diag("died: $@");
    if ($self) {
        ok(defined $self->{secret} && length $self->{secret},
            q{and decrypts to a non-empty stringification of the ref});
    }

    my $file = scratch_file('json');
    write_file($file, $encrypted);
    my $out       = `$sops_bin -d $file 2>&1`;
    my $exit_code = $? >> 8;
    is($exit_code, 0, 'sops -d accepts the document') or diag("sops output: $out");
};

###############################################################################
# 7. The pre-fix wire shape was valid JSON; the defect was on the WRITING
#    side, where File::SOPS produced a file whose DOC and DIGEST disagreed.
#    The two halves of the proof are the cases above: cases 1, 2, 3 show
#    that the new code refuses to write the file, and we never have to
#    construct the broken file at all. sops itself, with a real SOPS
#    document, would compute the MAC over the value it parsed back out
#    (`true`), not over the heap address the broken code digested
#    (`SCALAR(0x...)`), so the broken file's two halves disagreed by
#    construction -- the MAC has no consistent answer on either side.
#
#    Cases 5 and 6 (mac_only_encrypted and empty {} / []) are the
#    regression: the boolean exception and the container loop must keep
#    working.
###############################################################################

done_testing;
