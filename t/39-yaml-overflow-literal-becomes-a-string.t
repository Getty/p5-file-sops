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
# karr #102 / docs/adr/0023: a YAML literal whose magnitude overflows a double.
#
# libyaml resolves `1e400`, a 401-digit integer and the bare spelling `Inf` to a
# NUMBER, and the number it lands on is +Inf. go-yaml resolves none of them --
# strconv.ParseFloat answers ErrRange and yaml.v3 keeps a STRING -- so sops
# writes `type:str` and digests the token's own bytes, while this module wrote
# `type:float` and digested `+Inf`.
#
# Both halves were broken. Measured against sops 3.13.3 at c8eee80, over 20
# documents sops writes and sops -d reads:
#
#   sops -e  -> File::SOPS->decrypt      3 of 20 read   (MAC verification failed)
#   File::SOPS->encrypt -> sops -d       0 of 20 written (non-finite croak)
#
# The three that read did so by coincidence: FormatFloat renders those three
# doubles as the very text the source token used.
#
# The repair is a walk in Format::YAML::parse that hands back the leaf go-yaml
# sees. What makes it safe is a disjointness, and section 2 is where this file
# pins it: the twelve tokens Go DOES resolve to a non-finite float come back
# from YAML::XS POK-ONLY, so they cannot fire a predicate that requires NOK.
#
# Sections 1 to 5 need no binary. Section 6 is the compatibility claim and is
# skipped without one.
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

# A leaf exactly as the YAML format handler hands it over -- which is the only
# place the repair lives, so it is the only place worth asking.
sub yaml_leaf {
    my ($source) = @_;
    my ($data) = File::SOPS::Format::YAML->parse("v: $source\n");
    return $data->{v};
}

sub leaf_type  { File::SOPS::Encrypted->detect_type($_[0]) }
sub leaf_bytes { File::SOPS::Encrypted->value_to_bytes($_[0]) }

# The ten literals of karr #102 proper: every one of them a document sops writes
# and sops -d reads, and none of them readable here before this change. The last
# is 2**1024 - 2**970, the exact rounding threshold, where Go's ErrRange and
# Perl's NV going non-finite are measurably the same bit.
my @OVERFLOW = (
    '1e400', '-1e400', '1.5e400', '1e309', '1e310', '1e4000',
    '1' . ('0' x 400), '-1' . ('0' x 400), '+1' . ('0' x 400),
    '17976931348623158079372897140530341507993413271003782693617377898044'
  . '49682927647509466490179775872070963302864166928879109465555478519404'
  . '02630657488671505820681908902000708383676273854845817711531764475730'
  . '27006985557136695962284291481986083493647529271907416844436551070434'
  . '2711559699508093042880177904174497792',
);

# The second class, same mechanism: libyaml numifies each of these too.
my @SPELLINGS = qw( Inf inf INF NaN nan NAN -Inf +Inf Infinity -nan );

# The twelve go-yaml really does resolve to a non-finite float. In THIS file's
# plaintext parse -- yaml_leaf() below hands Format::YAML->parse a document
# with no sops: section -- these must NOT move: they stay POK-only here, and
# they are type:float to sops but str to us. ADR 0026 (karr #105, resolved)
# is why that is no longer the whole story: the same twelve DO move -- they
# come back a float whose digest is +Inf / -Inf / NaN -- once the document
# carries a sops: section, which this file's helper never gives it. See
# t/42-yaml-plain-infinity-is-a-float.t sections 1 and 7 for that other half.
my @GO_RESOLVES = qw(
    .inf .Inf .INF +.inf +.Inf +.INF -.inf -.Inf -.INF .nan .NaN .NAN
);

###############################################################################
# 1. THE MOVED ROWS. A literal libyaml pushed past the end of a double is the
#    string go-yaml kept, and its digest input is the literal's own text.
###############################################################################

subtest 'an overflowing literal parses to the string sops digests' => sub {
    for my $source (@OVERFLOW) {
        my $short = length($source) > 20 ? substr($source, 0, 17) . '...' : $source;
        my $leaf  = yaml_leaf($source);

        is(ref($leaf), '', "[$short] a plain scalar");
        is(leaf_type($leaf), 'str', "[$short] typed str, not float");
        is(leaf_bytes($leaf), $source,
            "[$short] and its digest input is the literal, not +Inf");
    }
};

subtest 'a bare Inf / NaN spelling is the same leaf' => sub {
    for my $source (@SPELLINGS) {
        my $leaf = yaml_leaf($source);
        is(leaf_type($leaf), 'str', "[$source] typed str");
        is(leaf_bytes($leaf), $source, "[$source] digested verbatim");
    }
};

###############################################################################
# 2. WHAT MUST NOT MOVE, IN A PLAINTEXT PARSE. The predicate reads SVf_NOK, and
#    every token Go resolves to a non-finite float arrives here POK-ONLY --
#    that disjointness is the whole safety of ADR 0023's walk, so it is pinned
#    rather than assumed. ADR 0026 (karr #105) narrows this on the OTHER side:
#    the same twelve tokens DO move -- they come back a float -- once the
#    document carries a sops: section, which yaml_leaf() here never gives it.
#    See t/42-yaml-plain-infinity-is-a-float.t sections 1 and 7 for that half.
###############################################################################

subtest 'the twelve tokens Go reads as a float are untouched' => sub {
    for my $source (@GO_RESOLVES) {
        my $leaf = yaml_leaf($source);
        is(leaf_type($leaf), 'str', "[$source] still a str here");
        is(leaf_bytes($leaf), $source,
            "[$source] still digested as the token -- karr #105, unchanged");
    }
};

subtest 'a finite number is still the number it was' => sub {
    my @rows = (
        [ '0',        'int',   '0'    ],
        [ '1',        'int',   '1'    ],
        [ '-1',       'int',   '-1'   ],
        [ '007',      'int',   '7'    ],
        [ '1e3',      'int',   '1000' ],
        [ '3.14',     'float', '3.14' ],
        [ '1.5',      'float', '1.5'  ],
        [ '9223372036854775807', 'int', '9223372036854775807' ],
    );
    for my $row (@rows) {
        my ($source, $type, $bytes) = @$row;
        my $leaf = yaml_leaf($source);
        is(leaf_type($leaf), $type, "[$source] stays $type");
        is(leaf_bytes($leaf), $bytes, "[$source] with its own digest input");
    }

    # The three extremes libyaml still resolves to a FINITE double, the last of
    # them one bit below the rounding threshold where this change takes over.
    # ADR 0006 owns what a float's digest text is; what matters here is only
    # that these are still floats and still not +Inf.
    for my $source ('5e-324', '1e308', '1.7976931348623157e308',
        '17976931348623158079372897140530341507993413271003782693617377898044'
      . '49682927647509466490179775872070963302864166928879109465555478519404'
      . '02630657488671505820681908902000708383676273854845817711531764475730'
      . '27006985557136695962284291481986083493647529271907416844436551070434'
      . '2711559699508093042880177904174497791') {
        my $short = length($source) > 24 ? substr($source, 0, 21) . '...' : $source;
        my $leaf  = yaml_leaf($source);
        is(leaf_type($leaf), 'float', "[$short] a finite double, still a float");
        my $bytes = leaf_bytes($leaf);
        unlike($bytes, qr/\A[-+]?(?:Inf|NaN)\z/, "[$short] and not a non-finite one");
        like($bytes, qr/\A[0-9.]+\z/, "[$short] digested positionally as its double");
        isnt($bytes, $source, "[$short] canonicalised, not written as its source text");
    }
};

subtest 'a quoted literal was already a string and stays one' => sub {
    my $leaf = yaml_leaf(q{"1e400"});
    is(leaf_type($leaf), 'str', 'a quoted 1e400 is a str');
    is(leaf_bytes($leaf), '1e400', 'digested as its text');
};

subtest 'an underflowing literal is untouched' => sub {
    # karr #106: 1e-400 is an int here and a float to sops, both digesting `0`.
    # A non-finite NV never appears, so this predicate cannot fire on it, and
    # this pins that it does not.
    for my $source ('1e-400', '1e-500') {
        my $leaf = yaml_leaf($source);
        is(leaf_type($leaf), 'int', "[$source] still an int -- karr #106");
        is(leaf_bytes($leaf), '0', "[$source] still digesting 0");
    }
};

subtest 'nothing that is not a number moves' => sub {
    for my $source (qw( localhost .env .gitignore 123abc Inf-x 1e400x a-b-c )) {
        my $leaf = yaml_leaf($source);
        is(leaf_type($leaf), 'str', "[$source] a str");
        is(leaf_bytes($leaf), $source, "[$source] digested verbatim");
    }
    is(ref(yaml_leaf('true')), 'JSON::PP::Boolean', 'a bool is still a bool');
    is(yaml_leaf('null'), undef, 'a null is still a null');
};

###############################################################################
# 3. THE WALK'S REACH. Every leaf of the tree, containers included, and nothing
#    outside it.
###############################################################################

subtest 'the walk reaches nested hashes and sequences' => sub {
    my ($data) = File::SOPS::Format::YAML->parse(<<'YAML');
top: 1e400
nested:
  deep:
    leaf: 1e400
list:
  - 1e400
  - inner:
      - 1e400
YAML
    is(leaf_type($data->{top}), 'str', 'a top-level leaf');
    is(leaf_type($data->{nested}{deep}{leaf}), 'str', 'a leaf three levels down');
    is(leaf_type($data->{list}[0]), 'str', 'a sequence entry');
    is(leaf_type($data->{list}[1]{inner}[0]), 'str', 'a sequence inside a mapping');
};

subtest 'an alias shared by two keys is handled once and correctly' => sub {
    my ($data) = File::SOPS::Format::YAML->parse(
        "a: &x\n  v: 1e400\nb: *x\n");
    is(leaf_type($data->{a}{v}), 'str', 'through the anchor');
    is(leaf_type($data->{b}{v}), 'str', 'and through the alias -- the same leaf');
};

subtest 'the sops section is split off before the walk runs' => sub {
    my $plain = eval { File::SOPS->encrypt(
        data       => { keep => 'x', v_unencrypted => yaml_leaf('1e400') },
        recipients => [$public],
        format     => 'yaml',
    ) };
    ok(defined $plain, 'a document with such a leaf can be written at all')
        or do { diag($@); return };

    my ($data, $metadata) = File::SOPS::Format::YAML->parse($plain);
    ok(!exists $data->{sops}, 'the metadata is out of the tree');
    ok(defined $metadata, 'and came back as a Metadata object');
    is($metadata->version, '3.7.3', 'with its version intact');
    is(leaf_type($data->{v_unencrypted}), 'str',
        'while the document leaf was still repaired');
};

###############################################################################
# 4. THE GUARD FROM karr #59 IS UNTOUCHED. This change removes an artefact of
#    the parser; it does not loosen a rule about values. A caller who hands
#    encrypt() a real non-finite float still gets the refusal.
###############################################################################

subtest 'a real non-finite float is still refused' => sub {
    my $inf = 9**9**9;
    my @values = ( [ '+Inf', $inf ], [ '-Inf', -$inf ], [ 'NaN', $inf - $inf ] );

    for my $case (@values) {
        my ($name, $value) = @$case;
        for my $key (qw( v v_unencrypted )) {
            my $out = eval { File::SOPS->encrypt(
                data       => { $key => $value, keep => 'x' },
                recipients => [$public],
                format     => 'yaml',
            ) };
            ok(!defined $out, "[$name in $key] refused");
            like($@, qr/\Qvalue is a non-finite float\E/,
                "[$name in $key] with the karr #59 message");
        }
    }
};

###############################################################################
# 5. AN ENCRYPTED SLOT IS OUT OF REACH BY CONSTRUCTION. The walk runs at parse
#    time, when every encrypted leaf is still an ENC[...] STRING -- so it cannot
#    see, let alone rewrite, a plaintext the cipher has not produced yet.
###############################################################################

subtest 'an ENC[...] leaf is a plain string to the walk' => sub {
    my $document = File::SOPS->encrypt(
        data       => { v => 'secret', keep => 'x' },
        recipients => [$public],
        format     => 'yaml',
    );
    my ($data) = File::SOPS::Format::YAML->parse($document);
    ok(File::SOPS::Encrypted->is_encrypted($data->{v}),
        'the leaf is still the wire string at parse time');
    is(leaf_type($data->{v}), 'str', 'which is a str, so the predicate is blind to it');
};

###############################################################################
# 6. THE COMPATIBILITY CLAIM. Everything above says what this module does; only
#    this section says what sops does, and it is the only proof that the two now
#    agree. Both directions, all twenty literals.
###############################################################################

SKIP: {
    skip "no sops binary (\$SOPS_BIN, PATH, /tmp/sops) -- the compatibility "
       . "claim this file makes was NOT verified", 3
        unless $sops_bin;

    subtest 'a document sops wrote is readable here' => sub {
        for my $source (@OVERFLOW, @SPELLINGS) {
            my $short = length($source) > 20 ? substr($source, 0, 17) . '...' : $source;
            my $file  = "$tempdir/read.yaml";
            write_file("$tempdir/read.plain.yaml",
                "keep: x\nv_unencrypted: $source\n");

            my $out = `$sops_bin -e --age $public --input-type yaml --output-type yaml $tempdir/read.plain.yaml 2>&1`;
            is($? >> 8, 0, "[$short] sops -e writes the document") or diag($out);
            write_file($file, $out);
            like($out, qr/^\Qv_unencrypted: $source\E$/m,
                "[$short] with the literal verbatim, as a string");

            my $got = eval { File::SOPS->decrypt(
                encrypted => scalar read_file($file), identities => [$secret]) };
            ok(defined $got, "[$short] and this module verifies its MAC")
                or diag($@);
            is($got->{v_unencrypted}, $source,
                "[$short] reading back the literal sops digested") if $got;
        }
    };

    subtest 'a document written here is readable by sops' => sub {
        for my $source (@OVERFLOW, @SPELLINGS) {
            my $short = length($source) > 20 ? substr($source, 0, 17) . '...' : $source;
            my ($data) = File::SOPS::Format::YAML->parse(
                "keep: x\nv: $source\nv_unencrypted: $source\n");

            my $document = eval { File::SOPS->encrypt(
                data => $data, recipients => [$public], format => 'yaml') };
            ok(defined $document, "[$short] written without a refusal") or do {
                diag($@); next;
            };
            like($document, qr/^v: ENC\[AES256_GCM,.*type:str\]$/m,
                "[$short] with sops's own token for the encrypted slot");

            my $file = "$tempdir/write.yaml";
            write_file($file, $document);
            my $out = `$sops_bin -d --input-type yaml --output-type yaml $file 2>&1`;
            is($? >> 8, 0, "[$short] and sops -d accepts it") or diag($out);

            my ($back) = $out =~ /^v_unencrypted: (.*)$/m;
            $back = '' unless defined $back;
            $back =~ s/\A'//; $back =~ s/'\z//;
            is($back, $source, "[$short] reading back the same literal");
        }
    };

    subtest 'an encrypted type:float that IS non-finite still decrypts to one' => sub {
        # The one place a walk drawn one leaf too wide would silently destroy
        # data. sops writes a bare `.inf` in an ENCRYPTED slot as type:float
        # with the plaintext +Inf, and this module has always handed that back
        # as a real Perl infinity. It still must.
        write_file("$tempdir/inf.plain.yaml",
            "keep: x\npos: .inf\nneg: -.inf\nnn: .nan\n");
        my $out = `$sops_bin -e --age $public --input-type yaml --output-type yaml $tempdir/inf.plain.yaml 2>&1`;
        is($? >> 8, 0, 'sops -e writes the document') or diag($out);
        like($out, qr/^pos: ENC\[AES256_GCM,.*type:float\]$/m,
            'with type:float for the encrypted slot');
        write_file("$tempdir/inf.yaml", $out);

        my $got = eval { File::SOPS->decrypt(
            encrypted => scalar read_file("$tempdir/inf.yaml"),
            identities => [$secret]) };
        ok(defined $got, 'and this module reads it') or diag($@);

        my $inf = 9**9**9;
        is(unpack('H*', pack('d', $got->{pos})), unpack('H*', pack('d', $inf)),
            'the positive infinity comes back as the same double');
        is(unpack('H*', pack('d', $got->{neg})), unpack('H*', pack('d', -$inf)),
            'and the negative one');
        ok($got->{nn} != $got->{nn}, 'and the NaN is still a NaN');
    };
}

done_testing();
