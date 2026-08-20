package File::SOPS::Format::YAML;
# ABSTRACT: YAML format handler for SOPS
our $VERSION = '0.003';
use Moo;
use Carp qw(croak);
use Scalar::Util qw(blessed dualvar);
use YAML::XS qw(Load Dump);
use File::SOPS::Encrypted;
use File::SOPS::Metadata;
use namespace::clean;

# Carp reports the caller of the frame croak stands in, and every frame between
# a caller and this module is this distribution's own: File::SOPS::encrypt calls
# emit(), emit() calls File::SOPS::Encrypted->canonical_float_tree, and the walk
# calls the guards below BACK. So a refusal named a line in Encrypted.pm -- the
# walk's own recursion -- where the house rule asks for the line the caller
# wrote encrypt() or emit() on (karr #71). Naming both packages here makes Carp
# walk out of them: it skips a frame when either side trusts the other, so this
# one list also fixes the guard that croaks from inside the walk.
#
# It is the frames, not the messages, that this changes. Every message still
# names the leaf's key path (karr #68), which is what a caller acts on.
our @CARP_NOT = qw( File::SOPS File::SOPS::Encrypted );

# 'JSON::PP' here is one of YAML::XS's own two mode names (the other is
# 'boolean'), not a module this distribution loads or talks to. It makes
# Load/Dump round-trip YAML true/false as JSON::PP::Boolean objects -- the same
# class JSON::MaybeXS blesses into on every backend. Do not "modernise" this
# string to 'JSON::MaybeXS'; YAML::XS would reject it.
#
# LOCALISED around our own calls, never assigned at load time. $YAML::XS::Boolean
# is a process-global that changes what YAML::XS::Load and ::Dump do for
# EVERYONE in the program, and setting it as a side effect of `use File::SOPS`
# silently rewrote the semantics of unrelated code that merely happened to share
# the interpreter.
our $BOOLEAN_MODE = 'JSON::PP';

=head1 SYNOPSIS

    use File::SOPS::Format::YAML;

    # Parse YAML with SOPS metadata
    my ($data, $metadata) = File::SOPS::Format::YAML->parse($yaml_content);

    # Serialize data with SOPS metadata
    my $yaml = File::SOPS::Format::YAML->serialize(
        data     => $encrypted_data,
        metadata => $metadata_obj,
    );

    # Check if filename is YAML
    if (File::SOPS::Format::YAML->detect('secrets.yaml')) {
        # It's a YAML file
    }

=head1 DESCRIPTION

YAML format handler for File::SOPS. Handles parsing and serialization of
SOPS-encrypted YAML files.

Uses L<YAML::XS> for fast, spec-compliant YAML processing.

Booleans are round-tripped as C<JSON::PP::Boolean> objects, by setting
YAML::XS's C<$YAML::XS::Boolean> mode to C<'JSON::PP'>. That is the class
L<JSON::MaybeXS> blesses booleans into on every one of its backends, so a
C<true> loaded from YAML and a C<true> decoded from JSON are the same kind of
object throughout this distribution, and both are emitted as bare C<true> /
C<false> rather than degrading to C<1> / C<0> on the next write.

The mode is set with C<local> around this module's own C<Load> and C<Dump>
calls. C<$YAML::XS::Boolean> is a process global that changes what L<YAML::XS>
does for every other user of it in the same interpreter, so before 0.003 merely
loading File::SOPS changed how unrelated code parsed YAML.

=head2 Multi-document YAML

B<A YAML stream with more than one document is refused.> L</parse> dies rather
than returning part of it.

This is a restriction, not a preference: it replaces silent data loss. Until
0.003 the stream was loaded in scalar context, which yields only the B<last>
document, so C<a: 1\n---\nb: 2> parsed to C<{b =E<gt> 2}> and
L<File::SOPS/encrypt_file> wrote that back as the entire file. Every document
but the last disappeared with no error.

sops itself does support multi-document YAML, so this is a gap to close rather
than a rule to keep. Its model, measured against sops 3.13.3, is not "several
independent files in one":

=over 4

=item * One metadata section for the whole stream, written into B<every>
document -- the same age blob, C<lastmodified> and C<mac> byte for byte. On
read it is taken from the B<first> document; a stream carrying it only in a
later document is rejected with C<sops metadata not found>.

=item * B<One MAC spanning all documents, in order.> Removing a document or
swapping two of them fails verification.

=item * The AAD carries B<no> document index. A given key path has the same
AAD in every document, so a value encrypted in one document decrypts in
another document's slot at that path.

=item * Documents are joined by C<--->; a B<leading> separator is dropped,
while a trailing one is preserved as a real (empty) document. An empty document
anywhere is a document: it gets its own metadata block and reads back as C<{}>.

=item * Every document must be a mapping. sops rejects a top-level sequence or
scalar itself (C<YAML documents that are sequences are not supported>), which
is the same rule as the HashRef check in L</parse>.

=back

Supporting that means one tree of N branches with a shared metadata and a
digest spanning all of them, which reaches into encryption, MAC computation and
the shape of the public API -- not this parser alone.

=cut

sub parse {
    my ($class, $content) = @_;
    croak "content required" unless defined $content;

    local $YAML::XS::Boolean = $BOOLEAN_MODE;

    # LIST context is load-bearing. YAML::XS::Load in SCALAR context returns
    # only the LAST document of a multi-document stream, so `a: 1\n---\nb: 2`
    # used to parse to just {b=>2} -- and encrypt_file then wrote that back as
    # the whole file. Silent data loss on a write path, with no error.
    #
    # sops does support multi-document YAML, but not as "several files in one":
    # it is ONE tree with N branches, carrying ONE metadata section (written
    # into every document) and ONE MAC spanning all documents in order.
    # Reproducing that is a data-model change well beyond this parser, so until
    # it exists the input is refused rather than quietly truncated.
    my @docs = Load($content);
    croak sprintf(
        "YAML input has %d documents; File::SOPS handles one document per "
        . "file. Multi-document YAML is not supported yet -- it used to be "
        . "accepted and silently reduced to the last document.",
        scalar @docs
    ) if @docs > 1;

    my $data = $docs[0];
    croak "YAML did not parse to a hash" unless ref $data eq 'HASH';

    my $metadata;
    if (exists $data->{sops}) {
        $metadata = File::SOPS::Metadata->from_hash(delete $data->{sops});
    }

    return ($data, $metadata);
}

=method parse

    my ($data, $metadata) = File::SOPS::Format::YAML->parse($yaml_string);

Class method to parse a YAML string.

Returns a two-element list:

=over 4

=item 1. C<$data> - HashRef of the data (without the C<sops> section)

=item 2. C<$metadata> - L<File::SOPS::Metadata> object, or C<undef> if no C<sops> section

=back

Dies if the YAML is invalid, doesn't parse to a HashRef, or contains more
than one document. See L</Multi-document YAML>.

Dies too if the document has a top-level C<sops> entry that is B<not> a
mapping -- C<sops: mine>, a list, or an explicit C<null>. Until 0.003 that
entry was deleted from the tree and reported as no metadata at all, so
L<File::SOPS/encrypt_file> wrote the document back without it. See
L<File::SOPS::Metadata/from_hash>, which is where the refusal lives.

=cut

sub serialize {
    my ($class, %args) = @_;
    my $data     = $args{data}     // croak "data required";
    my $metadata = $args{metadata} // croak "metadata required";

    # The metadata goes into `sops`, so a value already there would be
    # overwritten -- and since the digest was computed over the tree BEFORE
    # serialization, the document that came out failed its own MAC. Refuse
    # instead, as sops does (exit 203). See File::SOPS::encrypt.
    croak "data contains a top-level 'sops' entry, which is where the SOPS "
        . "metadata section goes"
        if exists $data->{sops};

    my %output = %$data;
    $output{sops} = $metadata->to_hash;

    # The timestamp fixup applies to the metadata section only, so it sits here
    # rather than in emit -- a plaintext document has no `sops:` block to fix.
    #
    # mac_covered turns on the foreign-resolution guard (karr #86, ADR 0013):
    # this document carries a MAC, and sops recomputes that MAC from the values
    # ITS parser resolves out of these bytes. Not set for mac_only_encrypted,
    # where the digest covers encrypted values only -- an unencrypted leaf
    # cannot make such a document disagree with its own MAC, measured, and
    # refusing it would refuse a document that works today.
    return _quote_sops_timestamp($class->emit(\%output,
        mac_covered => $metadata->mac_only_encrypted ? 0 : 1));
}

# YAML::XS emits plain (unquoted) scalars for anything its resolver does not
# recognise as a YAML core-schema type. $YAML::XS::QuoteNumericStrings (on by
# default) already covers numbers, booleans and nulls -- '3.8', '123', 'true'
# and 'null' all come out quoted -- but the resolver has no notion of
# timestamps, so an RFC3339 lastmodified is emitted bare.
#
# Go's yaml.v3 DOES resolve a bare RFC3339 scalar, to time.Time, and sops then
# refuses the whole file before it decrypts anything:
#
#   decoding failed due to the following error(s):
#   'lastmodified' expected type 'string', got unconvertible type 'time.Time'
#
# sops itself writes lastmodified: "2026-08-08T21:28:58Z" -- quoted. YAML::XS
# exposes no per-scalar style control (no tag, no forced-quote hook), so the
# only way to get a quoted scalar out of this emitter is to quote it after the
# dump. Kept deliberately narrow: it rewrites one key, only inside the
# top-level `sops:` block, so a user's own `lastmodified:` in the data section
# is never touched. JSON needs none of this -- JSON has no timestamp type and
# its strings are always quoted.
sub _quote_sops_timestamp {
    my ($yaml) = @_;

    my @lines = split /\n/, $yaml, -1;
    my $in_sops = 0;

    for my $line (@lines) {
        if ($line =~ /\A sops : \s* \z/x) {
            $in_sops = 1;
            next;
        }
        # any other column-0 line ends the sops block (Dump sorts keys, so a
        # data key sorting after "sops" can follow it)
        $in_sops = 0 if $in_sops && $line =~ /\A\S/;
        next unless $in_sops;

        # already-quoted values are left alone
        $line =~ s{
            \A (\s+ lastmodified: [ \t]+) (?!['"]) (\S.*?) [ \t]* \z
        }{$1"$2"}x;
    }

    return join "\n", @lines;
}

=method serialize

    my $yaml = File::SOPS::Format::YAML->serialize(
        data     => \%data,
        metadata => $metadata_obj,
    );

Class method to serialize data and metadata to YAML.

The C<data> parameter must be a HashRef. The C<metadata> parameter must be
a L<File::SOPS::Metadata> object.

Dies if C<data> has a top-level C<sops> key: that is where the metadata section
is written, so the value would be overwritten. Until 0.003 it was, silently,
and the resulting document failed its own MAC because the digest had already
covered the discarded value.

Returns a YAML string with the C<sops> section appended.

B<A leaf whose YAML spelling Go's parser resolves differently is refused here,
and only here.> The document this method writes carries a MAC, and sops
recomputes that MAC from the values C<gopkg.in/yaml.v3> resolves out of these
bytes -- so a leaf that libyaml and Go read differently makes the file
disagree with its own MAC. C<mode: 0755> is the realistic case: this module
reads 755, Go reads 493, and the file was written silently and rejected later
with C<MAC mismatch>. Refused as well: C<0o10>, C<0x1f>, C<0b101>, C<1_000>,
C<.inf>, C<.nan>, C<Null>, C<TRUE> and a date that is not already exactly
RFC3339 -- all spellings libyaml leaves a string and Go resolves to something
else. C<007>, C<08>, C<1e3>, C<True>, C<null>, C<yes>, C<1:30> and
C<2015-01-01T12:00:00Z> are B<not> refused: measured, the two resolvers derive
the same digest bytes from each of them.

The rule does not apply to an B<encrypted> slot (an C<ENC[...]> string carries
any spelling verbatim), to L</emit> on its own (a plaintext document has no MAC
for a reader to disagree with), to the C<sops> metadata section (the digest does
not cover it), or to a C<mac_only_encrypted> document (there the digest does not
cover an unencrypted leaf either). See
L<docs/adr/0013|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0013-a-yaml-spelling-the-go-parser-resolves-differently-is-refused.md>
and karr #86.

=cut

# The one place this distribution turns a Perl tree into YAML. serialize() is
# this plus the metadata section, and File::SOPS::_serialize_plaintext (what
# decrypt_file writes and what edit hands the editor) is this on its own.
#
# It stays ONE sub because the emitter options are not local taste: the MAC's
# encrypt side walks the tree in sorted order and is correct only because this
# emitter writes keys sorted, and the boolean mode decides whether a
# JSON::PP::Boolean reaches the file as `true` or as
# `!!perl/scalar:JSON::PP::Boolean 1`. A second copy of those options is a
# second answer to a question that has one -- which is what karr #35 found: the
# plaintext emitter used to work only because this module set
# $YAML::XS::Boolean process-wide at load time.
#
# Consequence, deliberately accepted: this sub is on the wire path. Changing
# what it emits changes the encrypted document too, so it is not a plaintext
# formatting knob.
sub emit {
    my ($class, $data, %args) = @_;
    croak "data required" unless defined $data;

    local $YAML::XS::Boolean = $BOOLEAN_MODE;
    return Dump(File::SOPS::Encrypted->canonical_float_tree(
        $data,
        roundtrips => \&_float_roundtrips,
        carrier    => \&_float_carrier,
        reject     => \&_reject_unwritable_leaf,

        # Only a document that carries a MAC has a reader to disagree with it.
        # serialize sets this; the plaintext emitters (decrypt_file, edit) do
        # not, and must not -- refusing there would refuse to WRITE OUT a
        # document this module reads correctly. See docs/adr/0013.
        ($args{mac_covered} ? (reject_scalar => \&_reject_foreign_resolution) : ()),
    ));
}

# A referenced leaf YAML::XS cannot write as the text the digest covers.
#
# detect_type calls every blessed leaf but a JSON::PP::Boolean `str`, so the
# digest covers its STRINGIFICATION. YAML::XS writes it as a Perl-specific
# tagged structure instead -- measured against sops 3.13.3, one document per
# row, leaf under _unencrypted:
#
#   Math::BigFloat->new("1.5")  !!perl/hash:Math::BigFloat + guts   exit 51
#   bless {a=>1}, 'Foo'         !!perl/hash:Foo + guts              exit 51
#   an object overloading ""    !!perl/hash:Overloaded + guts       exit 51
#   bless \$s, 'Bar'            !!perl/scalar:Bar x                 exit 51
#   sub { 1 }                   !!perl/code '{ "DUMMY" }'           exit 51
#   \1  (unblessed)             !!perl/ref + `=: 1`                 exit 51
#   qr/abc/                     !!perl/regexp (?^:abc)              exit 0 (!)
#
# All seven fail their own MAC check here. qr// is the one sops accepts, because
# yaml.v3 resolves the unknown tag to the scalar text -- which is what we
# digested -- while YAML::XS reconstructs a Regexp from it, so File::SOPS cannot
# read back what it just wrote. Both halves of the same disagreement.
#
# JSON has refused all of these since before ADR 0006 (Cpanel::JSON::XS will not
# encode a blessed reference without allow_blessed/convert_blessed/allow_tags),
# which is the asymmetry this closes. See docs/adr/0008.
#
# The exception is the EXACT class, not ->isa: detect_type accepts a
# JSON::PP::Boolean subclass as bool, but YAML::XS writes one as
# `!!perl/scalar:MyBool 1` while the digest still says True -- the same defect
# wearing the whitelist. The exact class is what $YAML::XS::Boolean = 'JSON::PP'
# knows how to write, so it is the only reference that survives this emitter.
#
# Unblessed refs are in scope deliberately: \1 and a coderef fail identically,
# and the callback already has them in hand.
#
# Not in assert_representable: that runs on the verify side too, and over
# leaves that are about to become ENC[...] strings. A blessed leaf in an
# ENCRYPTED slot works in both formats today (type:str, plaintext = the same
# stringification) and must keep working.
#
# $where is the leaf's key path from canonical_float_tree, in the shape the MAC
# walk's messages already use. It goes in FRONT of the message: the class alone
# told a caller what was wrong and left finding it a manual search (karr #68).
sub _reject_unwritable_leaf {
    my ($node, $where) = @_;

    return if ref($node) eq 'JSON::PP::Boolean';

    my $what = blessed($node) ? "a leaf blessed into " . ref($node)
                              : "an unblessed " . ref($node) . " reference";

    croak "$where: cannot write $what to a SOPS document: YAML::XS writes it "
        . "as a Perl-specific !!perl/ tagged structure while the digest covers its "
        . "stringification, so the document and its own MAC would state "
        . "different things and neither sops nor this module could read the "
        . "file. Pass a plain Perl scalar, or the string you want stored. A "
        . "boolean has to be an exact JSON::PP::Boolean (JSON->true / "
        . "JSON->false); a subclass of it is written as a tag as well";
}

###############################################################################
# The reader on the other side of the file (karr #86, docs/adr/0013)
#
# Everything above asks THIS distribution's emitter what it does. This asks what
# Go's gopkg.in/yaml.v3 -- the parser sops uses -- makes of the bytes we are
# about to write, because sops recomputes the MAC from the values ITS parser
# resolves. YAML::XS is libyaml, whose resolver is YAML 1.1 as libyaml
# implements it; yaml.v3's is neither 1.1 nor 1.2 but its own. Where the two
# land on different values, the document and its own MAC state different things.
#
# Measured against sops 3.13.3, leaf under _unencrypted, one document per row:
#
#   source   we read        Go reads    sops -d
#   0755     int 755        493         exit 51    <- `mode: 0755`, the real case
#   010      int 10         8           exit 51
#   007      int 7          7           exit 0     <- agrees, 7 is 7 in both bases
#   08       int 8          float 8     exit 0     <- agrees, same digest bytes
#   0o10     str "0o10"     int 8       exit 51    <- the mirror case: WE say str
#   0x1f     str            int 31      exit 51
#   1_000    str            int 1000    exit 51
#   .inf     str            +Inf        exit 51
#   Null     str            null        exit 51
#   TRUE     str            bool        exit 51
#   True     str "True"     bool        exit 0     <- agrees, Go digests `True`
#   2015-01-01            str  time     exit 51    <- rendered 2015-01-01T00:00:00Z
#   2015-01-01T12:00:00Z  str  time     exit 0     <- rendered identically
#
# sops itself resolves a plaintext `mode: 0755` to the INTEGER 493 and writes
# that, so the spelling never survives a `sops -e` -- which is why the read path
# needs nothing here, and why the message can name 493 as what to pass instead.
#
# This is NOT typing by text (ADR 0002). detect_type still reads the SV and
# nothing else, and this runs after it. What is inspected here is what a foreign
# parser will make of bytes -- a question the SV cannot answer, because the SV is
# on this side of the file. _quote_sops_timestamp two hundred lines up has
# matched a text pattern in the emitted document for the same reason since 0.003.

# Go's resolveTable: the first byte decides whether the resolver looks at a
# plain scalar at all. Anything else is a string to it, immediately -- which is
# what keeps `localhost` and `supersecret` from paying for any of this.
my $GO_LOOKS_AT = qr/\A[-+.0-9yYnNtTfFoO~]/;

# Go's resolveMap, mapped to the bytes sops's ToBytes derives from each value.
# A bool is Title-cased (the same rule Encrypted::value_to_bytes follows) and a
# null contributes nothing -- measured: a sops-written `x_unencrypted: null`
# verifies against this module's own digest, which covers the empty string.
my %GO_CONSTANT = (
    'true'  => 'True',  'True'  => 'True',  'TRUE'  => 'True',
    'false' => 'False', 'False' => 'False', 'FALSE' => 'False',
    ''      => '',      '~'     => '',
    'null'  => '',      'Null'  => '',      'NULL'  => '',
    '.inf'  => '+Inf',  '.Inf'  => '+Inf',  '.INF'  => '+Inf',
    '+.inf' => '+Inf',  '+.Inf' => '+Inf',  '+.INF' => '+Inf',
    '-.inf' => '-Inf',  '-.Inf' => '-Inf',  '-.INF' => '-Inf',
    '.nan'  => 'NaN',   '.NaN'  => 'NaN',   '.NAN'  => 'NaN',
);

# strconv.ParseInt/ParseUint with base 0, as a digit string. The magnitude is
# accumulated in Perl's own integer space, guarded by a STRING comparison
# against the base's uint64 maximum -- dividing to test for overflow is exactly
# where a double stops being exact, and a wrong answer here is a document
# refused or written for the wrong reason.
my %GO_BASE_MAX = (
    2  => '1111111111111111111111111111111111111111111111111111111111111111',
    8  => '1777777777777777777777',
    10 => '18446744073709551615',
    16 => 'ffffffffffffffff',
);
my $INT64_MAGNITUDE = 9223372036854775808;   # 2**63: int64 min is -this

sub _go_digits {
    my ($digits, $base) = @_;

    (my $d = lc $digits) =~ s/\A0+(?=.)//;
    my $max = $GO_BASE_MAX{$base};
    return undef if length($d) > length($max);
    return undef if length($d) == length($max) && $d gt $max;

    my $v = 0;
    $v = $v * $base + index('0123456789abcdef', $_) for split //, $d;
    return $v;
}

# undef: not an integer to Go. 'RANGE': an integer it reads as a uint64, which
# sops has no case for -- measured, `sops -e` on a plaintext 9223372036854775808
# fails with `Cannot walk value, unknown type: uint64`, exit 23. Otherwise the
# decimal text sops would digest.
sub _go_int {
    my ($p) = @_;

    my $neg = ($p =~ s/\A-//) ? 1 : 0;
    $p =~ s/\A\+//;
    return undef unless length $p;

    my $v;
    if    ($p =~ /\A0[xX]([0-9a-fA-F]+)\z/) { $v = _go_digits($1, 16) }
    elsif ($p =~ /\A0[bB]([01]+)\z/)        { $v = _go_digits($1, 2) }
    elsif ($p =~ /\A0[oO]([0-7]+)\z/)       { $v = _go_digits($1, 8) }
    elsif ($p =~ /\A0([0-7]*)\z/)           { $v = _go_digits($1, 8) }
    elsif ($p =~ /\A[1-9][0-9]*\z/)         { $v = _go_digits($p, 10) }
    else                                    { return undef }

    return undef unless defined $v;         # past uint64: Go falls through to float
    # `-0` is the integer 0 to Go, sign and all: strconv.Itoa(0) is `0`, and a
    # document holding `-0` verifies against a digest covering `0` (measured,
    # exit 0). The sign only survives on a FLOAT, which is ADR 0006's -0.0.
    return $neg && $v ? "-$v" : "$v"
        if $neg ? $v <= $INT64_MAGNITUDE : $v < $INT64_MAGNITUDE;
    return undef if $neg;                   # ParseUint rejects a sign
    return 'RANGE';
}

# strconv.ParseFloat, through the one conversion this distribution has for a
# double. The CANONICAL TEXT decides whether Go got a number, never a numeric
# comparison of the scalar: `$nv == 0` sets the public IOK on an integral NV and
# takes the sign off -0.0 with it, which is ADR 0002's contamination in the one
# place that must not have it.
sub _go_float {
    my ($p) = @_;

    my $bytes = File::SOPS::Encrypted->value_to_bytes($p * 1.0);
    return undef if $bytes =~ /\A[-+]Inf\z/;   # Go: ErrRange, so not a float to it
    return $bytes;
}

# Go's parseTimestamp: four layouts, and sops digests what comes out of it as
# RFC3339 NANO -- always a capital T, `Z` for a zero offset, and a fractional
# second that keeps at most nine digits and no trailing zero. So a token agrees
# with itself only when it is already spelled exactly that way; every other shape
# Go PARSES renders differently, and every shape it does not parse is a string to
# it and agrees for free. Measured, leaf under _unencrypted:
#
#   2015-01-01T12:00:00Z            exit 0    <- already RFC3339
#   2015-01-01T12:00:00.5Z          exit 0    <- Nano keeps the fraction
#   2015-01-01T12:00:00.123456789Z  exit 0
#   2015-01-01T12:00:00.50Z         exit 51   <- trailing zero trimmed
#   2015-01-01T12:00:00.0Z          exit 51   <- fraction disappears entirely
#   2015-01-01T12:00:00.1234567891Z exit 51   <- truncated to nine digits
#   2015-01-01T12:00:00+00:00       exit 51   <- a zero offset renders as Z
#   2015-01-01                      exit 51   <- becomes 2015-01-01T00:00:00Z
#   2015-1-01T12:00:00Z             exit 51   <- a short field is padded
#   2016-02-29                      exit 51   <- a real date, so it is parsed
#   2015-02-29                      exit 0    <- not a date, so Go leaves a string
#   2015-01-01T24:00:00Z            exit 0    <- hour 24: same, a string
#
# The calendar check is what tells 2016-02-29 from 2015-02-29 -- one is a date
# and the other is not -- and it is why `2024-13-45` and `1234-5678` are not
# refused either.
sub _go_timestamp {
    my ($s) = @_;

    my ($y, $mo, $d, $h, $mi, $sec, $frac, $zone);
    if ($s =~ /\A([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})[Tt]([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2})(?:\.([0-9]+))?(Z|[-+][0-9]{2}:[0-9]{2})\z/) {
        ($y, $mo, $d, $h, $mi, $sec, $frac, $zone) = ($1, $2, $3, $4, $5, $6, $7, $8);
    }
    elsif ($s =~ /\A([0-9]{4})-([0-9]{1,2})-([0-9]{1,2}) ([0-9]{1,2}):([0-9]{1,2}):([0-9]{1,2})(?:\.([0-9]+))?\z/) {
        ($y, $mo, $d, $h, $mi, $sec, $frac, $zone) = ($1, $2, $3, $4, $5, $6, $7, 'Z');
    }
    elsif ($s =~ /\A([0-9]{4})-([0-9]{1,2})-([0-9]{1,2})\z/) {
        ($y, $mo, $d, $h, $mi, $sec, $frac, $zone) = ($1, $2, $3, 0, 0, 0, undef, 'Z');
    }
    else { return undef }

    return undef if $mo < 1 || $mo > 12 || $d < 1 || $h > 23 || $mi > 59 || $sec > 59;
    my @length = (31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31);
    my $last = $mo == 2 && (($y % 4 == 0 && $y % 100 != 0) || $y % 400 == 0)
        ? 29 : $length[$mo - 1];
    return undef if $d > $last;

    my $nano = '';
    if (defined $frac) {
        (my $digits = substr($frac, 0, 9)) =~ s/0+\z//;
        $nano = ".$digits" if length $digits;
    }
    $zone = 'Z' if $zone =~ /\A[-+]00:00\z/;
    return sprintf('%04d-%02d-%02dT%02d:%02d:%02d%s%s',
                   $y, $mo, $d, $h, $mi, $sec, $nano, $zone);
}

# The bytes sops digests for this token when it stands BARE in a YAML document,
# or undef for "this module cannot prove what Go does with it".
#
# A model, and treated as one: written from yaml.v3's resolve() and sops's
# ToBytes, and verified branch by branch against the binary rather than trusted.
# There is no oracle to ask instead -- the reader is in another process, in
# another language, and YAML::PP, this distribution's second parser, resolves
# 0755 as 755 like libyaml and unlike Go, so it agrees with the side that is
# already wrong.
sub _go_scalar_bytes {
    my ($s) = @_;

    return '' unless length $s;
    return $s unless $s =~ $GO_LOOKS_AT;
    return $GO_CONSTANT{$s} if exists $GO_CONSTANT{$s};

    my $first = substr($s, 0, 1);

    # Hinted only because it could have been a constant, and it was not.
    return $s if index('yYnNtTfFoO~', $first) >= 0;

    # Go's case '.': ParseFloat on the token as it stands, underscores included --
    # they are part of a Go float literal, but only BETWEEN digits, which is why
    # `._5` is a string to it and `.5_0` is the number 0.5. `.`, `..`,
    # `.gitignore` and `.env` match nothing here and stay strings, as they are on
    # both sides (measured, exit 0).
    if ($first eq '.') {
        (my $stripped = $s) =~ tr/_//d;
        return _go_float($stripped) // $s
            if $s =~ /\A\.[0-9]+(?:_[0-9]+)*(?:[eE][-+]?[0-9]+(?:_[0-9]+)*)?\z/;
        return $s;
    }

    # A timestamp is tried before any number, and only for exactly four leading
    # digits followed by `-` (Go's own quick check), so `12345-01-01` is not one.
    return _go_timestamp($s) // $s if $s =~ /\A[0-9]{4}-/;

    my $plain = $s;
    $plain =~ tr/_//d;                       # Go strips every underscore first

    my $int = _go_int($plain);
    if (defined $int) {
        return undef if $int eq 'RANGE';
        return $int;
    }

    # yamlStyleFloat, the regexp resolve.go gates ParseFloat with.
    return _go_float($plain) // $s
        if $plain =~ /\A[-+]?(?:\.[0-9]+|[0-9]+(?:\.[0-9]*)?)(?:[eE][-+]?[0-9]+)?\z/;

    return $s;
}

# What YAML::XS actually writes for this leaf, when it writes it as a bare
# single-line plain scalar -- and undef when it does not, because a quoted or
# block scalar is a string to every YAML reader and cannot be resolved into
# anything else. Measured rather than modelled: libyaml quotes a string its OWN
# resolver would read as a number, a boolean or a null ('007', '5432', 'yes',
# '1:30' all come back quoted), and that is most of the reason this guard fires
# as rarely as it does.
sub _emitted_plain_scalar {
    my ($leaf) = @_;

    local $YAML::XS::Boolean = $BOOLEAN_MODE;
    my $dump = eval { Dump({ v => $leaf }) };
    return undef unless defined $dump && $dump =~ /\A---\nv: (.*)\n\z/;

    my $token = $1;
    return undef if $token =~ /\A['"|>&*!]/;
    return $token;
}

sub _go_agrees {
    my ($token, $text) = @_;

    my $bytes = _go_scalar_bytes($token);
    return defined $bytes && $bytes eq $text ? 1 : 0;
}

# WHY the two disagree, for the message. A property of the spelling, never the
# spelling itself: an error goes into bug reports.
sub _foreign_resolution_reason {
    my ($token) = @_;

    return 'a leading-zero integer, which libyaml reads as decimal and Go as octal'
        if $token =~ /\A[-+]?0[0-9]+\z/;
    return 'a 0o / 0x / 0b prefixed number, which Go resolves and libyaml does not'
        if $token =~ /\A[-+]?0[obxOBX]/;
    return 'a number written with _ digit separators, which Go strips and libyaml does not'
        if $token =~ /_/;
    return 'a date or timestamp, which Go resolves to a time and renders back in RFC3339'
        if $token =~ /\A[0-9]{4}-/;
    return 'a YAML 1.2 constant -- an infinity, a not-a-number, a null, or a '
        . 'boolean spelled in a case libyaml leaves a string'
        if $token =~ /\A[-+]?\./ || exists $GO_CONSTANT{$token};
    return 'a number outside the int64 range, which sops refuses to write at all'
        unless defined _go_scalar_bytes($token);
    return 'a spelling the two resolvers do not agree on';
}

# A leaf whose SPELLING this module cannot prove Go resolves the way it does.
#
# Runs on the encrypt path only, and never over the `sops` branch: the digest
# does not cover the metadata, and the one leaf there that Go resolves
# differently -- lastmodified, which it reads as a time -- is already handled,
# by _quote_sops_timestamp and the other way round, by quoting it.
#
# Encrypted slots cannot reach this at all: _encrypt_tree has replaced every
# encrypted leaf with an ENC[...] string long before the emitter runs, and that
# string starts with `E`, which no resolver looks twice at.
sub _reject_foreign_resolution {
    my ($leaf, $where, $path, $text) = @_;

    return if @$path && $path->[0] eq 'sops';
    return unless "$leaf" =~ $GO_LOOKS_AT;

    # THE one conversion -- the text the MAC digest covers. The walk hands it
    # over where it already derived one (and for a carrier that is the ORIGINAL
    # value's text, which is what the digest has); otherwise it comes from the
    # same method on the same scalar. Never a second rendering derived here.
    $text //= File::SOPS::Encrypted->value_to_bytes($leaf);
    return if _go_agrees("$leaf", $text);

    # It disagrees if written bare. Ask the emitter whether it is written bare.
    my $token = _emitted_plain_scalar($leaf);
    return unless defined $token;
    return if _go_agrees($token, $text);

    croak "$where: cannot write this leaf to a SOPS YAML document: its spelling "
        . "is " . _foreign_resolution_reason($token) . ". The MAC digest covers "
        . "the value this module resolves, while sops re-reads the document with "
        . "Go's yaml.v3 and resolves a different one, so the file would fail its "
        . "own MAC and neither sops nor this module could read it back (measured, "
        . "sops -d exit 51). sops itself resolves such a spelling when it writes: "
        . "a plaintext `mode: 0755` becomes the integer 493 in its output, and "
        . "that decimal is what to pass here. To keep the spelling as text, "
        . "encrypt the leaf -- an ENC[...] string carries it verbatim and is "
        . "unaffected by this rule";
}

###############################################################################

# Does YAML::XS's own rendering of this float come back as the same double?
#
# Measured, not modelled: the value goes through the real Dump and the real
# Load. YAML::XS renders a float by Perl stringification, which is ~15
# significant digits, so 0.1+0.2 comes back as 0.3 -- a different number from
# the one value_to_bytes digested, and a document that fails its own MAC.
#
# It answers YES far more often than that suggests, and that is the point:
# YAML::XS retains the PV of every float it PARSES and emits it verbatim, so a
# value read from a document round-trips by construction and keeps the exact
# bytes it arrived with. Only floats that reach us as bare NVs -- computed by
# the caller, or parsed out of JSON -- ever need the carrier.
#
# Equality is decided by value_to_bytes on both sides rather than by ==, so it
# means the same thing the digest means. == cannot tell -0.0 from 0.0.
sub _float_roundtrips {
    my ($value, $text) = @_;

    my $back = eval { Load(Dump({ v => $value }))->{v} };
    return 0 unless defined $back;
    return File::SOPS::Encrypted->value_to_bytes($back) eq $text ? 1 : 0;
}

# A dualvar's numeric half keeps the value a float for anything that looks at
# the SV; YAML::XS writes the string half, unquoted, as a plain scalar.
#
# Note what this is: a raw-text primitive with no guard rail. YAML::XS emits
# whatever the PV says -- dualvar(0.3, 'hello') writes `v: hello` -- so this is
# safe only because $text came from value_to_bytes. Do not derive it here.
#
# The ONE exception, and the only place in this distribution where a written
# decimal is not value_to_bytes's output verbatim: a negative zero. Its
# canonical text is `-0`, which YAML resolves as an INTEGER -- Go's yaml.v3 and
# YAML::XS agree on that -- so a document carrying `-0` is digested as `0` by
# every reader while our MAC covers `-0`. Measured against sops 3.13.3, one
# document per spelling, leaf under _unencrypted, digest `-0`:
#
#   -0        sops -d exit 51 (MAC mismatch)   self-MAC FAIL   <- karr #62
#   !!float -0  sops -d exit 51                self-MAC FAIL
#   -0.0      sops -d exit 0, reads back -0    self-MAC OK     <- this
#   -0.       sops -d exit 0                   self-MAC OK
#   -0.0e0    sops -d exit 0                   self-MAC FAIL (YAML::XS differs)
#
# sops cannot write this value either: `sops -e` on a plaintext `-0.0` emits
# `-0` and then rejects its own file with exit 51, in YAML and in JSON alike.
# So `-0.0` is not "the bytes sops writes", it is the only spelling both
# implementations read as the double the digest covers -- which is exactly what
# ADR 0006 asks of an emitted decimal, and it says so: the text has to parse
# back to the same double, not to be spelled canonically.
#
# Narrow on purpose. `-0` is the only canonical float text an integer
# resolution changes the digest of: every other integral one digests the same
# whether Go reads it as an int or a float (`3` is `3` either way), and every
# float that needs a fraction already carries a `.`. A general "append .0"
# would move bytes for cases nobody has measured.
sub _float_carrier {
    my ($value, $text) = @_;
    return dualvar($value, $text eq '-0' ? '-0.0' : $text);
}

=method emit

    my $yaml = File::SOPS::Format::YAML->emit(\%data);

Class method to emit a data structure as YAML, with no C<sops> section and no
metadata of any kind -- a plain document. This is what L<File::SOPS/decrypt_file>
writes and what L<File::SOPS/edit> hands to the editor.

Returns UTF-8 encoded bytes, unconditionally: L<YAML::XS> encodes regardless of
whether the strings it is given carry Perl's UTF-8 flag. See
L<File::SOPS/Character encoding>.

The output B<begins with the document-start marker C<--->>, because L<YAML::XS>
always emits one. sops writes none, in either direction. The line is cosmetic --
YAML resolves a document with or without it identically, C<sops -d> accepts
these files, and the MAC covers values rather than serialized text -- and it is
kept rather than stripped, since the MAC's encrypt side rides on this emitter
(C<docs/adr/0001>). See L<File::SOPS/Every YAML file starts with C<--->, where
sops writes none> and karr #83.

Called on its own -- which is what the plaintext emitters do -- it writes every
YAML spelling it is given, C<0755>, C<.inf> and C<2015-01-01> included. The
guard L</serialize> installs against those is deliberately not here: a plaintext
document carries no MAC for a reader to disagree with, and refusing them would
refuse to write out documents this module reads correctly. L</serialize> turns
it on by passing C<< mac_covered => 1 >>, which is the only argument this method
takes beyond the tree.

L</serialize> is this method plus the metadata section, so both go through the
same emitter options rather than two copies of them. Those options are not
cosmetic -- sorted key emission is what the MAC's encrypt side relies on -- so a
change here moves the encrypted document as well as the plaintext one.

B<Floats are written in a form that parses back to the same double.> L<YAML::XS>
renders a float by Perl stringification, roughly 15 significant digits, while
the MAC digest covers the shortest decimal that round-trips -- up to 17. For a
value needing 16 or 17 the document stated one number and the digest another,
and the file failed its own verification. This method now reparses its own
output and substitutes the canonical decimal from
L<File::SOPS::Encrypted/value_to_bytes> only where the value does not survive,
so a float that already emitted faithfully keeps exactly the bytes it had. In
practice that is most of them: YAML::XS retains the text of every float it
parsed, so only bare NVs -- computed by the caller, or parsed out of JSON --
are ever rewritten. C<NaN> and C<Inf> are unchanged -- they have no YAML form
Go reads back, and L<File::SOPS::Encrypted/assert_representable> refuses them
on the encrypt path. A negative zero B<is> rewritten, and it is the one value
whose written decimal is not L<File::SOPS::Encrypted/value_to_bytes>'s output
verbatim: that is C<-0>, which YAML resolves as an B<integer> and every reader
digests as C<0>, so this emitter writes C<-0.0> instead -- the spelling
measured to read back as the same double in sops 3.13.3 and here. See
L<docs/adr/0006|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0006-floats-are-emitted-in-a-form-that-parses-back-to-the-same-double.md>.

B<An integer leaf whose string form contradicts its number is refused.>
L<YAML::XS> writes the string half bare -- C<five> for a
C<Scalar::Util::dualvar> of C<5> -- while
L<File::SOPS::Encrypted/detect_type> calls the leaf an C<int>, so the MAC
digest covers the B<number>. The document and its own MAC then state different
things: measured against sops 3.13.3, C<sops -d> exit 51. A source B<spelling>
is not refused here, and that is measured too -- a C<007>, C<+7>, C<-0> or
C<1e3> this emitter received from a YAML parse is written back exactly as it
came, and Go reads the same number the digest covers (exit 0), where
L<File::SOPS::Format::JSON> has to refuse them because it quotes them. The
refusal names the leaf's key path and neither half of the value; an
B<encrypted> slot is unaffected. See karr #84 and
L<docs/adr/0012|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0012-an-integer-leaf-whose-string-half-disagrees-is-refused.md>.

B<A reference as a leaf value is refused>, with one exception. L<YAML::XS>
writes a blessed reference as a Perl-specific C<!!perl/> tagged structure --
C<!!perl/hash:Math::BigFloat>, C<!!perl/scalar:Foo>, C<!!perl/regexp> -- and an
unblessed one as C<!!perl/ref> or C<!!perl/code>, while
L<File::SOPS::Encrypted/detect_type> calls the leaf C<str> so the MAC digest
covers its B<stringification>. The document and its own MAC then state
different things, and the file is unreadable to sops and to this module alike.
Until 0.003 it was written anyway, without a word; now it dies naming the class
(never the value).

The exception is an exact L<JSON::PP::Boolean>, which this emitter writes as
bare C<true> / C<false> -- the one reference whose document form and digest
agree. A B<subclass> of it is not covered: C<detect_type> calls it C<bool> but
L<YAML::XS> writes it as a tag, so it is refused like any other object.

Only leaves that reach the document B<verbatim> can trigger this -- values
excluded by the encryption rules, everything in a plaintext document, and the
C<sops> section. A value that gets encrypted is an C<ENC[...]> string by the
time this method sees it, so an object in an encrypted slot is unaffected and
still stores its stringification as C<type:str>. L<File::SOPS::Format::JSON>
has refused the same leaves all along; see
L<docs/adr/0008|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0008-a-leaf-the-emitter-cannot-write-as-what-the-digest-covers-is-refused.md>.

=cut

sub format_name { 'yaml' }

=method format_name

Returns C<'yaml'>.

=cut

sub file_extensions { qw(yaml yml) }

=method file_extensions

Returns a list of file extensions: C<('yaml', 'yml')>.

=cut

sub detect {
    my ($class, $filename) = @_;
    return 1 if $filename =~ /\.ya?ml$/i;
    return 0;
}

=method detect

    if (File::SOPS::Format::YAML->detect($filename)) {
        # File is YAML based on extension
    }

Class method to detect if a filename is YAML based on extension.

Returns true if filename ends with C<.yaml> or C<.yml> (case-insensitive).

=cut

=head1 SEE ALSO

=over 4

=item * L<File::SOPS> - Main SOPS interface

=item * L<YAML::XS> - YAML parser/serializer

=back

=cut

1;
