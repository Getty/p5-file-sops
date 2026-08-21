package File::SOPS::Format::YAML;
# ABSTRACT: YAML format handler for SOPS
our $VERSION = '0.003';
use Moo;
use B ();
use Carp qw(carp croak);
use Scalar::Util qw(blessed dualvar refaddr);
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

    # AFTER the split, so the sops section is never rewritten -- and after the
    # HashRef check, so there is a tree to walk. See _restring_non_finite_leaf.
    _restring_non_finite_leaves($data, {});

    return ($data, $metadata);
}

###############################################################################
# A literal libyaml numifies past the end of a double (karr #102, docs/adr/0023)
#
# `1e400`, a 401-digit integer, `Inf`, `NaN`: libyaml resolves each of them to a
# number, and the number it lands on is +Inf, -Inf or NaN. go-yaml resolves none
# of them -- strconv.ParseFloat answers ErrRange and yaml.v3 keeps a STRING --
# so sops writes `type:str` and digests the token's own bytes. Ours said `float`
# and digested `+Inf`, which is a document sops wrote that we cannot read and a
# value we cannot write.
#
# The repair is at PARSE time and nowhere else, because what is wrong is our
# parse result and not any guard downstream. _go_scalar_bytes already models the
# Go side correctly for all 29 spellings measured; detect_type already reads the
# SV and nothing else (ADR 0002); the non-finite guard from karr #59 is right
# about every value it was written for and is untouched here. What this does is
# hand the rest of the distribution the leaf go-yaml sees.
#
# The predicate is the SV, not the text (ADR 0002): a leaf whose PUBLIC SVf_NOK
# and SVf_POK are both set and whose NV is NaN or +-Inf. It cannot collide with
# the tokens Go DOES resolve to a non-finite float -- `.inf .Inf .INF +.inf
# +.Inf +.INF -.inf -.Inf -.INF .nan .NaN .NAN`, the twelve in %GO_CONSTANT --
# because YAML::XS hands every one of those back POK-ONLY. Measured against
# sops 3.13.3: those twelve are `type:float` to sops and fire nothing here; the
# 29 spellings that do fire are `type:str` to sops, every one. The two sets are
# disjoint, and that disjointness is what keeps this from retyping a leaf Go
# reads as a float.
#
# JSON is deliberately NOT walked. sops refuses such a JSON document at
# unmarshal time (`strconv.ParseFloat: value out of range`, exit 2), so the
# croak Format::JSON's leaf earns there is the reference behaviour -- see
# ADR 0020, which predicted this lever and expected it to answer for both
# parsers at once. Measured, it must not.
my $POSITIVE_INFINITY = 9**9**9;

sub _restring_non_finite_leaves {
    my ($node, $seen) = @_;

    # A recursive YAML anchor (`root: &a\n  b: *a`) really does come back from
    # YAML::XS as a cycle, so this walk carries its own visited set. That keeps
    # THIS walk terminating; the encrypt and decrypt walks do not and hang on
    # such a document today, which is karr #110 and not widened into here.
    return if $seen->{refaddr($node)}++;

    if (ref $node eq 'HASH') {
        for my $key (keys %$node) {
            ref $node->{$key}
                ? _restring_non_finite_leaves($node->{$key}, $seen)
                : _restring_non_finite_leaf($node->{$key});
        }
    }
    elsif (ref $node eq 'ARRAY') {
        for my $entry (@$node) {
            ref $entry
                ? _restring_non_finite_leaves($entry, $seen)
                : _restring_non_finite_leaf($entry);
        }
    }

    return;
}

# $_[0] is the caller's element by alias, deliberately: the flags are read off
# the SV the tree holds rather than off a copy, and the replacement is written
# back into the same slot. Nothing here numifies anything -- B reads the NV and
# the PV out of the SV's own slots, so this cannot retype a scalar the way a
# numeric comparison on it would (karr #32).
sub _restring_non_finite_leaf {
    return unless defined $_[0];

    my $sv    = B::svref_2object(\$_[0]);
    my $flags = $sv->FLAGS;
    return unless ($flags & B::SVf_NOK()) && ($flags & B::SVf_POK());

    my $nv = $sv->NV;
    return unless $nv != $nv
        || $nv == $POSITIVE_INFINITY
        || $nv == -$POSITIVE_INFINITY;

    # The string half is what go-yaml kept, so it is what replaces the number.
    # An empty one is not a token Go reads as anything but a null, and there is
    # nothing to hand back, so the leaf is left exactly as it came.
    my $pv = $sv->PV;
    return unless length $pv;

    $_[0] = $pv;
    return;
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

=head3 A literal that overflows a double comes back as a string

C<1e400>, a 401-digit integer, and the bare spellings C<Inf>, C<inf>, C<INF>,
C<Infinity>, C<NaN>, C<nan>, C<NAN>, C<-Inf> and C<+Inf> are all resolved to a
B<number> by libyaml, and the number each of them lands on is C<+Inf>, C<-Inf>
or C<NaN>. go-yaml -- the parser sops reads a document with -- resolves none of
them: C<strconv.ParseFloat> answers C<ErrRange> and it keeps a B<string>. So
sops writes C<type:str> for such a leaf and digests the literal's own text.

Since 0.003 this method hands back the string go-yaml sees, so that
L<File::SOPS::Encrypted/detect_type> and the MAC agree with sops. Before it,
such a document could be neither read (17 of 20 measured documents that sops
writes failed MAC verification here) nor written (all 20 hit the non-finite
refusal in L<File::SOPS::Encrypted/assert_representable>).

Three things this is B<not>. It does not touch the twelve spellings go-yaml
really does resolve to a non-finite float -- C<.inf .Inf .INF +.inf +.Inf
+.INF -.inf -.Inf -.INF .nan .NaN .NAN> -- because L<YAML::XS> returns every
one of those as a plain string with no numeric half at all. It does not loosen
L<File::SOPS::Encrypted/assert_representable>: a caller who passes
L<File::SOPS/encrypt> a real C<9**9**9> still gets the refusal, because what is
repaired here is a parse result and not a rule about values. And it does not
apply to L<File::SOPS::Format::JSON>, where sops refuses the equivalent
document itself, at unmarshal time.

The cost is that the leaf is written back B<quoted> -- C<v: '1e400'> where sops
writes C<v: 1e400>. Both are a string to both parsers, so the digest is the same
text either way. See
L<docs/adr/0023|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0023-a-yaml-literal-that-overflows-a-double-is-a-string-not-a-float.md>.

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
    # ITS parser resolves out of these bytes.
    #
    # For mac_only_encrypted the digest covers encrypted values only, so an
    # unencrypted leaf cannot make such a document disagree with its own MAC and
    # refusing it would refuse a document that works today -- measured, sops -d
    # exit 0. It still reads 493 out of a `0755` this module reads as 755, so
    # the same check runs there and WARNS instead (karr #87, ADR 0018).
    return _quote_sops_timestamp($class->emit(\%output,
        $metadata->mac_only_encrypted ? (warn_foreign_resolution => 1)
                                      : (mac_covered            => 1)));
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

B<A C<True> or C<False> string is warned about instead, in both MAC modes.>
The digest bytes agree -- sops renders a boolean Title-cased, which is the same
text this module derives from the string -- so the MAC holds and C<sops -d>
exits 0. What differs is the B<type>: L<YAML::XS> writes the string as a bare
C<True> because libyaml's resolver knows only C<true> and C<false>, and Go's
yaml.v3 reads a boolean out of it. Measured, sops 3.13.3: C<sops -d> hands the
value on as C<true>, and C<sops rotate>, C<sops set> and C<sops edit> each
rewrite the leaf to a bare C<true>, after which this module reads a
C<JSON::PP::Boolean> where the caller put a string. Nothing fails at any point,
which is why it is a C<carp> and not a refusal -- refusing it would refuse a
document sops reads. The two remedies that work are in the message: encrypt the
leaf, or write the document as JSON, where every string is quoted. Neighbours
that look like this one do B<not> warn, because measured they do not diverge:
C<Yes>, C<No>, C<on>, C<off>, C<y>, C<n> and the rest of YAML 1.1's boolean
family are strings to yaml.v3 and to libyaml alike, C<~> and C<null> are
written quoted, and an RFC3339 timestamp -- a string here and a C<time.Time> to
Go -- comes back from C<sops rotate> as the identical token. See
L<docs/adr/0019|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0019-a-string-go-resolves-as-a-boolean-is-warned-about-in-both-modes.md>
and karr #92.

The rule does not apply to an B<encrypted> slot (an C<ENC[...]> string carries
any spelling verbatim), to L</emit> on its own (a plaintext document has no MAC
for a reader to disagree with), or to the C<sops> metadata section (the digest
does not cover it). See
L<docs/adr/0013|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0013-a-yaml-spelling-the-go-parser-resolves-differently-is-refused.md>
and karr #86.

B<In a C<mac_only_encrypted> document the same leaf is warned about rather than
refused.> There the digest covers encrypted values only, so an unencrypted leaf
cannot make the document disagree with its own MAC -- measured, the same
C<mode_unencrypted: 0755> is C<sops -d> exit 0 with the flag set. What remains
is that sops reads B<493> out of it where this module reads 755, in a file
neither of them complains about, so the check runs and C<carp>s instead of
refusing: the document is written exactly as before. The warning names the
leaf's key path and never the value. Silence it with a local C<$SIG{__WARN__}>
if the divergence is known and accepted. Measured over 217 such documents: 66
warn, all 66 really do diverge, none is refused, and 0 warn about a leaf the two
implementations agree on. See
L<docs/adr/0018|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0018-a-mac-only-encrypted-document-warns-where-it-cannot-refuse.md>
and karr #87.

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

        # Only a document that a reader re-derives values from has anything to
        # disagree with. serialize sets one of these; the plaintext emitters
        # (decrypt_file, edit) set neither, and must not -- refusing there would
        # refuse to WRITE OUT a document this module reads correctly, and
        # warning would warn about a file with no MAC and no second reader. The
        # two differ in the verdict only: croak where the MAC covers the leaf,
        # carp where mac_only_encrypted means it does not. See docs/adr/0013 and
        # docs/adr/0018.
        ($args{mac_covered}              ? (reject_scalar => \&_reject_foreign_resolution)
       : $args{warn_foreign_resolution}  ? (reject_scalar => \&_warn_foreign_resolution)
       :                                   ()),
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
#
# The copy is pack/unpack for the same reason, and this one was learned twice.
# It was `value_to_bytes($p * 1.0)` until karr #89, and Perl's arithmetic settles
# a token like `-0.0e0` on its INTEGER path: the model answered 0, this module
# answered 0, the guard saw agreement, and a document sops -d rejects with exit
# 51 was written silently. A model that shares a conversion with the code it
# checks can only catch the cases where the two happen to differ. Measured, the
# same token scalar three times in one process:
#
#   $p * 1.0    0 | 0 | 0        0 + $p     0 | 0 | 0
#   $p * 1      0 | 0 | 0        $p - 0.0   0 | 0 | 0
#   unpack('d', pack('d', $p))   -0 | -0 | -0
#
# `-0.0` WITHOUT an exponent survives `* 1.0` as an NV, which is why the guard
# was right for it and why this gap outlived ADR 0013. See ADR 0015 and the
# karr #89 amendment in ADR 0013.
sub _go_float {
    my ($p) = @_;

    my $bytes = File::SOPS::Encrypted->value_to_bytes(unpack('d', pack('d', $p)));
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

# Could Go's resolver look at what the emitter will write for this leaf? A gate,
# never an answer: it decides whether the emit below is worth paying for, and
# the verdict is taken from the token that emit returns.
#
# The stringification stands in for the token here, and it may: for a leaf that
# is not a boolean the two are the same string, or the token is quoted. Probed
# over 2119 non-bool leaves -- every printable ASCII character alone and in
# either position, 600 integers, 900 floats over 30 orders of magnitude, the
# int64 and subnormal edges, dualvars, embedded newlines, leading whitespace,
# non-ASCII -- 2 tokens start with a different byte, and both are the UTF-8
# encoding of a non-ASCII first character. Neither can matter: every UTF-8 byte
# is >= \x80 and every byte in $GO_LOOKS_AT is ASCII.
#
# A BOOLEAN is the exception and gets the second clause. Its stringification is
# `1` or the empty string while both emitters write a bare `true`/`false`
# (docs/adr/0016), so the empty one slipped past this gate entirely. detect_type
# is the same ladder the digest goes through and the same predicate the emitters
# use -- not a second answer to the question of what a boolean is.
sub _go_might_look_at {
    my ($leaf) = @_;

    return 1 if "$leaf" =~ $GO_LOOKS_AT;
    return File::SOPS::Encrypted->detect_type($leaf) eq 'bool' ? 1 : 0;
}

# The token this emitter writes for a leaf whose SPELLING this module cannot
# prove Go resolves the way it does, and WHICH KIND of disagreement it is --
# and the empty list when there is nothing to say.
#
#   'mac'   Go derives different BYTES from the token, so the document would
#           state one value and its own MAC cover another.
#   'type'  Go derives the same bytes and a different TYPE. The MAC holds and
#           sops reads the file; what it reads is not what this module reads.
#
# ONE check, three verdicts. What a document does with the answer depends on
# whether its MAC covers the leaf (refuse: the file would fail its own MAC) or
# not (warn: the two implementations simply read different values) -- and a
# 'type' disagreement is warned about in BOTH modes, because the MAC covers the
# same bytes either way and there is nothing for it to refuse. A second copy of
# the check for a second verdict is the defect class this whole layer keeps
# producing, so there is one. See docs/adr/0018 and docs/adr/0019.
#
# Runs on the encrypt path only, and never over the `sops` branch: the digest
# does not cover the metadata, and the one leaf there that Go resolves
# differently -- lastmodified, which it reads as a time -- is already handled,
# by _quote_sops_timestamp and the other way round, by quoting it.
#
# Encrypted slots cannot reach this at all: _encrypt_tree has replaced every
# encrypted leaf with an ENC[...] string long before the emitter runs, and that
# string starts with `E`, which no resolver looks twice at.
sub _foreign_resolution_token {
    my ($leaf, $path, $text) = @_;

    return if @$path && $path->[0] eq 'sops';
    return unless _go_might_look_at($leaf);

    # WHAT THE EMITTER WRITES is the only thing Go gets to resolve, so it is the
    # only thing asked about. The leaf's stringification decided this until
    # karr #91 -- it is the same string for every leaf class but a boolean, and
    # for a boolean it was wrong in both directions: karr #90 reached a document
    # through exactly that step, because `1` resolved to the `1` the digest then
    # covered and the guard returned before asking the emitter anything. A
    # quoted or multi-line scalar is a string to every YAML reader, and undef
    # here says so. See docs/adr/0017.
    my $token = _emitted_plain_scalar($leaf);
    return unless defined $token;

    # THE one conversion -- the text the MAC digest covers. The walk hands it
    # over where it already derived one (and for a carrier that is the ORIGINAL
    # value's text, which is what the digest has); otherwise it comes from the
    # same method on the same scalar. Never a second rendering derived here.
    $text //= File::SOPS::Encrypted->value_to_bytes($leaf);
    return ($token, 'mac') unless _go_agrees($token, $text);

    # The bytes agree and the TYPE does not. A second axis, invisible to
    # everything above: the digest cannot see it, so neither could this guard
    # until karr #92. See docs/adr/0019.
    return ($token, 'type') if _go_retypes($leaf, $token);

    return;
}

# The tokens Go resolves to a boolean, derived from the one table rather than
# listed a second time next to it.
my %GO_BOOL_TOKEN = map { $_ => 1 }
    grep { $GO_CONSTANT{$_} eq 'True' || $GO_CONSTANT{$_} eq 'False' }
    keys %GO_CONSTANT;

# Does Go read a BOOLEAN out of a token whose bytes already agree with the
# digest? Only `True` and `False` can be here: libyaml quotes `true` and
# `false` (its own resolver knows them), and `TRUE` / `FALSE` disagree on bytes
# -- sops digests a boolean Title-cased -- so they are refused one step up.
#
# What that leaves is a string here and a bool to sops, in a document neither of
# them complains about: measured, sops -d exit 0 and `true` in its output. It is
# not stable, either -- `sops rotate`, `sops set` and `sops edit` each write the
# resolved value back as a bare `true`, after which this module reads a boolean
# too, so the caller's string is gone.
#
# Both authorities are the ones already in use: %GO_CONSTANT for what Go makes
# of the token, detect_type for what the leaf is. A leaf that really is a
# boolean writes `true` and is read as one on both sides -- nothing to say.
sub _go_retypes {
    my ($leaf, $token) = @_;

    return 0 unless $GO_BOOL_TOKEN{$token};
    return File::SOPS::Encrypted->detect_type($leaf) eq 'bool' ? 0 : 1;
}

# The MAC holds and the two implementations still read different things, so
# there is nothing to refuse and something to say. Identical in both modes --
# the digest covers the same bytes either way -- which is why one sub serves
# both verdicts. See docs/adr/0019 and karr #92.
sub _carp_foreign_retyping {
    my ($where) = @_;

    carp "$where: this leaf is a string here and a boolean to sops. libyaml "
        . "leaves the spelling a string while Go's yaml.v3 resolves it as a "
        . "boolean, and both digest the same bytes, so the MAC holds and sops "
        . "reads the file (measured, sops -d exit 0). What differs is the type: "
        . "sops hands the value on as a boolean, and any sops write-back "
        . "(rotate, set, edit) rewrites the spelling to a bare true/false, after "
        . "which this module reads a boolean as well. Encrypt the leaf -- an "
        . "ENC[...] string carries the text verbatim and is a string to both -- "
        . "or write the document as JSON, where every string is quoted";
}

# The document carries a MAC that covers this leaf, so the disagreement is with
# the file's own verification and there is nothing to write.
sub _reject_foreign_resolution {
    my ($leaf, $where, $path, $text) = @_;

    my ($token, $kind) = _foreign_resolution_token($leaf, $path, $text);
    return unless defined $token;
    return _carp_foreign_retyping($where) if $kind eq 'type';

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

# mac_only_encrypted: the digest covers encrypted values only, so this leaf
# cannot make the document disagree with its own MAC and refusing it would
# refuse a file that works. What is left is that the two implementations read
# different VALUES out of a document neither of them complains about -- measured
# for `mode_unencrypted: 0755`, sops -d exit 0 and it reads 493 where this
# module reads 755. Nothing tells the caller that but this line. See karr #87
# and docs/adr/0018.
#
# carp rather than warn, for the same reason the refusals croak: the line worth
# printing is the caller's, and @CARP_NOT above already walks out of the emitter
# and the walk. The value never appears here -- a warning goes to logs.
sub _warn_foreign_resolution {
    my ($leaf, $where, $path, $text) = @_;

    my ($token, $kind) = _foreign_resolution_token($leaf, $path, $text);
    return unless defined $token;
    return _carp_foreign_retyping($where) if $kind eq 'type';

    carp "$where: this leaf's spelling is " . _foreign_resolution_reason($token)
        . ", so sops resolves a different value from the one this module reads "
        . "(measured: a `mode: 0755` is 493 to sops and 755 here). With "
        . "mac_only_encrypted set the MAC does not cover this leaf, so nothing "
        . "will fail -- the document is written and sops reads it. Pass the "
        . "value sops itself would write (the decimal for `0755` is 493), or "
        . "encrypt the leaf, to make the two agree";
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
#   -0.0e0    sops -d exit 0                   self-MAC OK     <- karr #89
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
it on with one of the two arguments this method takes beyond the tree --
C<< mac_covered => 1 >> to refuse such a leaf, or
C<< warn_foreign_resolution => 1 >> to warn about it, which is what a
C<mac_only_encrypted> document gets. They install the same check and differ only
in the verdict -- and B<either> of them warns about a leaf whose spelling Go
resolves to a boolean where this module holds a string (C<True>, C<False>),
because there the digest bytes agree and there is nothing for the first one to
refuse. See L</serialize>.

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
