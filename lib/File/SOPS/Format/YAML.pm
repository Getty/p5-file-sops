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
    return _quote_sops_timestamp($class->emit(\%output));
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
    my ($class, $data) = @_;
    croak "data required" unless defined $data;

    local $YAML::XS::Boolean = $BOOLEAN_MODE;
    return Dump(File::SOPS::Encrypted->canonical_float_tree(
        $data,
        roundtrips => \&_float_roundtrips,
        carrier    => \&_float_carrier,
        reject     => \&_reject_unwritable_leaf,
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
