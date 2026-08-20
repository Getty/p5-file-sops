package File::SOPS::Format::JSON;
# ABSTRACT: JSON format handler for SOPS
our $VERSION = '0.003';
use Moo;
use Carp qw(croak);
use Cpanel::JSON::XS ();
use Math::BigFloat ();
use Scalar::Util qw(blessed);
use File::SOPS::Encrypted;
use namespace::clean;

# The only JSON encoder AND decoder in this distribution's document path, and
# the only definition of their options. utf8 makes it emit encoded bytes
# whatever Perl's UTF-8 flag says (and expect encoded bytes on the way in),
# canonical makes it emit keys sorted -- which the MAC's encrypt side depends
# on, since that walk hashes in sorted order. emit() and parse() below are the
# only entry points to it.
#
# The backend is NAMED here rather than left to JSON::MaybeXS, which binds once
# per process to whichever backend is already in %INC -- so the calling program
# decided our wire bytes, and CryptX (loaded by File::SOPS::Encrypted) pulls in
# JSON::XS. That is not a formatting preference:
#
#   * JSON::XS's decoder is not correctly rounded. It reads 0.3 back as the
#     double whose shortest form is 0.30000000000000004, so File::SOPS in a
#     process that had loaded JSON::XS REFUSED a valid sops document
#     ("MAC verification failed") over an unencrypted 0.3.
#   * JSON::XS writes an NV -0.0 as `-0`, which parses back as the INTEGER zero
#     and digests as "0" while the MAC covers "-0". Such a document fails its
#     own MAC here and in sops (exit 51). sops writes `-0` itself and cannot
#     read that file back either -- matching its bytes would import its bug.
#   * JSON::PP loses the sign entirely (`0`), same failure.
#
# Cpanel writes `1.0` and `-0.0` where sops writes `1` and `-0`; the first is
# cosmetic (both digest as "1", sops -d accepts ours), the second is the point.
# See docs/adr/0005. Do not "modernise" this back to JSON::MaybeXS.
#
# TWO objects, ONE definition of the options, because allow_bignum is not
# symmetric and must not be enabled on the decoder. On the way out it makes
# Cpanel render a Math::BigFloat as a bare JSON number, which is the only way
# measured to get a 17-digit double into JSON unquoted (docs/adr/0006). On the
# way IN it would hand back Math::BigFloat and Math::BigInt OBJECTS for
# ordinary literals -- measured, `0.30000000000000004` decodes to a
# Math::BigFloat and `100000000000000000000` to a Math::BigInt -- and
# detect_type calls a blessed leaf `str`, so every float in every document we
# read would change type and digest.
#
# It has no effect on the way out for anything that is not one of those objects:
# a sample of integers, NVs, strings, booleans, undef, arrays and -0.0 encodes
# byte-identically with and without it.
sub _configured_json { return Cpanel::JSON::XS->new->utf8->pretty->canonical }

my $json    = _configured_json();                   # parse(): NEVER allow_bignum
my $encoder = _configured_json()->allow_bignum;     # emit()

=head1 SYNOPSIS

    use File::SOPS::Format::JSON;

    # Parse JSON with SOPS metadata
    my ($data, $metadata) = File::SOPS::Format::JSON->parse($json_content);

    # Serialize data with SOPS metadata
    my $json = File::SOPS::Format::JSON->serialize(
        data     => $encrypted_data,
        metadata => $metadata_obj,
    );

    # Check if filename is JSON
    if (File::SOPS::Format::JSON->detect('secrets.json')) {
        # It's a JSON file
    }

=head1 DESCRIPTION

JSON format handler for File::SOPS. Handles parsing and serialization of
SOPS-encrypted JSON files.

Uses L<Cpanel::JSON::XS> for JSON processing, B<named rather than chosen at
runtime>. It used to go through L<JSON::MaybeXS>, which binds to a backend once
per process depending on what was loaded first, so the same data was written
differently depending on the calling program -- and the alternatives are not
merely differently formatted: L<JSON::XS> reads C<0.3> back as a different
double, and both it and L<JSON::PP> write an C<-0.0> in a form that makes the
document fail its own MAC. See
L<docs/adr/0005|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0005-the-json-backend-is-chosen-not-inherited.md>.

Output is always pretty-printed and canonically ordered for consistent diffs.

=cut

sub parse {
    my ($class, $content) = @_;
    croak "content required" unless defined $content;

    my $data = $json->decode($content);
    croak "JSON did not parse to a hash" unless ref $data eq 'HASH';

    my $metadata;
    if (exists $data->{sops}) {
        require File::SOPS::Metadata;
        $metadata = File::SOPS::Metadata->from_hash(delete $data->{sops});
    }

    return ($data, $metadata);
}

=method parse

    my ($data, $metadata) = File::SOPS::Format::JSON->parse($json_string);

Class method to parse a JSON string.

Returns a two-element list:

=over 4

=item 1. C<$data> - HashRef of the data (without the C<sops> section)

=item 2. C<$metadata> - L<File::SOPS::Metadata> object, or C<undef> if no C<sops> section

=back

Dies if the JSON is invalid or doesn't parse to a HashRef.

Dies on a document with B<duplicate keys> (C<Duplicate keys not allowed>). Such
a document cannot have a well-defined MAC -- it carries two values under one
key and the digest covers one of them -- so it is refused rather than silently
resolved. Until 0.003 that depended on which JSON backend the process had
loaded: L<JSON::XS> accepted such a document and kept the last value.

Dies too if the document has a top-level C<sops> entry that is B<not> an
object -- C<"sops": "mine">, an array, or C<null>. Until 0.003 that entry was
deleted from the tree and reported as no metadata at all, so
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

    return $class->emit(\%output);
}

=method serialize

    my $json = File::SOPS::Format::JSON->serialize(
        data     => \%data,
        metadata => $metadata_obj,
    );

Class method to serialize data and metadata to JSON.

The C<data> parameter must be a HashRef. The C<metadata> parameter must be
a L<File::SOPS::Metadata> object.

Dies if C<data> has a top-level C<sops> key: that is where the metadata section
is written, so the value would be overwritten. Until 0.003 it was, silently,
and the resulting document failed its own MAC because the digest had already
covered the discarded value.

Returns a pretty-printed, canonically-ordered JSON string with the C<sops>
section included.

=cut

# The one place this distribution turns a Perl tree into JSON. serialize() is
# this plus the metadata section, and File::SOPS::_serialize_plaintext (what
# decrypt_file writes and what edit hands the editor) is this on its own.
#
# It stays ONE sub because the options above have to be identical in both, and
# until karr #35 they were kept identical by hand: decrypt_file built its own
# encoder with the same options copied across -- and, being a second encoder,
# it could also have bound a different backend. canonical in particular is not
# a formatting preference -- the
# MAC's encrypt side hashes in sorted key order, and that is only the document's
# own order because this emitter sorts.
#
# Consequence, deliberately accepted: this sub is on the wire path. Changing
# what it emits changes the encrypted document too, so it is not a plaintext
# formatting knob.
sub emit {
    my ($class, $data) = @_;
    croak "data required" unless defined $data;

    return $encoder->encode(File::SOPS::Encrypted->canonical_float_tree(
        $data,
        roundtrips => \&_float_roundtrips,
        carrier    => \&_float_carrier,
        reject     => \&_reject_referenced_leaf,
    ));
}

# Every referenced leaf the JSON emitter cannot write as the text the digest
# covers. Closes the asymmetry Format::YAML closed in karr #65 / ADR 0008:
# detect_type calls every reference but a JSON::PP::Boolean `str`, so the
# digest covers the leaf's STRINGIFICATION, while Cpanel::JSON::XS -- with
# allow_bignum widened for _float_carrier -- writes a Math::BigFloat /
# Math::BigInt as a bare number, and writes an UNBLESSED scalar ref as a bare
# true/false (the documented JSON::XS convention for \1 / \0). Measured
# against sops 3.13.3, unencrypted leaf x_unencrypted:
#
#   Math::BigFloat->new("1.5")  bare number 1.5         self-MAC FAIL, exit 51
#   Math::BigInt->new("42")     bare number 42          self-MAC FAIL, exit 51
#   bless {a=>1}, 'Foo'         Cpanel refuses           self-MAC FAIL, exit 51
#   \1 (unblessed)              bare true                self-MAC FAIL, exit 51
#   \0 (unblessed)              bare false               self-MAC FAIL, exit 51
#
# All five -- the two we caught, the two Cpanel catches on its own, and the
# two nobody caught -- are the same defect: document and digest state
# different things, and the file is unreadable, written silently.
#
# The exception is the EXACT class, not ->isa: detect_type accepts a
# JSON::PP::Boolean subclass as bool, but neither Cpanel nor the carrier
# pipeline knows how to write it as bare true/false, and the guard's job is
# what the emitter can write. ref($node) eq 'JSON::PP::Boolean' matches the
# one class $YAML::XS::Boolean = 'JSON::PP' produces, JSON->true / JSON->false
# produce, and every JSON::MaybeXS backend produces -- the only reference
# whose document form and digest agree.
#
# Unblessed refs are in scope deliberately: \1 and \0 are the karr #66 case
# and the callback already has them in hand. They are not blessed, so the
# earlier "Math::BigFloat / Math::BigInt by name" rule could not see them.
#
# Not in assert_representable: that runs on the verify side too, and over
# leaves that are about to become ENC[...] strings. A referenced leaf in an
# ENCRYPTED slot works in both formats today (type:str, plaintext = the same
# stringification) and must keep working. See docs/adr/0008 and karr #66.
#
# $where is the leaf's key path from canonical_float_tree, in the shape the MAC
# walk's messages already use. It goes in FRONT of the message: the class alone
# told a caller what was wrong and left finding it a manual search (karr #68).
sub _reject_referenced_leaf {
    my ($node, $where) = @_;

    return if ref($node) eq 'JSON::PP::Boolean';

    my $what = Scalar::Util::blessed($node)
        ? "a leaf blessed into " . ref($node)
        : "an unblessed " . ref($node) . " reference";

    croak "$where: cannot write $what to a SOPS document: Cpanel::JSON::XS "
        . "writes it differently from the stringification the digest covers -- a "
        . "Math::BigFloat or Math::BigInt as a bare number, an unblessed "
        . "scalar reference as bare true/false, any other object is refused "
        . "by Cpanel itself. The document and its own MAC would state "
        . "different things, and neither sops nor this module could read the "
        . "file. Pass a plain Perl scalar, or the string you want stored. A "
        . "boolean has to be an exact JSON::PP::Boolean (JSON->true / "
        . "JSON->false); a subclass of it is written as a tag as well";
}

# Does this emitter's own rendering of the float come back as the same double?
#
# Measured through the two objects the document itself goes through, so the
# question asked is exactly "if I write this and read it back, do I get the
# same number". Cpanel renders an NV through %.15g, so 0.1+0.2 comes back as
# 0.3 -- a different double from the one value_to_bytes digested.
#
# Unlike YAML::XS, Cpanel keeps no PV, so a float PARSED from a JSON document
# is a bare NV and fails this test too. That is why rotate on a legitimate
# sops-written JSON file used to rewrite 0.30000000000000004 as 0.3.
#
# Equality via value_to_bytes on both sides, not ==, so it means what the digest
# means; == cannot tell -0.0 from 0.0, and -0.0 is a case ADR 0005 paid for.
#
# The reparsed leaf has to come back a FLOAT, and that is asked FIRST, because
# the byte comparison below cannot see the case where it does not.
# Cpanel::JSON::XS writes a scalar carrying a public PV as a JSON STRING, so a
# float leaf that is a Scalar::Util::dualvar -- numerically the double, as text
# the canonical decimal -- is emitted quoted. The byte test then passes: the
# reparsed value is the string "0.30000000000000004", whose value_to_bytes is
# itself, which is the text the digest covers. Equal, so the walk left the leaf
# alone and the document silently held a string where the caller passed a
# number. Measured against sops 3.13.3, leaf ratio_unencrypted:
#
#   dualvar(0.1+0.2, "0.30000000000000004")
#     -> "ratio_unencrypted" : "0.30000000000000004"
#     -> sops -d exit 0, read back AS A STRING
#
# The MAC holds either way -- Go's ToBytes of that JSON string is the same
# text -- so nothing fails and nothing says anything. That is why it is a
# refusal here rather than a repair: the value's TYPE changed between what the
# caller handed in and what the document states, and this distribution's rule
# is that such a disagreement is named, not written (docs/adr/0008).
#
# The nearest route in is ordinary caller code, not a contrivance:
# `my $v = File::SOPS->extract(...)` returns exactly that dualvar for a float
# leaf since ADR 0010, and feeding it back into encrypt() under an unencrypted
# key lands here. ADR 0010 keeps the dualvar out of every tree for this reason
# and records the gap as karr #78; this closes it.
#
# JSON ONLY, deliberately. The same question asked of Format::YAML would refuse
# `0.0` and `2.0`: YAML::XS writes an integral float as `0` / `2`, which
# reparses as an INT, and both are handled correctly today -- `0.0` compares
# equal on bytes and is left alone, `-0.0` goes to the carrier that writes
# `-0.0` (ADR 0005/0006). Cpanel writes every NV with a `.0` or an exponent, so
# a non-float reparse there means a quoted string and nothing else.
#
# It cannot fire on a float that was merely printed: measured, Perl does not
# set the PUBLIC SVf_POK when it stringifies an NV, and Cpanel reads the public
# flag, so `my $s = "$float"` leaves the emission bare. A real dualvar is the
# only shape that reaches this.
sub _float_roundtrips {
    my ($value, $text) = @_;

    my $back = eval { $json->decode($encoder->encode({ v => $value }))->{v} };
    return 0 unless defined $back;

    croak "cannot write a float leaf that carries its own string form to a "
        . "SOPS document: Cpanel::JSON::XS writes any scalar with a string "
        . "half as a quoted JSON string, so the document would state a string "
        . "where a number was passed -- silently, because the digest covers "
        . "the same text either way and the file still verifies. The usual "
        . "source is File::SOPS->extract, which returns a dualvar for a float "
        . "leaf (see File::SOPS::Encrypted->canonical_float_dualvar); put a "
        . "plain number in the document, or the string you want stored"
        unless File::SOPS::Encrypted->detect_type($back) eq 'float';

    return File::SOPS::Encrypted->value_to_bytes($back) eq $text ? 1 : 0;
}

# Math::BigFloat is the only carrier measured to survive into JSON as a bare
# number: a dualvar, a plain string and a TO_JSON return are all quoted by every
# backend, and Cpanel::JSON::XS::Type's JSON_TYPE_FLOAT still renders 0.3.
#
# The explicit `undef, undef` are the accuracy and precision arguments, and they
# are load-bearing. Math::BigFloat->new otherwise applies CLASS-GLOBAL accuracy
# and precision, so a caller who had set Math::BigFloat->accuracy(5) anywhere in
# their program silently turned our text into 0.30000 -- the calling program
# deciding our wire bytes again, which is the whole subject of ADR 0005. A
# subclass would be immune to that, but allow_bignum matches the class name
# exactly and refuses one.
sub _float_carrier {
    my ($value, $text) = @_;

    my $big = Math::BigFloat->new($text, undef, undef);

    # The bypass above is measured, but the failure it prevents is silent and
    # produces a document that fails its own MAC, so it is asserted rather than
    # trusted. No value in the message: it is the plaintext.
    croak "Math::BigFloat did not render a float leaf at full precision. "
        . "Check for a global Math::BigFloat->accuracy or ->precision setting."
        unless "$big" eq $text;

    return $big;
}

=method emit

    my $json = File::SOPS::Format::JSON->emit(\%data);

Class method to emit a data structure as JSON, with no C<sops> section and no
metadata of any kind -- a plain document. This is what L<File::SOPS/decrypt_file>
writes and what L<File::SOPS/edit> hands to the editor.

Returns UTF-8 encoded bytes, unconditionally (the encoder is built with
C<utf8 =E<gt> 1>, which encodes regardless of whether the strings carry Perl's
UTF-8 flag), pretty-printed and canonically ordered. See
L<File::SOPS/Character encoding>.

L</serialize> is this method plus the metadata section, so both go through the
same encoder rather than two copies of its options. Those options are not
cosmetic -- C<canonical> is what makes key order sorted, which the MAC's encrypt
side relies on -- so a change here moves the encrypted document as well as the
plaintext one.

B<Floats are written in a form that parses back to the same double.>
L<Cpanel::JSON::XS> renders a float through C<%.15g>, while the MAC digest
covers the shortest decimal that round-trips -- up to 17 significant digits. For
a value needing 16 or 17 the document stated one number and the digest another,
and the file failed its own verification; because this backend keeps no copy of
the text it parsed, that applied to floats read out of a sops-written document
as much as to computed ones, so C<rotate> could destroy a value the reference
implementation had written correctly. This method now reparses its own output
and substitutes the canonical decimal from
L<File::SOPS::Encrypted/value_to_bytes> only where the value does not survive,
carried as a L<Math::BigFloat> under C<allow_bignum> -- the only wrapper
measured to reach JSON as a bare number instead of a quoted string. A float that
already emitted faithfully keeps exactly the bytes it had, C<-0.0> included.
C<NaN> and C<Inf> are unchanged. See
L<docs/adr/0006|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0006-floats-are-emitted-in-a-form-that-parses-back-to-the-same-double.md>.

B<A float leaf carrying its own string form is refused.> L<Cpanel::JSON::XS>
writes any scalar with a public string half as a quoted JSON string, so such a
leaf reached the document as a B<string> where the caller passed a number. It
failed nothing: the digest covers the canonical decimal either way, the file
verifies, and C<sops -d> exits 0 and reads a string back -- the value's type
changed and nothing said so. The round-trip check above could not see it, because
the reparsed string re-derives the very text the digest covers. It now also
requires the reparsed leaf to still be a float, and dies where it is not.

The usual source is L<File::SOPS/extract>, which returns a
L<Scalar::Util/dualvar> for a float leaf (see
L<File::SOPS::Encrypted/canonical_float_dualvar>); feeding that return value
back into L<File::SOPS/encrypt> under an unencrypted key is what reaches this.
An B<encrypted> slot is unaffected -- the leaf is an C<ENC[...]> string before
this method sees it -- and so is L<File::SOPS::Format::YAML>, which writes the
string half bare and correctly. Only the leaves Cpanel actually quotes are
refused: a dualvar whose text is what Cpanel would have written anyway, such as
C<1.5> or C<-0.0>, still emits as the number it always did. See karr #78 and
L<docs/adr/0010|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0010-extract-returns-a-float-that-prints-all-its-digits.md>.

B<A reference as a leaf value is refused>, with one exception. L<Cpanel::JSON::XS>
under C<allow_bignum> writes a C<Math::BigFloat> / C<Math::BigInt> as a bare
number, and an unblessed C<\1> / C<\0> as bare C<true> / C<false> -- the
documented JSON::XS convention for SCALAR refs -- while
L<File::SOPS::Encrypted/detect_type> calls the leaf C<str> so the MAC digest
covers its B<stringification>. The document and its own MAC then state different
things, and the file is unreadable to sops and to this module alike. Until
0.003 it was written anyway, without a word; now it dies naming the class or
reference kind (never the value).

The exception is an exact L<JSON::PP::Boolean>, which this emitter writes as
bare C<true> / C<false> -- the one reference whose document form and digest
agree. A B<subclass> of it is not covered: C<detect_type> calls it C<bool> but
Cpanel refuses it (or the carrier pipeline writes it as a tag), so it is
refused like any other object.

Only leaves that reach the document B<verbatim> can trigger this -- values
excluded by the encryption rules, everything in a plaintext document, and the
C<sops> section. A value that gets encrypted is an C<ENC[...]> string by the
time this method sees it, so an object in an encrypted slot is unaffected and
still stores its stringification as C<type:str>. L<File::SOPS::Format::YAML>
has refused the same leaves since 0.003; see
L<docs/adr/0008|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0008-a-leaf-the-emitter-cannot-write-as-what-the-digest-covers-is-refused.md>
and karr #66 for the unblessed-ref half of the same defect.

=cut

sub format_name { 'json' }

=method format_name

Returns C<'json'>.

=cut

sub file_extensions { qw(json) }

=method file_extensions

Returns a list of file extensions: C<('json')>.

=cut

sub detect {
    my ($class, $filename) = @_;
    return 1 if $filename =~ /\.json$/i;
    return 0;
}

=method detect

    if (File::SOPS::Format::JSON->detect($filename)) {
        # File is JSON based on extension
    }

Class method to detect if a filename is JSON based on extension.

Returns true if filename ends with C<.json> (case-insensitive).

=cut

=head1 SEE ALSO

=over 4

=item * L<File::SOPS> - Main SOPS interface

=item * L<Cpanel::JSON::XS> - the JSON parser and serializer, named deliberately

=back

=cut

1;
