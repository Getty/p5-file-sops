package File::SOPS::Format::JSON;
# ABSTRACT: JSON format handler for SOPS
our $VERSION = '0.003';
use Moo;
use B ();
use Carp qw(croak);
use Cpanel::JSON::XS ();
use Cpanel::JSON::XS::Type qw(JSON_TYPE_INT);
use Math::BigFloat ();
use Scalar::Util qw(blessed dualvar);
use File::SOPS::Encrypted;
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

    # The second argument is an OUTPUT parameter: Cpanel fills $types with a
    # parallel tree of type constants and hands back exactly the data it would
    # have handed back without it (measured -- structurally identical, and the
    # duplicate-key refusal below is unchanged). See _restore_wide_numbers.
    my $data = $json->decode($content, my $types);
    croak "JSON did not parse to a hash" unless ref $data eq 'HASH';

    my $metadata;
    if (exists $data->{sops}) {
        require File::SOPS::Metadata;
        $metadata = File::SOPS::Metadata->from_hash(delete $data->{sops});
    }

    # AFTER the sops section is split off, so the metadata is never rewritten:
    # its version and lastmodified are strings the reference wrote and this
    # walk has no business touching. $types still carries a `sops` branch, and
    # the walk never reaches it because it descends $data.
    _restore_wide_numbers($data, $types);

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

B<A bare JSON integer literal too wide for a Perl integer comes back as a
float>, carrying its source spelling -- the same leaf L<YAML::XS> has always
returned for the same digits, a L<Scalar::Util/dualvar>. L<Cpanel::JSON::XS>
returns such a literal as a plain string SV, indistinguishable from the same
digits B<quoted>, so C<100000000000000000000> was typed C<str> and
L<File::SOPS/rotate> wrote it back into the document as a JSON B<string>: the
schema of a file the reference implementation had written changed, silently,
and nothing failed because a string's digest is its own text either way. There
is no big integer in the SOPS data model -- past C<int64> a JSON number is a
C<float64> to Go, and sops writes such a leaf as C<type:float> -- so the value
is now a float here too, and the document keeps the bare number it came with.

A B<quoted> C<"100000000000000000000"> is unaffected and stays a C<str>: the
two are told apart by the decoder's own type map, never by a pattern match on
the text (ADR 0002). So is every value the decoder could hold, C<undef>, every
boolean and every reference -- and every B<float>, which is why the C<0.3>
handling above is untouched. A document this library has already written
carries the value quoted, so it keeps verifying and keeps reading back exactly
as before.

Two consequences worth naming. The value the caller receives is now numeric as
well as printable, and C<value_to_bytes> re-derives its digits from the double,
so a literal that is not its own double's canonical decimal --
C<99999999999999999999>, which no C<sops -e> writes, because sops rounds it to
C<100000000000000000000> itself -- rounds the same way here. And a literal that
overflows a double, C<1> followed by 400 zeros, now dies in
L<File::SOPS::Encrypted/assert_representable> where it used to be written as a
string; sops refuses that document itself, at unmarshal time. See karr #63 and
L<docs/adr/0020|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0020-a-json-number-perl-cannot-hold-is-a-float-not-a-string.md>.

=cut

# Give back the leaf YAML::XS has always given back for the same digits.
#
# Cpanel::JSON::XS returns a bare JSON integer literal it cannot hold in an IV
# or a UV as a plain PV -- a STRING -- so `100000000000000000000` reached the
# tree indistinguishable from `"100000000000000000000"` (measured: bit-identical
# SVs, FLAGS 0x4403, POK alone). detect_type therefore called it `str`, and
# rotate wrote a document sops had written with a NUMBER there back with a
# string. Silent schema drift on the reference's own file, karr #63.
#
# There is no big integer in the SOPS data model: past int64 a JSON number is a
# float64 to Go, and sops writes such a leaf as type:float in an encrypted slot
# and loses the digits itself in an unencrypted one (`sops -e` on
# 99999999999999999999 writes 100000000000000000000). YAML::XS already hands
# back the right shape for the same literal -- the double, carrying its source
# spelling, i.e. a dualvar -- which is a leaf class this distribution handles
# end to end. So the fix is only that THIS parser gives what the OTHER one
# gives; nothing in Format::YAML moves, and nothing in emit() moves either,
# because ADR 0011's repair path already writes such a leaf as a bare number.
# See docs/adr/0020.
#
# The ORACLE is the decoder's own type map, read from the same $json object the
# document goes through (ADR 0005: the backend is named, so its options are
# ours) -- never allow_bignum, which would hand back Math::BigFloat objects for
# every ordinary float and retype every document, and costs two orders of
# magnitude more besides (docs/adr/0020 has the figures). A plain-PV leaf is a
# plain PV for exactly two reasons, a JSON string or a bare integer too wide for
# an IV/UV, and the map separates them without fail: re-measured here across
# every IV/UV boundary and a set of pathological literals (400-digit integers,
# 400-digit fractions, 1e309, thirty ones), every plain-PV leaf is either
# JSON_TYPE_INT or JSON_TYPE_STRING and there is no third case. karr #63's
# parking note dismissed this mechanism over encode($data, $type) rewriting the
# value as UINT64_MAX; that is the ENCODE side, and the map is read here and
# handed to no encoder.
#
# The GATE is the plain tree, not the map. A leaf is touched only where the
# plain decode left a defined, unreferenced scalar carrying the public SVf_POK
# and NEITHER SVf_IOK NOR SVf_NOK; everywhere else the map is not even read.
# That is what keeps the float path out of this: a bare float literal decodes
# NOK and fails the first test. It is also why no Math::BigInt ever enters the
# tree, so _reject_referenced_leaf below keeps refusing one, unchanged.
sub _restore_wide_numbers {
    my ($node, $type) = @_;

    if (ref $node eq 'HASH') {
        my $map = ref $type eq 'HASH' ? $type : undef;
        for my $key (keys %$node) {
            my $wide = _wide_number($node->{$key}, $map ? $map->{$key} : undef);
            $node->{$key} = $wide if defined $wide;
        }
    }
    elsif (ref $node eq 'ARRAY') {
        my $map = ref $type eq 'ARRAY' ? $type : undef;
        for my $index (0 .. $#$node) {
            my $wide = _wide_number($node->[$index],
                $map ? $map->[$index] : undef);
            $node->[$index] = $wide if defined $wide;
        }
    }

    return;
}

# The dualvar for a leaf the decoder could not hold, or undef for a leaf that
# is to be left EXACTLY as the decoder returned it -- containers included, which
# are walked in place instead of being handed back.
#
# undef rather than the leaf itself so that an untouched slot is never assigned
# to at all. Storing a leaf back over itself preserves every flag that carries
# meaning -- measured, IOK/NOK/POK and their private twins identical across
# floats, integers, strings, -0.0, booleans, null and a UTF-8 string -- but it
# does set the pad housekeeping bits on an SV this walk had no business
# touching, and a parse path that leaves fingerprints on leaves it did not fix
# is one a later flag-level regression test cannot read.
#
# TWO leaf classes end up as that dualvar, one magnitude apart, and the public
# flags of the decoder's own SV are what tell them apart:
#
#   IOK       a bare literal Perl DID hold and Go cannot, [2**63 .. 2**64-1] --
#             a UV here, a float64 there. karr #101, docs/adr/0021.
#   POK alone a bare literal Perl could NOT hold, past 2**64-1, which the
#             decoder hands back as a plain string. karr #63, docs/adr/0020.
#
# The flags are read ONCE for both, which is why the second class costs nothing:
# ADR 0021 measured the fold slightly FASTER than the single read this walk
# already made through the plain-PV test, which used to be a sub of its own.
# The question that test asks is unchanged and so is the reason it asks it of
# the PUBLIC SVf_POK -- as Encrypted::_has_public_pv does, because merely
# stringifying a number sets the PRIVATE pPOK and reading that would call an
# integer a string because someone had logged it. It is a question about the
# DECODER's output, not about the SOPS type; the type ladder stays in
# File::SOPS::Encrypted::detect_type and is not repeated here.
#
# THE ORDER OF THE TWO GATES IN THE IOK BRANCH IS CORRECTNESS, NOT COST.
# The flag comes first and the numeric comparison second, never the other way
# round: a numeric comparison against a scalar sets the PUBLIC SVf_IOK on it in
# place, so run ahead of the flag test over {"port":"5432","zip":"007",
# "ver":"1.50"} it retypes three of four string leaves -- measured, '5432' and
# '007' become ints and '1.50' a float, and the document either changes schema
# or croaks on ADR 0012's guard, from a walk that never reached the window.
# That is karr #32's mechanism and ADR 0002's rule. Two things keep it away
# from here and BOTH are deliberate: the SVf_IOK test that gates the branch,
# and the copying done by this sub's own `my ($node, $type) = @_` and again by
# Encrypted::integer_fits_int64. Neither is the redundant half -- the order is
# also what keeps the comparison off a leaf where it would warn, measured: one
# "isn't numeric" warning per string leaf.
sub _wide_number {
    my ($node, $type) = @_;

    if (ref $node eq 'HASH' || ref $node eq 'ARRAY') {
        _restore_wide_numbers($node, $type);
        return;
    }

    return if !defined $node || ref $node;

    my $flags = B::svref_2object(\$node)->FLAGS;

    if ($flags & B::SVf_IOK()) {
        # The boundary is asked of File::SOPS::Encrypted and is NOT spelled a
        # second time here: two copies of int64 drift together, which leaves
        # the wire self-consistent and only the reference disagreeing. Only
        # the upper end can fail -- an IV cannot reach below int64min, so the
        # negative half of this window does not exist and -9223372036854775809
        # is already the plain-PV branch's leaf.
        return if File::SOPS::Encrypted->integer_fits_int64($node);

        # NOT `$digits + 0`, which is what the branch below can use: these
        # digits still fit a UV, so numifying them gives back an INTEGER and
        # detect_type would go on calling the leaf an int -- the fix would be
        # a silent no-op. pack/unpack forces the double Go reads there, and
        # value_to_bytes then re-derives sops's own digits from it
        # (9223372036854775808 -> 9223372036854776000, measured identical to
        # what `sops -e` writes for the same input, in both slots).
        my $digits = "$node";

        return dualvar(unpack('d', pack('d', $digits)), $digits);
    }

    return unless $flags & B::SVf_POK();
    return if $flags & B::SVf_NOK();
    return unless defined $type && !ref $type && $type == JSON_TYPE_INT;

    # The numification runs on a COPY of the PV. Perl marks a scalar numeric IN
    # PLACE the first time it is read as a number, so numifying the leaf itself
    # would set a flag on an SV the decoder still holds -- the trap ADR 0002
    # and karr #72/#73 are about, one frame earlier.
    my $digits = "$node";
    my $number = $digits + 0;

    return dualvar($number, $digits);
}

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
# Cpanel::JSON::XS writes a scalar carrying a public PV as a JSON STRING when
# that PV differs from its own rendering of the number, so a float leaf that is
# a Scalar::Util::dualvar -- numerically the double, as text the canonical
# decimal -- is emitted quoted. The byte test then passes: the reparsed value
# is the string "0.30000000000000004", whose value_to_bytes is itself, which is
# the text the digest covers. Equal, so the walk left the leaf alone and the
# document silently held a string where the caller passed a number. Measured
# against sops 3.13.3, leaf ratio_unencrypted:
#
#   dualvar(0.1+0.2, "0.30000000000000004")
#     -> "ratio_unencrypted" : "0.30000000000000004"
#     -> sops -d exit 0, read back AS A STRING
#
# Answering NO sends the leaf to _float_carrier, which writes that same
# canonical decimal as a BARE NUMBER -- the document YAML has always produced
# for the same leaf, and, for the karr #78 case, byte-identical to the one a
# bare NV of the same value produces (both go through the carrier). 89ed194
# croaked here instead; that refused every float that arrived through a YAML
# parse as well, because YAML::XS keeps the source text of every scalar it
# parses. See docs/adr/0011, which replaces that refusal, and karr #85 for the
# question it leaves open (a string half that CONTRADICTS the number, such as
# dualvar(1.5, 'banana'), is written as 1.5 here and in YAML alike).
#
# The nearest route in is ordinary caller code, not a contrivance:
# `my $v = File::SOPS->extract(...)` returns exactly that dualvar for a float
# leaf since ADR 0010, and feeding it back into encrypt() under an unencrypted
# key lands here.
#
# JSON ONLY, deliberately. The same question asked of Format::YAML would send
# `0.0` and `2.0` to a carrier they do not need: YAML::XS writes an integral
# float as `0` / `2`, which reparses as an INT, and both are handled correctly
# today -- `0.0` compares equal on bytes and is left alone, `-0.0` goes to the
# carrier that writes `-0.0` (ADR 0005/0006). Cpanel writes every NV with a
# `.0` or an exponent, so a non-float reparse there means a quoted string and
# nothing else.
#
# It cannot fire on a float that was merely printed: measured, Perl does not
# set the PUBLIC SVf_POK when it stringifies an NV, and Cpanel reads the public
# flag, so `my $s = "$float"` leaves the emission bare. A real dualvar, or a
# scalar a YAML parser kept the source text of, is what reaches this.
sub _float_roundtrips {
    my ($value, $text) = @_;

    my $back = eval { $json->decode($encoder->encode({ v => $value }))->{v} };
    return 0 unless defined $back;

    return 0 unless File::SOPS::Encrypted->detect_type($back)
                 eq File::SOPS::Encrypted->detect_type($value);

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
#
# The ONE canonical float text it cannot carry is a NEGATIVE ZERO: Math::BigFloat
# has no signed zero, so new('-0') stringifies as `0` and the assertion below
# fired -- on a sign, with a message about a precision setting that was never in
# play (karr #88). Measured: of 2018 canonical texts from value_to_bytes, `-0` is
# the only one it does not reproduce.
#
# So a negative zero is carried by the DOUBLE ITSELF, stripped of the string half
# that sent it here. Cpanel writes a bare NV -0.0 as `-0.0` (ADR 0005 names that
# as the reason this handler binds Cpanel and not JSON::XS), and that text parses
# back to the same double -- which is what ADR 0006 asks of an emitted decimal,
# not that it be spelled canonically. Measured against sops 3.13.3, an
# unencrypted JSON leaf whose digest is `-0`:
#
#   -0.0     sops -d exit 0, reads back -0     <- this, and what a bare NV writes
#   -0       sops -d exit 51 (MAC mismatch)    <- Go reads a JSON -0 as an INTEGER
#
# The same split the YAML carrier measured in karr #62, in the other format: `-0`
# is the canonical text and the one spelling neither implementation reads back.
#
# The copy goes through pack/unpack, and NO arithmetic route works. Measured on
# a leaf out of a YAML parse, three rounds each:
#
#   0 + $v      -0 once, then 0     $v * 1     -0 once, then 0
#   $v * 1.0    0 every round       $v - 0.0   0 every round
#   unpack d pack d                 -0 every round
#
# Two mechanisms, and the second is the dangerous one. IEEE-754 makes
# -0.0 + 0.0 a POSITIVE zero, so adding zero drops the sign outright. And
# Perl's arithmetic ops call SvIV_please on their operands, which sets the
# PRIVATE IOK on the CALLER'S scalar in place -- so the next multiplication of
# the same leaf takes the integer path and returns a plain 0. That is karr #72
# and #73 again, one frame further in: the first document written would have
# been right and every later one wrong, in the same process, from the same
# tree. pack 'd' reads the NV and nothing else.
#
# The strip is not cosmetic: with the PV still on it, Cpanel quotes the leaf and
# the document holds a string where the caller passed a number.
sub _float_carrier {
    my ($value, $text) = @_;

    my $carrier = $text eq '-0' ? unpack('d', pack('d', $value))
                                : Math::BigFloat->new($text, undef, undef);

    # Both bypasses above are measured, but the failure they prevent is silent
    # and produces a document that fails its own MAC, so it is asserted rather
    # than trusted -- through value_to_bytes, so the assertion means what the
    # digest means. No value in the message: it is the plaintext.
    croak "the JSON float carrier did not reproduce the text the MAC digest "
        . "covers, so nothing was written. Everything but a negative zero is "
        . "carried by a Math::BigFloat, where the cause is a global "
        . "Math::BigFloat->accuracy or ->precision setting that survived the "
        . "explicit undef, undef; a negative zero is carried by the double "
        . "itself, where it is a build whose arithmetic drops the sign of a "
        . "signed zero"
        unless File::SOPS::Encrypted->value_to_bytes($carrier) eq $text;

    return $carrier;
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

B<A float leaf carrying its own string form is written as a number.>
L<Cpanel::JSON::XS> writes a scalar with a public string half as a quoted JSON
string whenever that half differs from its own rendering of the number, so such
a leaf reached the document as a B<string> where the caller passed a number. It
failed nothing: the digest covers the canonical decimal either way, the file
verifies, and C<sops -d> exits 0 and reads a string back -- the value's type
changed and nothing said so. The round-trip check above could not see it,
because the reparsed string re-derives the very text the digest covers. It now
also asks whether the reparsed leaf is still a float and, where it is not,
sends the leaf to the same L<Math::BigFloat> carrier, which writes the
canonical decimal as a bare number.

The usual source is L<File::SOPS/extract>, which returns a
L<Scalar::Util/dualvar> for a float leaf (see
L<File::SOPS::Encrypted/canonical_float_dualvar>); feeding that return value
back into L<File::SOPS/encrypt> under an unencrypted key is what reaches this.
The other is a float that arrived through a YAML parse, since L<YAML::XS>
retains the source text of every scalar it parses. An B<encrypted> slot is
unaffected -- the leaf is an C<ENC[...]> string before this method sees it --
and L<File::SOPS::Format::YAML> has always written the string half bare and
correctly, which is the document this now produces too. A dualvar whose text is
what Cpanel would have written anyway, such as C<1.5> or C<-0.0>, still emits
as the number it always did, byte for byte. See karr #78,
L<docs/adr/0011|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0011-a-float-leaf-that-carries-its-own-string-form-is-repaired.md>
and
L<docs/adr/0010|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0010-extract-returns-a-float-that-prints-all-its-digits.md>.

B<An integer leaf carrying its own, different string form is refused.>
L<Cpanel::JSON::XS> writes it as a quoted string -- C<"007"> for a C<7> a YAML
parser kept the source spelling of, C<"five"> for a
C<Scalar::Util/dualvar> -- while L<File::SOPS::Encrypted/detect_type> calls the
leaf an C<int>, so the MAC digest covers the B<number>. The document and its
own MAC then state different things and neither sops nor this module can read
the file back: measured against sops 3.13.3, C<sops -d> exit 51 for C<007>,
C<+7>, C<-0>, C<1e3> and every contradicting dualvar. The refusal names the
leaf's key path and neither half of the value. Refused rather than repaired
because nothing measurable separates a spelling from a contradiction; an
B<encrypted> slot is unaffected, and L<File::SOPS::Format::YAML> refuses only
the contradicting ones, because it writes a source spelling back faithfully.
See karr #84 and
L<docs/adr/0012|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0012-an-integer-leaf-whose-string-half-disagrees-is-refused.md>.

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
