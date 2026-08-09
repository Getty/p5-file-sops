package File::SOPS::Format::JSON;
# ABSTRACT: JSON format handler for SOPS
our $VERSION = '0.003';
use Moo;
use Carp qw(croak);
use Cpanel::JSON::XS ();
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
my $json = Cpanel::JSON::XS->new->utf8->pretty->canonical;

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

    return $json->encode($data);
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
