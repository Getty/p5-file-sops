package File::SOPS::Format::YAML;
# ABSTRACT: YAML format handler for SOPS
our $VERSION = '0.003';
use Moo;
use Carp qw(croak);
use YAML::XS qw(Load Dump);
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

    local $YAML::XS::Boolean = $BOOLEAN_MODE;
    return _quote_sops_timestamp(Dump(\%output));
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
