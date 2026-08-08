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
$YAML::XS::Boolean = 'JSON::PP';

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

=cut

sub parse {
    my ($class, $content) = @_;
    croak "content required" unless defined $content;

    my $data = Load($content);
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

Dies if the YAML is invalid or doesn't parse to a HashRef.

=cut

sub serialize {
    my ($class, %args) = @_;
    my $data     = $args{data}     // croak "data required";
    my $metadata = $args{metadata} // croak "metadata required";

    my %output = %$data;
    $output{sops} = $metadata->to_hash;

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
