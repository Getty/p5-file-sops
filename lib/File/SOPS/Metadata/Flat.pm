package File::SOPS::Metadata::Flat;
# ABSTRACT: the flat sops_age__list_0__map_enc metadata encoding of the ENV and INI formats
our $VERSION = '0.003';
use Moo;
use Carp qw(croak);
use Scalar::Util qw(blessed);
use namespace::clean;

# The two path separators, measured against sops 3.13.3 rather than read out
# of the Go source. Every descent into the metadata tree appends one of them:
# a map key gets `__map_` . $key, a list index gets `__list_` . $index. The
# root field name carries no separator at all. They compose to any depth --
# `key_groups__list_0__map_age__list_0__map_enc` is a real document sops
# writes for a key-group file, and it is five levels.
our $MAP_SEPARATOR  = '__map_';
our $LIST_SEPARATOR = '__list_';

has prefix => (is => 'ro', default => '');

=head1 SYNOPSIS

    use File::SOPS::Metadata;
    use File::SOPS::Metadata::Flat;

    # ENV: the flat keys live among the data keys under a sops_ prefix
    my $flat = File::SOPS::Metadata::Flat->new(prefix => 'sops_');

    # INI: the flat keys live bare inside a [sops] section
    my $flat = File::SOPS::Metadata::Flat->new;

    my @pairs = $flat->flatten($meta->to_hash);
    # => ([ 'sops_age__list_0__map_enc' => '-----BEGIN…\n…\n' ], …)

    my $meta = File::SOPS::Metadata->from_hash($flat->unflatten(\%lines));

=head1 DESCRIPTION

The C<sops> metadata section has B<two> wire formats, not one. YAML and JSON
carry it as the nested mapping L<File::SOPS::Metadata/to_hash> produces. The
ENV and INI formats have no nesting to carry it in, so sops flattens the same
mapping onto single keys with a path-mangling scheme of its own:

    ENV:  sops_age__list_0__map_enc=-----BEGIN AGE ENCRYPTED FILE-----\n…
          sops_lastmodified=2026-08-21T01:34:51Z

    INI:  [sops]
          age__list_0__map_enc       = -----BEGIN AGE ENCRYPTED FILE-----\n…
          lastmodified               = 2026-08-21T01:34:51Z

That is a second metadata wire format and not a formatting detail, which is
why it is a module rather than a helper inside a format handler: B<the two
formats differ only in where the flat keys are put>, and building it twice is
how they would drift apart. The difference is L</prefix> and nothing else.

This class is deliberately B<untyped and schema-free>. It knows the mangling
scheme and the escape, and nothing about what a C<sops> section contains --
L<File::SOPS::Metadata> owns that. Feed L</flatten> the output of
C<< $meta->to_hash >> and feed C<< File::SOPS::Metadata->from_hash >> the
output of L</unflatten>.

=head2 The scheme, as measured

Against sops 3.13.3, both formats, with two age recipients so that
C<__list_1__> is a real observation and not a guess:

=over 4

=item * B<Descending into a map> under key C<K> appends C<__map_K>.

=item * B<Descending into a list> at index C<N> appends C<__list_N>.

=item * B<The root field name is bare> -- C<age>, not C<__map_age>.

=item * B<They compose to any depth.> C<key_groups__list_0__map_age__list_0__map_enc>
is what a C<--shamir-secret-sharing-threshold 2> document writes.

=item * B<List indices must run from 0 without gaps.> Renumbering
C<age__list_1__> to C<age__list_2__> in a file sops wrote makes it refuse the
document with C<Error while unflattening: Incomplete list>, exit 1. L</unflatten>
croaks on the same input rather than handing back a list with a hole in it.

=back

=head2 Empty lists vanish, and must

C<< $meta->to_hash >> always emits C<kms>, C<gcp_kms>, C<azure_kv>,
C<hc_vault>, C<age> and C<pgp>, empty arrays included, because the nested
format needs the keys to exist. B<The flat format has no way to write an empty
list, and writing one anyway breaks the file.> Measured: adding C<sops_kms=>
and C<sops_pgp=> to a document sops wrote makes C<sops -d> fail with

    'kms[0]' expected a map or struct, got "string"
    'pgp[0]' expected a map or struct, got "string"

because an empty value is read as a one-element list holding an empty string,
not as an empty list. So L</flatten> emits nothing at all for an empty list or
map, which is exactly what sops does.

Nothing is lost by it: L<File::SOPS::Metadata/from_hash> defaults every one of
those fields to C<[]> when the document does not carry it, so the round trip
back through this class and C<from_hash> restores them.

=head2 Line order is cosmetic, and produced anyway

L</flatten> returns B<ordered pairs>, walking maps in sorted key order and
lists in ascending index order -- which is the order sops writes, verified with
eleven recipients: C<age__list_10__map_enc> comes B<after> C<age__list_9__map_enc>,
so the output is a structural walk and B<not> a byte sort of the finished flat
keys.

Reordering the lines changes nothing on the read side (a file with its C<sops_>
lines reversed still decrypts, exit 0), and the metadata section is excluded
from the MAC structurally, so no digest depends on this. It is matched because
producing the same bytes as the reference implementation is what this
distribution is for, and because a HashRef return would throw the information
away for no gain.

=cut

=attr prefix

The string every flat key carries, and B<the only difference between the ENV
and INI encodings>. C<sops_> for ENV, where the metadata shares one flat
namespace with the document's own keys; the empty string (the default) for INI,
where the C<[sops]> section already separates them.

=cut

sub is_metadata_key {
    my ($self, $key) = @_;
    my $prefix = $self->prefix;
    return 1 unless length $prefix;
    return index($key, $prefix) == 0 ? 1 : 0;
}

=method is_metadata_key

    next unless $flat->is_metadata_key($key);

Whether a flat key belongs to the metadata section. With an empty L</prefix>
every key does, which is correct for INI -- the caller has already narrowed the
input to the C<[sops]> section -- and is why an ENV caller B<must> set the
prefix before handing this class a whole document.

This exists so that the ENV handler does not have to spell C</^sops_/> itself.
That spelling and the one L</flatten> writes have to agree, and the way they
stay agreeing is by being the same string in one place.

=cut

sub escape_value {
    my ($self, $value) = @_;

    return '' unless defined $value;

    # A metadata section carries JSON::PP::Boolean for mac_only_encrypted, and
    # sops writes it as a bare lowercase `true`. Perl's stringification of that
    # object is 1/0, so it has to be asked rather than interpolated.
    if (blessed $value) {
        croak "cannot write a " . ref($value) . " object into the flat "
            . "metadata encoding; only plain scalars and JSON::PP::Boolean "
            . "have a form sops writes there"
            unless $value->isa('JSON::PP::Boolean');
        return $value ? 'true' : 'false';
    }

    croak "cannot write a " . ref($value) . " reference as a flat metadata "
        . "leaf; flatten() descends into HASH and ARRAY and every other "
        . "reference is a value it has no encoding for"
        if ref $value;

    my $escaped = $value;
    $escaped =~ s/\n/\\n/g;
    return $escaped;
}

=method escape_value

    my $line_safe = $flat->escape_value($value);

Turns a value into the single line the flat formats store. B<A newline becomes
the two characters backslash and C<n>, and nothing else is touched> -- not a
tab, not a carriage return, and B<not a backslash>.

That is measured, not assumed. Feeding sops an C<unencrypted_suffix> holding
each character in turn and reading the bytes back off the file it writes:

    value passed to sops        bytes sops wrote
    a<TAB>b                     a<TAB>b        (a real tab, unescaped)
    a<CR>b                      a<CR>b         (a real CR, unescaped)
    a\\b                        a\\b           (backslash not doubled)
    a\tb                        a\tb           (left alone)
    a<LF><LF>b                  a\n\nb

The age C<enc> block is what makes this matter: it is PEM armor, so it is
almost entirely newlines, and it has to arrive back at C<age> byte-exact or the
data key does not unwrap.

B<The escape is lossy, deliberately.> Since a backslash is not escaped on the
way out and C<\n> is not protected on the way in, a value that already contains
the two characters backslash-C<n> is indistinguishable from one containing a
newline, and comes back as a newline. That is sops's behaviour and this class
reproduces it rather than inventing a lossless escape sops would not read --
see docs/adr/0022.

=cut

sub unescape_value {
    my ($self, $value) = @_;

    return '' unless defined $value;

    my $unescaped = $value;
    $unescaped =~ s/\\n/\n/g;
    return $unescaped;
}

=method unescape_value

    my $value = $flat->unescape_value($line_safe);

The inverse of L</escape_value>: the two characters backslash and C<n> become a
newline, everything else is left alone.

B<Non-recursive, and a preceding backslash does not escape it> -- which is
sops's rule and was measured by putting each spelling into C<sops_lastmodified>
and reading the value back out of Go's own parse error, which quotes the string
it got:

    file bytes    sops parsed
    A\nB          A<LF>B
    A\\nB         A\<LF>B        (a backslash, then a newline)
    A\tB          A\tB           (untouched)
    A\rB          A\rB           (untouched)

Perl's C<s/\\n/\n/g> is exactly that transform, left to right, without
rescanning what it substituted.

=cut

sub flatten {
    my ($self, $hash) = @_;

    croak "flatten needs the HashRef that File::SOPS::Metadata->to_hash "
        . "returns, got " . (ref($hash) ? ref($hash) . " reference"
                                        : defined $hash ? "a scalar" : "undef")
        unless ref $hash eq 'HASH';

    my @pairs;
    $self->_flatten_node($hash, undef, \@pairs);
    return @pairs;
}

# $path is undef exactly at the root, which is how a top-level field name comes
# out bare (`age`) while everything below it carries a separator
# (`age__list_0__map_enc`). A length check would do the same job for every real
# metadata section and the wrong one for a field named with the empty string.
sub _flatten_node {
    my ($self, $node, $path, $pairs) = @_;

    my $ref = blessed($node) ? '' : ref $node;

    if ($ref eq 'HASH') {
        for my $key (sort keys %$node) {
            $self->_flatten_node(
                $node->{$key},
                defined $path ? $path . $MAP_SEPARATOR . $key : $key,
                $pairs,
            );
        }
        return;
    }

    if ($ref eq 'ARRAY') {
        # An empty list emits nothing, because the loop does not run. That is
        # the behaviour sops has and the one the format needs -- see
        # "Empty lists vanish, and must" above.
        for my $i (0 .. $#$node) {
            $self->_flatten_node(
                $node->[$i],
                (defined $path ? $path : '') . $LIST_SEPARATOR . $i,
                $pairs,
            );
        }
        return;
    }

    croak "flatten reached a leaf with no key path at all; the top level of a "
        . "metadata section is a mapping and its leaves are named"
        unless defined $path;

    push @$pairs, [ $self->prefix . $path, $self->escape_value($node) ];
    return;
}

=method flatten

    my @pairs = $flat->flatten($meta->to_hash);

Turns the nested C<sops> mapping into the flat key/value pairs the ENV and INI
formats store, as a list of two-element ArrayRefs, in the order sops writes
them: maps in sorted key order, lists in ascending index order.

Keys already carry L</prefix>; values are already escaped. An empty list or map
contributes B<nothing>, which is what the format requires -- see
L</Empty lists vanish, and must>.

Croaks on a leaf it has no encoding for: a blessed object that is not a
C<JSON::PP::Boolean>, or any reference that is neither HASH nor ARRAY. The flat
format cannot express those and writing something approximate would produce a
document sops refuses at a distance from the cause.

=cut

sub unflatten {
    my ($self, $flat) = @_;

    croak "unflatten needs a HashRef of flat key => value, got "
        . (ref($flat) ? ref($flat) . " reference"
                      : defined $flat ? "a scalar" : "undef")
        unless ref $flat eq 'HASH';

    my $root = {};

    for my $key (sort keys %$flat) {
        next unless $self->is_metadata_key($key);

        my $slot = \$root;
        for my $step ($self->_split_path($key)) {
            my ($kind, $name) = @$step;
            my $container = $$slot;

            if ($kind eq 'map') {
                croak "flat metadata key '$key' needs a mapping at '$name', "
                    . "where another key has already put "
                    . (ref $container ? 'a ' . lc(ref $container) : 'a value')
                    if defined $container && ref $container ne 'HASH';
                $$slot = $container = {} unless defined $container;
                $slot = \$container->{$name};
            }
            else {
                croak "flat metadata key '$key' needs a list at index $name, "
                    . "where another key has already put "
                    . (ref $container ? 'a ' . lc(ref $container) : 'a value')
                    if defined $container && ref $container ne 'ARRAY';
                $$slot = $container = [] unless defined $container;
                $slot = \$container->[$name];
            }
        }

        croak "flat metadata key '$key' is set twice" if defined $$slot;
        $$slot = $self->unescape_value($flat->{$key});
    }

    _assert_complete_lists($root, '');

    return $root;
}

sub _split_path {
    my ($self, $key) = @_;

    my $bare = substr($key, length $self->prefix);

    croak "flat metadata key '$key' has nothing after the prefix '"
        . $self->prefix . "'"
        unless length $bare;

    # A capturing split hands back the separators interleaved with the names,
    # so the result is always name, sep, name, sep, name...
    my @parts = split /(\Q$MAP_SEPARATOR\E|\Q$LIST_SEPARATOR\E)/, $bare, -1;

    my @path = ([ 'map', shift @parts ]);

    while (@parts) {
        my $separator = shift @parts;
        my $name      = shift @parts;
        $name = '' unless defined $name;

        if ($separator eq $LIST_SEPARATOR) {
            croak "flat metadata key '$key' has '$LIST_SEPARATOR$name' where a "
                . "list index has to be a non-negative integer"
                unless $name =~ /\A[0-9]+\z/;
            push @path, [ 'list', 0 + $name ];
        }
        else {
            push @path, [ 'map', $name ];
        }
    }

    return @path;
}

# sops refuses a list whose indices do not run from 0 without gaps -- renumber
# age__list_1__ to age__list_2__ in a file it wrote and it stops with
# "Error while unflattening: Incomplete list", exit 1. Autovivifying index 2
# leaves index 1 undef, so a hole is exactly what an undef element is here:
# nothing else in this class ever stores one.
sub _assert_complete_lists {
    my ($node, $path) = @_;

    if (ref $node eq 'HASH') {
        _assert_complete_lists($node->{$_}, length $path ? "$path.$_" : $_)
            for sort keys %$node;
        return;
    }

    if (ref $node eq 'ARRAY') {
        for my $i (0 .. $#$node) {
            croak "incomplete list at '$path': index $i is missing, and the "
                . "flat metadata encoding has no way to write a list with a "
                . "hole in it. sops refuses the same document with "
                . "'Error while unflattening: Incomplete list'"
                unless defined $node->[$i];
            _assert_complete_lists($node->[$i], "$path\[$i]");
        }
        return;
    }

    return;
}

=method unflatten

    my $section = $flat->unflatten(\%lines);
    my $meta    = File::SOPS::Metadata->from_hash($section);

Rebuilds the nested C<sops> mapping from flat key/value pairs. Keys that do not
carry L</prefix> are skipped, so an ENV caller may pass the whole document's
key/value set; an INI caller passes the C<[sops]> section.

Croaks rather than guessing, on every input sops also refuses: a list with a
gap in its indices, a C<__list_> whose index is not a non-negative integer, a
key that needs a mapping where another key already put a list (or the other way
round), and a key set twice.

=head3 Every leaf comes back a string, and one of them is a trap

The flat formats are untyped -- there is no parser here to say that C<2> was a
number and C<true> a boolean, the way YAML::XS and Cpanel::JSON::XS do for the
nested format. This method is faithful to that and hands back exactly what the
file holds, unescaped and otherwise untouched.

B<That makes C<mac_only_encrypted> a live hazard for the caller, and the caller
is the one that has to close it.> Measured against sops 3.13.3:
C<sops_mac_only_encrypted=false> added to a document whose MAC covers every
value decrypts fine (exit 0), and C<sops_mac_only_encrypted=true> on the same
document fails with C<MAC mismatch>, exit 51 -- the option selects the digest.
Perl's C<'false'> is B<true>, so handing this method's output straight to
L<File::SOPS::Metadata/from_hash> turns a document sops reads into one this
library computes the wrong digest for.

Typing the flat formats' values is karr #77's decision and it is not this
class's to make -- see docs/adr/0022 and the ticket. Until it lands, a format
handler wiring this up has to map C<true>/C<false> to
L<JSON::MaybeXS>'s booleans itself, and say so.

=head1 SEE ALSO

=over 4

=item * L<File::SOPS::Metadata> - the section this encodes, and its nested form

=item * docs/adr/0022 - why the escape is reproduced lossy rather than fixed

=back

=cut

1;
