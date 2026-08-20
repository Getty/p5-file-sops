package File::SOPS::Metadata;
# ABSTRACT: SOPS metadata section handling
our $VERSION = '0.003';
use Moo;
use Carp qw(croak);
use POSIX qw(strftime);
use JSON::MaybeXS;
use namespace::clean;

our $SOPS_VERSION = '3.7.3';

# The encryption rules this class models, in the order should_encrypt_path
# applies them.
our @ENCRYPTION_RULES = qw(
    unencrypted_suffix encrypted_suffix unencrypted_regex encrypted_regex
);

# Rules the reference implementation has and this distribution does not: they
# select values by the COMMENT attached to them, and neither of our parsers
# keeps comments. They are listed because they take part in the mutual
# exclusion below -- a document carrying one of these must not also carry one
# of ours, whether we understand it or not.
our @UNSUPPORTED_ENCRYPTION_RULES = qw(
    unencrypted_comment_regex encrypted_comment_regex
);

our $DEFAULT_UNENCRYPTED_SUFFIX = '_unencrypted';

# Every field that holds the data key wrapped for one recipient or one
# backend. key_groups is in the list although this class does not model it:
# whatever else it is, it holds wrapped copies of the data key, and a caller
# generating a new one has to know it is there.
our @KEY_MATERIAL_FIELDS = qw(
    age pgp kms gcp_kms azure_kv hc_vault key_groups
);
my %IS_KEY_MATERIAL = map { $_ => 1 } @KEY_MATERIAL_FIELDS;

# Everything this class holds in an attribute of its own. Anything else in a
# document's sops section goes to, and comes back out of, `extra`.
my %MODELLED_FIELD = map { $_ => 1 } qw(
    age pgp kms gcp_kms azure_kv hc_vault
    mac lastmodified version mac_only_encrypted
), @ENCRYPTION_RULES;

=head1 SYNOPSIS

    use File::SOPS::Metadata;

    # Create new metadata
    my $meta = File::SOPS::Metadata->new(
        unencrypted_suffix => '_unencrypted',
    );

    # Add age recipient
    $meta->add_age_recipient(
        recipient => 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p',
        enc       => '-----BEGIN AGE ENCRYPTED FILE-----...',
    );

    # Update timestamp
    $meta->update_lastmodified;

    # Set MAC
    $meta->mac($mac_string);

    # Convert to hash for serialization
    my $hash = $meta->to_hash;

    # Parse from existing hash
    my $meta = File::SOPS::Metadata->from_hash($sops_section);

=head1 DESCRIPTION

File::SOPS::Metadata manages the C<sops> metadata section of encrypted files.
This section contains:

=over 4

=item * Encrypted data keys for each recipient/backend

=item * MAC for tamper detection

=item * Timestamp of last modification

=item * Rules for which keys should be encrypted

=item * SOPS version information

=back

=cut

has age => (is => 'rw', default => sub { [] });

=attr age

ArrayRef of age-encrypted data keys. Each entry is a HashRef with:

    {
        recipient => 'age1...',
        enc       => '-----BEGIN AGE ENCRYPTED FILE-----...'
    }

Defaults to C<[]>.

=cut

has pgp => (is => 'rw', default => sub { [] });

=attr pgp

ArrayRef of PGP-encrypted data keys. Not yet implemented. Defaults to C<[]>.

=cut

has kms => (is => 'rw', default => sub { [] });

=attr kms

ArrayRef of AWS KMS-encrypted data keys. Not yet implemented. Defaults to C<[]>.

=cut

has gcp_kms => (is => 'rw', default => sub { [] });

=attr gcp_kms

ArrayRef of Google Cloud KMS-encrypted data keys. Not yet implemented. Defaults to C<[]>.

=cut

has azure_kv => (is => 'rw', default => sub { [] });

=attr azure_kv

ArrayRef of Azure Key Vault-encrypted data keys. Not yet implemented. Defaults to C<[]>.

=cut

has hc_vault => (is => 'rw', default => sub { [] });

=attr hc_vault

ArrayRef of HashiCorp Vault-encrypted data keys. Not yet implemented. Defaults to C<[]>.

=cut

has mac => (is => 'rw');

=attr mac

Message Authentication Code over the entire encrypted data structure.

Stored as an encrypted value string: C<ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]>

=cut

has lastmodified => (is => 'rw');

=attr lastmodified

ISO 8601 timestamp of last modification. Example: C<2025-01-10T12:00:00Z>

=cut

has version => (is => 'rw', default => sub { $SOPS_VERSION });

=attr version

SOPS version string. Defaults to C<3.7.3> for compatibility with the Go implementation.

=cut

has unencrypted_suffix => (
    is      => 'rw',
    lazy    => 1,
    builder => '_build_unencrypted_suffix',
);

# The default applies only when NO other rule was asked for. sops does the
# same (`sops -e` writes `unencrypted_suffix: _unencrypted`, but
# `sops -e --encrypted-suffix _enc` writes only `encrypted_suffix: _enc`), and
# it is not cosmetic: the six rule fields are mutually exclusive and sops
# refuses a document carrying two of them outright, so a default that ignored
# the others would make every configured document unreadable.
sub _build_unencrypted_suffix {
    my ($self) = @_;
    return undef if $self->_other_rules_configured('unencrypted_suffix');
    return $DEFAULT_UNENCRYPTED_SUFFIX;
}

=attr unencrypted_suffix

Keys ending with this suffix are not encrypted (but are included in MAC).

Example: C<api_key_unencrypted> would not be encrypted.

Defaults to C<_unencrypted>, but B<only when no other encryption rule is
set> -- see L</Encryption rules are mutually exclusive>. Constructed with any
of L</encrypted_suffix>, L</unencrypted_regex> or L</encrypted_regex>, it
defaults to C<undef> instead.

Passing C<< unencrypted_suffix => undef >> explicitly means B<no rule at
all>, which is a different thing from leaving it out: with no rule every leaf
is encrypted, including one whose key ends in C<_unencrypted>. That is what
L</from_hash> does for a document that carries no rule field, and it is what
the reference implementation does with such a document.

=cut

has encrypted_suffix => (is => 'rw');

=attr encrypted_suffix

If set, a value is encrypted only when some component of its path ends with
this suffix -- see L</should_encrypt_path>.

Defaults to C<undef>. Mutually exclusive with the other rules, see
L</Encryption rules are mutually exclusive>.

=cut

has unencrypted_regex => (is => 'rw');

=attr unencrypted_regex

Regular expression: a value is not encrypted when some component of its path
matches it -- see L</should_encrypt_path>.

Defaults to C<undef>. Mutually exclusive with the other rules, see
L</Encryption rules are mutually exclusive>.

=cut

has encrypted_regex => (is => 'rw');

=attr encrypted_regex

Regular expression: a value is encrypted only when some component of its path
matches it -- see L</should_encrypt_path>.

Defaults to C<undef>. Mutually exclusive with the other rules, see
L</Encryption rules are mutually exclusive>.

=head2 Encryption rules are mutually exclusive

L</unencrypted_suffix>, L</encrypted_suffix>, L</unencrypted_regex> and
L</encrypted_regex> -- together with C<unencrypted_comment_regex> and
C<encrypted_comment_regex>, which this distribution does not implement but
does recognise -- select which values get encrypted, and B<at most one of them
may be set>. Constructing a Metadata with two of them dies:

    Cannot use more than one of unencrypted_suffix, encrypted_suffix, ...
    in the same document (got unencrypted_suffix and encrypted_regex);
    sops refuses such a file outright

That is not a house rule; it is the reference implementation's, which reports
the same conflict and refuses the document before decrypting anything.
Constructing the object is the earliest point at which the conflict can be
seen, so it is where it is reported.

The consequence worth knowing is the one on L</unencrypted_suffix>: its
C<_unencrypted> default has to stand down as soon as any other rule is set,
or every configured document would carry two rules and be unreadable.

=cut

has mac_only_encrypted => (is => 'rw');

=attr mac_only_encrypted

When true, the MAC covers only the values that are actually encrypted; when
false (the default) it covers every value in the document, encrypted or not.

Both MAC implementations honour this, and a MAC computed with it on additionally
starts from a fixed 32-byte initialization block (C<MACOnlyEncryptedInitialization>
in the Go source), so the two settings can never produce the same digest for the
same document.

C<undef> or false is emitted as no key at all in the C<sops> section, which is
what the Go implementation writes.

B<What it costs, in YAML:> a leaf the MAC no longer covers is one no reader
verifies, and this distribution and sops do not resolve every YAML spelling the
same way. C<mode_unencrypted: 0755> is the realistic case -- sops reads the
integer B<493>, this module reads 755, and with C<mac_only_encrypted> set
neither the MAC nor C<sops -d> reports anything (measured, sops 3.13.3, exit 0).
The same holds for C<0o10>, C<0x1f>, C<1_000>, C<.inf>, C<Null>, C<TRUE> and a
date that is not exactly RFC3339. Without this option such a leaf is B<refused>
at encrypt time, because the document would fail its own MAC; with it set the
document is written and the divergence is B<warned> about instead, naming the
leaf's key path. See L<File::SOPS::Format::YAML/serialize> for the full rule and
docs/adr/0018 for the measurement.

=cut

has extra => (is => 'rw', default => sub { {} });

=attr extra

HashRef of the fields in a document's C<sops> section that this class does not
model, kept verbatim so that a rewrite does not drop them. Defaults to C<{}>.

The reference implementation knows more metadata fields than this
distribution does -- C<shamir_threshold>, C<key_groups>, and the two
comment-based encryption rules among them -- and it B<preserves the ones it
knows> across a rewrite. Measured against sops 3.13.3: C<sops rotate> on a
document carrying C<shamir_threshold: 2> writes it back out, and drops a field
it does not recognise. Modelling each of those fields here would mean
modelling C<key_groups>, whose semantics this distribution cannot implement,
so instead everything unrecognised is preserved. That is a superset of what Go
keeps, and a safe one: Go ignores a field it does not know, so preserving one
can never make a document unreadable, whereas dropping C<shamir_threshold>
demonstrably changes what sops does with it.

Fields this class does model are never stored here -- L</to_hash> lets the
attributes win -- so C<extra> cannot be used to shadow C<mac> or C<age>.

=cut

sub BUILD {
    my ($self) = @_;

    # unencrypted_suffix's builder stands its default down as soon as another
    # rule is configured, so asking the object -- rather than counting the
    # constructor arguments -- cannot report the default as a conflict.
    my @set = grep {
        my $value = $self->rule_value($_);
        defined $value && length $value;
    } @ENCRYPTION_RULES, @UNSUPPORTED_ENCRYPTION_RULES;

    croak "Cannot use more than one of "
        . join(', ', @ENCRYPTION_RULES, @UNSUPPORTED_ENCRYPTION_RULES)
        . " in the same document (got " . join(' and ', @set) . "); "
        . "sops refuses such a file outright"
        if @set > 1;

    return;
}

# The name of a configured rule field other than $except, or undef if there is
# none. $except keeps unencrypted_suffix's lazy builder from asking for the
# value it is in the middle of producing.
sub _other_rules_configured {
    my ($self, $except) = @_;

    for my $rule (@ENCRYPTION_RULES, @UNSUPPORTED_ENCRYPTION_RULES) {
        next if $rule eq $except;
        my $value = $self->rule_value($rule);
        return $rule if defined $value && length $value;
    }

    return;
}

sub rule_value {
    my ($self, $rule) = @_;
    return $self->$rule if $self->can($rule);
    return $self->extra->{$rule};
}

=method rule_value

    my $suffix = $meta->rule_value('unencrypted_suffix');
    my $regex  = $meta->rule_value('encrypted_comment_regex');

Returns the value of an encryption rule by name, or C<undef> if the document
does not carry it.

The point of going through a name rather than an accessor is the rules this
class does not model: C<unencrypted_comment_regex> and
C<encrypted_comment_regex> have no attribute, but a caller deciding whether it
can honour a document's rule has to be able to ask about them. The names worth
asking about are in C<@File::SOPS::Metadata::ENCRYPTION_RULES> and
C<@File::SOPS::Metadata::UNSUPPORTED_ENCRYPTION_RULES>.

=cut

sub policy_args {
    my ($self) = @_;

    # All four are handed over even when undef, because "no rule at all" is a
    # setting and not an absence: passing them through as explicit undef is
    # what stops the constructor's default from inventing an
    # unencrypted_suffix the source document did not have -- which would leave
    # every key ending in _unencrypted in plaintext on the next write.
    my %args = map { $_ => $self->$_ } @ENCRYPTION_RULES;
    $args{mac_only_encrypted} = 1 if $self->mac_only_encrypted;

    # Unmodelled fields come along, minus any that turn out to hold key
    # material: key_groups wraps the data key that is about to be replaced,
    # so carrying it over would leave the new document advertising a stale
    # copy of the old key.
    $args{extra} = {
        map  { $_ => $self->extra->{$_} }
        grep { !$IS_KEY_MATERIAL{$_} } keys %{ $self->extra }
    };

    return %args;
}

=method policy_args

    my $fresh = File::SOPS::Metadata->new($meta->policy_args);

Returns the constructor arguments that describe B<how> a document is
encrypted, so they can be carried onto a new metadata object: the four
encryption rules and L</mac_only_encrypted>.

Deliberately B<not> included is everything that describes B<what> encrypted
this particular document, because none of it survives a re-encryption: the
per-backend key material (L</age>, L</pgp>, L</kms> and friends) wraps a data
key that is about to be replaced, L</mac> authenticates values that are about
to be rewritten, L</lastmodified> is the AAD of that MAC, and L</version>
names the implementation doing the writing rather than the one that wrote the
file before.

This is what L<File::SOPS/rotate> passes to L<File::SOPS/encrypt> so that a
rotated file keeps the rules it was written under.

=cut

sub key_material_fields {
    my ($self) = @_;

    return grep {
        my $value = $self->can($_) ? $self->$_ : $self->extra->{$_};
        ref $value eq 'ARRAY' ? scalar @$value : defined $value;
    } @KEY_MATERIAL_FIELDS;
}

=method key_material_fields

    my @found = $meta->key_material_fields;
    # => ('age', 'pgp')

Returns the names of the fields in which this document actually carries a
wrapped copy of the data key -- L</age>, L</pgp>, L</kms>, L</gcp_kms>,
L</azure_kv>, L</hc_vault> and C<key_groups>, skipping the ones that are empty
or absent. C<key_groups> is included although this class does not model it,
because a caller about to replace the data key has to know it is there.

This is what L<File::SOPS/rotate> asks before it generates a new data key: age
is the only backend implemented here, so a document holding key material for
any other one cannot be rotated without either revoking those recipients or
leaving them a wrapped copy of a key that no longer encrypts anything.

=cut

# What the `sops` entry turned out to be, for the refusal below. Names the
# shape only -- never the value, which in a document using that key for its own
# purposes is the user's data.
sub _shape_of {
    my ($value) = @_;
    return 'null'                unless defined $value;
    my $ref = ref $value;
    return 'a scalar'            unless $ref;
    return 'a list'              if $ref eq 'ARRAY';
    return 'a code reference'    if $ref eq 'CODE';
    return "a $ref reference";
}

sub from_hash {
    my ($class, $hash) = @_;

    # Returning undef here is how a document lost a key. Both format handlers
    # call this as from_hash(delete $data->{sops}) once they have seen the key
    # EXIST, so undef meant "there was a top-level sops entry, it was not a
    # mapping, and it has already been removed from the tree" -- and every
    # caller reads undef as "this document has no metadata". File::SOPS::encrypt
    # then wrote a document without the entry, over the original if the caller
    # had asked for that. `sops: mine` in a plaintext file was silently deleted.
    #
    # sops refuses such a document from both directions, and does not care what
    # the entry holds: `sops -e` stops with exit code 203 on the same
    # reserved-key message it gives an already-encrypted file, whether the entry
    # is a scalar, a list, null or an empty mapping; `sops -d` and `sops rotate`
    # stop with "Found sops entry that is not a mapping". Measured on 3.13.3.
    #
    # The check cannot live at the call sites' `delete`, which collapses "no
    # entry" and "entry holding null" into the same undef, and sops refuses the
    # second. So an undef arriving here is a caller that has already established
    # the key exists -- there is no reason to ask this method about a section
    # that is not there, and no caller in this distribution does.
    croak "the top-level 'sops' entry is " . _shape_of($hash) . ", not a "
        . "mapping. That name is reserved for the SOPS metadata section, so a "
        . "document using it for anything else can neither be read (there is "
        . "no metadata to read) nor encrypted (the entry is where the metadata "
        . "goes). If this is plaintext that happens to use the name, rename the "
        . "entry. sops refuses the same document: 'Found sops entry that is not "
        . "a mapping' when reading, exit code 203 when encrypting."
        unless ref $hash eq 'HASH';

    my %extra = map  { $_ => $hash->{$_} }
                grep { !$MODELLED_FIELD{$_} } keys %$hash;

    return $class->new(
        extra              => \%extra,
        age                => $hash->{age}                // [],
        pgp                => $hash->{pgp}                // [],
        kms                => $hash->{kms}                // [],
        gcp_kms            => $hash->{gcp_kms}            // [],
        azure_kv           => $hash->{azure_kv}           // [],
        hc_vault           => $hash->{hc_vault}           // [],
        mac                => $hash->{mac},
        lastmodified       => $hash->{lastmodified},
        version            => $hash->{version}            // $SOPS_VERSION,
        unencrypted_suffix => $hash->{unencrypted_suffix},
        encrypted_suffix   => $hash->{encrypted_suffix},
        unencrypted_regex  => $hash->{unencrypted_regex},
        encrypted_regex    => $hash->{encrypted_regex},
        mac_only_encrypted => $hash->{mac_only_encrypted},
    );
}

=method from_hash

    my $meta = File::SOPS::Metadata->from_hash($hash);

Class method to create a Metadata object from a HashRef.

Typically used when parsing the C<sops> section from a YAML/JSON file.

An B<absent encryption rule stays absent>. Every rule field is passed to the
constructor whether the document had it or not, so a document with no rule
field produces a Metadata with no rule -- not one with the C<_unencrypted>
default a freshly constructed object gets. The asymmetry is deliberate and it
is the reference implementation's: a default belongs to B<creating> a
document, not to B<reading> one. Measured against sops 3.13.3 -- take a file
it wrote, delete C<unencrypted_suffix> from the C<sops> section, and it stops
treating a C<_unencrypted> key as plaintext, failing with C<Input string ...
does not match sops' data format>. Applying the default here would make this
library leave a value in plaintext that the document's own producer encrypts.

B<Dies if the input is not a HashRef>, naming the shape it got instead. Until
0.003 it returned C<undef>, and that return was a data-loss path rather than a
convenience: both format handlers call this as
C<< from_hash(delete $data->{sops}) >> after seeing the key B<exist>, so C<undef>
came back meaning "there was a top-level C<sops> entry, it was not a mapping,
and it is now gone from the tree" while every caller reads C<undef> as "this
document has no metadata". A plaintext file containing C<sops: mine> therefore
lost that key on the way through L<File::SOPS/encrypt_file> -- over the original
file if C<output> was omitted -- and L<File::SOPS/decrypt> reported the generic
C<No SOPS metadata found> for a document whose C<sops> section it had in fact
just discarded.

sops refuses such a document from both directions and does not care what the
entry holds -- a scalar, a list, C<null> or an empty mapping are all the same to
it. Measured against sops 3.13.3: C<sops encrypt> stops with exit code 203 and
the same reserved-key message it gives an already-encrypted file, C<sops decrypt>
and C<sops rotate> stop with C<Found sops entry that is not a mapping>.

C<undef> dies too, rather than being read as "no section". The distinction
between an absent C<sops> key and one holding C<null> does not survive the
C<delete> at the call site, and sops refuses both, so the only caller that can
tell them apart is the one that still has the document -- it asks C<exists>
first and does not call this method at all when the answer is no.

Dies if the document carries more than one encryption rule, see
L</Encryption rules are mutually exclusive>.

=cut

sub to_hash {
    my ($self) = @_;

    # Unmodelled fields go down first so that a modelled one always wins: the
    # attributes are the truth about this document, extra is only what nobody
    # here has an opinion about.
    my $hash = {
        %{ $self->extra },
        kms      => $self->kms,
        gcp_kms  => $self->gcp_kms,
        azure_kv => $self->azure_kv,
        hc_vault => $self->hc_vault,
        age      => $self->age,
        pgp      => $self->pgp,
    };

    $hash->{lastmodified} = $self->lastmodified if defined $self->lastmodified;
    $hash->{mac}          = $self->mac          if defined $self->mac;
    $hash->{version}      = $self->version      if defined $self->version;

    $hash->{unencrypted_suffix} = $self->unencrypted_suffix
        if defined $self->unencrypted_suffix;
    $hash->{encrypted_suffix} = $self->encrypted_suffix
        if defined $self->encrypted_suffix;
    $hash->{unencrypted_regex} = $self->unencrypted_regex
        if defined $self->unencrypted_regex;
    $hash->{encrypted_regex} = $self->encrypted_regex
        if defined $self->encrypted_regex;
    # sops omits the key entirely when the option is off, so a false must not
    # be written back as `mac_only_encrypted: false`.
    $hash->{mac_only_encrypted} = JSON->true if $self->mac_only_encrypted;

    return $hash;
}

=method to_hash

    my $hash = $meta->to_hash;

Converts the Metadata object to a HashRef for serialization.

This HashRef is written to the C<sops> section of the encrypted file.

=cut

sub update_lastmodified {
    my ($self) = @_;
    $self->lastmodified(strftime('%Y-%m-%dT%H:%M:%SZ', gmtime));
    return $self;
}

=method update_lastmodified

    $meta->update_lastmodified;

Sets C<lastmodified> to the current time in ISO 8601 format (UTC).

Returns C<$self> for chaining.

=cut

sub add_age_recipient {
    my ($self, %args) = @_;
    my $recipient = $args{recipient} // croak "recipient required";
    my $enc       = $args{enc}       // croak "enc required";

    push @{$self->age}, {
        recipient => $recipient,
        enc       => $enc,
    };

    return $self;
}

=method add_age_recipient

    $meta->add_age_recipient(
        recipient => 'age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p',
        enc       => '-----BEGIN AGE ENCRYPTED FILE-----...',
    );

Adds an age recipient with their encrypted data key.

The C<enc> parameter should be the PEM-armored age-encrypted data key.

Returns C<$self> for chaining.

=cut

sub get_age_encrypted_keys {
    my ($self) = @_;
    return @{$self->age};
}

=method get_age_encrypted_keys

    my @keys = $meta->get_age_encrypted_keys;

Returns a list of age-encrypted data key entries (HashRefs).

Each entry has C<recipient> and C<enc> fields.

=cut

sub should_encrypt_key {
    my ($self, $key) = @_;

    if (defined $self->unencrypted_suffix) {
        return 0 if $key =~ /\Q$self->{unencrypted_suffix}\E$/;
    }

    if (defined $self->encrypted_suffix) {
        return 1 if $key =~ /\Q$self->{encrypted_suffix}\E$/;
        return 0;
    }

    if (defined $self->unencrypted_regex) {
        return 0 if $key =~ /$self->{unencrypted_regex}/;
    }

    if (defined $self->encrypted_regex) {
        return 1 if $key =~ /$self->{encrypted_regex}/;
        return 0;
    }

    return 1;
}

=method should_encrypt_key

    if ($meta->should_encrypt_key('api_key')) {
        # Encrypt this key
    }

Determines if a single hash key, considered on its own, should be encrypted
based on suffix/regex rules.

B<This is not the rule a document is encrypted under> -- that is
L</should_encrypt_path>, which applies the same tests to every component of a
value's key path, and it is what L<File::SOPS> walks the tree with. The two
agree whenever a rule can only exclude (C<unencrypted_suffix>,
C<unencrypted_regex>), because an excluded branch stays excluded all the way
down. They disagree on C<encrypted_suffix> and C<encrypted_regex>: a leaf
whose own key does not match is still encrypted when a key above it does.

This method remains for callers asking about one key in isolation.

Rules are applied in this order:

=over 4

=item 1. If C<unencrypted_suffix> is set and key ends with it, return false

=item 2. If C<encrypted_suffix> is set, return true if key ends with it, else false

=item 3. If C<unencrypted_regex> is set and key matches, return false

=item 4. If C<encrypted_regex> is set and key matches, return true, else false

=item 5. Default: return true (encrypt everything)

=back

Returns true if the key should be encrypted, false otherwise.

=cut

sub should_encrypt_path {
    my ($self, $path) = @_;
    $path //= [];

    my $encrypted = 1;

    if (defined $self->unencrypted_suffix && length $self->unencrypted_suffix) {
        $encrypted = 0 if grep { /\Q$self->{unencrypted_suffix}\E$/ } @$path;
    }

    if (defined $self->encrypted_suffix && length $self->encrypted_suffix) {
        $encrypted = (grep { /\Q$self->{encrypted_suffix}\E$/ } @$path) ? 1 : 0;
    }

    if (defined $self->unencrypted_regex && length $self->unencrypted_regex) {
        $encrypted = 0 if grep { /$self->{unencrypted_regex}/ } @$path;
    }

    if (defined $self->encrypted_regex && length $self->encrypted_regex) {
        $encrypted = (grep { /$self->{encrypted_regex}/ } @$path) ? 1 : 0;
    }

    return $encrypted;
}

=method should_encrypt_path

    if ($meta->should_encrypt_path(['database', 'password'])) {
        # This leaf is one of the encrypted ones
    }

Whole-path counterpart of L</should_encrypt_key>, mirroring C<shouldBeEncrypted>
in the Go implementation: each rule is evaluated against B<every> component of
the path, in the same order, with later rules overriding earlier ones.

A leaf is unencrypted if any component carries C<unencrypted_suffix> or matches
C<unencrypted_regex>, and (when those are configured) encrypted only if some
component carries C<encrypted_suffix> or matches C<encrypted_regex>.

This is the predicate L<File::SOPS> encrypts a document with, and the one it
uses to decide which values the MAC covers when L</mac_only_encrypted> is set.
Measured against sops 3.13.3 with C<--encrypted-suffix _enc>: every value
under a C<top_enc:> block is encrypted, a C<nested_enc:> under an ordinary
parent is encrypted, and the elements of a C<list_enc:> array are encrypted
because an array contributes no path component of its own and its elements
carry the parent's path.

Returns true if the value at that path should be encrypted.

=cut

=head1 SEE ALSO

=over 4

=item * L<File::SOPS> - Main SOPS interface

=back

=cut

1;
