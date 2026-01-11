package File::SOPS::Metadata;
# ABSTRACT: SOPS metadata section handling

use Moo;
use Carp qw(croak);
use POSIX qw(strftime);
use namespace::clean;

our $SOPS_VERSION = '3.7.3';

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

has unencrypted_suffix => (is => 'rw', default => '_unencrypted');

=attr unencrypted_suffix

Keys ending with this suffix are not encrypted (but are included in MAC).

Defaults to C<_unencrypted>.

Example: C<api_key_unencrypted> would not be encrypted.

=cut

has encrypted_suffix => (is => 'rw');

=attr encrypted_suffix

If set, only keys ending with this suffix are encrypted.

Defaults to C<undef> (all keys are encrypted unless they match unencrypted rules).

=cut

has unencrypted_regex => (is => 'rw');

=attr unencrypted_regex

Regular expression for keys that should not be encrypted.

Defaults to C<undef>.

=cut

has encrypted_regex => (is => 'rw');

=attr encrypted_regex

Regular expression for keys that should be encrypted.

Defaults to C<undef>.

=cut

sub from_hash {
    my ($class, $hash) = @_;
    return unless ref $hash eq 'HASH';

    return $class->new(
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
    );
}

=method from_hash

    my $meta = File::SOPS::Metadata->from_hash($hash);

Class method to create a Metadata object from a HashRef.

Typically used when parsing the C<sops> section from a YAML/JSON file.

Returns C<undef> if the input is not a HashRef.

=cut

sub to_hash {
    my ($self) = @_;

    my $hash = {
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

Determines if a hash key should be encrypted based on suffix/regex rules.

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

=head1 SEE ALSO

=over 4

=item * L<File::SOPS> - Main SOPS interface

=back

=cut

1;
