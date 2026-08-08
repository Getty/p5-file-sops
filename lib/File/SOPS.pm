package File::SOPS;
# ABSTRACT: Perl implementation of Mozilla SOPS encrypted file format

use Moo;
use Carp qw(croak);
use Scalar::Util qw(blessed);
use Digest::SHA qw(sha512);
use JSON::MaybeXS;
use YAML::XS ();
use YAML::PP;
use YAML::PP::Common qw(PRESERVE_ORDER);
use File::SOPS::Encrypted;
use File::SOPS::Metadata;
use File::SOPS::Backend::Age;
use File::SOPS::Format::YAML;
use File::SOPS::Format::JSON;
use namespace::clean;

our $VERSION = '0.003';

=head1 SYNOPSIS

    use File::SOPS;

    # Encrypt a data structure
    my $encrypted = File::SOPS->encrypt(
        data       => {
            database => {
                password => 'secret123',
                host     => 'db.example.com',
            },
        },
        recipients => ['age1ql3z7hjy54pw3hyww5ayyfg7zqgvc7w3j2elw8zmrj2kg5sfn9aqmcac8p'],
        format     => 'yaml',
    );

    # Decrypt
    my $data = File::SOPS->decrypt(
        encrypted  => $encrypted,
        identities => ['AGE-SECRET-KEY-1...'],
    );

    # File operations
    File::SOPS->encrypt_file(
        input      => 'secrets.yaml',
        output     => 'secrets.enc.yaml',
        recipients => ['age1...'],
    );

    File::SOPS->decrypt_file(
        input      => 'secrets.enc.yaml',
        output     => 'secrets.yaml',
        identities => ['AGE-SECRET-KEY-1...'],
    );

    # Extract single value
    my $password = File::SOPS->extract(
        file       => 'secrets.enc.yaml',
        path       => '["database"]["password"]',
        identities => ['AGE-SECRET-KEY-1...'],
    );

    # Rotate data key
    File::SOPS->rotate(
        file       => 'secrets.enc.yaml',
        identities => ['AGE-SECRET-KEY-1...'],
    );

=head1 DESCRIPTION

File::SOPS is a pure Perl implementation of Mozilla SOPS (Secrets OPerationS),
compatible with the reference Go implementation at L<https://github.com/getsops/sops>.

SOPS encrypts B<values> in structured files (YAML, JSON) while keeping B<keys>
readable. This enables:

=over 4

=item * Git-friendly diffs - see which keys changed without decrypting

=item * Partial file inspection without full decryption

=item * Multiple encryption backends (currently age, with PGP/KMS planned)

=item * MAC verification to detect tampering

=back

=head2 How SOPS Works

=over 4

=item 1. Generate a random 256-bit data key

=item 2. Encrypt the data key for each recipient using age (X25519 + ChaCha20-Poly1305)

=item 3. Store encrypted data keys in the C<sops> metadata section

=item 4. Encrypt each value with AES-256-GCM using the data key

=item 5. Compute MAC over the entire structure for tamper detection

=back

=head2 Encrypted Value Format

Each encrypted value is stored as:

    ENC[AES256_GCM,data:base64==,iv:base64==,tag:base64==,type:str]

=head2 File Structure Example

    database:
        password: ENC[AES256_GCM,data:xyz,iv:abc,tag:def,type:str]
        host: ENC[AES256_GCM,data:xyz,iv:abc,tag:def,type:str]
    sops:
        age:
            - recipient: age1ql3z7hjy...
              enc: |
                -----BEGIN AGE ENCRYPTED FILE-----
                <encrypted data key>
                -----END AGE ENCRYPTED FILE-----
        lastmodified: "2025-01-10T12:00:00Z"
        mac: ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]
        version: 3.7.3

=head2 Special Features

=over 4

=item * B<unencrypted_suffix> - Keys ending with C<_unencrypted> are not encrypted but included in MAC

=item * B<Key rotation> - Re-encrypt all values with a new data key via L</rotate>

=item * B<Multiple recipients> - Encrypt once, multiple recipients can decrypt

=back

=head2 Character encoding

B<The API boundary is characters. The wire is UTF-8 bytes. Encoding happens
exactly once, and this module owns it.>

Everything File::SOPS hands you and everything it takes from you is a Perl
B<character string>: the keys and values you pass to L</encrypt>, the tree
L</decrypt> returns, the value L</extract> returns, and the path you look it up
by. Encoding to UTF-8 happens at the edge where data becomes ciphertext, digest
input or file content -- never in your code:

=over 4

=item * Values, and the key path that forms each value's B<AAD>, are UTF-8
encoded on the way into AES-GCM, and the MAC digest is taken over those same
UTF-8 bytes. This is what the Go implementation authenticates against; a
document whose keys or values leave the ASCII range is not interoperable
otherwise.

=item * L</decrypt> reverses it, so a structure survives
C<encrypt>/C<decrypt> unchanged and C<is_deeply> against the original holds for
any input. Prior to 0.003 decrypted values came back as UTF-8 B<bytes>, which
compared unequal to the characters that went in and turned into mojibake when
L</decrypt_file> encoded them a second time.

=item * L</encrypt_file> and L</decrypt_file> read and write UTF-8 encoded
files. They decode on the way in and encode on the way out, so the characters
rule holds across the file API too.

=back

The one place bytes surface deliberately is C<type:bytes>, SOPS's binary type,
which is returned as raw bytes because it is not text. See
L<File::SOPS::Encrypted/decrypt_value>.

If you hand C<encrypt> UTF-8 B<bytes> rather than characters, the wire output
is still correct -- a scalar without Perl's UTF-8 flag is treated as bytes and
passed through untouched, which is what makes the rule safe to apply to
existing callers. What you get back from C<decrypt> is characters either way,
so do not decode it yourself.

=cut

my %FORMATS = (
    yaml => 'File::SOPS::Format::YAML',
    yml  => 'File::SOPS::Format::YAML',
    json => 'File::SOPS::Format::JSON',
);

sub encrypt {
    my ($class, %args) = @_;
    my $data       = $args{data}       // croak "data required";
    my $recipients = $args{recipients} // croak "recipients required";
    my $format     = $args{format}     // 'yaml';

    croak "data must be a hash ref" unless ref($data) eq 'HASH';
    croak "recipients must be an array ref" unless ref($recipients) eq 'ARRAY';

    # Generate random 256-bit data key
    my $data_key = _random_bytes(32);

    # Create metadata
    my $metadata = File::SOPS::Metadata->new(
        defined $args{mac_only_encrypted}
            ? (mac_only_encrypted => $args{mac_only_encrypted}) : ()
    );
    $metadata->update_lastmodified;

    # Encrypt data key for each recipient
    my $encrypted_keys = File::SOPS::Backend::Age->encrypt_data_key(
        data_key   => $data_key,
        recipients => $recipients,
    );
    $metadata->age($encrypted_keys);

    # Compute MAC over plaintext values BEFORE encryption (SOPS behavior)
    my $mac = _compute_mac($data, $data_key, $metadata);
    $metadata->mac($mac);

    # Encrypt all values in the data structure
    my $encrypted_data = _encrypt_tree($data, $data_key, $metadata, []);

    # Serialize
    my $format_class = $FORMATS{$format} // croak "Unknown format: $format";
    return $format_class->serialize(
        data     => $encrypted_data,
        metadata => $metadata,
    );
}

=method encrypt

    my $encrypted = File::SOPS->encrypt(
        data               => \%data,
        recipients         => \@age_public_keys,
        format             => 'yaml',  # or 'json', defaults to 'yaml'
        mac_only_encrypted => 0,       # optional
    );

Encrypts a data structure for specified recipients.

Takes a HashRef in C<data>, encrypts all values (not keys) using AES-256-GCM,
and encrypts the data key for each age recipient. Returns serialized encrypted
content as a string.

Keys and values are character strings and are UTF-8 encoded on their way to the
cipher and the digest; the returned document is UTF-8 encoded bytes, ready to
write to a C<:raw> handle. See L</Character encoding>.

The C<recipients> parameter must be an ArrayRef of age public keys (starting
with C<age1...>).

Supported formats: C<yaml>, C<yml>, C<json>.

C<mac_only_encrypted> is the equivalent of the reference implementation's
C<--mac-only-encrypted>: it restricts the MAC to the values that are actually
encrypted, and records that choice in the C<sops> section so a reader knows
which rule to verify under. See
L<File::SOPS::Metadata/mac_only_encrypted>. Off by default, which is what sops
defaults to as well.

=cut

sub decrypt {
    my ($class, %args) = @_;
    my $encrypted  = $args{encrypted}  // croak "encrypted required";
    my $identities = $args{identities} // croak "identities required";
    my $format     = $args{format};

    croak "identities must be an array ref" unless ref($identities) eq 'ARRAY';

    # Auto-detect format if not specified
    $format //= _detect_format($encrypted);

    my $format_class = $FORMATS{$format} // croak "Unknown format: $format";

    # Parse the encrypted content
    my ($data, $metadata) = $format_class->parse($encrypted);
    croak "No SOPS metadata found" unless $metadata;

    # Decrypt data key using age backend
    my $data_key = File::SOPS::Backend::Age->decrypt_data_key(
        age_keys   => $metadata->age,
        identities => $identities,
    );

    # Decrypt all values first
    my $decrypted_data = _decrypt_tree($data, $data_key, $metadata, []);

    _verify_mac(
        document => $encrypted,
        data     => $data,
        data_key => $data_key,
        metadata => $metadata,
    ) unless $args{ignore_mac};

    return $decrypted_data;
}

=method decrypt

    my $data = File::SOPS->decrypt(
        encrypted  => $encrypted_content,
        identities => \@age_secret_keys,
        format     => 'yaml',  # optional, auto-detected
        ignore_mac => 0,       # optional, see below
    );

Decrypts SOPS-encrypted content.

Takes encrypted content as a string, decrypts the data key using provided age
identities, verifies the MAC, and returns the decrypted data structure as a
HashRef.

The returned structure holds B<character strings>, so it compares equal to the
structure L</encrypt> was given. Do not decode it again. See
L</Character encoding>.

The C<identities> parameter must be an ArrayRef of age secret keys (starting
with C<AGE-SECRET-KEY-1...>).

If C<format> is not specified, it will be auto-detected from the content.

Dies if none of the provided identities can decrypt the data key, or if MAC
verification does not succeed. B<Verification failing to run counts as not
succeeding>: a document whose C<sops> section has no C<mac>, or a C<mac> that
is not a well-formed C<ENC[...]> value, or one that will not decrypt under the
data key and this document's C<lastmodified>, is refused rather than returned
unverified. This mirrors the Go implementation, which reports C<File has no
MAC> / C<Cannot decrypt MAC> and stops.

C<ignore_mac> is the equivalent of the reference implementation's
C<--ignore-mac>, and the only way to read such a document. It skips
verification entirely, so what it returns is decrypted but B<not
authenticated> -- the AAD binding on each individual value still holds, but
nothing detects a value that was deleted, duplicated, moved to another key, or
replaced with one taken from elsewhere in the same document. Use it to recover
data, not to consume it.

=cut

sub encrypt_file {
    my ($class, %args) = @_;
    my $input      = $args{input}      // croak "input required";
    my $output     = $args{output}     // $args{input};
    my $recipients = $args{recipients} // croak "recipients required";
    my $format     = $args{format};

    # Auto-detect format from filename
    $format //= _detect_format_from_filename($input);

    # Read input file
    open my $fh, '<:raw', $input
        or croak "Cannot open input file '$input': $!";
    my $content = do { local $/; <$fh> };
    close $fh;

    # Parse to get data structure
    my $format_class = $FORMATS{$format} // croak "Unknown format: $format";
    my ($data, undef) = $format_class->parse($content);

    # Encrypt
    my $encrypted = $class->encrypt(
        data               => $data,
        recipients         => $recipients,
        format             => $format,
        mac_only_encrypted => $args{mac_only_encrypted},
    );

    # Write output
    open my $out_fh, '>:raw', $output
        or croak "Cannot open output file '$output': $!";
    print $out_fh $encrypted;
    close $out_fh;

    return 1;
}

=method encrypt_file

    File::SOPS->encrypt_file(
        input      => 'secrets.yaml',
        output     => 'secrets.enc.yaml',  # optional, defaults to input (in-place)
        recipients => \@age_public_keys,
        format     => 'yaml',              # optional, auto-detected from filename
    );

Encrypts a file.

Reads the input file, encrypts it for the specified recipients, and writes the
encrypted content to the output file. If C<output> is not specified, encrypts
in-place (overwrites the input file).

The input is read as UTF-8; see L</Character encoding>.

Format is auto-detected from the filename extension (C<.yaml>, C<.yml>, C<.json>)
unless explicitly specified.

C<mac_only_encrypted> is passed through to L</encrypt>.

Returns true on success.

=cut

sub decrypt_file {
    my ($class, %args) = @_;
    my $input      = $args{input}      // croak "input required";
    my $output     = $args{output}     // croak "output required";
    my $identities = $args{identities} // croak "identities required";
    my $format     = $args{format};

    $format //= _detect_format_from_filename($input);

    # Read encrypted file
    open my $fh, '<:raw', $input
        or croak "Cannot open input file '$input': $!";
    my $content = do { local $/; <$fh> };
    close $fh;

    # Decrypt
    my $data = $class->decrypt(
        encrypted  => $content,
        identities => $identities,
        format     => $format,
        ignore_mac => $args{ignore_mac},
    );

    # Serialize decrypted data
    my $format_class = $FORMATS{$format} // croak "Unknown format: $format";

    my $decrypted;
    if ($format eq 'json') {
        # canonical => 1 keeps key order sorted; the MAC depends on it
        $decrypted = JSON::MaybeXS->new(utf8 => 1, pretty => 1, canonical => 1)
            ->encode($data);
    } else {
        $decrypted = YAML::XS::Dump($data);
    }

    # Write output
    open my $out_fh, '>:raw', $output
        or croak "Cannot open output file '$output': $!";
    print $out_fh $decrypted;
    close $out_fh;

    return 1;
}

=method decrypt_file

    File::SOPS->decrypt_file(
        input      => 'secrets.enc.yaml',
        output     => 'secrets.yaml',
        identities => \@age_secret_keys,
        format     => 'yaml',  # optional, auto-detected from filename
    );

Decrypts a SOPS-encrypted file.

Reads the encrypted input file, decrypts it using the provided identities,
and writes the decrypted content to the output file.

The output is UTF-8 encoded, so a file round-tripped through L</encrypt_file>
and back is byte-identical in its non-ASCII content rather than double-encoded.
See L</Character encoding>.

Unlike L</encrypt_file>, C<output> is required to prevent accidental data loss.

C<ignore_mac> is passed through to L</decrypt>; read the warning there before
using it.

Returns true on success.

=cut

sub extract {
    my ($class, %args) = @_;
    my $file       = $args{file}       // croak "file required";
    my $path       = $args{path}       // croak "path required";
    my $identities = $args{identities} // croak "identities required";
    my $format     = $args{format};

    $format //= _detect_format_from_filename($file);

    # Read and decrypt
    open my $fh, '<:raw', $file
        or croak "Cannot open file '$file': $!";
    my $content = do { local $/; <$fh> };
    close $fh;

    my $data = $class->decrypt(
        encrypted  => $content,
        identities => $identities,
        format     => $format,
        ignore_mac => $args{ignore_mac},
    );

    # Navigate to path
    return _extract_path($data, $path);
}

=method extract

    my $value = File::SOPS->extract(
        file       => 'secrets.enc.yaml',
        path       => '["database"]["password"]',
        identities => \@age_secret_keys,
        format     => 'yaml',  # optional, auto-detected from filename
    );

Extracts and decrypts a single value from an encrypted file.

This is more efficient than decrypting the entire file when you only need
one value.

Path can be specified in two formats:

=over 4

=item * Bracket notation: C<["database"]["password"]>

=item * Dot notation: C<database.password>

=back

For array indices, use numeric keys: C<["items"][0]> or C<items.0>

The whole file is still decrypted and MAC-verified; C<extract> saves you the
navigation, not the work. C<ignore_mac> is passed through to L</decrypt>.

C<path> is a character string and is matched against the document's keys as
characters, so a non-ASCII key is written in C<path> exactly as you would write
it in C<data>. The returned value is a character string. See
L</Character encoding>.

Returns the decrypted value (scalar, not reference).

=cut

sub rotate {
    my ($class, %args) = @_;
    my $file       = $args{file}       // croak "file required";
    my $identities = $args{identities} // croak "identities required";
    my $recipients = $args{recipients};
    my $format     = $args{format};

    $format //= _detect_format_from_filename($file);

    # Read encrypted file
    open my $fh, '<:raw', $file
        or croak "Cannot open file '$file': $!";
    my $content = do { local $/; <$fh> };
    close $fh;

    my $format_class = $FORMATS{$format} // croak "Unknown format: $format";
    my (undef, $metadata) = $format_class->parse($content);

    # Get current recipients if not specified
    unless ($recipients) {
        $recipients = [ map { $_->{recipient} } @{$metadata->age} ];
    }

    # Decrypt
    my $data = $class->decrypt(
        encrypted  => $content,
        identities => $identities,
        format     => $format,
        ignore_mac => $args{ignore_mac},
    );

    # Re-encrypt with new data key
    my $encrypted = $class->encrypt(
        data               => $data,
        recipients         => $recipients,
        format             => $format,
        mac_only_encrypted => $metadata->mac_only_encrypted,
    );

    # Write back
    open my $out_fh, '>:raw', $file
        or croak "Cannot write file '$file': $!";
    print $out_fh $encrypted;
    close $out_fh;

    return 1;
}

=method rotate

    File::SOPS->rotate(
        file       => 'secrets.enc.yaml',
        identities => \@age_secret_keys,
        recipients => \@new_recipients,  # optional, keeps current recipients
        format     => 'yaml',            # optional, auto-detected from filename
    );

Rotates the data key (re-encrypts all values with a new key).

This operation:

=over 4

=item 1. Decrypts the file using C<identities>

=item 2. Generates a new random data key

=item 3. Re-encrypts all values with the new data key

=item 4. Encrypts the new data key for C<recipients> (or existing recipients if not specified)

=item 5. Writes back to the same file

=back

Key rotation is recommended periodically for security, or when removing
a recipient's access.

C<mac_only_encrypted> is carried over from the existing file. The other
encryption rules (C<unencrypted_suffix> and friends) are B<not> yet -- L</encrypt>
builds fresh metadata with the defaults, so rotating a file that customised
them rewrites it under the default rules.

C<ignore_mac> is passed through to L</decrypt>; rotating a file you could not
verify re-signs whatever it contained, so prefer to fail.

Returns true on success.

=cut

# Internal helpers

sub _encrypt_tree {
    my ($node, $key, $metadata, $path) = @_;

    if (ref $node eq 'HASH') {
        my %result;
        for my $k (keys %$node) {
            my $new_path = [@$path, $k];
            if ($metadata->should_encrypt_key($k)) {
                $result{$k} = _encrypt_tree($node->{$k}, $key, $metadata, $new_path);
            } else {
                $result{$k} = $node->{$k};
            }
        }
        return \%result;
    }
    elsif (ref $node eq 'ARRAY') {
        my @result;
        for my $item (@$node) {
            # SOPS does NOT add array index to path - all array elements share parent's path
            push @result, _encrypt_tree($item, $key, $metadata, $path);
        }
        return \@result;
    }
    else {
        # Leaf value - encrypt it
        # SOPS doesn't encrypt empty values, returns empty string.
        # The !blessed() guard is load-bearing: JSON::PP::Boolean overloads eq,
        # and JSON->false eq '' is TRUE (while it stringifies to '0'). Without
        # the guard every false boolean was skipped here and written to the file
        # as a plaintext '', after _compute_mac had already hashed 'False' --
        # so the document failed its own MAC check on the next read. sops
        # encrypts false as type:bool with plaintext 'False'.
        return '' if !defined $node || (!blessed($node) && $node eq '');

        my $aad = _path_to_aad($path);
        my $enc = File::SOPS::Encrypted->encrypt_value(
            value => $node,
            key   => $key,
            aad   => $aad,
        );
        return $enc->to_string;
    }
}

sub _decrypt_tree {
    my ($node, $key, $metadata, $path) = @_;

    if (ref $node eq 'HASH') {
        my %result;
        for my $k (keys %$node) {
            my $new_path = [@$path, $k];
            $result{$k} = _decrypt_tree($node->{$k}, $key, $metadata, $new_path);
        }
        return \%result;
    }
    elsif (ref $node eq 'ARRAY') {
        my @result;
        for my $item (@$node) {
            # SOPS does NOT add array index to path - all array elements share parent's path
            push @result, _decrypt_tree($item, $key, $metadata, $path);
        }
        return \@result;
    }
    elsif (File::SOPS::Encrypted->is_encrypted($node)) {
        my $enc = File::SOPS::Encrypted->parse($node);
        my $aad = _path_to_aad($path);
        return $enc->decrypt_value(key => $key, aad => $aad);
    }
    else {
        return $node;
    }
}

sub _path_to_aad {
    my ($path) = @_;
    return '' unless $path && @$path;
    # SOPS format: path components joined with ":" plus trailing ":"
    #
    # This is a CHARACTER string -- the components are keys straight out of the
    # parser. UTF-8 encoding it is File::SOPS::Encrypted's job, done once at the
    # cipher boundary (_utf8_bytes) so that encrypt_value, decrypt_bytes and the
    # MAC's decrypt_bytes call cannot drift apart on it. Do not encode here as
    # well; that would double-encode every non-ASCII key.
    return join(':', @$path) . ':';
}

# --- MAC ----------------------------------------------------------------
#
# The MAC is a SHA-512 over the plaintext of EVERY leaf in the document -- no
# keys, no paths -- uppercase hex, itself AES-GCM encrypted with lastmodified
# as AAD. Two things about it are easy to get wrong and impossible to notice
# from inside this library, because both sides of a self-produced file agree
# with each other while disagreeing with sops:
#
#   1. It covers unencrypted values too. Values excluded from encryption by
#      unencrypted_suffix (or any of the other rules) are hashed exactly like
#      encrypted ones. Only mac_only_encrypted changes that, and then the
#      digest additionally starts from a fixed 32-byte block so the two
#      settings can never collide.
#
#   2. It is order dependent, and the order is DOCUMENT order. The encrypt
#      side has only a Perl hash to walk, whose iteration order is randomized,
#      so it walks sorted -- which is correct precisely because both
#      serializers emit sorted keys (see t/05-format-key-order.t). The decrypt
#      side must reproduce whatever order the producer used, and for a file
#      written by sops that is the order of the original document, not sorted
#      order. Hence _document_leaves, which recovers key order from an
#      order-preserving reparse of the raw text.
#
# Both directions funnel into _mac_digest so the two rules above are stated
# once. What differs is only how the leaves are collected and what a leaf's
# bytes are.

# MACOnlyEncryptedInitialization, verbatim from sops.go.
our $MAC_ONLY_ENCRYPTED_INIT = pack 'C*',
    0x8a, 0x3f, 0xd2, 0xad, 0x54, 0xce, 0x66, 0x52,
    0x7b, 0x10, 0x34, 0xf3, 0xd1, 0x47, 0xbe, 0x0b,
    0x0b, 0x97, 0x5b, 0x3b, 0xf4, 0x4f, 0x72, 0xc6,
    0xfd, 0xad, 0xec, 0x81, 0x76, 0xf2, 0x7d, 0x69;

my $ORDERED_LOADER = YAML::PP->new(
    boolean  => 'JSON::PP',
    preserve => PRESERVE_ORDER,
);

sub _compute_mac {
    my ($data, $key, $metadata) = @_;

    my $mac_value = _mac_digest(
        leaves   => _sorted_leaves($data, [], []),
        metadata => $metadata,
    );

    my $enc = File::SOPS::Encrypted->encrypt_value(
        value => $mac_value,
        key   => $key,
        # AAD is the lastmodified timestamp in RFC3339 format
        aad   => $metadata->lastmodified // '',
        type  => 'str',
    );

    return $enc->to_string;
}

sub _verify_mac {
    my (%args) = @_;
    my $metadata = $args{metadata};
    my $data_key = $args{data_key};

    my $stored = $metadata->mac;
    croak "File has no MAC - refusing to return unverified data "
        . "(pass ignore_mac => 1 to override)"
        unless defined $stored && length $stored;

    my $mac_enc = File::SOPS::Encrypted->parse($stored)
        or croak "Cannot parse MAC - refusing to return unverified data "
        . "(pass ignore_mac => 1 to override)";

    my $expected = eval {
        $mac_enc->decrypt_bytes(key => $data_key, aad => $metadata->lastmodified // '')
    };
    croak "Cannot decrypt MAC - refusing to return unverified data "
        . "(pass ignore_mac => 1 to override)"
        unless defined $expected;

    # Document order where we can recover it, sorted order otherwise -- which
    # is the same thing for every file this library writes. Getting the order
    # wrong can only make verification fail, never wrongly succeed.
    my $ordered = _parse_in_document_order($args{document});
    my $leaves  = $ordered
        ? _document_leaves($ordered, $args{data}, [], [])
        : _sorted_leaves($args{data}, [], []);

    my $computed = _mac_digest(
        leaves   => $leaves,
        metadata => $metadata,
        data_key => $data_key,
    );

    croak "MAC verification failed" unless $expected eq $computed;

    return 1;
}

sub _mac_digest {
    my (%args) = @_;
    my $leaves   = $args{leaves};
    my $metadata = $args{metadata};
    my $data_key = $args{data_key};   # decrypt side only

    my $only_encrypted = $metadata && $metadata->mac_only_encrypted;

    my $ctx = Digest::SHA->new(512);
    $ctx->add($MAC_ONLY_ENCRYPTED_INIT) if $only_encrypted;

    for my $leaf (@$leaves) {
        my ($path, $value) = @$leaf;
        next if $only_encrypted && !$metadata->should_encrypt_path($path);
        $ctx->add(_mac_bytes($value, $path, $data_key));
    }

    # Uppercase hex digest (SOPS format)
    return uc($ctx->hexdigest);
}

sub _mac_bytes {
    my ($value, $path, $data_key) = @_;

    # Decrypt side. Hash the authenticated plaintext exactly as it came off
    # the cipher: running it back through decrypt_value's type conversion
    # would hash '007' as 7 and Go's 100000000000000000000 as 1e+20, and the
    # document would fail its own MAC. type:bool is the one case that needs
    # normalising, because SOPS's ToBytes titlecases the boolean it parsed
    # rather than echoing the spelling it was given.
    if (defined $data_key && File::SOPS::Encrypted->is_encrypted($value)) {
        my $enc   = File::SOPS::Encrypted->parse($value);
        my $bytes = $enc->decrypt_bytes(key => $data_key, aad => _path_to_aad($path));
        return $bytes unless $enc->type eq 'bool';
        return (lc($bytes) eq 'true' || $bytes eq '1') ? 'True' : 'False';
    }

    # Encrypt side, and unencrypted leaves on the decrypt side.
    return _value_to_bytes($value);
}

# Leaves in sorted-key order: [ [ \@path, $value ], ... ]
sub _sorted_leaves {
    my ($node, $path, $out) = @_;

    if (ref $node eq 'HASH') {
        _sorted_leaves($node->{$_}, [@$path, $_], $out) for sort keys %$node;
    }
    elsif (ref $node eq 'ARRAY') {
        # SOPS does NOT add array index to path - all elements share parent's
        _sorted_leaves($_, $path, $out) for @$node;
    }
    else {
        push @$out, [ $path, $node ];
    }

    return $out;
}

# Leaves in document order. $ordered is the same document reparsed with key
# order preserved and supplies the order; $node is the tree the rest of the
# library is working with and supplies the values, so the digest never sees a
# value the second parser resolved differently. A structural disagreement
# between the two makes verification fail, which is the safe direction.
sub _document_leaves {
    my ($ordered, $node, $path, $out) = @_;

    if (ref $ordered eq 'HASH') {
        return $out unless ref $node eq 'HASH';
        _document_leaves($ordered->{$_}, $node->{$_}, [@$path, $_], $out)
            for keys %$ordered;
    }
    elsif (ref $ordered eq 'ARRAY') {
        return $out unless ref $node eq 'ARRAY';
        _document_leaves($ordered->[$_], $node->[$_], $path, $out)
            for 0 .. $#$ordered;
    }
    else {
        push @$out, [ $path, $node ];
    }

    return $out;
}

# Reparse the raw document with hash key order preserved, purely to recover
# document order. YAML::PP is used for both formats: JSON is a subset of YAML
# 1.2, and it agrees with YAML::XS and JSON::MaybeXS on everything sops emits.
# Returns undef if the text will not parse that way, leaving the caller on
# sorted order.
sub _parse_in_document_order {
    my ($content) = @_;
    return unless defined $content;

    # YAML::XS::Load hands back decoded characters, so the reparse has to
    # decode too or a non-ASCII key would not match its twin in the tree.
    my $text = $content;
    utf8::decode($text) unless utf8::is_utf8($text);

    my $doc = eval { $ORDERED_LOADER->load_string($text) };
    return unless ref $doc eq 'HASH';

    # The metadata MAC lives here and must not hash itself. It is dropped the
    # same way the format handlers drop it -- by removing the whole sops
    # branch -- rather than by pattern-matching "mac:" in the raw text, which
    # is what used to swallow any user key ending in "mac" (hmac, webmac).
    delete $doc->{sops};

    return $doc;
}

sub _value_to_bytes {
    my ($value) = @_;
    return '' unless defined $value;

    my $str;

    # Handle JSON::PP::Boolean (the class every JSON::MaybeXS backend blesses
    # into). blessed() guard: ->isa dies on an unblessed ref, and a plain
    # SCALAR/CODE ref reaches here through _hash_values_for_mac's leaf branch.
    if (blessed($value) && $value->isa('JSON::PP::Boolean')) {
        $str = $value ? 'True' : 'False';
    }
    else {
        # Detect type same as encryption
        my $type = _detect_type_for_mac($value);

        if ($type eq 'bool') {
            # Must stay byte-identical to Encrypted::_serialize_value or the
            # MAC disagrees with the ciphertext. See the note there.
            $str = (lc("$value") eq 'true' || "$value" eq '1') ? 'True' : 'False';
        } else {
            $str = "$value";
        }
    }

    # Encode to UTF-8 bytes for hashing (Digest::SHA requires bytes)
    utf8::encode($str) if utf8::is_utf8($str);
    return $str;
}

sub _detect_type_for_mac {
    my ($value) = @_;
    return 'str' unless defined $value;
    # JSON::PP::Boolean (see _value_to_bytes for the blessed() guard)
    return 'bool' if blessed($value) && $value->isa('JSON::PP::Boolean');
    # Only string literals 'true'/'false' are bool, not '1'/'0' (those are ints)
    return 'bool' if $value eq 'true' || $value eq 'false';
    return 'int' if $value =~ /^-?\d+$/;
    return 'float' if $value =~ /^-?\d+\.\d+$/;
    return 'str';
}

sub _extract_path {
    my ($data, $path) = @_;

    # Parse path like ["database"]["password"] or .database.password
    my @parts;
    if ($path =~ /^\[/) {
        while ($path =~ /\["([^"]+)"\]/g) {
            push @parts, $1;
        }
    } else {
        $path =~ s/^\.//;
        @parts = split /\./, $path;
    }

    my $current = $data;
    for my $part (@parts) {
        if (ref $current eq 'HASH') {
            $current = $current->{$part};
        } elsif (ref $current eq 'ARRAY' && $part =~ /^\d+$/) {
            $current = $current->[$part];
        } else {
            croak "Cannot navigate path: $path";
        }
    }

    return $current;
}

sub _detect_format {
    my ($content) = @_;

    # Try to detect based on content
    if ($content =~ /^\s*\{/) {
        return 'json';
    }
    return 'yaml';
}

sub _detect_format_from_filename {
    my ($filename) = @_;

    return 'json' if $filename =~ /\.json$/i;
    return 'yaml' if $filename =~ /\.ya?ml$/i;
    return 'yaml';
}

sub _random_bytes {
    my ($length) = @_;
    my $bytes = '';
    if (eval { require Crypt::PRNG; 1 }) {
        $bytes = Crypt::PRNG::random_bytes($length);
    } else {
        open my $fh, '<:raw', '/dev/urandom'
            or croak "Cannot open /dev/urandom: $!";
        read $fh, $bytes, $length;
        close $fh;
    }
    return $bytes;
}

=head1 SEE ALSO

=over 4

=item * L<File::SOPS::Encrypted> - Encrypted value parsing and generation

=item * L<File::SOPS::Metadata> - SOPS metadata section handling

=item * L<File::SOPS::Backend::Age> - Age encryption backend

=item * L<Crypt::Age> - Perl age encryption implementation

=item * L<https://github.com/getsops/sops> - Reference SOPS implementation in Go

=item * L<https://age-encryption.org/> - age encryption specification

=back

=cut

1;
