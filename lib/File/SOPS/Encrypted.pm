package File::SOPS::Encrypted;
# ABSTRACT: Parse and generate SOPS encrypted values
our $VERSION = '0.003';
use Moo;
use Carp qw(croak);
use Scalar::Util qw(blessed);
use MIME::Base64 qw(encode_base64 decode_base64);
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use JSON::MaybeXS;
use namespace::clean;

=head1 SYNOPSIS

    use File::SOPS::Encrypted;

    # Parse an encrypted value string
    my $enc = File::SOPS::Encrypted->parse(
        'ENC[AES256_GCM,data:xyz,iv:abc,tag:def,type:str]'
    );

    # Check if a string is encrypted
    if (File::SOPS::Encrypted->is_encrypted($string)) {
        my $decrypted = $enc->decrypt_value(key => $data_key, aad => $path);
    }

    # Encrypt a value
    my $enc = File::SOPS::Encrypted->encrypt_value(
        value => 'secret',
        key   => $data_key,
        aad   => 'database:password',
    );

    # Get encrypted string representation
    my $string = $enc->to_string;
    # => ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]

=head1 DESCRIPTION

File::SOPS::Encrypted handles parsing and generation of SOPS encrypted value
strings. Each encrypted value in a SOPS file is represented as:

    ENC[AES256_GCM,data:base64,iv:base64,tag:base64,type:str]

Values are encrypted with AES-256-GCM using:

=over 4

=item * A shared data key (32 bytes, encrypted separately for each recipient)

=item * A random initialization vector (IV) per value (32 bytes -- see L</iv>)

=item * Additional Authenticated Data (AAD) derived from the value's path

=item * Type preservation (str, int, float, bool, bytes)

=back

=cut

has algorithm => (is => 'ro', default => 'AES256_GCM');

=attr algorithm

Encryption algorithm. Currently only C<AES256_GCM> is supported. Defaults to C<AES256_GCM>.

=cut

has data => (is => 'ro', required => 1);

=attr data

Encrypted ciphertext as raw bytes. Required.

=cut

has iv => (is => 'ro', required => 1);

=attr iv

Initialization vector (IV) as raw bytes, B<32 bytes>. Required.

Note that this is deliberately B<not> the conventional 12-byte (96-bit) AES-GCM
nonce. The SOPS reference implementation generates a 32-byte nonce and builds
its cipher with Go's C<cipher.NewGCMWithNonceSize>, so 32 bytes is part of the
on-the-wire format rather than a choice this module is free to make. AES-GCM
derives its initial counter block differently for non-96-bit nonces (the nonce
is folded through GHASH instead of being used directly), which means an IV of a
different length does not merely look unusual -- it produces a value the Go
implementation cannot authenticate, and vice versa.

C<encrypt_value> generates 32 random bytes accordingly. Do not "correct" this
to 12.

=cut

has tag => (is => 'ro', required => 1);

=attr tag

Authentication tag as raw bytes, 16 bytes for AES-GCM. Required.

=cut

has type => (is => 'ro', default => 'str');

=attr type

Original value type for deserialization. One of: C<str>, C<int>, C<float>, C<bool>, C<bytes>.

Defaults to C<str>.

=cut

my $ENC_REGEX = qr/^ENC\[([^,]+),data:([^,]+),iv:([^,]+),tag:([^,]+),type:([^\]]+)\]$/;

sub parse {
    my ($class, $string) = @_;

    return unless defined $string && $string =~ $ENC_REGEX;

    my ($algo, $data, $iv, $tag, $type) = ($1, $2, $3, $4, $5);

    return $class->new(
        algorithm => $algo,
        data      => decode_base64($data),
        iv        => decode_base64($iv),
        tag       => decode_base64($tag),
        type      => $type,
    );
}

=method parse

    my $enc = File::SOPS::Encrypted->parse($string);
    # Returns undef if $string is not encrypted

Parses a SOPS encrypted value string.

Takes a string like C<ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]> and
returns a File::SOPS::Encrypted object with decoded attributes.

Returns C<undef> if the string is not in the encrypted format.

=cut

sub is_encrypted {
    my ($class, $string) = @_;
    return defined $string && $string =~ $ENC_REGEX;
}

=method is_encrypted

    if (File::SOPS::Encrypted->is_encrypted($string)) {
        # It's an encrypted value
    }

Class method to check if a string is in SOPS encrypted format.

Returns true if the string matches the C<ENC[...]> pattern.

=cut

sub to_string {
    my ($self) = @_;

    my $data = _encode_base64_oneline($self->data);
    my $iv   = _encode_base64_oneline($self->iv);
    my $tag  = _encode_base64_oneline($self->tag);

    return sprintf('ENC[%s,data:%s,iv:%s,tag:%s,type:%s]',
        $self->algorithm, $data, $iv, $tag, $self->type);
}

=method to_string

    my $string = $enc->to_string;
    # => ENC[AES256_GCM,data:xyz==,iv:abc==,tag:def==,type:str]

Serializes the encrypted value to SOPS string format.

Returns a string representation with base64-encoded components.

=cut

sub encrypt_value {
    my ($class, %args) = @_;
    my $value    = $args{value};
    my $key      = $args{key}      // croak "key required";
    my $aad      = _aad_bytes($args{aad});
    my $type     = $args{type}     // _detect_type($value);

    $value //= '';
    my $plaintext = _serialize_value($value, $type);
    my $iv = _random_bytes(32);  # SOPS uses 32-byte nonce

    my ($ciphertext, $tag) = gcm_encrypt_authenticate('AES', $key, $iv, $aad, $plaintext);

    return $class->new(
        algorithm => 'AES256_GCM',
        data      => $ciphertext,
        iv        => $iv,
        tag       => $tag,
        type      => $type,
    );
}

=method encrypt_value

    my $enc = File::SOPS::Encrypted->encrypt_value(
        value => 'secret',
        key   => $data_key,        # 32 bytes
        aad   => 'database:password',  # Additional Authenticated Data
        type  => 'str',            # optional, auto-detected
    );

Class method to encrypt a value.

Encrypts a scalar value using AES-256-GCM with a random IV. Returns a
File::SOPS::Encrypted object.

The C<aad> (Additional Authenticated Data) is typically the path to the value
in the data structure (e.g., C<database:password:>), used to prevent value
substitution attacks.

Both C<value> and C<aad> are encoded to UTF-8 before they reach the cipher,
which is what the Go implementation authenticates against, but by two
deliberately different rules:

=over 4

=item * C<aad> is B<always> encoded. It names a key that the format handler
writes to the file with C<YAML::XS::Dump> or C<JSON::MaybeXS(utf8 =E<gt> 1)>,
and both of those encode a key to UTF-8 regardless of Perl's UTF-8 flag. The
AAD has to say what the emitter wrote, or a document fails its own MAC on the
next read.

=item * C<value> is encoded only if it carries the UTF-8 flag, so a caller
handing over UTF-8 bytes rather than characters still writes the bytes it
meant. Nothing outside this call has to agree on the plaintext -- the
ciphertext and the MAC are both taken over exactly these bytes.

=back

Type is auto-detected from the value if not specified: C<int>, C<float>, C<bool>,
or C<str>.

=cut

sub decrypt_bytes {
    my ($self, %args) = @_;
    my $key = $args{key} // croak "key required";
    my $aad = _aad_bytes($args{aad});

    croak "Unsupported algorithm: " . $self->algorithm
        unless $self->algorithm eq 'AES256_GCM';

    my $plaintext = gcm_decrypt_verify('AES', $key, $self->iv, $aad, $self->data, $self->tag);
    croak "Authentication failed - data may be corrupted" unless defined $plaintext;

    return $plaintext;
}

=method decrypt_bytes

    my $bytes = $enc->decrypt_bytes(
        key => $data_key,  # 32 bytes
        aad => 'database:password:',
    );

Decrypts the value and returns the authenticated plaintext B<as raw bytes>,
with no type conversion and B<no character decoding> applied.

C<aad> is UTF-8 encoded before verification by the same unconditional rule
L</encrypt_value> uses, so the two sides derive the same AAD from the same key
path however Perl happens to be storing it.

This is what the MAC is computed over. L</decrypt_value> runs the same bytes
through a type conversion (C<int()>, C<+ 0.0>, C<JSON::PP::Boolean>) whose
inverse is not exact in Perl: C<'007'> comes back as C<7>, C<'1.50'> as
C<1.5>, and the C<100000000000000000000> that Go writes for C<1e20>
restringifies as C<1e+20>. Feeding a re-serialization of the converted value
to the digest therefore produces a different hash than the one the producer
computed over the plaintext. Anything hashing a decrypted value must use this
method, not L</decrypt_value> -- the one exception being C<type:bool>, where
SOPS's C<ToBytes> titlecases whatever spelling it parsed, so the caller
normalises C<true>/C<false> to C<True>/C<False>.

Dies if authentication fails (wrong key, corrupted data, or mismatched AAD).

=cut

sub decrypt_value {
    my ($self, %args) = @_;
    return _deserialize_value($self->decrypt_bytes(%args), $self->type);
}

=method decrypt_value

    my $value = $enc->decrypt_value(
        key => $data_key,  # 32 bytes
        aad => 'database:password',
    );

Decrypts the encrypted value.

Returns the decrypted value with type conversion applied (int, float, bool
are converted to appropriate Perl types) and, for textual types, B<decoded
from UTF-8 into a character string> -- the inverse of what L</encrypt_value>
accepted. This is the Perl-facing side of the boundary; L</decrypt_bytes> is
the wire side and is what anything feeding a digest must use.

C<type:bytes> is the one exception: it is SOPS's binary type, so it is returned
as raw bytes with nothing decoded. A C<type:str> whose plaintext is not valid
UTF-8 is also returned as bytes rather than being mangled.

Dies if authentication fails (wrong key, corrupted data, or mismatched AAD).

=cut

sub _detect_type {
    my ($value) = @_;
    return 'str' unless defined $value;
    # JSON::PP::Boolean is the class every JSON::MaybeXS backend blesses into
    # (Cpanel::JSON::XS and JSON::XS included), so this test is backend-agnostic.
    # blessed() guard: ->isa dies on an unblessed ref, and a plain SCALAR/CODE
    # ref can reach here from encrypt_value or the _encrypt_tree leaf branch.
    return 'bool' if blessed($value) && $value->isa('JSON::PP::Boolean');
    # Only string literals 'true'/'false' are bool, not '1'/'0' (those are ints)
    return 'bool' if $value eq 'true' || $value eq 'false';
    return 'int' if $value =~ /^-?\d+$/;
    return 'float' if $value =~ /^-?\d+\.\d+$/;
    return 'str';
}

sub _serialize_value {
    my ($value, $type) = @_;
    return '' unless defined $value;

    my $str;

    # SOPS uses Titlecase for bools: "True" / "False"
    if ($type eq 'bool') {
        # Handle JSON::PP::Boolean (see _detect_type for the blessed() guard)
        if (blessed($value) && $value->isa('JSON::PP::Boolean')) {
            $str = $value ? 'True' : 'False';
        } else {
            # Explicit rule, symmetric with _deserialize_value. The old test
            # ended in "|| $value", a bare Perl truthiness fallback, so the
            # non-empty string 'false' came out as 'True'.
            $str = (lc("$value") eq 'true' || "$value" eq '1') ? 'True' : 'False';
        }
    } else {
        $str = "$value";
    }

    return _utf8_bytes($str);
}

# The plaintext's crossing from characters into bytes. CryptX takes bytes, so a
# character string arriving at the cipher is either downgraded to Latin-1
# (U+0080..U+00FF) or dies outright with "Wide character in subroutine entry"
# (above U+00FF).
#
# Only a flagged scalar is encoded here. An unflagged one is taken to be a byte
# string already, so encoding it would double-encode a caller who handed us
# UTF-8 bytes rather than characters -- and unlike the AAD below, nothing else
# in the document has to agree with this decision: the plaintext is what the
# ciphertext and the MAC are both taken over, and both derive it from here.
sub _utf8_bytes {
    my ($str) = @_;
    return $str unless defined $str;
    utf8::encode($str) if utf8::is_utf8($str);
    return $str;
}

# The AAD's crossing, and it is UNCONDITIONAL -- deliberately not the rule
# above.
#
# The AAD is derived from the document's key path, and the key it names is
# written to the file by YAML::XS::Dump / JSON::MaybeXS(utf8 => 1). Both of
# those encode a key to UTF-8 whether or not it carries Perl's UTF-8 flag,
# because for a string whose characters are all below U+0100 that flag is an
# internal storage detail and not a statement about the string's meaning. So
# "caf\x{e9}" is written to the file as the five bytes caf\xc3\xa9 no matter how
# Perl happens to be holding it, and the AAD has to say the same thing.
#
# Under a flag-guarded rule it did not: an unflagged "caf\x{e9}" authenticated
# against caf\xe9: while the emitter wrote caf\xc3\xa9, so the very next read of
# our own file re-derived the UTF-8 form and the document failed its own MAC.
# Matching the emitter is what makes the AAD single-valued for a given
# document, and it is also what Go does, where a map key is UTF-8 by
# construction.
sub _aad_bytes {
    my ($aad) = @_;
    return '' unless defined $aad;
    utf8::encode($aad);   # unconditional: no-op for ASCII, correct for the rest
    return $aad;
}

sub _deserialize_value {
    my ($data, $type) = @_;

    # SOPS's binary type. Not text, so there is nothing to decode -- see the
    # boundary note in the decrypt_value POD.
    return $data if $type eq 'bytes';

    return int($data) if $type eq 'int';
    return $data + 0.0 if $type eq 'float';
    if ($type eq 'bool') {
        # SOPS uses "True"/"False" (titlecase)
        # Return JSON::PP::Boolean to preserve bool type through YAML/JSON serialization
        return (lc($data) eq 'true' || $data eq '1') ? JSON->true : JSON->false;
    }

    # str, and any type this ladder does not know, are text: hand back
    # characters, matching what the parsers give the caller for the keys and
    # for every value that was not encrypted. utf8::decode leaves the scalar
    # alone and returns false if the plaintext is not valid UTF-8, which is the
    # graceful direction -- such a value comes back as the bytes it was.
    utf8::decode($data);
    return $data;
}

sub _encode_base64_oneline {
    my ($data) = @_;
    my $encoded = encode_base64($data, '');
    return $encoded;
}

sub _random_bytes {
    my ($length) = @_;
    my $bytes = '';
    if (eval { require Crypt::PRNG; 1 }) {
        $bytes = Crypt::PRNG::random_bytes($length);
    } else {
        open my $fh, '<:raw', '/dev/urandom' or croak "Cannot open /dev/urandom: $!";
        read $fh, $bytes, $length;
        close $fh;
    }
    return $bytes;
}

=head1 SEE ALSO

=over 4

=item * L<File::SOPS> - Main SOPS interface

=item * L<Crypt::AuthEnc::GCM> - AES-GCM implementation from CryptX

=back

=cut

1;
