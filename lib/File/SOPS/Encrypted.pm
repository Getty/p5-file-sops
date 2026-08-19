package File::SOPS::Encrypted;
# ABSTRACT: Parse and generate SOPS encrypted values
our $VERSION = '0.003';
use Moo;
use B ();
use Carp qw(croak);
use Scalar::Util qw(blessed);
use MIME::Base64 qw(encode_base64 decode_base64);
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate gcm_decrypt_verify);
use Crypt::PRNG ();
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

Original value type for deserialization. One of C<str>, C<int>, C<float>,
C<bool>, C<bytes>, C<time> or C<comment> -- the seven the reference
implementation writes. Anything else makes L</decrypt_value> die with
C<Unknown datatype>, as Go does; until 0.003 it silently returned the raw
plaintext, so a document this module could not actually interpret looked like
it had been read.

C<time> and C<comment> are read but never produced here. C<time> is Go's
C<time.Time>, stored as RFC3339 and returned as that string, because Perl has
no native date type. C<comment> is a YAML comment, which sops writes as
C<#ENC[...]> on its own line -- L<YAML::XS> discards comments, so a document
never carries one into this module.

Defaults to C<str>.

=cut

my $ENC_REGEX = qr/^ENC\[([^,]+),data:([^,]+),iv:([^,]+),tag:([^,]+),type:([^\]]+)\]$/;

sub parse {
    my ($class, $string) = @_;

    return unless defined $string && $string =~ $ENC_REGEX;

    my ($algo, $data, $iv, $tag, $type) = ($1, $2, $3, $4, $5);

    return $class->new(
        algorithm => $algo,
        data      => _decode_base64_strict($data, 'data'),
        iv        => _decode_base64_strict($iv,   'iv'),
        tag       => _decode_base64_strict($tag,  'tag'),
        type      => $type,
    );
}

# MIME::Base64::decode_base64 IGNORES anything outside the alphabet and stops
# at a short group, so a corrupted field decoded to a shorter string and turned
# into "Authentication failed - data may be corrupted" three calls later, or --
# for the iv and the tag -- into a wrong length passed straight to the cipher.
# Go decodes with base64.StdEncoding, which fails on the spot and says so, and
# the field it fails on is the useful half of the message.
sub _decode_base64_strict {
    my ($encoded, $field) = @_;

    croak "Invalid base64 in the '$field' field of an ENC value: "
        . "characters outside the standard alphabet"
        unless $encoded =~ m{\A[A-Za-z0-9+/]*={0,2}\z};
    croak "Invalid base64 in the '$field' field of an ENC value: "
        . "length is not a multiple of 4"
        if length($encoded) % 4;

    return decode_base64($encoded);
}

=method parse

    my $enc = File::SOPS::Encrypted->parse($string);
    # Returns undef if $string is not encrypted

Parses a SOPS encrypted value string.

Takes a string like C<ENC[AES256_GCM,data:...,iv:...,tag:...,type:str]> and
returns a File::SOPS::Encrypted object with decoded attributes.

Returns C<undef> if the string is not in the encrypted format.

B<Dies if the string has the shape but not the content>: a C<data>, C<iv> or
C<tag> field that is not valid standard base64 -- a character outside the
alphabet, or a length that is not a multiple of four. L<MIME::Base64> silently
drops what it cannot read, so such a field used to decode to something shorter
and fail much later, as C<Authentication failed - data may be corrupted> or as
a cipher rejecting the nonce length. Go decodes with C<base64.StdEncoding>,
which fails immediately and names the problem.

L</is_encrypted> is unaffected and never dies: it answers about the B<shape>,
which is what decides whether a value is a candidate for decryption at all.

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
    my $type     = $args{type}     // $class->detect_type($value);

    $value //= '';
    $class->assert_representable($value);
    my $plaintext = $class->value_to_bytes($value, $type);

    # AES-GCM ciphertext is exactly as long as its plaintext, so an empty
    # value produces an empty `data:` field -- and neither implementation's
    # parser accepts that. Ours requires one character ([^,]+); sops stops with
    # "Input string ENC[...] does not match sops' data format" (exit 25). sops
    # never produces the shape either: it leaves an empty value unencrypted,
    # which is what File::SOPS::encrypt does before it ever gets here.
    croak "Cannot encrypt an empty value: the SOPS wire format has no "
        . "representation for empty ciphertext. Leave the value unencrypted "
        . "instead, which is what sops does with an empty scalar."
        unless length $plaintext;

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

Both C<value> and C<aad> are B<always> encoded to UTF-8 before they reach the
cipher, which is what the Go implementation authenticates against, and
B<neither consults Perl's UTF-8 flag>. For a string whose characters are all
below U+0100 that flag is an internal storage detail rather than a statement
about meaning: C<"caf\x{e9}"> may be held as one byte or as two, Perl considers
both the same string, and C<YAML::XS::Dump> and the JSON emitter (built with
C<utf8>) write both to the file as C<caf\xc3\xa9>. Anything that reads the flag
therefore disagrees with the bytes our own emitter wrote, which is a document
that fails its own MAC.

The exception is C<type =E<gt> 'bytes'>, SOPS's binary type, which is passed
through untouched -- and which is how a caller says that a scalar really is
bytes rather than characters. See L</value_to_bytes> and
L<docs/adr/0003|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0003-value-encoding-is-unconditional-like-the-aad.md>.

Type is auto-detected from the value if not specified, by L</detect_type>.

Passing C<type> explicitly overrides the B<label> only, never the bytes: those
always come from what the value is. C<encrypt_value(value =E<gt> '007', type
=E<gt> 'int')> writes the label C<int> and the plaintext C<007>, because a
Perl string is written verbatim. That is how you reproduce a document some
other producer wrote; it is not how you write C<007> as an integer, which no
SOPS implementation does (see L</value_to_bytes>).

Dies if the value is one no SOPS document can carry -- today, an integer wider
than Go's C<int64>. See L</assert_representable>.

Dies if the value's plaintext is B<empty> (which includes C<undef>). GCM
ciphertext is the length of its plaintext, so the result would be an
C<ENC[AES256_GCM,data:,...]> that neither L</parse> nor sops accepts -- sops
stops with C<Input string ENC[...] does not match sops' data format>. Until
0.003 such a string was built and returned. Empty values belong in the document
unencrypted, which is what sops does with them and what L<File::SOPS/encrypt>
does before calling this.

=cut

sub decrypt_bytes {
    my ($self, %args) = @_;
    my $key = $args{key} // croak "key required";
    my $aad = _aad_bytes($args{aad});

    croak "Unsupported algorithm: " . $self->algorithm
        unless $self->algorithm eq 'AES256_GCM';

    my $plaintext = gcm_decrypt_verify('AES', $key, $self->iv, $aad, $self->data, $self->tag);
    croak "Authentication failed - data may be corrupted" unless defined $plaintext;

    # The stringify is load-bearing, and `return $plaintext` is a silent
    # data-corruption bug -- do not "simplify" it away.
    #
    # CryptX (measured on 0.087) hands back the plaintext in an SV whose PV
    # buffer is NOT NUL-terminated at SvCUR. Perl's own string-to-number
    # conversion depends on that terminator: sv_2nv only
    # consults SvCUR through grok_number, and for anything grok_number cannot
    # settle as an integer inside a UV -- every float, and every integer wider
    # than 64 bits -- it falls through to Atof(SvPVX), a C string read with no
    # length. So a numeric read of the raw scalar runs off the end of the
    # plaintext into whatever the allocator left there, and when that byte is
    # one of the ten digit characters it joins the number: the
    # 100000000000000000000 Go writes for 1e20 came back as 1e21, on maybe one
    # leaf in a hundred, with the ciphertext and the MAC both intact.
    # Assignment through a stringify goes via sv_setpvn, which allocates a
    # buffer Perl terminates itself.
    #
    # It belongs here rather than at the two conversions in _deserialize_value
    # because this is the boundary the foreign scalar crosses: the type
    # conversion, the MAC digest and any caller doing arithmetic on what this
    # method returns are all downstream of it, and a fix at the conversions
    # would have to be repeated at each new one. See t/18-decrypt-determinism.t.
    #
    # This is the ONLY such normalisation, deliberately: the ciphertext, the tag
    # and the IV come out of CryptX just as unterminated, and are left alone
    # because nothing ever reads them as anything but length-delimited bytes.
    # docs/adr/0004 has the measurements and says why "normalise every CryptX
    # boundary" is not the rule -- and why "normalise every foreign scalar"
    # would break ADR 0002 outright.
    return "$plaintext";
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
through a type conversion (C<0 + $x>, C<+ 0.0>, C<JSON::PP::Boolean>) whose
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

Also dies, rather than guessing, on a plaintext that does not match its label:

=over 4

=item * a C<type:int> plaintext that is not a decimal integer, or is one Go's
C<strconv.Atoi> would refuse -- that is, outside C<int64>. Until 0.003 that
went through Perl's C<int()>, which is exact up to C<2**64-1> on a 64-bit Perl
and silently rounds above it, so the same document produced one answer here and
C<value out of range> in sops.

=item * a C<type:float> plaintext that is not a number, which C<+ 0.0> turned
into C<0> without a word and C<strconv.ParseFloat> rejects.

=item * an unrecognised C<type:> altogether -- C<Unknown datatype>, as Go says.

=back

L</decrypt_bytes> still returns the authenticated plaintext in every one of
those cases, which is how a value is recovered from such a file.

=cut

sub detect_type {
    my ($class, $value) = @_;
    return 'str' unless defined $value;
    # JSON::PP::Boolean is the class every JSON::MaybeXS backend blesses into
    # (Cpanel::JSON::XS and JSON::XS included), and the class YAML::XS blesses
    # into under $YAML::XS::Boolean = 'JSON::PP', so this test is
    # backend-agnostic. blessed() guard: ->isa dies on an unblessed ref, and a
    # plain SCALAR/CODE ref can reach here from encrypt_value or the
    # _encrypt_tree leaf branch.
    return 'bool' if blessed($value) && $value->isa('JSON::PP::Boolean');
    return 'str'  if ref $value;
    return _sv_kind($value);
}

=method detect_type

    my $type = File::SOPS::Encrypted->detect_type($value);
    # => 'str' | 'int' | 'float' | 'bool'

Class method. Returns the SOPS type of a Perl scalar, B<from the scalar
itself> rather than from a pattern match on its text.

=over 4

=item * a L<JSON::PP::Boolean> (C<JSON-E<gt>true>, C<JSON-E<gt>false>, or a
C<true>/C<false> loaded by L<YAML::XS> or L<JSON::MaybeXS>) is C<bool>

=item * a scalar Perl holds as an integer is C<int>

=item * a scalar Perl holds as a floating point number is C<float>

=item * everything else, including every string, is C<str>

=back

This is the rule the Go implementation uses -- it takes the type from what the
YAML/JSON parser returned -- and both parsers this distribution uses preserve
the distinction, so a quoted scalar is a string end to end. Measured against
sops 3.13.3: bare C<false> is C<type:bool>, but C<"false">, C<"true">, C<"1">,
C<"0">, C<"007"> and C<"1.50"> are B<all> C<type:str>.

The corollary is that Perl's own literals decide the type for a structure
passed straight to L<File::SOPS/encrypt>: C<5432> is C<int> and C<'5432'> is
C<str>. Perl has no native boolean, so C<type:bool> needs a
L<JSON::PP::Boolean> or an explicit C<type>; the string C<'true'> is a string.

Note that Perl marks a scalar as numeric B<in place> the first time it is used
in numeric context, so C<if ($cfg-E<gt>{port} E<gt> 1024)> before encrypting
turns C<'8080'> into an C<int>. See
L<docs/adr/0002|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0002-value-type-comes-from-the-scalar-not-from-a-pattern.md>.

=cut

# Go's int is int64 on every platform SOPS ships for, and its range is what
# strconv.Atoi accepts on the way back in. Written as MAX-1 plus one so the
# literal itself never has to survive as a negative UV.
my $INT64_MAX = 9223372036854775807;
my $INT64_MIN = -9223372036854775807 - 1;

# Range test on the DECIMAL TEXT, not on a numified copy. -9223372036854775809
# rounds to exactly -2**63 as a double, so `0 + $s >= $INT64_MIN` says yes to a
# value Go says no to. $s has already been matched against /\A[+-]?[0-9]+\z/.
sub _decimal_fits_int64 {
    my ($s) = @_;
    my ($sign, $digits) = $s =~ /\A([+-]?)0*([0-9]+)\z/;
    my $limit = $sign eq '-' ? '9223372036854775808' : '9223372036854775807';
    return 0 if length($digits) > length($limit);
    return 0 if length($digits) == length($limit) && $digits gt $limit;
    return 1;
}

sub assert_representable {
    my ($class, $value) = @_;
    return 1 unless defined $value;

    # karr #67: an unblessed reference in an encrypted slot would be
    # stringified as 'SCALAR(0x...)' / 'ARRAY(0x...)' / 'HASH(0x...)' /
    # 'CODE(0x...)' -- a heap address that differs per process run -- and
    # value_to_bytes would feed that same address into the MAC digest. The
    # document verifies (the doc and the digest agree on the address), but the
    # stored value is unrecognisable and impossible to reproduce on a later
    # read. Refused here, the same shape as the int64 check below. A blessed
    # object passes: ADR 0008 measured that an encrypted Math::BigFloat, an
    # object overloading "" and a qr// all round-trip correctly -- they have a
    # stringification the caller chose.
    if (ref $value) {
        return 1 if blessed($value);
        croak "cannot encrypt an unblessed " . ref($value)
            . " reference; the SOPS digest covers the reference's heap "
            . "address (e.g. SCALAR(0x...)), which differs per run, and "
            . "storing that as an encrypted value is almost never what the "
            . "caller means. Pass a string (the value the ref was holding, "
            . "or its stringification), or a blessed object whose "
            . "stringification is the value you mean.";
    }

    # karr #59: a non-finite float (NaN, +Inf, -Inf) has no agreed form on
    # the wire. value_to_bytes writes +Inf / -Inf / NaN -- the same text
    # Yo's strconv.FormatFloat produces -- but neither emitter can carry it:
    # Cpanel::JSON::XS writes it as `null` (the document is silently rounded),
    # JSON::XS writes bare `inf` (invalid JSON, sops refuses with "invalid
    # character i"), and YAML::XS writes bare `Inf` (self-MAC OK, sops -d exit
    # 51). All three put a file on disk that no implementation can read back.
    # Refused here, the same shape as the ref and int64 checks. Reading is
    # unaffected -- a type:float plaintext of +Inf or NaN is accepted by
    # _deserialize_value today (karr #59's request, and Go writes it) and stays
    # accepted: assert_representable is encrypt-side only.
    if (_sv_kind($value) eq 'float') {
        my $inf = 9**9**9;
        my $form
            = $value != $value              ? 'NaN'
            : $value == $inf                ? '+Inf'
            : $value == -$inf               ? '-Inf'
            :                                  undef;
        croak "value is a non-finite float ($form) and no SOPS document can "
            . "carry it: the JSON emitter writes it as null, the YAML emitter "
            . "writes bare Inf / NaN, and what one writes the other cannot "
            . "read back. sops itself writes type:float +Inf / NaN, but only "
            . "because Go has a strconv.FormatFloat rule that does not survive "
            . "the round-trip through Perl's encoder. Store the value as a "
            . "string (type:str), which is written verbatim and round-trips "
            . "exactly through both implementations."
            if defined $form;
    }

    return 1 unless _sv_kind($value) eq 'int';

    # The same decimal value_to_bytes would write, tested by the same rule the
    # decrypt side uses -- so what we refuse to write is exactly what we refuse
    # to read.
    return 1 if _decimal_fits_int64('' . (0 + $value));

    croak
        "value is an integer outside the range the SOPS int type can hold "
      . "($INT64_MIN .. $INT64_MAX, Go's int64). Perl's integers are wider "
      . "than Go's, and there is no SOPS wire form that preserves this one: "
      . "written as type:int, sops refuses the file with "
      . "\"strconv.Atoi: value out of range\"; written as type:float it would "
      . "silently lose digits. Pass it as a string to store it exactly.";
}

=method assert_representable

    File::SOPS::Encrypted->assert_representable($value);

Class method. Dies if C<$value> is something no SOPS document can carry, and
returns true otherwise. Called for every leaf L<File::SOPS/encrypt> is about to
write -- encrypted or not -- before anything is emitted.

There are three such values today:

=over 4

=item B<An unblessed reference.> C<\1>, C<\$x>, C<\@arr>, C<\%hash>, C<sub {}>.
B<detect_type> calls a reference C<str>, so L</value_to_bytes> would digest
its stringification -- C<SCALAR(0x...)>, C<ARRAY(0x...)>, C<HASH(0x...)> or
C<CODE(0x...)>, the ref's heap address. _encrypt_tree would feed that same
address into the encrypted slot, and the document would verify against itself
(doc and digest agree on the address) but store a value that differs per run
and is meaningless on a later read. The pre-fix code wrote the file silently
and the caller had no reason to notice; that is the defect karr #67 exists to
close. A blessed object B<passes>: ADR 0008 measured that an encrypted
L<Math::BigFloat>, an object overloading C<"">, and a L<Regexp> all
round-trip correctly today -- they have a stringification the caller chose,
which is exactly what an encrypted slot carries. The exception is the same
class B<detect_type> uses for the digest, which is C<blessed($v)> and so
covers any subclass: the encrypted-slot rule and the unencrypted-slot guard
asked the same question in different ways and the encrypted slot is the
looser one.

=item B<A non-finite float:> C<NaN>, C<+Inf>, C<-Inf>. L</value_to_bytes>
writes them as C<NaN> / C<+Inf> / C<-Inf> -- the same text Go's
C<strconv.FormatFloat> produces -- but no emitter can carry it: Cpanel's
JSON encoder writes C<null> (the document is silently rounded), JSON::XS
writes bare C<inf> (invalid JSON, sops refuses with C<invalid character i>),
and YAML::XS writes bare C<Inf> / C<NaN> (self-MAC OK, sops -d exit 51).
All three put a file on disk nothing can read back. The pre-fix code wrote
the file anyway, and the caller had no reason to notice -- that is the
defect karr #59 exists to close. Store the value as a B<string> instead --
that is C<type:str>, written verbatim, and the same number (or its
deliberate stringification) is round-tripped exactly through both
implementations. Reading is unaffected: a C<type:float> plaintext of
C<+Inf> or C<NaN> is accepted by L</_deserialize_value> today, and sops
itself writes such a value, so the read path has to keep accepting it.

=item B<An integer outside Go's C<int64> range.> Perl's integers reach
C<2**64-1>, Go's C<int> stops at C<2**63-1>, and the reference implementation
writes C<type:int> only within that range. Measured against sops 3.13.3, a
wider integer produces a document it will not read:

=over 4

=item * encrypted, it is C<type:int> with a plaintext C<strconv.Atoi> rejects
-- C<sops -d> stops with C<value out of range>

=item * unencrypted, it reaches the document verbatim, and C<sops -d> either
refuses to walk it (YAML: C<unknown type: uint64>) or recomputes the digest
from the C<float64> it parsed and reports C<MAC mismatch> (JSON)

=back

sops's own JSON store truncates such an integer to a C<float64> and writes the
truncated value. File::SOPS does not: a value silently losing digits on its way
through a library whose job is to preserve it is the defect this method exists
to prevent. Store the digits as a B<string> instead -- that is C<type:str>,
written verbatim, and it round-trips exactly through both implementations.

=back

This is a B<write>-side rule only. Reading is unaffected: sops's truncated
C<12345678901234567000> parses back as a Perl integer above C<int64>, and
L</value_to_bytes> must still hash it as those digits or a legitimate sops
document would fail verification. An older file this library itself wrote
under 0.003 with an unblessed ref in an encrypted slot is read back as the
heap address that was stored, which is unrecognisable but verifiable; the
guard refuses the B<new> write and leaves the read path alone.

=cut

sub value_to_bytes {
    my ($class, $value, $type) = @_;
    return '' unless defined $value;
    $type //= $class->detect_type($value);

    # SOPS uses Titlecase for bools: "True" / "False"
    if (blessed($value) && $value->isa('JSON::PP::Boolean')) {
        return $value ? 'True' : 'False';
    }
    if ($type eq 'bool') {
        # Explicit rule, symmetric with _deserialize_value, for a caller who
        # forced type => 'bool' on a plain scalar. The old test ended in
        # "|| $value", a bare Perl truthiness fallback, so the non-empty
        # string 'false' came out as 'True'.
        return (lc("$value") eq 'true' || "$value" eq '1') ? 'True' : 'False';
    }

    # SOPS's binary type is not text, so there is nothing to encode. Mirrors
    # _deserialize_value, which does not decode it either. This is also the
    # only way a caller can say "these really are bytes" -- see the encoding
    # note on _utf8_bytes.
    return "$value" if $type eq 'bytes';

    # Everything else is decided by what the scalar IS, not by the label:
    # a number is written in the canonical form Go would re-derive from it,
    # a string is written verbatim.
    my $kind = ref($value) ? 'str' : _sv_kind($value);
    my $str
        = $kind eq 'int'   ? '' . (0 + $value)
        : $kind eq 'float' ? _float_bytes($value)
        :                    "$value";

    return _utf8_bytes($str);
}

=method value_to_bytes

    my $bytes = File::SOPS::Encrypted->value_to_bytes($value);
    my $bytes = File::SOPS::Encrypted->value_to_bytes($value, $type);

Class method. Returns the wire plaintext for a value: the bytes that get
encrypted, and the bytes the MAC digest is taken over. Those are the same
bytes by definition, which is why there is one method and not two -- the
ciphertext and the digest disagreeing is this distribution's signature defect,
and it is invisible from inside Perl because both sides are then consistently
wrong.

C<$type> defaults to L</detect_type>. It selects the boolean spelling and
nothing else; the bytes always come from the value:

=over 4

=item * a boolean is C<True> or C<False> (SOPS titlecases them)

=item * an integer is its canonical decimal form -- Perl's C<0 + $value>,
which is what Go's C<strconv.Itoa> writes

=item * a float is C<strconv.FormatFloat($v, 'f', -1, 64)>: the shortest
decimal that round-trips, in positional notation and never in exponent
notation. Measured against sops 3.13.3, which stores C<1.0> as C<1>, C<1.50>
as C<1.5>, C<.5> as C<0.5> and C<1e20> as C<100000000000000000000>

=item * anything else, including every string, is written verbatim

=back

C<type =E<gt> 'bytes'> is the one type that is B<not> UTF-8 encoded on its way
out, mirroring L</decrypt_value>, which does not decode it either. It is
SOPS's binary type, so it is not text, and it is the only way to tell this
module that an unflagged scalar really is a byte string rather than a Perl
string that happens to be stored as bytes -- a distinction Perl itself does not
make. Everything else is encoded unconditionally; see L</encrypt_value>.

So a Perl string is never renormalised -- C<'007'> stays C<007> and C<'1.50'>
stays C<1.50> -- while a Perl number always is. A document that gets this
wrong is not merely odd-looking: Go recomputes the MAC by re-serializing the
value it parsed out of the plaintext, so C<007> stored under C<type:int>
digests as C<7> on the reading side and C<sops -d> rejects the whole file.

Character strings are UTF-8 encoded on the way out, by the same flag-guarded
rule L</encrypt_value> documents.

=cut

# Canonical texts that no emitter has an agreed wire form for, left exactly as
# they are today. YAML's -0 resolves back to an integer zero, and JSON has no
# representation for the non-finite values at all -- both are karr #62, with a
# different answer per format, and folding them in here would move bytes for
# values this walk is not about. See docs/adr/0006.
my $NO_AGREED_FORM = qr/\A(?:NaN|[+-]Inf|-0)\z/;

sub canonical_float_tree {
    my ($class, $tree, %args) = @_;
    my $roundtrips = $args{roundtrips} // croak "roundtrips callback required";
    my $carrier    = $args{carrier}    // croak "carrier callback required";
    my $reject     = $args{reject};

    return _canonical_floats($tree, $roundtrips, $carrier, $reject, []);
}

# WHERE a rejected leaf sits, in the shape File::SOPS::_at_path already uses for
# the MAC walk's messages -- keys colon-joined, '(document root)' for the empty
# path. One copy of the convention, here, rather than one per reject callback:
# a caller who has to learn two notations for the same document is the reason
# karr #68 exists at all.
#
# Array INDICES are carried, where the MAC's own _sorted_leaves drops them --
# that omission is the AAD rule (SOPS gives every element of an array its
# parent's path), and this string is a diagnostic, never an AAD. `items:3:key`
# is the same shape _extract_path reports a navigation failure at.
sub _leaf_location {
    my ($path) = @_;
    return ($path && @$path) ? join(':', @$path) : '(document root)';
}

sub _canonical_floats {
    my ($node, $roundtrips, $carrier, $reject, $path) = @_;

    return { map { $_ => _canonical_floats($node->{$_}, $roundtrips, $carrier,
                                           $reject, [ @$path, $_ ]) }
                 keys %$node }
        if ref $node eq 'HASH';
    return [ map { _canonical_floats($node->[$_], $roundtrips, $carrier,
                                     $reject, [ @$path, $_ ]) }
                 0 .. $#$node ]
        if ref $node eq 'ARRAY';

    # Blessed leaves (JSON::PP::Boolean) and anything else with a reference are
    # not floats and must reach the emitter untouched -- unless the caller's
    # emitter says it cannot write this one faithfully.
    if (ref $node) {
        $reject->($node, _leaf_location($path)) if $reject;
        return $node;
    }
    return $node unless defined $node;
    return $node unless _sv_kind($node) eq 'float';

    # THE one conversion. This is the same method, on the same scalar, that the
    # MAC digest goes through -- not a second rendering that happens to agree
    # today. Do not inline a copy of it here.
    my $text = __PACKAGE__->value_to_bytes($node);
    return $node if $text =~ $NO_AGREED_FORM;

    # The emitter's own output already comes back as this number: leave the
    # scalar alone, so the document keeps the bytes it has always had.
    return $node if $roundtrips->($node, $text);

    return $carrier->($node, $text);
}

=method canonical_float_tree

    my $tree = File::SOPS::Encrypted->canonical_float_tree(
        $data,
        roundtrips => sub { my ($value, $text) = @_; ... },
        carrier    => sub { my ($value, $text) = @_; ... },
    );

Class method. Returns a B<copy> of C<$data> in which every float leaf that the
caller's emitter cannot write faithfully has been replaced by a carrier holding
the canonical decimal from L</value_to_bytes> -- the same text the MAC digest
covers.

This exists because the digest and the document have to state the same number.
L</value_to_bytes> writes a float as Go's
C<strconv.FormatFloat($v, 'f', -1, 64)>, up to 17 significant digits, while
every emitter in this distribution renders a double with 15. For a value that
needs 16 or 17 the document said one number and the digest covered another, and
the file failed its own MAC. See
L<docs/adr/0006|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0006-floats-are-emitted-in-a-form-that-parses-back-to-the-same-double.md>.

Two callbacks, both given the original scalar and its canonical text:

=over 4

=item * C<roundtrips> answers whether the emitter's own rendering of this value
parses back to the same double. It must B<measure> that -- emit and reparse --
rather than model it, which is what keeps this correct if an emitter changes.
Returning true leaves the scalar untouched, so a value the emitter already
writes faithfully keeps exactly the bytes it has today.

=item * C<carrier> returns the replacement, and is format-specific: L<YAML::XS>
emits a L<Scalar::Util/dualvar>'s string half verbatim and unquoted, while
every JSON backend quotes it and needs a L<Math::BigFloat> under
C<allow_bignum> instead.

=item * C<reject> is optional and is called as C<< $reject->($leaf, $where) >>
for every blessed or otherwise referenced leaf, so a handler can refuse one its
emitter cannot write as the text the digest covers. C<$where> is that leaf's
key path, colon-joined, or the string C<(document root)> -- the same shape the
MAC walk's own messages use, with array indices carried because this is a
diagnostic and not an AAD. Both handlers put it in front of their message, so
one bad leaf in a large document is named rather than searched for (karr #68).
L</detect_type> calls every reference but a
L<JSON::PP::Boolean> C<str>, so the digest covers its stringification, and an
emitter that writes something else instead produces a document that fails its
own MAC. Both handlers use it: L<File::SOPS::Format::YAML> refuses every
reference except an exact L<JSON::PP::Boolean>, because L<YAML::XS> writes the
rest as C<!!perl/> tagged structures; L<File::SOPS::Format::JSON> refuses
every reference except an exact L<JSON::PP::Boolean>, for the same reason --
under C<allow_bignum> Cpanel::JSON::XS writes a Math::BigFloat or Math::BigInt
as a bare number and an unblessed C<\1> / C<\0> as bare C<true> / C<false>.
Both messages name the class or ref kind and never the value; the exception
is the exact class (a C<JSON::PP::Boolean> subclass is refused the same way
C<detect_type> accepts it -- the guard's question is what the emitter can
write). See
L<docs/adr/0008|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0008-a-leaf-the-emitter-cannot-write-as-what-the-digest-covers-is-refused.md>
(karr #65 on the YAML side, karr #66 closing the known gap on the JSON side).

=back

The canonical text is B<not> recomputed by the caller and must not be: a second
conversion is how the ciphertext and the digest came to disagree in the first
place, and it is invisible from inside Perl because both sides are then
consistently wrong.

Call this at B<emit time, on a copy, after the digest has been taken>. A
carrier is a blessed reference or a dualvar, so L</detect_type> would call it
C<str> and the walk that computes the MAC must never see one.

C<NaN>, C<+Inf>, C<-Inf> and C<-0> are returned unchanged. Those have no wire
form both implementations agree on, the answer differs per format, and they are
tracked separately.

=cut

# Which of Perl's three scalar shapes this is, read off the SV rather than off
# its text. The PUBLIC IOK/NOK flags deliberately, not the private pIOK/pNOK
# that JSON::PP's number heuristic uses: the private ones are set by merely
# READING a string numerically, which would make a caller's `$h{port} > 1024`
# rewrite the document's type fields. The public ones are set less often, but
# not never -- see the contamination note in detect_type's POD.
#
# Nothing on the encrypt path numifies a leaf before this runs. The one thing
# that touches it is _encrypt_tree's `$node eq ''`, which is a string
# comparison: it can set pPOK on a number, never IOK or NOK on a string.
#
# \$_[0] aliases the caller's scalar instead of copying it. Copying preserves
# the flags too, but the alias makes that independent of how Perl chooses to
# implement assignment.
sub _sv_kind {
    my $flags = B::svref_2object(\$_[0])->FLAGS;
    return 'int'   if $flags & B::SVf_IOK();
    return 'float' if $flags & B::SVf_NOK();
    return 'str';
}

# strconv.FormatFloat(v, 'f', -1, 64).
#
# 'f' means positional notation, never an exponent. -1 means the shortest
# digit string that parses back to the same float64. Perl's own
# stringification is neither: it is roughly %.15g, so it exponentiates 1e20
# and truncates 0.1+0.2 to 0.3, and both of those disagree with what the Go
# side re-derives when it recomputes the MAC.
sub _float_bytes {
    my ($n) = @_;

    my $inf = 9**9**9;
    return 'NaN' if $n != $n;                       # only NaN is unequal to itself
    return $n > 0 ? '+Inf' : '-Inf' if $n == $inf || $n == -$inf;

    my $g;
    for my $precision (1 .. 17) {                   # 17 always round-trips a double
        $g = sprintf('%.*g', $precision, $n);
        last if $g + 0 == $n;
    }

    return _expand_exponent($g);
}

# "1.5e-07" -> "0.00000015", "1e+20" -> "100000000000000000000".
sub _expand_exponent {
    my ($s) = @_;
    return $s unless $s =~ /\A([+-]?)(\d+)(?:\.(\d+))?[eE]([+-]?\d+)\z/;

    my ($sign, $int, $frac, $exp) = ($1, $2, $3 // '', $4 + 0);
    my $digits = $int . $frac;
    my $point  = length($int) + $exp;   # where the decimal point lands in $digits

    return $sign . '0.' . ('0' x -$point) . $digits         if $point <= 0;
    return $sign . $digits . ('0' x ($point - length $digits))
        if $point >= length $digits;
    return $sign . substr($digits, 0, $point) . '.' . substr($digits, $point);
}

# The plaintext's crossing from characters into bytes. CryptX takes bytes, so a
# character string arriving at the cipher is either downgraded to Latin-1
# (U+0080..U+00FF) or dies outright with "Wide character in subroutine entry"
# (above U+00FF).
#
# UNCONDITIONAL, by the same argument as _aad_bytes below: for a string whose
# characters are all under U+0100 Perl's UTF-8 flag is storage, not meaning,
# and neither emitter consults it -- YAML::XS::Dump and Format::JSON's encoder
# (utf8) write "caf\x{e9}" as caf\xc3\xa9 whichever way Perl is holding it.
# Under the old flag-guarded rule an unflagged "caf\x{e9}" reached the wire as
# caf\xe9, which is not UTF-8 at all, with two measured consequences: an
# UNENCRYPTED value went into the document as UTF-8 and into the digest as
# Latin-1, so the file failed its own MAC and sops reported "MAC mismatch";
# and an encrypted one was self-consistent but came back out of `sops -d` as
# `!!binary Y2Fm6Q==` rather than as café. See ADR 0003.
#
# The cost is a caller who passes UTF-8 BYTES rather than characters: their
# plaintext is now double-encoded, because Perl cannot tell that scalar apart
# from an unflagged Latin-1 string and the ambiguity has to be resolved the
# same way everywhere. Note the emitters were already double-encoding such a
# caller's unencrypted values, so this was never a whole guarantee. A caller
# who really means bytes says so with type => 'bytes', which skips this
# entirely (see value_to_bytes).
sub _utf8_bytes {
    my ($str) = @_;
    return $str unless defined $str;
    utf8::encode($str);   # no-op for ASCII, correct for the rest
    return $str;
}

# The AAD's crossing, which has always been unconditional and is where the rule
# above came from.
#
# The AAD is derived from the document's key path, and the key it names is
# written to the file by YAML::XS::Dump / Format::JSON's encoder (utf8). Both of
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
# construction. The value conversion above now says the same thing about the
# same scalar; a document cannot hold two answers to that question.
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

    # Go reads this back with strconv.Atoi, so int64 is the whole range, and
    # anything outside it stops sops with "value out of range". int() would
    # instead route it through a double and hand back a DIFFERENT number
    # without saying so -- the silent half of the same defect. Refuse, and
    # leave decrypt_bytes as the way to recover the digits.
    if ($type eq 'int') {
        croak "type:int plaintext is not an integer"
            unless $data =~ /\A[+-]?[0-9]+\z/;
        croak "type:int plaintext is outside the int64 range "
            . "($INT64_MIN .. $INT64_MAX); sops refuses such a value too "
            . "(\"strconv.Atoi: value out of range\"). "
            . "Use decrypt_bytes to recover the plaintext."
            unless _decimal_fits_int64($data);
        return 0 + $data;
    }
    # Go reads this back with strconv.ParseFloat, which fails on anything that
    # is not a number. Perl's + 0.0 turns it into 0 and says nothing.
    if ($type eq 'float') {
        croak "type:float plaintext is not a number"
            unless $data =~ /\A[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)
                             (?:[eE][+-]?[0-9]+)?\z/x
                || $data =~ /\A[+-]?(?:Inf(?:inity)?|NaN)\z/i;
        return $data + 0.0;
    }

    if ($type eq 'bool') {
        # SOPS uses "True"/"False" (titlecase)
        # Return JSON::PP::Boolean to preserve bool type through YAML/JSON serialization
        return (lc($data) eq 'true' || $data eq '1') ? JSON->true : JSON->false;
    }

    # str, time and comment are all text on the wire, and all come back as the
    # text they are.
    #
    #   time    -- Go stores a time.Time as RFC3339, which is what the
    #              plaintext holds. Measured against sops 3.13.3: a bare
    #              `2026-08-09T12:00:00Z` and a bare `2026-08-09` both become
    #              type:time, the latter as `2026-08-09T00:00:00Z`. Perl has no
    #              native date, and handing back a DateTime would make this
    #              module a data-model library, so the RFC3339 string is the
    #              value. It is also what the YAML and JSON parsers give the
    #              caller for the same scalar when it is NOT encrypted, so the
    #              document reads consistently either way.
    #   comment -- a YAML comment sops writes as `#ENC[...]` on its own line.
    #              YAML::XS drops comments, so File::SOPS never meets one
    #              through a document; this is here for a direct caller.
    #
    # utf8::decode leaves the scalar alone and returns false if the plaintext
    # is not valid UTF-8, which is the graceful direction -- such a value comes
    # back as the bytes it was.
    if ($type eq 'str' || $type eq 'time' || $type eq 'comment') {
        utf8::decode($data);
        return $data;
    }

    # Everything else used to fall through to the branch above and return the
    # raw string, so a document this library could not actually interpret
    # looked like it had been read. Go stops here, and so do we.
    croak "Unknown datatype: $type";
}

sub _encode_base64_oneline {
    my ($data) = @_;
    my $encoded = encode_base64($data, '');
    return $encoded;
}

# The only source of random bytes in this distribution. Both things that must
# never repeat come from here: the per-value GCM nonce above, and the data key
# in File::SOPS::encrypt, which calls this directly. It lived in both files
# once, byte-identical; nothing made them stay that way.
#
# The length check is not defensive noise, and it is the reason this is a sub
# at all rather than a bare call. A short return is invisible to everything
# downstream of it -- measured here against CryptX 0.087 and sops 3.13.3:
#
#   * A data key truncated to 16 or 24 bytes is a valid AES-128 or AES-192
#     key. Encryption succeeds, our own decrypt succeeds, and `sops -d`
#     accepts the document and exits 0. The key is silently weaker than the
#     one every part of the system believes it is using, and no error exists
#     anywhere to say so.
#   * An IV truncated to anything from 1 to 31 bytes is accepted by GCM
#     identically at both ends, because the nonce length is not fixed by the
#     construction. A 1-byte nonce also round-trips through `sops -d` with
#     exit 0 -- from an 8-bit space, so it repeats under the same data key
#     within a couple of hundred values, which is the one thing GCM does not
#     survive.
#
# Only two short lengths fail on their own: a data key that is not 16, 24 or
# 32 bytes, and an IV of exactly 0 bytes. Both fail inside CryptX as "FATAL:
# ccm_memory failed: Invalid key size" attributed to the gcm call, naming
# neither the CSPRNG nor which of the two values was short. Nothing else in
# either implementation looks at these lengths, so this is the only place that
# can look at them.
#
# Crypt::PRNG is not optional and there is no fallback: it ships in CryptX,
# the same distribution as the Crypt::AuthEnc::GCM this module already loads at
# compile time, so an install missing it cannot compile this file. The
# /dev/urandom branch that used to stand here was unreachable, and if it had
# ever been reached it would have downgraded a seeded CSPRNG to an unchecked
# read without telling anyone.
sub _random_bytes {
    my ($length) = @_;

    my $bytes = Crypt::PRNG::random_bytes($length);

    # Lengths only. The bytes themselves are the data key or the nonce, and an
    # error message is something a user pastes into a bug report.
    croak "Refusing to use the result: Crypt::PRNG::random_bytes($length) "
        . "returned "
        . (defined $bytes ? length($bytes) . " bytes" : "undef")
        . ". A wrong length here becomes a data key or a GCM nonce of that "
        . "length, which neither this implementation nor sops rejects."
        unless defined $bytes && length($bytes) == $length;

    return $bytes;
}

=head1 SEE ALSO

=over 4

=item * L<File::SOPS> - Main SOPS interface

=item * L<Crypt::AuthEnc::GCM> - AES-GCM implementation from CryptX

=back

=cut

1;
