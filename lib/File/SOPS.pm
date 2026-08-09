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

=item * B<Encryption rules> - C<unencrypted_suffix> (C<_unencrypted> by
default), C<encrypted_suffix>, C<unencrypted_regex> and C<encrypted_regex>
choose which values get encrypted; the rest stay readable but are still
covered by the MAC. See L</Choosing what gets encrypted>

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
which is neither encoded on the way in nor decoded on the way out, because it
is not text. See L<File::SOPS::Encrypted/value_to_bytes>.

=head3 The boundary is characters, and it does not read Perl's UTF-8 flag

B<Do not hand C<encrypt> UTF-8 bytes.> Decode them first:

    utf8::decode($value);              # or read the file with an :encoding layer

Everything that crosses to the wire -- the value, and the key path that forms
its AAD -- is UTF-8 encoded B<unconditionally>. Perl's UTF-8 flag is not
consulted, because below U+0100 it is a storage detail and not a statement
about meaning: C<"caf\x{e9}"> may be held as one byte or as two, Perl considers
both the same string, and both serializers write it to the file as
C<caf\xc3\xa9> either way. A rule that read the flag would disagree with the
bytes our own emitter wrote, and a document that disagrees with itself fails
its own MAC.

Prior to 0.003 the value was encoded only when the flag was set, so an
unflagged C<"caf\x{e9}"> reached the wire as the single byte C<\xe9>. With
C<unencrypted_suffix> -- on by default -- such a document failed its own MAC
and C<sops -d> reported C<MAC mismatch>; when the value was encrypted the
document was self-consistent but C<sops -d> handed the value back as
C<!!binary Y2Fm6Q==> rather than as C<café>. Passing UTF-8 bytes appeared to
work in those releases, and for encrypted values it did; for unencrypted ones
the emitter double-encoded them and the document already failed verification.
See
L<docs/adr/0003|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0003-value-encoding-is-unconditional-like-the-aad.md>.

=head2 Value types

B<A value's C<type:> on the wire is decided by what the value is, never by
what its text looks like.> A Perl string encrypts as C<type:str> however
numeric or boolean it reads:

    File::SOPS->encrypt(data => { v => 'true' })  # type:str,   plaintext true
    File::SOPS->encrypt(data => { v => '007'  })  # type:str,   plaintext 007
    File::SOPS->encrypt(data => { v => '1.50' })  # type:str,   plaintext 1.50
    File::SOPS->encrypt(data => { v => 5432   })  # type:int,   plaintext 5432
    File::SOPS->encrypt(data => { v => 1.50   })  # type:float, plaintext 1.5
    File::SOPS->encrypt(data => { v => JSON->true })  # type:bool, plaintext True

This is the rule the reference implementation follows -- it types a value by
what the YAML/JSON parser returned, so a quoted scalar is a string -- and
L<YAML::XS> and L<JSON::MaybeXS> preserve the same distinction, so a document
loaded from a file keeps the types the file gave it. Perl has no native
boolean, so C<type:bool> requires C<JSON-E<gt>true>/C<JSON-E<gt>false> or a
C<true>/C<false> loaded from YAML or JSON.

Prior to 0.003 the type was guessed by pattern-matching the value's text. That
turned C<'true'> into a boolean and C<'007'> into the integer 7 on the way
back out, and -- because the reference implementation renormalises a numeric
plaintext when it recomputes the MAC, C<007> to C<7> and C<1.50> to C<1.5> --
made C<sops -d> reject any document containing such a value outright.

The full rule, the caller-visible round trips it changes, and the one case
where Perl's flags can be contaminated by the caller are in
L<File::SOPS::Encrypted/detect_type> and
L<File::SOPS::Encrypted/value_to_bytes>.

=head3 Integers are Go's int64, and Perl's are wider

Perl's integers reach C<2**64-1>; the SOPS C<int> type is Go's C<int64> and
stops at C<2**63-1>. L</encrypt> B<dies> rather than write an integer outside
that range, and L</decrypt> dies rather than read one, because there is no wire
form that preserves it: C<type:int> makes C<sops -d> stop with C<strconv.Atoi:
value out of range>, and C<type:float> -- what sops's own JSON store falls back
to -- silently drops digits. Pass such a value as a B<string>; that is
C<type:str>, written verbatim, and it survives both implementations intact.
See L<File::SOPS::Encrypted/assert_representable>.

=head3 Saying what a value is

There is no per-leaf type argument to L</encrypt>, and none is needed: the
scalar is the type, so you say what a value is by handing over the scalar that
says it.

    $data->{port}  = "$data->{port}";   # type:str
    $data->{port}  = 0 + $data->{port}; # type:int
    $data->{ratio} = 0.0 + $data->{ratio};  # type:float
    $data->{flag}  = JSON->true;        # type:bool

The case that makes this worth spelling out is the one
L<File::SOPS::Encrypted/detect_type> warns about. Perl marks a string as
numeric B<in place> the first time it is read in numeric context, so

    if ($cfg->{port} > 1024) { ... }    # $cfg->{port} is now an int

turns a later C<< encrypt(data => $cfg) >> into C<type:int>. Reading a scalar
numerically sets the numeric flag but B<leaves the string alone>, so
C<< $cfg->{port} = "$cfg->{port}" >> puts it back exactly -- type C<str> and
the original text, padding and trailing zeros included.

What that idiom cannot undo is a numeric B<assignment>:

    $cfg->{ratio} += 0;                 # '1.50' is now the number 1.5
    $cfg->{ratio} = "$cfg->{ratio}";    # type:str, but the text is '1.5'

Here the scalar's string really was replaced, by your code, before this module
saw it. No argument to C<encrypt> could recover C<1.50> either -- a type
override would write the same C<1.5> under a different label -- so the value
has to be re-read from wherever it came from.

=head2 Multi-document YAML

B<Not supported, and refused rather than truncated.> A YAML file holding more
than one document (separated by C<--->) makes L</encrypt_file>, L</decrypt>,
L</extract> and L</rotate> die.

Until 0.003 such a file was accepted and silently reduced to its B<last>
document, so encrypting a two-document file wrote one document back and
discarded the other without an error. sops does support multi-document YAML;
what its model is, and why matching it is more than a parser change, is in
L<File::SOPS::Format::YAML/Multi-document YAML>.

=cut

my %FORMATS = (
    yaml => 'File::SOPS::Format::YAML',
    yml  => 'File::SOPS::Format::YAML',
    json => 'File::SOPS::Format::JSON',
);

# Everything that describes HOW a document gets encrypted, as opposed to what
# gets encrypted or for whom. encrypt and encrypt_file must accept exactly the
# same set or the file API silently offers less than the string API does.
my @ENCRYPTION_OPTIONS = (
    @File::SOPS::Metadata::ENCRYPTION_RULES,
    'mac_only_encrypted',
    'metadata',
);

sub encrypt {
    my ($class, %args) = @_;
    my $data       = $args{data}       // croak "data required";
    my $recipients = $args{recipients} // croak "recipients required";
    my $format     = $args{format}     // 'yaml';

    croak "data must be a hash ref" unless ref($data) eq 'HASH';
    croak "recipients must be an array ref" unless ref($recipients) eq 'ARRAY';
    croak _sops_key_reserved('data') if exists $data->{sops};

    # Generate random 256-bit data key
    my $data_key = _random_bytes(32);

    # Create metadata
    my $metadata = _metadata_for_encrypt(\%args);
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

        # optional, at most ONE of these four
        unencrypted_suffix => '_unencrypted',
        encrypted_suffix   => '_enc',
        unencrypted_regex  => '^public_',
        encrypted_regex    => '^secret_',

        # optional, carry another document's rules forward
        metadata           => $metadata,
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

B<Dies if C<data> has a top-level C<sops> key.> That name is reserved for the
metadata section; there is nowhere else to put the metadata, so a document
using it cannot be encrypted. Until 0.003 the user's value was silently
replaced by the metadata -- and since the digest had already covered it, the
resulting document failed its own MAC on the next read. sops refuses such a
file too, with exit code 203, and its advice applies here: rename the entry.

Supported formats: C<yaml>, C<yml>, C<json>.

C<mac_only_encrypted> is the equivalent of the reference implementation's
C<--mac-only-encrypted>: it restricts the MAC to the values that are actually
encrypted, and records that choice in the C<sops> section so a reader knows
which rule to verify under. See
L<File::SOPS::Metadata/mac_only_encrypted>. Off by default, which is what sops
defaults to as well.

=head3 Choosing what gets encrypted

C<unencrypted_suffix>, C<encrypted_suffix>, C<unencrypted_regex> and
C<encrypted_regex> are the equivalents of the sops command line options of the
same names, and B<at most one of them may be given> -- passing two dies, as
does a document carrying two, because sops refuses such a file outright. Each
is matched against B<every component> of a value's key path, so
C<< encrypted_suffix => '_enc' >> encrypts everything under a C<database_enc:>
block as well as a C<password_enc:> anywhere in the document; the exact rule
is in L<File::SOPS::Metadata/should_encrypt_path>.

With none of them given, C<unencrypted_suffix> defaults to C<_unencrypted>,
which is what sops does when it creates a document. Pass
C<< unencrypted_suffix => undef >> for a document with B<no> rule, where every
value is encrypted whatever its key.

Values excluded from encryption are still covered by the MAC, so they are
authenticated even though they are readable -- unless C<mac_only_encrypted> is
on.

=head3 Reusing another document's rules

C<metadata> takes a L<File::SOPS::Metadata> object -- typically one just
parsed out of an existing file -- and starts from its encryption policy
instead of from the defaults. Only the policy is taken: the rules and
C<mac_only_encrypted>. The key material, the MAC and C<lastmodified> are
always regenerated, because a new data key is generated here and none of them
would survive it. See L<File::SOPS::Metadata/policy_args>.

Any rule passed explicitly alongside C<metadata> replaces the template's rule
rather than adding to it. This is how L</rotate> keeps a file's rules across a
key rotation.

Dies if C<metadata> carries a rule this distribution cannot apply
(C<unencrypted_comment_regex> or C<encrypted_comment_regex>, which select
values by their comment -- neither parser here keeps comments, so every value
would be classified wrongly).

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

    # Parse to get data structure.
    #
    # parse() SPLITS OFF the sops section, so by the time $data reaches
    # encrypt() an already-encrypted input is indistinguishable from a plain
    # tree of ENC[...] strings -- which encrypt would happily wrap a second
    # time. $metadata being defined is exactly "the input had a top-level sops
    # entry", which is the condition sops itself refuses on.
    my $format_class = $FORMATS{$format} // croak "Unknown format: $format";
    my ($data, $metadata) = $format_class->parse($content);
    croak _sops_key_reserved("input file '$input'") if $metadata;

    # Encrypt
    my $encrypted = $class->encrypt(
        data       => $data,
        recipients => $recipients,
        format     => $format,
        _encryption_options(\%args),
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

B<Dies if the input already has a top-level C<sops> entry> -- which is what an
already-encrypted file looks like. Until 0.003 there was no such check, and the
result destroyed data: parsing split the C<sops> section off before L</encrypt>
ever saw it, so the C<ENC[...]> strings were encrypted a second time under a
B<new> data key while the old section -- holding the key they were encrypted
with -- was discarded rather than written back. The doubly-wrapped file was
written out successfully and silently, over the original if C<output> was
omitted, and decrypting it returns the inner C<ENC[...]> strings that nothing
can now decrypt. To re-key an encrypted file use L</rotate>; to change its
contents, decrypt it first. sops refuses the same input with exit code 203.

Format is auto-detected from the filename extension (C<.yaml>, C<.yml>, C<.json>)
unless explicitly specified.

C<mac_only_encrypted>, the four encryption rules and C<metadata> are all
passed through to L</encrypt>; see L</Choosing what gets encrypted>.

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
        # Same boolean mode File::SOPS::Format::YAML dumps under, and localised
        # for the same reason: without it a JSON::PP::Boolean comes out as
        # `!!perl/scalar:JSON::PP::Boolean 1` instead of `true`. This used to
        # work only because Format::YAML set the variable process-wide at load
        # time -- an action-at-a-distance dependency, on a global that is not
        # ours to set.
        local $YAML::XS::Boolean = $File::SOPS::Format::YAML::BOOLEAN_MODE;
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

Path can be specified in two formats:

=over 4

=item * Bracket notation: C<["database"]["password"]>, C<['database']['password']>

=item * Dot notation: C<database.password>

=back

For array indices, use a bare number: C<["items"][0]> or C<items.0>. Before
0.003 the bracket parser only recognised double-quoted components, so
C<["items"][0]> matched C<items> alone and returned the whole ArrayRef.

The whole file is decrypted and MAC-verified either way. C<extract> saves you
the navigation, not the work -- it is not a cheaper L</decrypt>.
C<ignore_mac> is passed through to L</decrypt>.

C<path> is a character string and is matched against the document's keys as
characters, so a non-ASCII key is written in C<path> exactly as you would write
it in C<data>. See L</Character encoding>.

Returns whatever the path names: a decrypted scalar for a leaf, or a HashRef or
ArrayRef for a branch -- C<extract(path =E<gt> '["database"]')> returns the
whole subtree, as C<sops --extract> does.

B<Dies if the path does not exist>, at any depth, naming the component that was
not found. Before 0.003 a missing B<top-level> key returned C<undef> while a
missing nested one died, so the same mistake was silent or loud depending on
where it was made -- and C<undef> was indistinguishable from a key whose value
really is null. sops reports C<component ['nope'] not found> at every level.

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
    croak "No SOPS metadata found in '$file'" unless $metadata;

    _assert_rotatable($metadata, $file);

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

    # Re-encrypt with new data key, under the rules this document already had
    my $encrypted = $class->encrypt(
        data       => $data,
        recipients => $recipients,
        format     => $format,
        metadata   => $metadata,
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

The rotated file keeps the C<sops> section it had, apart from what a new data
key necessarily replaces. Its encryption rules, C<mac_only_encrypted> and any
field this distribution does not model -- C<shamir_threshold> and whatever a
later sops adds -- are carried over; the wrapped data keys, the MAC and
C<lastmodified> are regenerated. Until 0.003 none of that was carried: rotate
called L</encrypt>, which built fresh metadata with the defaults, so a file
that customised any of it was rewritten under the default rules.

=head3 Files rotate refuses

Rotation makes a new data key, and this distribution can only wrap one for age
recipients. A file whose C<sops> section holds key material for another
backend -- C<pgp>, C<kms>, C<gcp_kms>, C<azure_kv>, C<hc_vault> or
C<key_groups> -- is therefore B<refused> rather than rotated:

    Refusing to rotate 'shared.yaml': its sops section holds key material
    this distribution cannot re-encrypt (pgp). ...

Both alternatives are wrong and the quiet one is worse. Dropping those entries
-- which is what happened before 0.003 -- revokes access for everyone behind
them while reporting success, and the file still decrypts perfectly for
whoever runs the command, so nothing looks amiss until someone else needs it.
Keeping them would leave a wrapped copy of a key that no longer decrypts
anything. Rotate such a file with the sops CLI, which can re-encrypt for every
backend; or, if losing those recipients is the intention, say so by calling
L</decrypt> and L</encrypt> yourself.

C<ignore_mac> is passed through to L</decrypt>; rotating a file you could not
verify re-signs whatever it contained, so prefer to fail.

Returns true on success.

=cut

# Internal helpers

# The top-level `sops` key is reserved for the metadata section, and there is
# no way to encrypt a document that already uses it: serialization assigns the
# metadata into that key unconditionally, so the user's value is overwritten --
# after the digest has already covered it, which leaves a document that fails
# its own MAC on the very next read.
#
# sops refuses the same thing, before encrypting anything, with exit code 203:
#
#   The file you have provided contains a top-level entry called 'sops' [...]
#   SOPS uses a top-level entry called 'sops' to store the metadata required to
#   decrypt the file. For this reason, SOPS can not encrypt files that already
#   contain such an entry.
#
# It makes no distinction between "already encrypted" and "a user key that
# happens to be called sops" -- and neither do we, because from the outside
# they are the same document.
sub _sops_key_reserved {
    my ($what) = @_;
    return
        "$what contains a top-level 'sops' entry, which is reserved for the "
      . "SOPS metadata section. Encrypting would overwrite it and produce a "
      . "document that fails its own MAC verification. This usually means the "
      . "input is already encrypted -- use rotate to re-key it, or decrypt it "
      . "first. If it really is plaintext, rename the entry. (sops refuses "
      . "such a file too, with exit code 203.)";
}

# Say WHERE something went wrong. A generic failure in a document of a hundred
# leaves costs an afternoon; the key path costs nothing to carry and is the
# only thing that makes the message actionable.
#
# The path is made of KEYS, which a SOPS document leaves readable by design.
# Nothing derived from the plaintext, the data key or an age identity is ever
# interpolated into an error -- an error message goes to logs and bug reports,
# and a value that leaks there was not encrypted for any practical purpose.
sub _at_path {
    my ($path, $err) = @_;
    my $where = ($path && @$path) ? join(':', @$path) : '(document root)';
    return "$where: " . _reason($err);
}

# An inner error's own text, without the file and line croak appended to it --
# the outer croak supplies a fresh one. Empty $@ becomes something readable
# rather than an empty pair of parentheses.
sub _reason {
    my ($err) = @_;
    return 'no reason given' unless defined $err && length $err;
    $err =~ s/\s+at\s+\S+\s+line\s+\d+\.?\s*\z//;
    return length($err) ? $err : 'no reason given';
}

# The metadata a fresh encryption starts from. Only the encryption POLICY can
# be carried in from a caller: a new data key is about to be generated, so
# every wrapped copy of the old one, the MAC over the old values and the
# lastmodified that authenticates it are all regenerated regardless of what
# was handed over.
sub _metadata_for_encrypt {
    my ($args) = @_;

    my @given = grep { exists $args->{$_} } @File::SOPS::Metadata::ENCRYPTION_RULES;

    my %attr;
    if (defined(my $template = $args->{metadata})) {
        croak "metadata must be a File::SOPS::Metadata object"
            unless blessed($template)
                && $template->isa('File::SOPS::Metadata');

        %attr = $template->policy_args;

        # An explicit rule REPLACES the template's rather than joining it: the
        # rules are mutually exclusive, so merging the two could only ever
        # build a document sops refuses.
        delete @attr{@File::SOPS::Metadata::ENCRYPTION_RULES} if @given;
    }

    $attr{$_} = $args->{$_} for @given;
    $attr{mac_only_encrypted} = $args->{mac_only_encrypted}
        if defined $args->{mac_only_encrypted};

    my $metadata = File::SOPS::Metadata->new(%attr);
    _assert_rules_supported($metadata);

    return $metadata;
}

# Refuse to WRITE a document under a rule we cannot apply. Reading one is fine
# -- decryption is driven by which values look encrypted, not by the rule --
# but writing under a rule we ignore would leave values in plaintext that the
# rule says to encrypt, or the reverse, in a file that looks perfectly
# well-formed.
sub _assert_rules_supported {
    my ($metadata) = @_;

    for my $rule (@File::SOPS::Metadata::UNSUPPORTED_ENCRYPTION_RULES) {
        my $value = $metadata->rule_value($rule);
        next unless defined $value && length $value;
        croak "Refusing to encrypt under '$rule': it selects values by their "
            . "comment, and neither of this distribution's parsers keeps "
            . "comments, so every value would be classified wrongly. Use the "
            . "sops CLI for documents that use it.";
    }

    return 1;
}

# age is the only backend implemented here, so a document holding key material
# for another one cannot be rotated: the new data key can be wrapped for its
# age recipients and for nobody else. Both ways out of that are wrong, and the
# quiet one is the worse -- dropping the entries revokes those recipients'
# access while reporting success, and keeping them leaves a wrapped copy of a
# key that no longer decrypts anything, which fails later and further away.
sub _assert_rotatable {
    my ($metadata, $file) = @_;

    my @foreign = grep { $_ ne 'age' } $metadata->key_material_fields;
    return 1 unless @foreign;

    croak "Refusing to rotate '$file': its sops section holds key material "
        . "this distribution cannot re-encrypt (" . join(', ', @foreign) . "). "
        . "Rotation generates a new data key, so those entries would be "
        . "silently dropped and the recipients behind them would lose access. "
        . "Rotate this file with the sops CLI, or, if losing them is what you "
        . "want, say so explicitly with decrypt followed by encrypt.";
}

sub _encryption_options {
    my ($args) = @_;
    return map { $_ => $args->{$_} }
        grep { exists $args->{$_} } @ENCRYPTION_OPTIONS;
}

sub _encrypt_tree {
    my ($node, $key, $metadata, $path) = @_;

    if (ref $node eq 'HASH') {
        my %result;
        for my $k (keys %$node) {
            # The walk descends unconditionally and the rules are applied at
            # the leaf, against the WHOLE path. Deciding per level and
            # skipping the subtree is the same answer for the unencrypted
            # rules -- an excluded branch stays excluded all the way down --
            # but not for the encrypted ones, where the reference
            # implementation encrypts a leaf as soon as SOME component of its
            # path matches. Measured against sops 3.13.3 with
            # --encrypted-suffix _enc: everything under a `top_enc:` block is
            # encrypted, and a `nested_enc:` under a plain parent is too.
            $result{$k} = _encrypt_tree($node->{$k}, $key, $metadata, [@$path, $k]);
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
        # A leaf the rules exclude is written as it stands. It is still
        # covered by the MAC, so it is readable but authenticated.
        return $node unless $metadata->should_encrypt_path($path);

        # Leaf value - encrypt it
        # SOPS doesn't encrypt empty values; they stay in the document AS THEY
        # ARE. A null stays a null and an empty string stays an empty string.
        # Returning '' for both turned every null in the input into an empty
        # string, where sops leaves a null alone in YAML and in JSON alike
        # (measured: `a: null` comes back out of `sops -d` as `a: null`). The
        # digest does not notice, because Go hashes a nil as nothing and so do
        # we -- but the value the caller stored came back changed, which is the
        # one thing this library exists not to do.
        #
        # The !blessed() guard is load-bearing: JSON::PP::Boolean overloads eq,
        # and JSON->false eq '' is TRUE (while it stringifies to '0'). Without
        # the guard every false boolean was skipped here and written to the file
        # as a plaintext '', after _compute_mac had already hashed 'False' --
        # so the document failed its own MAC check on the next read. sops
        # encrypts false as type:bool with plaintext 'False'.
        return undef if !defined $node;
        return ''    if !blessed($node) && $node eq '';

        my $aad = _path_to_aad($path);
        my $enc = eval {
            File::SOPS::Encrypted->encrypt_value(
                value => $node,
                key   => $key,
                aad   => $aad,
            );
        } or croak _at_path($path, $@);
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
        my $aad = _path_to_aad($path);
        my @value = eval {
            my $enc = File::SOPS::Encrypted->parse($node);
            (scalar $enc->decrypt_value(key => $key, aad => $aad));
        };
        croak _at_path($path, $@) if $@;
        return $value[0];
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

    my $leaves = _sorted_leaves($data, [], []);

    # Every leaf this document will contain has to be one both implementations
    # can write and read back. Checked HERE, before anything is emitted,
    # because this is the only walk on the encrypt side that sees every leaf --
    # including the ones the encryption rules exclude, which reach the document
    # verbatim and are the case Go rejects hardest (a uint64 stops `sops -d`
    # outright in YAML and produces a MAC mismatch in JSON). Doing it in
    # encrypt_value would miss exactly those, and doing it in value_to_bytes
    # would also reject legitimate sops documents on the READ side, where the
    # same walk is used to verify.
    for my $leaf (@$leaves) {
        my ($path, $value) = @$leaf;
        eval { File::SOPS::Encrypted->assert_representable($value); 1 }
            or croak _at_path($path, $@);
    }

    my $mac_value = _mac_digest(
        leaves   => $leaves,
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

    # parse() now dies on a well-shaped ENC value whose base64 is not valid,
    # rather than decoding it to something shorter. Catch it here so the
    # message still says WHICH value was unreadable -- the sops section's mac,
    # not some leaf.
    my $mac_enc = eval { File::SOPS::Encrypted->parse($stored) };
    croak "Cannot parse MAC (" . _reason($@) . ") - refusing to return "
        . "unverified data (pass ignore_mac => 1 to override)"
        unless $mac_enc;

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

    # Say what was checked. Neither digest is printed: it is a SHA-512 over the
    # concatenated plaintexts of the whole document, and a document with one
    # short secret in it is brute-forceable from that hash. sops prints both;
    # we print the shape of the check instead, which is the part that tells you
    # where to look. Nothing here is derived from a value, a data key or an age
    # identity.
    croak sprintf(
        "MAC verification failed: the digest over %d leaf value%s in %s "
        . "order does not match the one stored in the sops section%s. The "
        . "document has been altered since it was written, or was written by "
        . "something that computes the digest differently. Pass ignore_mac "
        . "=> 1 to read it anyway -- what you get back is decrypted but not "
        . "authenticated.",
        scalar @$leaves,
        (@$leaves == 1 ? '' : 's'),
        ($ordered ? 'document' : 'sorted-key'),
        ($metadata->mac_only_encrypted ? ', with mac_only_encrypted set' : ''),
    ) unless $expected eq $computed;

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
        # A value that will not parse or will not decrypt used to be skipped
        # here, so the digest quietly covered a different document than the one
        # on disk and the only symptom was "MAC verification failed" with no
        # indication of which leaf caused it. That is what made every other MAC
        # defect in this distribution expensive to find. Fail at the leaf, and
        # say which leaf.
        my ($bytes, $type) = do {
            my @r = eval {
                my $enc = File::SOPS::Encrypted->parse($value);
                ($enc->decrypt_bytes(key => $data_key, aad => _path_to_aad($path)),
                 $enc->type);
            };
            croak _at_path($path, $@) if $@;
            @r;
        };
        return $bytes unless $type eq 'bool';
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
# value the second parser resolved differently.
#
# A structural disagreement between the two is REPORTED, at the path it happens
# at. It used to return the leaves collected so far, which is not "verification
# fails" but "verification is performed over part of the document" -- and since
# a missing key contributed an undef leaf, which hashes as nothing, that could
# still produce a matching digest. Even when it did fail, the only symptom was
# a bare "MAC verification failed" with no hint that half the tree had been
# dropped before the digest was taken.
sub _document_leaves {
    my ($ordered, $node, $path, $out) = @_;

    if (ref $ordered eq 'HASH') {
        croak _at_path($path, "the document has a mapping here but the parsed "
            . "tree does not, so the digest cannot be built over the same "
            . "values the file contains")
            unless ref $node eq 'HASH';

        for my $k (keys %$ordered) {
            croak _at_path([@$path, $k], "present in the document but not in "
                . "the parsed tree")
                unless exists $node->{$k};
            _document_leaves($ordered->{$k}, $node->{$k}, [@$path, $k], $out);
        }
    }
    elsif (ref $ordered eq 'ARRAY') {
        croak _at_path($path, "the document has a sequence here but the parsed "
            . "tree does not")
            unless ref $node eq 'ARRAY';
        croak _at_path($path, sprintf("the document has %d entries here but "
            . "the parsed tree has %d", scalar @$ordered, scalar @$node))
            unless @$ordered == @$node;

        _document_leaves($ordered->[$_], $node->[$_], $path, $out)
            for 0 .. $#$ordered;
    }
    else {
        # Only a CONTAINER here is a disagreement. A blessed scalar is a leaf:
        # a JSON::PP::Boolean is what the format parsers hand back for a bare
        # true/false, while the order-preserving reparse yields a plain scalar
        # for the same node -- the two disagree about the boolean's
        # REPRESENTATION, never about the document's shape, and $ordered is
        # consulted for order only.
        croak _at_path($path, "the document has a scalar here but the parsed "
            . "tree has a " . lc(ref $node))
            if ref $node eq 'HASH' || ref $node eq 'ARRAY';

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

    # LIST context, and exactly one document -- the same one-document rule the
    # format handlers enforce, held here independently rather than assumed.
    # The two parsers disagree in scalar context on a multi-document stream:
    # YAML::PP->load_string returns the FIRST document, YAML::XS::Load the
    # LAST. This walk takes its order from one and its values from the other,
    # so on such a stream it would pair up two different documents. Refusing
    # it means falling back to sorted order, which can only make verification
    # fail, never wrongly succeed.
    my @docs = eval { $ORDERED_LOADER->load_string($text) };
    return unless @docs == 1 && ref $docs[0] eq 'HASH';
    my $doc = $docs[0];

    # The metadata MAC lives here and must not hash itself. It is dropped the
    # same way the format handlers drop it -- by removing the whole sops
    # branch -- rather than by pattern-matching "mac:" in the raw text, which
    # is what used to swallow any user key ending in "mac" (hmac, webmac).
    delete $doc->{sops};

    return $doc;
}

# The MAC digest input for a value, which is by definition the same bytes the
# cipher gets. This used to be a second implementation of the type ladder and
# the value->bytes conversion, kept byte-identical to
# File::SOPS::Encrypted's by hand. It never was: when the two drifted the
# ciphertext and the digest were consistently wrong TOGETHER, so every
# self-produced file verified and only the Go binary disagreed. There is now
# one implementation, and this is a call to it.
sub _value_to_bytes {
    my ($value) = @_;
    return File::SOPS::Encrypted->value_to_bytes($value);
}

sub _extract_path {
    my ($data, $path) = @_;

    my @parts = _split_path($path);

    # Navigation failure is an error at EVERY depth. It used to be an error
    # only when nested: a missing top-level key fell through the loop and came
    # back as undef, indistinguishable from a key whose value really is null.
    # sops answers the same question the same way at every level --
    # `error truncating tree: component ['nope'] not found`, exit 1.
    my $current = $data;
    my @walked;
    for my $part (@parts) {
        my $where = @walked ? join(':', @walked) : '(document root)';

        if (ref $current eq 'HASH') {
            croak "Cannot navigate path '$path': component '$part' not found "
                . "under $where"
                unless exists $current->{$part};
            $current = $current->{$part};
        }
        elsif (ref $current eq 'ARRAY' && $part =~ /\A\d+\z/) {
            croak "Cannot navigate path '$path': index $part is out of range "
                . "at $where"
                unless $part <= $#$current;
            $current = $current->[$part];
        }
        else {
            croak "Cannot navigate path '$path': $where is not a "
                . (ref($current) eq 'ARRAY' ? "list index" : "collection")
                . ", so it has no component '$part'";
        }

        push @walked, $part;
    }

    return $current;
}

# ["database"]["password"], ['database'][0], or database.password / .items.0
#
# The bracket form used to be matched with /\["([^"]+)"\]/g, which only knows
# QUOTED keys -- so the documented ["items"][0] matched only the first
# component and extract handed back the whole arrayref instead of the element.
# An unquoted component is what an index looks like, and it is the form sops
# itself accepts: `sops -d --extract '["items"][0]'` returns the element.
sub _split_path {
    my ($path) = @_;

    unless ($path =~ /\A\[/) {
        $path =~ s/\A\.//;
        return split /\./, $path;
    }

    my @parts;
    my $rest = $path;
    while (length $rest) {
        $rest =~ s{\A \[ (?: "([^"]*)" | '([^']*)' | ([^\[\]]+) ) \] }{}x
            or croak "Cannot parse path '$path' at '$rest': expected "
                   . qq{["key"], ['key'] or [index]};
        push @parts, $1 // $2 // $3;
    }

    return @parts;
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
