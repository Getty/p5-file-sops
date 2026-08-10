package File::SOPS;
# ABSTRACT: Perl implementation of Mozilla SOPS encrypted file format

use Moo;
use Carp qw(croak);
use Cwd ();
use Fcntl qw(O_CREAT O_EXCL O_WRONLY);
use File::Basename qw(basename);
use File::Spec;
use File::Temp ();
use Scalar::Util qw(blessed);
use Text::ParseWords qw(shellwords);
use Digest::SHA qw(sha512);
# Nothing below calls encode_json, decode_json or JSON(), and namespace::clean
# strips all three from this package.
#
# This line used to be load-bearing for the WIRE FORMAT: loading JSON::MaybeXS
# here, ahead of File::SOPS::Encrypted pulling in CryptX (which loads JSON.pm,
# and with it JSON::XS), was what decided the JSON backend for the process, and
# the backends do not emit or parse the same floats. It is not that any more --
# karr #56 / docs/adr/0005 -- because Format::JSON now names Cpanel::JSON::XS
# instead of inheriting whatever the calling program happened to bind. The
# ordering here no longer reaches a document.
#
# What is left is JSON::PP::Boolean for JSON->true/false, and that comes from
# File::SOPS::Encrypted's and File::SOPS::Metadata's own `use JSON::MaybeXS`,
# in the same files as the calls that need it (all three backends bless into
# JSON::PP::Boolean, so it is backend-independent). So this line is now a
# genuinely unused import -- which is what karr #49 first claimed and could not
# act on. Removing it is the API lane's call, not a wire question.
use JSON::MaybeXS;
# Used directly by _load_creation_rules to read a .sops.yaml, which is a config
# file rather than a SOPS document and so does not go through Format::YAML.
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

    # Encrypt a file over itself, atomically
    File::SOPS->encrypt_in_place(
        file       => 'secrets.yaml',
        recipients => ['age1...'],
    );

    # Decrypt, open $EDITOR, re-encrypt
    File::SOPS->edit(
        file       => 'secrets.enc.yaml',
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

    # Take the recipients and rules from the .sops.yaml governing a file
    my %args = File::SOPS->creation_rules_for(file => 'secrets/prod.yaml');
    File::SOPS->encrypt_in_place(file => 'secrets/prod.yaml', %args);

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
L<YAML::XS> and L<Cpanel::JSON::XS> preserve the same distinction, so a
document loaded from a file keeps the types the file gave it. Perl has no native
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

=head2 How a file is written

B<Every method here that writes a file writes it atomically.> The document goes
to a temporary file in the same directory, which is then C<rename>d over the
target. Nothing ever observes a half-written document, and a failure anywhere
before the rename -- a full disk, a signal, an error from the cipher -- leaves
the file that was there exactly as it was. This holds for L</encrypt_file>,
L</decrypt_file>, L</encrypt_in_place>, L</edit> and L</rotate> alike, whether
the target already exists or not.

Until 0.003 only C<encrypt_in_place> and C<edit> did that. The other three
opened the target with C<< '>' >>, which truncates it before the first byte is
written, and then checked neither the C<print> nor the C<close> -- so a write
that ran out of disk left an empty file B<and reported success>. C<encrypt_file>
defaults C<output> to C<input> and C<rotate> always writes back over the file it
read, so in both cases the file that was destroyed was the only copy: for
C<rotate>, one whose data key had already been replaced.

=head3 What C<rename> costs

sops truncates the file and rewrites it in place. Keeping the inode is the one
thing that buys, and it costs the file if the write stops half way; on a secrets
file being replaced by a re-encryption of itself, that trade goes the other way
round. The differences that follow from it are all visible from outside:

=over 4

=item * The file gets a B<new inode>. B<Hard links to it keep the old content>
-- where sops, which rewrites the same inode, updates every link at once. A
file with C<n> links comes back with one link and the other C<n-1> still
pointing at the previous content.

=item * Replacing a file needs write permission on its B<directory>, not on the
file. A read-only file in a writable directory is refused with C<Could not
open in-place file for writing: ...: permission denied>, the same wording
C<sops -e -i> uses (measured, 3.13.3). C<chmod 0444> is a guard against these
methods. The directory, by contrast, must be writable -- a read-only
C<secrets/> is the precondition that lets C<chmod 0444> on the file mean
anything, and these methods cannot write into a directory that is not.

=item * A B<symlink> is resolved: the link is left alone and the file it points
at is replaced. sops does the same (measured, 3.13.3) -- what differs is only
that the target picks up a new inode.

=item * An existing file keeps its B<mode>; a file that has to be created gets
the mode C<< open '>' >> would have given it, C<0666> against the process
umask. That is what sops's C<--output> does as well, so a decrypted file this
writes is no more and no less protected than before -- if that is too open for
plaintext, set the umask or the mode yourself.

The match-sops decision is deliberate (karr #45): the alternative, a hard
C<0600> on every new output, would break a caller whose next step is
another process reading the file -- loudly, not silently -- and would
diverge from the reference implementation without a measurable security
gain over a umask set to 077 by the caller. L</edit> uses 0600 for its
own temporary copy, which is a different question -- that file is known
to be removed at the end of the call rather than passed on.

=back

A target that exists and is B<not a regular file> -- C</dev/stdout>,
C</dev/null>, a fifo -- is written through directly instead. There is nothing
there to protect, and renaming over it would replace the device itself with an
ordinary file. C<sops --output /dev/stdout> works, and so does passing that as
C<output> here.

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

    # Generate random 256-bit data key. The one CSPRNG in this distribution
    # lives next to the per-value nonce that shares its failure mode; see the
    # comment on File::SOPS::Encrypted::_random_bytes for why a short return
    # has to be caught there and cannot be caught anywhere else.
    my $data_key = File::SOPS::Encrypted::_random_bytes(32);

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

    my $content = _read_file($input, 'input file');

    # Parse to get data structure.
    #
    # parse() SPLITS OFF the sops section, so by the time $data reaches
    # encrypt() an already-encrypted input is indistinguishable from a plain
    # tree of ENC[...] strings -- which encrypt would happily wrap a second
    # time. $metadata being defined is exactly "the input had a top-level sops
    # entry", which is the condition sops itself refuses on.
    my ($data, $metadata) = _format_class($format)->parse($content);
    croak _sops_key_reserved("input file '$input'") if $metadata;

    # Encrypt
    my $encrypted = $class->encrypt(
        data       => $data,
        recipients => $recipients,
        format     => $format,
        _encryption_options(\%args),
    );

    _replace_file($output, $encrypted);

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
in-place (overwrites the input file) -- which is what L</encrypt_in_place>
spells out.

The output is written atomically, whether it is the input file, another file
that already exists, or a new one: the plaintext input, or whatever the output
file held before, survives a write that cannot finish. Until 0.003 it did not,
and the consequences of the C<rename> that fixed it -- a new inode, so hard
links keep the old content -- are in L</How a file is written>.

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

It dies whatever that entry holds. A B<plaintext> file using the name for its
own value -- C<sops: mine>, a list, an explicit C<null> -- is refused for the
same reason and with the same exit code by sops, and until 0.003 this method
took it, dropped the key and wrote the rest back: parsing removed the entry
before deciding there was no metadata section, so the guard above never saw it
and the key was simply missing from the output. See
L<File::SOPS::Metadata/from_hash>.

Format is auto-detected from the filename extension (C<.yaml>, C<.yml>, C<.json>)
unless explicitly specified.

C<mac_only_encrypted>, the four encryption rules and C<metadata> are all
passed through to L</encrypt>; see L</Choosing what gets encrypted>.

Returns true on success.

=cut

sub encrypt_in_place {
    my ($class, %args) = @_;
    my $file       = $args{file}       // croak "file required";
    my $recipients = $args{recipients} // croak "recipients required";
    my $format     = $args{format} // _detect_format_from_filename($file);

    my $content = _read_file($file, 'file');

    # Same guard as encrypt_file, and it matters more here: there is no
    # separate output file to inspect afterwards, so an unnoticed double
    # encryption would have overwritten the only copy.
    my ($data, $metadata) = _format_class($format)->parse($content);
    croak _sops_key_reserved("file '$file'") if $metadata;

    my $encrypted = $class->encrypt(
        data       => $data,
        recipients => $recipients,
        format     => $format,
        _encryption_options(\%args),
    );

    _replace_file($file, $encrypted);

    return 1;
}

=method encrypt_in_place

    File::SOPS->encrypt_in_place(
        file       => 'secrets.yaml',
        recipients => \@age_public_keys,
        format     => 'yaml',   # optional, auto-detected from filename
    );

Encrypts a plaintext file over itself.

This is L</encrypt_file> with C<output> omitted, said in one argument instead
of two. There is nothing C<encrypt_file> will not do for you here -- since
0.003 both write atomically, so neither can leave the plaintext truncated or
half-encrypted (L</How a file is written>) -- but C<file> cannot be got wrong
the way an C<input>/C<output> pair can, and it is the same shape L</edit> and
L</rotate> take for the same job.

The file's permissions are preserved, it comes back with a B<new inode> so hard
links keep the old plaintext, and a symlink is resolved rather than replaced.
All three, and where they differ from sops, are in L</How a file is written>.

C<mac_only_encrypted>, the four encryption rules and C<metadata> are passed
through to L</encrypt>; see L</Choosing what gets encrypted>.

B<Dies if the file is already encrypted>, i.e. has a top-level C<sops> entry,
for the reasons in L</encrypt_file>. There is deliberately no "encrypt it
again" mode: to re-key an encrypted file use L</rotate>, to change its contents
use L</edit>. sops answers the same call the same way, with exit code 203 and
the same advice.

Returns true on success.

=cut

sub decrypt_file {
    my ($class, %args) = @_;
    my $input      = $args{input}      // croak "input required";
    my $output     = $args{output}     // croak "output required";
    my $identities = $args{identities} // croak "identities required";
    my $format     = $args{format};

    $format //= _detect_format_from_filename($input);

    my $content = _read_file($input, 'input file');

    # Decrypt
    my $data = $class->decrypt(
        encrypted  => $content,
        identities => $identities,
        format     => $format,
        ignore_mac => $args{ignore_mac},
    );

    my $decrypted = _serialize_plaintext($data, $format);

    _replace_file($output, $decrypted);

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

It is written by the format handler's C<emit>
(L<File::SOPS::Format::YAML/emit>, L<File::SOPS::Format::JSON/emit>) -- the
same emitter the encrypted document goes through, minus the C<sops> section --
so the plaintext and the encrypted file cannot disagree about quoting, booleans,
key order or float precision.

Unlike L</encrypt_file>, C<output> is required to prevent accidental data loss.
It is nonetheless written atomically, since nothing stops it naming a file that
matters -- the encrypted input itself, or a working copy being refreshed. Until
0.003 an output that already existed was truncated before the plaintext was
written and a failing write was not reported, so a full disk replaced that file
with an empty one and C<decrypt_file> still returned true. See L</How a file is
written>, which also covers what mode the output file gets.

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

    my $content = _read_file($file, 'file');

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

    my $content = _read_file($file, 'file');

    my (undef, $metadata) = _format_class($format)->parse($content);
    croak "No SOPS metadata found in '$file'" unless $metadata;

    _assert_rekeyable($metadata, $file, verb => 'rotate', noun => 'Rotation');

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

    _replace_file($file, $encrypted);

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

Step 5 is atomic: the rotated document is written next to the file and renamed
over it, so an interrupted rotation leaves the file readable under its old data
key rather than truncated. Until 0.003 the file was opened with C<< '>' >>
first, which is the worst moment to lose it -- the new data key exists only in
the buffer being written, so a file truncated there is not recoverable with any
identity. L</How a file is written> has the consequences of the C<rename>.

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

sub edit {
    my ($class, %args) = @_;
    my $file       = $args{file}       // croak "file required";
    my $identities = $args{identities} // croak "identities required";
    my $format     = $args{format} // _detect_format_from_filename($file);

    # Resolved BEFORE anything is decrypted: an unusable editor must not be
    # discovered with a plaintext copy of the document already on disk.
    my @editor = _editor_command($args{editor});

    my $content = _read_file($file, 'file');

    my (undef, $metadata) = _format_class($format)->parse($content);
    croak "No SOPS metadata found in '$file'" unless $metadata;

    # Re-encryption here generates a NEW data key, exactly as rotate does, so
    # it inherits rotate's refusal: a document also wrapped for pgp or a KMS
    # would come back out with those recipients silently dropped.
    _assert_rekeyable($metadata, $file, verb => 'edit', noun => 'Editing');

    my $data = $class->decrypt(
        encrypted  => $content,
        identities => $identities,
        format     => $format,
        ignore_mac => $args{ignore_mac},
    );

    my $before = _serialize_plaintext($data, $format);
    my $after  = _edit_text($before, $file, \@editor);

    # Nothing was changed: leave the file alone entirely rather than rewriting
    # an identical document under a new data key, MAC and lastmodified. sops
    # stops here too ("File has not changed, exiting.", exit code 200).
    return 0 unless defined $after;

    my ($edited, $edited_metadata) = do {
        my @parsed = eval { _format_class($format)->parse($after) };
        my $err    = $@;

        # A top-level `sops` entry of the user's own is NOT a parse failure and
        # must not be reported as one -- `sops: mine` parses perfectly, it just
        # cannot be encrypted over a metadata section that goes in the same
        # place, and the remedy is to rename one key rather than to hunt for a
        # syntax error that is not there.
        #
        # parse() reports the two shapes of that entry differently: a mapping
        # comes back as metadata, and every other shape (a scalar, a list, an
        # explicit null) is refused inside parse() by
        # File::SOPS::Metadata::from_hash, so it arrives here as an exception
        # and has to be sorted back out of the parse branch. Both shapes end at
        # the same croak.
        #
        # sops draws the line in exactly this place, with two distinct messages
        # (measured on 3.13.3 in editor mode): "Could not load tree, probably
        # due to invalid syntax" for text that does not parse, and "Tree not
        # valid for encryption" plus the reserved-key text for a top-level
        # `sops` entry -- for a scalar, a list, a null and a mapping alike.
        croak _edited_sops_key_reserved($file) if _is_sops_not_a_mapping($err);

        croak "The edited document does not parse (" . _reason($err) . "). "
            . "'$file' is unchanged, and the edited text has been discarded "
            . "together with the temporary file it was in -- there is no copy "
            . "of it left. sops keeps the editor open until the document "
            . "parses; this method cannot, because it may have no terminal to "
            . "return to."
            if $err;
        @parsed;
    };

    croak _edited_sops_key_reserved($file) if $edited_metadata;

    my $encrypted = $class->encrypt(
        data       => $edited,
        recipients => [ map { $_->{recipient} } @{ $metadata->age } ],
        format     => $format,
        metadata   => $metadata,
    );

    _replace_file($file, $encrypted);

    return 1;
}

=method edit

    File::SOPS->edit(
        file       => 'secrets.enc.yaml',
        identities => \@age_secret_keys,
        editor     => 'vim',   # optional, defaults to $ENV{EDITOR}
        format     => 'yaml',  # optional, auto-detected from filename
    );

Decrypts a file, opens it in an editor, and re-encrypts what comes back.

The decrypted document is written to a fresh temporary directory (mode C<0700>)
as a file (mode C<0600>) with the same basename as the original, the editor is
run on it, and the result is parsed and encrypted back over the original --
atomically, as L</encrypt_in_place> does, and for the same reason.

That is the same shape sops uses, and it has the same caveat: B<the plaintext
touches the filesystem>. Point C<TMPDIR> at a C<tmpfs> if that matters to you.

B<The decrypted copy is removed on every way out of this method>, which is
three of them:

=over 4

=item * Returning, or dying anywhere -- including from the editor failing, the
result not parsing, or the re-encryption refusing. The directory belongs to a
L<File::Temp> object scoped to the call, so unwinding removes it.

=item * C<SIGTERM> and C<SIGHUP>, which are caught for the duration of the
call, remove the directory and are then re-raised with the default disposition,
so the process still dies of the signal it was sent. Perl defers a signal that
arrives while the editor is running until the editor exits, so this happens on
the way back rather than immediately.

=item * C<Ctrl-C>, which does not reach here at all: Perl's C<system> ignores
C<SIGINT> for the duration of the child, so the interrupt goes to the editor.
The editor dying of it is an editor that exited non-zero, which is the first
case again -- reported as C<was killed by signal 2> with the file unchanged.

=back

Returns 1 if the file was rewritten, and B<0 if the editor left the content
byte-identical> -- in which case the file is not touched at all, so its
C<lastmodified>, MAC and wrapped data keys stay as they were. sops reports the
same situation as C<File has not changed, exiting.> with exit code 200.

=head3 The editor

C<editor> may be a string, which is split into words the way a shell would
(C<< editor => 'code --wait' >>), or an ArrayRef, which is used as it stands.
It defaults to C<$ENV{EDITOR}>, and the temporary file's path is appended as
the final argument. The editor is run without a shell.

B<Dies if neither is set.> sops falls back to C<vim>, C<nano> or C<vi> here;
this method does not, because a library that opens an interactive editor
nobody asked for hangs an unattended script rather than failing it.

B<Dies if the editor exits non-zero>, naming the status or the signal, and
leaves the file unchanged -- an editor that refused to start or was killed
has not produced an edit worth encrypting. sops behaves the same way
(C<Could not run editor: exit status 3>, exit code 201).

=head3 What comes back is checked before anything is written

The edited text must parse, as one document, to a mapping, and must not carry
a top-level C<sops> entry of its own. Any of those dies with the original file
untouched.

Those are two refusals, not one, and they say so: an entry of your own under
that name is refused as a reserved key -- whatever shape it has, a mapping, a
scalar, a list or an explicit C<null> -- and never as a parse failure, because
such a document parses perfectly well. sops separates the same two cases in
its editor mode, as C<Tree not valid for encryption> against C<Could not load
tree, probably due to invalid syntax>.

B<A document that does not parse is lost.> The temporary file is removed on the
way out, so the only copy of what was typed is whatever the editor still has in
its buffer. This is the one place where sops does better: it reopens the editor
on the same file until the document parses, which needs a terminal to return
to and an interactive user in front of it -- neither of which a library method
can assume.

=head3 Editing re-keys the file

Unlike C<sops edit>, which keeps the document's data key and only rewrites the
values, this method decrypts and encrypts, so the file comes back with a
B<new data key> -- the wrapped copies in the C<sops> section change on every
edit, and so does the diff. Nothing is lost by it: the age recipients and the
encryption policy (the rules, C<mac_only_encrypted>, and any C<sops> field this
distribution does not model) are carried over exactly as L</rotate> carries
them.

What it does mean is that C<edit> refuses the same files L</rotate> refuses: a
document whose C<sops> section also holds C<pgp>, C<kms>, C<gcp_kms>,
C<azure_kv>, C<hc_vault> or C<key_groups> material cannot be re-encrypted for
those recipients here, and dropping them silently would revoke their access
while reporting success. See L</Files rotate refuses>.

Key B<order> is not preserved either: the plaintext handed to the editor is
emitted from a Perl hash, so it comes out sorted whatever order the encrypted
file had. That is the same emitter L</decrypt_file> uses -- the format
handler's C<emit>, which is also what the encrypted document is written with --
and it is the order this distribution writes documents in anyway, so it does
not affect the MAC.

C<ignore_mac> is passed through to L</decrypt>; editing a file you could not
verify re-signs whatever it contained, so prefer to fail.

A C<data_key =E<gt> $bytes> argument would close the gap -- pass the
existing data key through and this method stops re-keying -- but it puts
raw key material on the public API, which is a real decision (and
probably an ADR) rather than a refactor. It will be worth doing once a
backend other than age exists (karr #39): today the refusal only fires
on documents this distribution could not have produced in the first
place.

=cut

# The config file, spelled exactly. Measured against sops 3.13.3: a .sops.yml
# is NOT read, and is warned about -- `ignoring "../.sops.yml" when searching
# for config file; the config file must be called ".sops.yaml"`.
our $CONFIG_FILE_NAME = '.sops.yaml';

# Creation-rule fields that name key material this distribution cannot produce.
#
# These are the CONFIG file's names, which are NOT the sops section's names:
# `azure_keyvault` and `hc_vault_transit_uri` here against `azure_kv` and
# `hc_vault` there. Measured against sops 3.13.3 by putting an unusable key in
# each field of a matching rule -- these five make it try to wrap the data key
# and fail on the key, while `aws_kms`, `azure_kv` and `hc_vault` in a creation
# rule are ignored entirely. Taking the list from
# @File::SOPS::Metadata::KEY_MATERIAL_FIELDS instead would therefore have let
# azure_keyvault and hc_vault_transit_uri walk straight through the guard.
#
# key_groups and shamir_threshold are here for the same reason one step on:
# both change how the data key is split and wrapped, sops writes
# shamir_threshold into the document it produces (measured), and a document
# this encrypted while ignoring them would be wrapped for age alone.
my @UNIMPLEMENTED_RULE_FIELDS = qw(
    pgp kms gcp_kms azure_keyvault hc_vault_transit_uri
    key_groups shamir_threshold
);

sub creation_rules_for {
    my ($class, %args) = @_;
    my $file = $args{file} // croak "file required";

    my $target = _clean_abs_path($file);

    my $config = $args{config};
    unless (defined $config) {
        $config = _find_config_file($target);
        croak "No $CONFIG_FILE_NAME found for '$file': looked in '"
            . _dir_of($target) . "' and in every directory above it, up to the "
            . "filesystem root. Pass recipients to encrypt yourself, or "
            . "config => '/path/to/$CONFIG_FILE_NAME' to name one. (sops stops "
            . "here too: \"config file not found, or has no creation rules, and "
            . "no keys provided through command line options\".)"
            unless defined $config;
    }

    my $rules   = _load_creation_rules($config);
    my $subject = _rule_subject_path($target, $config);

    my ($rule, $index) = _first_matching_rule($rules, $subject, $config);
    croak "No creation rule in '$config' matches '$subject'. A rule matches "
        . "when its path_regex matches that path -- which is '$file' resolved "
        . "and taken relative to the directory holding the config file -- or "
        . "when it has no path_regex at all, which is how a catch-all rule is "
        . "written. (sops stops here too: \"error loading config: no matching "
        . "creation rules found\".)"
        unless $rule;

    return _creation_rule_args($rule, $config, $index);
}

=method creation_rules_for

    my %args = File::SOPS->creation_rules_for(file => 'secrets/prod.yaml');

    File::SOPS->encrypt_in_place(
        file => 'secrets/prod.yaml',
        %args,
    );

Reads the C<.sops.yaml> that governs a file and returns the L</encrypt>
arguments its first matching creation rule asks for: C<recipients>, plus
whichever of the four encryption rules and C<mac_only_encrypted> that rule
carries. The returned list is meant to be splatted straight into L</encrypt>,
L</encrypt_file> or L</encrypt_in_place>, which is where the actual encrypting
still happens -- this method decides B<for whom and under which rules>, and
nothing else.

Nothing here reads C<.sops.yaml> implicitly. C<encrypt> and friends still want
their C<recipients> spelled out; this is the one method that will go and look.

=head3 Finding the config file

C<.sops.yaml> is looked for in the directory holding C<file> and then in every
directory above it, up to the filesystem root, and the first one found is used.
Nothing stops the walk earlier -- not a C<.git> directory, not C<$HOME> --
which is what sops does as well (measured on 3.13.3). The name must be exactly
C<.sops.yaml>: a C<.sops.yml> is ignored there and here.

B<This is a deliberate deviation, and it is the one thing here that differs
from the reference implementation.> sops walks up from the B<current working
directory>, not from the file: measured on 3.13.3, C<sops -e a/b/c/secrets.yaml>
run from the top of that tree does not see an C<a/b/.sops.yaml> at all, and
C<sops -e /abs/path/secrets.yaml> run from an unrelated directory reports
C<config file not found> however many config files sit above the file. That is
a sensible rule for a command a person types in the directory they are working
in, and a useless one for a library: the caller's working directory has nothing
to do with the file it was handed, and a daemon whose cwd is C</> would find
nothing at all. The two agree in the ordinary case -- one C<.sops.yaml> at the
top of a repository, the file somewhere underneath it -- and differ only when
config files are nested, where walking up from the file picks the nearer and
more specific one. The measurements and the two rejected alternatives are in
L<docs/adr/0007|https://github.com/Getty/p5-file-sops/blob/main/docs/adr/0007-the-config-search-starts-at-the-file-not-at-the-working-directory.md>.

C<config> names a config file explicitly, and skips the search entirely. It is
the equivalent of sops's C<--config>. Its value is B<not> taken from
C<$SOPS_CONFIG>, which sops does honour: an environment variable that
redirects which public keys a secret gets encrypted to is a reasonable thing
for a user to set for a command they are running, and not a reasonable thing
for a library to obey on behalf of a caller who never asked. Pass
C<< config => $ENV{SOPS_CONFIG} >> if you want it.

=head3 Which rule matches

The rules are tried in order and B<the first match wins>; a rule with no
C<path_regex> matches everything, which is how a catch-all is written at the
end of the list. Both are sops's behaviour.

B<C<path_regex> is not matched against the path you passed.> It is matched
against that path made absolute and normalised, and then taken relative to the
directory holding the config file -- so with a config at the top of a
repository, a rule matches C<secrets/prod.yaml> whether the caller said
C<secrets/prod.yaml>, C<./secrets//prod.yaml>, C<../repo/secrets/prod.yaml> or
the full absolute path, and whether it is called from the top of the repository
or from inside C<secrets/>. Symlinks are B<not> resolved, so a rule sees the
link's path and not the target's. All of that is measured against sops 3.13.3,
including the fallback: a file that is not under the config file's directory at
all -- only reachable by passing C<config> here -- is matched as an absolute
path instead of as a C<../..>-prefixed relative one.

The regex is a B<Perl> regex, and nothing translates it. sops compiles the same
string with Go's RE2, which is not the same dialect: C<(?i)> works in both, but
a lookbehind compiles here and makes sops stop with C<error parsing regexp>
(measured on 3.13.3). A C<path_regex> written in either dialect alone will
therefore pick different rules -- or no rule -- depending on which of the two
tools reads the config, and this does not warn about it. Keep a C<path_regex>
to what both accept. One that will not compile at all is reported here naming
the config file and the rule; sops reports it too.

=head3 Rules this refuses rather than half-applies

Each of these dies, naming the config file and which rule in it:

=over 4

=item * A rule naming B<key material for a backend other than age> --
C<pgp>, C<kms>, C<gcp_kms>, C<azure_keyvault>, C<hc_vault_transit_uri> -- or
C<key_groups> or C<shamir_threshold>. sops wraps the data key for every backend
the rule names; age is the only one implemented here, so honouring such a rule
would write a document the config says several parties can read and only the
age recipients actually can, and report success. This is the refusal
L</rotate> makes for the same reason. Those are the config file's field names
and not the C<sops> section's, which differ.

=item * A rule carrying B<more than one encryption rule>. sops refuses the
same config with C<cannot use more than one of encrypted_suffix,
unencrypted_suffix, ... for the same rule>, and L<File::SOPS::Metadata> refuses
the resulting document; catching it here names the config file instead of the
document that could not be built.

=item * A rule carrying C<unencrypted_comment_regex> or
C<encrypted_comment_regex>. Neither parser here keeps comments, so every value
would be classified wrongly -- the refusal L</encrypt> makes for a document
carrying one.

=item * A matching rule with B<no age recipient>, which leaves nothing to
encrypt for. sops stops on the same rule with C<Could not generate data key:
[empty key group provided]>.

=back

Not finding a config file at all, and finding one where no rule matches, die
too rather than returning an empty list: both are what sops exits non-zero on,
and a C<recipients> that quietly came back empty would be a document nobody can
decrypt -- or, since L</encrypt> refuses an empty recipient list, an error
naming neither the file nor the config that failed to produce one.

=head3 The rule's own fields

C<age> is a comma-separated list of recipients, or a YAML list of them, or a
list whose entries are themselves comma-separated. Whitespace around each
recipient is ignored, which is what makes the folded

    age: >-
      age1...,
      age1...

form work. Newlines are B<not> separators on their own: measured on 3.13.3, a
literal block of recipients without commas is handed to age as one string and
fails.

C<unencrypted_suffix>, C<encrypted_suffix>, C<unencrypted_regex>,
C<encrypted_regex> and C<mac_only_encrypted> are returned as the L</encrypt>
arguments of the same names -- see L</Choosing what gets encrypted>. Fields
this does not know are ignored, as sops ignores them.

Note what the returned rules do B<not> do: nothing is applied here. A caller
that drops the encryption rule out of C<%args> encrypts under the default
instead, and a caller that adds one of its own alongside gets the refusal
L<File::SOPS::Metadata/Encryption rules are mutually exclusive> gives any
document carrying two.

=cut

# Internal helpers

sub _format_class {
    my ($format) = @_;
    return $FORMATS{$format} // croak "Unknown format: $format";
}

# --- .sops.yaml creation rules -------------------------------------------
#
# Everything below is path arithmetic and a regex match. No wire bytes, no MAC,
# no crypto: this decides which recipients and which encryption rule a file is
# encrypted under, and then the ordinary encrypt path does the work.

# An absolute path the way Go's filepath.Abs + Clean makes one: relative to the
# current directory, with '.' and '..' resolved TEXTUALLY, and without touching
# the filesystem. Cwd::abs_path is deliberately not used -- it resolves
# symlinks, and sops does not: measured on 3.13.3, encrypting a symlink matches
# a path_regex against the LINK's path, not the target's. It also requires the
# file to exist, and a file about to be created still needs its rules.
sub _clean_abs_path {
    my ($path) = @_;

    my ($vol, $dirs, $file) = File::Spec->splitpath(File::Spec->rel2abs($path));

    my @parts;
    for my $part (File::Spec->splitdir($dirs), $file) {
        next if !length $part || $part eq File::Spec->curdir;
        if ($part eq File::Spec->updir) { pop @parts; next }
        push @parts, $part;
    }

    return File::Spec->catpath($vol,
        File::Spec->catdir(File::Spec->rootdir, @parts), '');
}

sub _dir_of {
    my ($abs) = @_;
    my ($vol, $dirs) = File::Spec->splitpath($abs);
    return File::Spec->canonpath(File::Spec->catpath($vol, $dirs, ''));
}

# The nearest .sops.yaml at or above the file's own directory, or undef.
#
# The search starts at the FILE, where sops starts it at the current working
# directory (measured on 3.13.3; see creation_rules_for for why this deviates).
# Nothing stops the walk short of the root -- not .git, not $HOME -- which is
# what sops does.
sub _find_config_file {
    my ($target) = @_;

    my ($vol, $dirs) = File::Spec->splitpath($target);
    my @parts = grep { length } File::Spec->splitdir($dirs);

    while (1) {
        my $dir = File::Spec->catpath($vol,
            File::Spec->catdir(File::Spec->rootdir, @parts), '');
        my $candidate = File::Spec->catfile($dir, $CONFIG_FILE_NAME);
        return $candidate if -f $candidate;
        last unless @parts;
        pop @parts;
    }

    return undef;
}

# The string path_regex is matched against: the file relative to the directory
# holding the config file, or -- when it is not under that directory at all --
# the absolute path. Measured on sops 3.13.3, both halves of it: a config at
# the top of a tree matches `a/b/c/secrets.yaml` however the file was named and
# from wherever sops was run, and a file outside the config's directory matches
# `^/` rather than `^\.\./`.
#
# With the config found by walking up from the file, the second case cannot
# arise -- the file is under the config's directory by construction. It is
# reachable only through an explicit `config`.
sub _rule_subject_path {
    my ($target, $config) = @_;

    my $rel = File::Spec->abs2rel($target, _dir_of(_clean_abs_path($config)));
    my ($first) = File::Spec->splitdir($rel);

    return $target if !length $rel || $first eq File::Spec->updir;
    return $rel;
}

sub _load_creation_rules {
    my ($config) = @_;

    my $content = _read_file($config, 'config file');

    # LIST context, as the format handlers use it: YAML::XS::Load in scalar
    # context returns the LAST document of a multi-document stream, which for a
    # config file would silently honour one half of it.
    my @docs = eval { YAML::XS::Load($content) };
    croak "Cannot parse config file '$config' (" . _reason($@) . "). sops "
        . "stops on the same file with \"error loading config: Could not "
        . "unmarshal config file\"."
        if $@;

    croak "Config file '$config' holds " . scalar(@docs) . " YAML documents; a "
        . "$CONFIG_FILE_NAME is a single mapping"
        if @docs > 1;

    my $conf = @docs ? $docs[0] : undef;

    croak "Config file '$config' has no creation_rules, so there is nothing "
        . "in it that says who a file should be encrypted for. (sops reports "
        . "\"config file not found, or has no creation rules, and no keys "
        . "provided through command line options\".)"
        if !defined $conf || (ref $conf eq 'HASH' && !defined $conf->{creation_rules});

    croak "Config file '$config' is not a mapping" unless ref $conf eq 'HASH';

    my $rules = $conf->{creation_rules};
    croak "creation_rules in '$config' is not a list"
        unless ref $rules eq 'ARRAY';

    return $rules;
}

sub _first_matching_rule {
    my ($rules, $subject, $config) = @_;

    my $index = 0;
    for my $rule (@$rules) {
        $index++;

        croak "Creation rule $index in '$config' is not a mapping"
            unless ref $rule eq 'HASH';

        my $regex = $rule->{path_regex};

        # No path_regex is a catch-all, which is how the last rule in a
        # .sops.yaml is usually written. Same in sops.
        return ($rule, $index) unless defined $regex && length $regex;

        my $matched = eval { $subject =~ /$regex/ ? 1 : 0 };
        croak "Cannot use the path_regex of creation rule $index in '$config' "
            . "as a regular expression (" . _reason($@) . "). It is compiled as "
            . "a Perl regex here and with Go's RE2 by sops, which accept "
            . "different things -- sops reports this one too, as \"error "
            . "parsing regexp\"."
            if $@;

        return ($rule, $index) if $matched;
    }

    return;
}

# Is a creation rule's field set, in the sense Go's zero value gives it? An
# empty string, an empty list and an absent key are all "not set".
sub _rule_field_set {
    my ($rule, $name) = @_;

    my $value = $rule->{$name};
    return 0 unless defined $value;
    return scalar @$value       if ref $value eq 'ARRAY';
    return scalar keys %$value  if ref $value eq 'HASH';
    return length $value;
}

# A creation rule's `age`, as a list of recipients. Comma-separated, or a YAML
# list, or a list of comma-separated strings; whitespace around each recipient
# is dropped, which is what makes the folded `age: >-` form work. A NEWLINE is
# not a separator: measured on sops 3.13.3, a literal block of recipients with
# no commas reaches age as one string and fails to parse.
sub _age_recipients {
    my ($value, $config, $index) = @_;

    return () unless defined $value;

    my @out;
    for my $entry (ref $value eq 'ARRAY' ? @$value : $value) {
        croak "The age entry of creation rule $index in '$config' holds a "
            . lc(ref $entry) . " reference; it takes a recipient, a "
            . "comma-separated list of them, or a YAML list"
            if ref $entry;
        next unless defined $entry;

        for my $recipient (split /,/, $entry) {
            $recipient =~ s/\A\s+//;
            $recipient =~ s/\s+\z//;
            push @out, $recipient if length $recipient;
        }
    }

    return @out;
}

sub _creation_rule_args {
    my ($rule, $config, $index) = @_;

    my @unimplemented = grep { _rule_field_set($rule, $_) }
        @UNIMPLEMENTED_RULE_FIELDS;

    croak "Refusing to encrypt under creation rule $index in '$config': it "
        . "names key material this distribution cannot produce ("
        . join(', ', @unimplemented) . ") -- age is the only backend "
        . "implemented here. sops "
        . "wraps the data key for every backend a rule names, so encrypting "
        . "under this rule while ignoring those fields would write a document "
        . "the config says several parties can read and only the age "
        . "recipients actually can, and report success. Encrypt such a file "
        . "with the sops CLI, or pass recipients to encrypt yourself."
        if @unimplemented;

    my @recipients = _age_recipients($rule->{age}, $config, $index);
    croak "Creation rule $index in '$config' matches, but names no age "
        . "recipient, so there is nobody to encrypt for. (sops stops on the "
        . "same rule with \"Could not generate data key: [empty key group "
        . "provided]\".)"
        unless @recipients;

    my %args = (recipients => \@recipients);

    # The same mutual exclusion File::SOPS::Metadata enforces on a document,
    # asked here so the message can name the config file rather than the
    # document that could not be built out of it. sops refuses such a rule at
    # config-load time too, listing the same six names.
    my @rules = grep { _rule_field_set($rule, $_) }
        @File::SOPS::Metadata::ENCRYPTION_RULES,
        @File::SOPS::Metadata::UNSUPPORTED_ENCRYPTION_RULES;

    croak "Creation rule $index in '$config' uses more than one of "
        . join(', ', @File::SOPS::Metadata::ENCRYPTION_RULES,
                     @File::SOPS::Metadata::UNSUPPORTED_ENCRYPTION_RULES)
        . " (got " . join(' and ', @rules) . "); they select which values get "
        . "encrypted and at most one may be given. sops refuses the same rule."
        if @rules > 1;

    if (my ($name) = @rules) {
        croak "Refusing to encrypt under creation rule $index in '$config': "
            . "'$name' selects values by their comment, and neither of this "
            . "distribution's parsers keeps comments, so every value would be "
            . "classified wrongly. Use the sops CLI for files that config "
            . "covers."
            if grep { $_ eq $name }
                @File::SOPS::Metadata::UNSUPPORTED_ENCRYPTION_RULES;

        $args{$name} = $rule->{$name};
    }

    $args{mac_only_encrypted} = $rule->{mac_only_encrypted} ? 1 : 0
        if exists $rule->{mac_only_encrypted};

    return %args;
}

sub _read_file {
    my ($path, $what) = @_;

    open my $fh, '<:raw', $path
        or croak "Cannot open $what '$path': $!";
    my $content = do { local $/; <$fh> };
    close $fh;

    return $content;
}

# The plaintext form of a decrypted tree: what decrypt_file writes out and what
# edit hands to the editor. Both have to agree, because edit compares the text
# it wrote with the text it gets back to decide whether anything changed.
#
# It is the format handler's own emitter, with no metadata section -- the same
# sub the handler's serialize() dumps through. Until karr #35 this WAS a second
# emitter, because the handlers only offered "serialize a document WITH its sops
# section", and it kept its options in sync with theirs by hand: a copy of
# JSON::MaybeXS->new(utf8/pretty/canonical) for JSON, and for YAML a boolean
# mode that at first was not set here at all and worked only because loading
# File::SOPS::Format::YAML assigned $YAML::XS::Boolean process-wide. Those
# options decide sorted key order, which the MAC's encrypt side depends on, so
# the twin was one edit away from a document that fails its own digest.
sub _serialize_plaintext {
    my ($data, $format) = @_;

    # _format_class croaks on an unknown format, before anything is written.
    return _format_class($format)->emit($data);
}

# Write $content to $path, atomically: the content goes to a temporary file in
# the SAME directory (so the rename cannot cross a filesystem) and that file is
# renamed over the target. Nothing observes a partial write, and a failure
# anywhere before the rename leaves whatever was there untouched.
#
# EVERY method here that writes a file goes through this, whether the target
# exists or not. Until 0.003 only encrypt_in_place and edit did: encrypt_file,
# decrypt_file and rotate opened the target with '>', which truncates it before
# the first byte is written, and then checked neither the print nor the close --
# so a write that ran out of disk left an empty file and returned success.
# encrypt_file defaults output to input and rotate always writes back over the
# file it read, so what that destroyed was the only copy.
#
# This is where this distribution differs from sops, which truncates the file
# and rewrites it. Truncate-and-rewrite keeps the inode -- hard links and the
# open handle someone else holds see the new content -- at the price of
# destroying the file if the write stops half way. On a file whose only copy is
# about to be replaced by a re-encryption of itself, that trade goes the other
# way round.
#
# A symlink is resolved first, so the target is replaced rather than the link;
# measured against sops 3.13.3, `sops -e -i` on a symlink leaves the link alone
# and rewrites the target too. Hard links to the target are NOT preserved; they
# keep the old content, and that is documented on the methods that call this.
sub _replace_file {
    my ($path, $content) = @_;

    my $target = -l $path ? (Cwd::abs_path($path) // $path) : $path;

    # karr #46: sops -e -i refuses a read-only file with EACCES; the atomic
    # write was happy because rename() checks the directory, not the file.
    # This is a behaviour change introduced by the atomic write itself, where
    # the old open '>' would have failed on the chmod for free. Match sops
    # and refuse here, before any work -- a different inode is no
    # consolation when the file was deliberately read-only.
    croak "Could not open in-place file for writing: $target: permission denied"
        if -e $target && !-w $target;

    return _write_through($target, $content) if -e $target && !-f $target;

    # The mode to end up with: the one the file already has, or -- when there
    # is no file yet -- the one open '>' would have given it. File::Temp
    # creates 0600, so without this, preserving a deliberately group-readable
    # file would quietly tighten it and routing a write path through here would
    # be a permissions change as well as an atomicity one. sops's --output
    # creates at 0666 against the umask as well (measured: 0644 under umask
    # 022), and leaves an existing file's mode alone.
    my $existing = (stat $target)[2];
    my $mode = defined $existing ? $existing & 07777 : 0666 & ~umask;

    my ($vol, $dir, $base) = File::Spec->splitpath($target);
    $dir = File::Spec->curdir unless length $dir;

    # tempfile() croaks with its own wording when the directory is missing or
    # unwritable. That used to be "Cannot open output file '...': $!" and has
    # to stay something that names the file the caller asked for.
    my ($fh, $tmp) = eval {
        File::Temp::tempfile(
            ".$base.sops-XXXXXXXX",
            DIR    => File::Spec->catpath($vol, $dir, ''),
            UNLINK => 0,
        );
    };
    croak "Cannot create a temporary file next to '$target' to write it "
        . "atomically (" . _reason($@) . ")"
        unless defined $fh;

    my $ok = eval {
        binmode $fh, ':raw';
        print {$fh} $content
            or croak "Cannot write to temporary file '$tmp': $!";
        close $fh
            or croak "Cannot write to temporary file '$tmp': $!";

        chmod $mode, $tmp
            or croak "Cannot set permissions on '$tmp': $!";

        rename $tmp, $target
            or croak "Cannot replace '$target' with '$tmp': $!";
        1;
    };

    unless ($ok) {
        my $err = $@;
        close $fh;
        unlink $tmp;
        croak $err;
    }

    return 1;
}

# The one target temp-file-and-rename cannot serve: something that exists and
# is not a regular file -- /dev/stdout, /dev/null, a fifo. There is no previous
# content to protect there, and renaming over it would replace the device or
# the fifo itself with an ordinary file. `sops --output /dev/stdout` works, so
# this has to keep working.
#
# Every step is checked, unlike the open/print/close this replaced elsewhere:
# an unreported short write was half of what made that path dangerous.
sub _write_through {
    my ($path, $content) = @_;

    open my $fh, '>:raw', $path
        or croak "Cannot open output file '$path': $!";
    print {$fh} $content
        or do { my $err = $!; close $fh; croak "Cannot write to '$path': $err" };
    close $fh
        or croak "Cannot write to '$path': $!";

    return 1;
}

# The editor to run, as a list, without a shell in between. A string is split
# the way a shell would split it -- `EDITOR="code --wait"` is a command with an
# argument, not a program with a space in its name -- which is what sops does
# with $EDITOR as well.
sub _editor_command {
    my ($editor) = @_;

    $editor //= $ENV{EDITOR};

    croak "No editor to run: pass editor => 'vim' to edit, or set the EDITOR "
        . "environment variable. (sops falls back to vim, nano or vi when "
        . "EDITOR is unset; this does not, because a library that opens an "
        . "interactive editor nobody asked for hangs an unattended script "
        . "instead of failing it.)"
        unless defined $editor && length $editor;

    my @command = ref $editor eq 'ARRAY' ? @$editor : shellwords($editor);
    croak "The editor command '" . (ref $editor eq 'ARRAY' ? join(' ', @$editor) : $editor)
        . "' is empty once split into words"
        unless @command;

    return @command;
}

# Put $text in front of the editor and return what came back, or undef if it
# was left byte for byte identical.
#
# The plaintext lives in a directory of its own for as long as this call, and
# no longer. File::Temp's object removes the tree when $tmpdir goes out of
# scope, which covers returning and dying alike; the handlers below cover being
# signalled, where the default disposition would terminate the process without
# running a destructor.
#
# SIGINT is deliberately in that list even though Ctrl-C during the editor does
# not arrive here: perl's system() ignores SIGINT for the duration of the child
# (perlfunc), so the interrupt reaches the EDITOR and comes back as a non-zero
# wait status, which the croak below turns into ordinary unwinding. The handler
# is for a SIGINT arriving in the rest of this call.
sub _edit_text {
    my ($text, $file, $editor) = @_;

    my $tmpdir = File::Temp->newdir(TEMPLATE => 'file-sops-edit-XXXXXXXX',
                                    TMPDIR   => 1);

    my $on_signal = sub {
        my ($signal) = @_;
        undef $tmpdir;              # removes the plaintext, now
        $SIG{$signal} = 'DEFAULT';  # and then die of the signal we were sent
        kill $signal, $$;
    };
    local $SIG{INT}  = $on_signal;
    local $SIG{TERM} = $on_signal;
    local $SIG{HUP}  = $on_signal;

    # Same basename as the original, so the editor's filetype detection sees
    # the extension it expects. sops does this too.
    my $path = File::Spec->catfile("$tmpdir", basename($file));

    sysopen my $fh, $path, O_WRONLY | O_CREAT | O_EXCL, 0600
        or croak "Cannot create temporary file '$path': $!";
    binmode $fh, ':raw';
    print {$fh} $text or croak "Cannot write temporary file '$path': $!";
    close $fh         or croak "Cannot write temporary file '$path': $!";

    my $status = system(@$editor, $path);
    croak "Editor (" . join(' ', @$editor) . ") " . _wait_status($status)
        . "; '$file' is unchanged"
        if $status != 0;

    my $edited = _read_file($path, 'edited file');

    return undef if $edited eq $text;
    return $edited;
}

# What system() reported, in words. $? is the wait status, not an exit code.
sub _wait_status {
    my ($status) = @_;

    return "could not be run: $!"      if $status == -1;
    return "was killed by signal " . ($status & 127) if $status & 127;
    return "exited with status " . ($status >> 8);
}

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
      . "input is already encrypted -- use edit to change its contents or "
      . "rotate to re-key it, or decrypt it first. If it really is plaintext, "
      . "rename the entry. (sops refuses such a file too, with exit code 203, "
      . "and points at its editor mode for the same reason.)";
}

# The same refusal for text that came back from an editor, which is a different
# situation with a different remedy: the document was just typed, nothing has
# been written yet, and pointing the user at edit -- which is where they
# already are -- would be no help at all.
#
# Both ways an edited document can carry the entry end here. See edit.
sub _edited_sops_key_reserved {
    my ($file) = @_;
    return
        "The edited document has a top-level 'sops' entry. That name is "
      . "reserved for the metadata section, which is written back "
      . "automatically -- remove it and edit again. '$file' is unchanged.";
}

# Is this exception the "top-level 'sops' entry is not a mapping" refusal?
#
# That refusal lives in File::SOPS::Metadata::from_hash, which the format
# handlers call from inside parse(), so a caller of parse() receives it as an
# exception -- indistinguishable, without this, from the document not parsing.
# edit is the only caller that has to tell the two apart.
#
# Keying on the message coupled this to another module's wording, deliberately
# and in preference to the alternatives: a syntax-only parse in the format
# handlers, or a typed exception, both reach well past the one call site that
# needs the distinction. t/17-in-place-and-edit.t pins both branches, so a
# rewording in Metadata.pm fails a test rather than quietly restoring the
# regression this replaced (karr #47) -- edit reporting a document that parses
# as one that does not.
sub _is_sops_not_a_mapping {
    my ($err) = @_;
    return defined $err && $err =~ /\Athe top-level 'sops' entry is\b/;
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
# for another one cannot be re-keyed: the new data key can be wrapped for its
# age recipients and for nobody else. Both ways out of that are wrong, and the
# quiet one is the worse -- dropping the entries revokes those recipients'
# access while reporting success, and keeping them leaves a wrapped copy of a
# key that no longer decrypts anything, which fails later and further away.
#
# Every operation that generates a new data key has to ask this, which is
# rotate and edit; the wording differs only in the verb.
sub _assert_rekeyable {
    my ($metadata, $file, %words) = @_;

    my @foreign = grep { $_ ne 'age' } $metadata->key_material_fields;
    return 1 unless @foreign;

    croak "Refusing to $words{verb} '$file': its sops section holds key material "
        . "this distribution cannot re-encrypt (" . join(', ', @foreign) . "). "
        . "$words{noun} generates a new data key, so those entries would be "
        . "silently dropped and the recipients behind them would lose access. "
        . "\u$words{verb} this file with the sops CLI, or, if losing them is "
        . "what you want, say so explicitly with decrypt followed by encrypt.";
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
