package File::SOPS::Backend::HCVault;
# ABSTRACT: HashiCorp Vault transit backend for SOPS
our $VERSION = '0.006';
use Moo;
use Carp qw(croak);
use HTTP::Tiny;
use JSON::MaybeXS ();
use MIME::Base64 qw(encode_base64 decode_base64);
use POSIX qw(strftime);
use Scalar::Util ();
use namespace::clean;

# Same reason as in Backend::Age: an error reports the caller's line, not ours.
our @CARP_NOT = qw( File::SOPS );

my $DATA_KEY_LEN = 32;

=head1 SYNOPSIS

    use File::SOPS::Backend::HCVault;

    # Wrap the data key with a transit key (VAULT_TOKEN, or token => ...)
    my $entries = File::SOPS::Backend::HCVault->encrypt_data_key(
        data_key   => $random_32_bytes,
        recipients => ['http://vault.example:8200/v1/transit/keys/sops-key'],
    );

    # Unwrap it again, from the document's sops.hc_vault list
    my $data_key = File::SOPS::Backend::HCVault->decrypt_data_key(
        hc_vault => $entries,
    );

=head1 DESCRIPTION

Encrypts and decrypts the SOPS data key (32 random bytes) through the transit
secrets engine of a HashiCorp Vault server, the way the reference C<sops> does
it: C<POST {vault_address}/v1/{engine_path}/encrypt/{key_name}> with
C<{"plaintext": base64(data key)}>, and C</decrypt/> with
C<{"ciphertext": "vault:v1:..."}> to get it back. The layout of the entries was
measured against sops 3.13.3 and a Vault 2.2.1 dev server.

B<The document chooses where the token goes.> C<vault_address> comes from the
C<sops> section of the file being decrypted, exactly as in the reference
implementation, so whoever can edit the file can name the server that receives
the Vault token. What this module does about it: only C<http> and C<https> are
spoken; an address with userinfo, a path, a query or a fragment is refused
before any request is made; redirects are never followed (so a server cannot
bounce the token elsewhere); TLS certificates are verified. A caller that
knows where its Vault lives should additionally pass C<allowed_addresses> to
L</decrypt_data_key>, which then refuses every other address before the token
leaves the process. Plain C<http> is permitted because sops writes it for dev
servers; it sends the token in the clear.

=cut

# --- the one place a Vault URI is understood -------------------------------

# http(s)://host[:port]/v1/<engine>/keys/<key>[/] -- the form `sops
# --hc-vault-transit` takes. Measured: sops derives engine_path and key_name
# from it (an engine path may span segments), writes nothing for a URI without
# a scheme, and mangles one with segments after the key name. We refuse what
# sops garbles. userinfo is refused too: sops would copy it into vault_address.
# Returns (address, engine_path, key_name), or the empty list.
sub _parse_uri {
    my ($uri) = @_;
    return unless defined $uri && !ref $uri;
    my ($addr, $engine, $key) = $uri =~ m{
        \A ( https?:// (?: [A-Za-z0-9.\-]+ | \[ [0-9A-Fa-f:.]+ \] ) (?: :[0-9]{1,5} )? )
        /v1/
        ( [A-Za-z0-9_.\-]+ (?: / [A-Za-z0-9_.\-]+ )* )
        /keys/
        ( [A-Za-z0-9_.\-]+ )
        /? \z
    }x or return;
    return if $key eq '.' || $key eq '..';
    return if grep { $_ eq 'keys' || $_ eq '.' || $_ eq '..' } split m{/}, $engine;
    return ($addr, $engine, $key);
}

# The same checks for an entry that came out of a document. Returns
# (address, engine, key) or (undef, reason).
sub _check_entry {
    my ($e) = @_;
    return (undef, 'entry is not a mapping') unless ref $e eq 'HASH';
    for my $f (qw( vault_address engine_path key_name enc )) {
        return (undef, 'entry has no '.$f)
            unless defined $e->{$f} && !ref $e->{$f} && length $e->{$f};
    }
    my ($addr, $engine, $key) = _parse_uri(
        $e->{vault_address}.'/v1/'.$e->{engine_path}.'/keys/'.$e->{key_name}
    );
    return (undef, 'vault_address, engine_path or key_name is not acceptable')
        unless defined $addr && $addr eq $e->{vault_address};
    return ($addr, $engine, $key);
}

sub _transport {
    my ($args) = @_;
    my $t = $args->{transport};
    return HTTP::Tiny->new(
        max_redirect => 0,
        verify_SSL   => 1,
        timeout      => 30,
        agent        => 'File-SOPS/'.$VERSION,
    ) unless defined $t;
    croak "transport must be an object with a post method"
        unless Scalar::Util::blessed($t) && $t->can('post');
    return $t;
}

sub _token {
    my ($args) = @_;
    my $token = $args->{token} // $ENV{VAULT_TOKEN};
    croak "no Vault token: pass token => ... or set VAULT_TOKEN"
        unless defined $token && length $token;
    # The token goes into a header; anything outside printable ASCII is a
    # header-injection attempt or a mangled value. Never echoed.
    croak "Vault token contains characters not allowed in a header"
        unless $token =~ /\A[\x21-\x7e]+\z/;
    return $token;
}

# One POST; returns the response's data hash. Errors name the endpoint and the
# HTTP status, never the token or any payload.
sub _post {
    my ($transport, $token, $addr, $path, $payload) = @_;
    my $url = $addr.'/v1/'.$path;
    my $res = $transport->post($url, {
        headers => {
            'X-Vault-Token' => $token,
            'Content-Type'  => 'application/json',
        },
        content => JSON::MaybeXS->new( utf8 => 1, canonical => 1 )->encode($payload),
    });
    croak "Vault request to ".$url." failed: no response" unless ref $res eq 'HASH';
    croak sprintf "Vault request to %s failed: HTTP %s %s",
        $url, $res->{status} // '?', $res->{reason} // ''
        unless $res->{success};
    my $doc = eval { JSON::MaybeXS->new( utf8 => 1 )->decode($res->{content} // '') };
    croak "Vault response from ".$url." is not valid JSON"
        unless ref $doc eq 'HASH' && ref $doc->{data} eq 'HASH';
    return $doc->{data};
}

sub encrypt_data_key {
    my ($class, %args) = @_;
    my $data_key   = $args{data_key}   // croak "data_key required";
    my $recipients = $args{recipients} // croak "recipients required";

    croak "recipients must be an array ref" unless ref($recipients) eq 'ARRAY';
    croak "at least one recipient required" unless @$recipients;
    croak sprintf "data_key must be %d bytes", $DATA_KEY_LEN
        if length($data_key) != $DATA_KEY_LEN;

    # Parse every URI before the first request: a typo in the third recipient
    # must not leave the first two already sent to a server.
    my @targets;
    for my $uri (@$recipients) {
        my @t = _parse_uri($uri);
        croak "not a Vault transit key URI (expected http(s)://host[:port]/v1/<engine>/keys/<key>): "
            .( defined $uri && !ref $uri ? $uri : 'non-string' )
            unless @t;
        push @targets, \@t;
    }

    my $token     = _token(\%args);
    my $transport = _transport(\%args);
    my $created   = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
    my @entries;

    for my $t (@targets) {
        my ($addr, $engine, $key) = @$t;
        my $data = _post($transport, $token, $addr, $engine.'/encrypt/'.$key,
            { plaintext => encode_base64($data_key, '') });
        my $enc = $data->{ciphertext};
        croak "Vault response from ".$addr." carries no ciphertext"
            unless defined $enc && !ref $enc && $enc =~ /\Avault:v[0-9]+:\S+\z/;
        push @entries, {
            created_at    => $created,
            enc           => $enc,
            engine_path   => $engine,
            key_name      => $key,
            vault_address => $addr,
        };
    }

    return \@entries;
}

=method encrypt_data_key

    my $entries = File::SOPS::Backend::HCVault->encrypt_data_key(
        data_key   => $random_32_bytes,
        recipients => ['http://127.0.0.1:8200/v1/transit/keys/sops-key'],
        token      => $token,        # optional, else $ENV{VAULT_TOKEN}
        transport  => $http,         # optional
    );

Wraps the data key with each transit key named in C<recipients>, which are URIs
in the form C<sops --hc-vault-transit> takes:
C<http(s)://host[:port]/v1/E<lt>engineE<gt>/keys/E<lt>keyE<gt>>. A URI without a
scheme, with userinfo, a query, or segments after the key name is refused
(sops writes nothing, or garbage, for those); every URI is checked before the
first request is sent. Note that Vault's transit C<encrypt> endpoint creates a
missing key, as it does for sops.

C<data_key> must be exactly 32 bytes. The token is C<token>, else
C<$ENV{VAULT_TOKEN}>, else the call croaks; it never appears in an error.

C<transport> is any object with an C<HTTP::Tiny>-style
C<post($url, \%options)> method returning an C<HTTP::Tiny> response hash
(C<success>, C<status>, C<reason>, C<content>). The default is an
C<HTTP::Tiny> with TLS verification on and redirects off. It exists so tests
need no network.

Returns an ArrayRef of HashRefs with exactly the five fields sops writes:

    {
        created_at    => '2026-10-25T02:57:10Z',
        enc           => 'vault:v1:...',
        engine_path   => 'transit',
        key_name      => 'sops-key',
        vault_address => 'http://127.0.0.1:8200',
    }

=cut

sub decrypt_data_key {
    my ($class, %args) = @_;
    my $entries = $args{hc_vault} // croak "hc_vault required";
    croak "hc_vault must be an array ref" unless ref($entries) eq 'ARRAY';
    croak "no hc_vault entries" unless @$entries;

    my $allowed = $args{allowed_addresses};
    croak "allowed_addresses must be an array ref"
        if defined $allowed && ref $allowed ne 'ARRAY';

    my $token     = _token(\%args);
    my $transport = _transport(\%args);
    my @why;

    for my $e (@$entries) {
        my ($addr, $engine, $key) = _check_entry($e);
        unless (defined $addr) {
            push @why, $engine;    # the reason
            next;
        }
        if ($allowed && !grep { $_ eq $addr } @$allowed) {
            push @why, 'vault_address '.$addr.' is not in allowed_addresses';
            next;
        }

        my $plain = eval {
            _post($transport, $token, $addr, $engine.'/decrypt/'.$key,
                { ciphertext => $e->{enc} })->{plaintext};
        };
        unless (defined $plain) {
            my $err = $@ || 'no plaintext in response';
            $err =~ s/ at \S+ line \d+\.?\s*\z//;
            chomp $err;
            push @why, $err;
            next;
        }

        croak "Vault returned a malformed plaintext"
            if ref $plain || $plain !~ m{\A[A-Za-z0-9+/]*={0,2}\z};
        my $data_key = decode_base64($plain);
        croak sprintf "Vault returned a data key of %d bytes, expected %d",
            length($data_key), $DATA_KEY_LEN
            if length($data_key) != $DATA_KEY_LEN;

        return $data_key;
    }

    croak "Could not decrypt data key with any hc_vault entry: ".join('; ', @why);
}

=method decrypt_data_key

    my $data_key = File::SOPS::Backend::HCVault->decrypt_data_key(
        hc_vault          => $entries,   # sops.hc_vault from the document
        token             => $token,     # optional, else $ENV{VAULT_TOKEN}
        transport         => $http,      # optional
        allowed_addresses => [ 'https://vault.example:8200' ],   # optional
    );

Unwraps the data key through the first entry that works. An entry that is
malformed, whose address is refused, or whose request fails is skipped; if none
works the call croaks listing one reason per entry (HTTP status, never the
token or any key material). A Vault answer whose plaintext is not exactly 32
bytes croaks at once, as in L<File::SOPS::Backend::Age>.

Each entry must carry C<vault_address> (C<http(s)://host[:port]> and nothing
else), C<engine_path>, C<key_name> and C<enc>. See L</DESCRIPTION> for what the
document gets to decide, and C<allowed_addresses> (exact C<vault_address>
strings) for pinning it down. Returns the 32 byte data key.

=cut

sub can_decrypt {
    my ($class, %args) = @_;
    return 0 unless ref($args{hc_vault}) eq 'ARRAY' && @{ $args{hc_vault} };
    my $data_key = eval { $class->decrypt_data_key(%args) };
    return defined $data_key ? 1 : 0;
}

=method can_decrypt

    if (File::SOPS::Backend::HCVault->can_decrypt(hc_vault => $entries)) { ... }

Non-throwing form of L</decrypt_data_key>: true if some entry unwraps, false
otherwise. Unlike the age backend this costs network requests.

=cut

=head1 SEE ALSO

=over 4

=item * L<File::SOPS> - Main SOPS interface

=item * L<File::SOPS::Backend::Age> - the age backend

=item * L<https://developer.hashicorp.com/vault/api-docs/secret/transit> - Vault transit API

=back

=cut

1;
