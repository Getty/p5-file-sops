#!/usr/bin/env perl
use strict;
use warnings;
use Test::More;
use File::Temp qw(tempdir);
use File::Slurper qw(read_binary write_binary);
use File::Path qw(make_path);
use YAML::XS qw(Load Dump);
use JSON::MaybeXS ();
use MIME::Base64 qw(encode_base64 decode_base64);
use Digest::MD5 qw(md5_base64);
use FindBin;
use lib "$FindBin::Bin/lib";

use File::SOPS;
use File::SOPS::Metadata;
use File::SOPS::Format::YAML;
use Crypt::Age;
use SopsBin qw(find_sops_bin);

# The HashiCorp Vault transit backend (k39). No network: every request goes
# through a mock transport that speaks the part of Vault's transit API sops
# uses, so what is pinned here is the REQUEST (path, header, body), the ENTRY
# that lands in the document, and what the library refuses.
#
# Format anchoring: the fixture t/fixtures/hc-vault-sops-3.13.3.yaml was written
# by the real sops 3.13.3 against a dev Vault (data key beside it, base64), so
# reading it proves we agree with sops on bytes, not with ourselves. The
# Perl-written direction against the real binary is the last subtest here (sops
# parses our sops section) and xt/author/hc-vault-live.t (a real Vault).

my $FIXTURE = "$FindBin::Bin/fixtures/hc-vault-sops-3.13.3.yaml";
my $DATAKEY = do {
    my $k = read_binary("$FindBin::Bin/fixtures/hc-vault-sops-3.13.3.datakey");
    $k =~ s/\s+//g;
    $k;
};
my $TOKEN = 'hvs.TOPSECRET-token-0123456789';
my $URI   = 'http://127.0.0.1:18201/v1/transit/keys/sops-key';
my $URI2  = 'https://vault.example:8200/v1/kv-engine/transit/keys/other.key';

my $dir    = tempdir(CLEANUP => 1);
my $serial = 0;

# ---------------------------------------------------------------------------
# The mock. A stateful Vault: encrypt stores the plaintext under a fresh
# ciphertext, decrypt looks it up. Wrong token -> 403 like Vault.
# ---------------------------------------------------------------------------
{
    package MockVault;
    my $J = JSON::MaybeXS->new(utf8 => 1);

    sub new {
        my ($class, %a) = @_;
        return bless { token => $TOKEN, store => {}, calls => [], n => 0, %a }, $class;
    }
    sub calls { $_[0]{calls} }
    sub post {
        my ($self, $url, $opt) = @_;
        push @{ $self->{calls} }, { url => $url, %$opt };
        my $tok = $opt->{headers}{'X-Vault-Token'} // '';
        return $self->_res(403, 'Forbidden', { errors => ['permission denied'] })
            unless $tok eq $self->{token};
        my $body = $J->decode($opt->{content});
        my ($op) = $url =~ m{/v1/.+/(encrypt|decrypt)/[^/]+\z}
            or return $self->_res(404, 'Not Found', { errors => [] });
        if ($op eq 'encrypt') {
            my $ct = 'vault:v1:' . Digest::MD5::md5_base64(++$self->{n} . $body->{plaintext});
            $ct =~ tr{/+=}{xyz};
            $self->{store}{$ct} = $body->{plaintext};
            return $self->_res(200, 'OK', { data => { ciphertext => $ct } });
        }
        my $plain = exists $self->{force_plain}
            ? $self->{force_plain}
            : $self->{store}{ $body->{ciphertext} };
        return $self->_res(400, 'Bad Request', { errors => ['invalid ciphertext'] })
            unless defined $plain;
        return $self->_res(200, 'OK', { data => { plaintext => $plain } });
    }
    sub _res {
        my ($self, $status, $reason, $doc) = @_;
        return {
            success => $status == 200 ? 1 : '',
            status  => $status,
            reason  => $reason,
            content => $J->encode($doc),
        };
    }
}

sub exception {
    my ($c) = @_;
    my $ok = eval { $c->(); 1 };
    return $ok ? undef : $@;
}

# a Perl-written hc_vault document -> ($yaml, $mock)
sub vault_doc {
    my (%a) = @_;
    my $mock = $a{mock} // MockVault->new;
    my $yaml = File::SOPS->encrypt(
        data                  => $a{data} // { a => 'secret', b => { c => 3 } },
        hc_vault_transit_uris => $a{uris} // [$URI],
        vault_token           => $TOKEN,
        vault_transport       => $mock,
        format                => 'yaml',
    );
    return ($yaml, $mock);
}

sub file_with {
    my ($content) = @_;
    my $f = "$dir/doc-" . ++$serial . '.yaml';
    write_binary($f, $content);
    return $f;
}

delete $ENV{VAULT_TOKEN};

# A subtest that dies is a failed subtest, not the end of the file: against a
# lib without the Vault backend every subtest has to report on its own.
sub safe_subtest {
    my ($name, $code) = @_;
    subtest $name => sub {
        my $ok = eval { $code->(); 1 };
        fail('died: ' . ($@ // 'unknown')) unless $ok;
    };
}

###############################################################################
safe_subtest 'the fixture sops 3.13.3 wrote is read, MAC included' => sub {
    my $fixture = read_binary($FIXTURE);
    my ($entry) = $fixture =~ /^\s+enc: (vault:v1:\S+)$/m;
    ok($entry, 'the fixture carries a vault:v1 ciphertext');

    my $mock = MockVault->new(store => { $entry => $DATAKEY });
    my $data = File::SOPS->decrypt(
        encrypted       => $fixture,
        format          => 'yaml',
        vault_token     => $TOKEN,
        vault_transport => $mock,
    );
    is_deeply($data, { a => 'secret', b => { c => 3 } },
        'decrypts to the values sops encrypted, with the MAC verified');

    my @calls = @{ $mock->calls };
    is(scalar @calls, 1, 'one request');
    is($calls[0]{url}, 'http://127.0.0.1:18201/v1/transit/decrypt/sops-key',
        'to /v1/transit/decrypt/sops-key at the vault_address in the document');
    is($calls[0]{headers}{'X-Vault-Token'}, $TOKEN, 'carrying the X-Vault-Token');
    is_deeply(JSON::MaybeXS->new->decode($calls[0]{content}), { ciphertext => $entry },
        'and the ciphertext, nothing else, in the body');

    # not a rubber stamp: another 32-byte key from the "Vault" fails
    my $wrong = MockVault->new(store => { $entry => encode_base64('x' x 32, '') });
    ok(exception(sub {
        File::SOPS->decrypt(encrypted => $fixture, format => 'yaml',
            vault_token => $TOKEN, vault_transport => $wrong) }),
        'a different data key does not open the document');
};

###############################################################################
safe_subtest 'encrypt and decrypt through a stateful Vault' => sub {
    my ($yaml, $mock) = vault_doc(uris => [$URI, $URI2]);

    my $sops = Load($yaml)->{sops};
    is(scalar @{ $sops->{hc_vault} }, 2, 'one entry per transit key');
    is_deeply([ sort keys %{ $sops->{hc_vault}[0] } ],
        [qw(created_at enc engine_path key_name vault_address)],
        'exactly the five fields sops writes');
    my ($e1, $e2) = @{ $sops->{hc_vault} };
    like($e1->{created_at}, qr/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ\z/, 'created_at is RFC3339 UTC');
    like($e1->{enc}, qr/\Avault:v1:\S+\z/, 'enc is the Vault ciphertext');
    is($e1->{engine_path},   'transit',                'engine_path split from the URI');
    is($e1->{key_name},      'sops-key',               'key_name split from the URI');
    is($e1->{vault_address}, 'http://127.0.0.1:18201', 'vault_address is scheme+host+port');
    is($e2->{engine_path},   'kv-engine/transit',      'an engine path may span segments');
    is($e2->{key_name},      'other.key',              'its key name');
    is($e2->{vault_address}, 'https://vault.example:8200', 'its address');
    is_deeply($sops->{age}, [], 'no age entries were invented');

    my @c = @{ $mock->calls };
    is($c[0]{url}, 'http://127.0.0.1:18201/v1/transit/encrypt/sops-key', 'encrypt URL');
    my $sent = decode_base64(JSON::MaybeXS->new->decode($c[0]{content})->{plaintext});
    is(length $sent, 32, 'the request carries the 32 byte data key, base64');

    is_deeply(
        File::SOPS->decrypt(encrypted => $yaml, format => 'yaml',
            vault_token => $TOKEN, vault_transport => $mock),
        { a => 'secret', b => { c => 3 } }, 'round trip');

    # the second entry unwraps on its own
    my $got = File::SOPS::Backend::HCVault->decrypt_data_key(
        hc_vault => [$e2], token => $TOKEN, transport => $mock);
    is(length($got // ''), 32, 'either entry alone yields the 32 byte key');
};

###############################################################################
safe_subtest 'what is refused' => sub {
    my $mock = MockVault->new;
    my $enc  = sub {
        my ($uri) = @_;
        exception(sub {
            File::SOPS->encrypt(data => { k => 'v' }, hc_vault_transit_uris => [$uri],
                vault_token => $TOKEN, vault_transport => $mock) });
    };

    for my $case (
        ['no scheme',      '127.0.0.1:8200/v1/transit/keys/k'],
        ['extra segments', 'http://127.0.0.1:8200/v1/transit/keys/k/extra'],
        ['userinfo',       'http://u:pw@127.0.0.1:8200/v1/transit/keys/k'],
        ['a query',        'http://127.0.0.1:8200/v1/transit/keys/k?x=1'],
        ['not a keys URI', 'http://127.0.0.1:8200/v1/transit/encrypt/k'],
    ) {
        like($enc->($case->[1]), qr/not a Vault transit key URI/, "$case->[0] is refused");
    }
    is(scalar @{ $mock->calls }, 0, 'and no request was made for any of them');

    # a bad URI in third place must not leave the first two already sent
    my $err = exception(sub {
        File::SOPS->encrypt(data => { k => 'v' },
            hc_vault_transit_uris => [$URI, $URI2, 'nonsense'],
            vault_token => $TOKEN, vault_transport => $mock) });
    like($err, qr/not a Vault transit key URI/, 'a bad third URI is refused');
    is(scalar @{ $mock->calls }, 0, 'before the first one was sent');

    $err = exception(sub {
        File::SOPS->encrypt(data => { k => 'v' }, hc_vault_transit_uris => [$URI],
            vault_transport => $mock) });
    like($err, qr/no Vault token/, 'no token: refused');
    is(scalar @{ $mock->calls }, 0, 'before any request');

    # wrong token
    my ($yaml);
    ($yaml, $mock) = vault_doc();
    $err = exception(sub {
        File::SOPS->decrypt(encrypted => $yaml, format => 'yaml',
            vault_token => 'hvs.WRONG-wrong-9999', vault_transport => $mock) });
    like($err, qr/HTTP 403/, 'a wrong token surfaces the HTTP status');
    unlike($err // '', qr/WRONG-wrong|TOPSECRET/, 'and no token in the message');
    $err = exception(sub {
        File::SOPS->encrypt(data => { k => 'v' }, hc_vault_transit_uris => [$URI],
            vault_token => 'hvs.WRONG-wrong-9999', vault_transport => $mock) });
    like($err, qr/HTTP 403/, 'the same on the write path');
    unlike($err // '', qr/WRONG-wrong|TOPSECRET/, 'no token there either');

    # the document names the server: pinning refuses before the token leaves
    my $store = $mock->{store};
    $mock = MockVault->new(store => $store);
    $err = exception(sub {
        File::SOPS->decrypt(encrypted => $yaml, format => 'yaml',
            vault_token => $TOKEN, vault_transport => $mock,
            vault_allowed_addresses => ['http://vault.elsewhere:8200']) });
    like($err, qr/not in allowed_addresses/, 'an address outside vault_allowed_addresses is refused');
    is(scalar @{ $mock->calls }, 0, 'with no request sent');
    is_deeply(
        File::SOPS->decrypt(encrypted => $yaml, format => 'yaml',
            vault_token => $TOKEN, vault_transport => $mock,
            vault_allowed_addresses => ['http://127.0.0.1:18201']),
        { a => 'secret', b => { c => 3 } }, 'and the pinned address itself works');

    # a document that lies about its address
    for my $bad ('http://u:pw@h:1', 'http://h:1/x', 'ftp://h', 'http://h:1?q') {
        (my $evil = $yaml) =~ s{vault_address: \S+}{vault_address: "$bad"};
        my $m = MockVault->new(store => $store);
        like(exception(sub {
            File::SOPS->decrypt(encrypted => $evil, format => 'yaml',
                vault_token => $TOKEN, vault_transport => $m) }),
            qr/not acceptable/, "document address $bad is refused");
        is(scalar @{ $m->calls }, 0, '... before any request');
    }

    # plaintext length
    for my $len (31, 33, 0) {
        my $m = MockVault->new(force_plain => encode_base64('k' x $len, ''));
        my $e = exception(sub {
            File::SOPS->decrypt(encrypted => $yaml, format => 'yaml',
                vault_token => $TOKEN, vault_transport => $m) });
        like($e, qr/data key of $len bytes, expected 32/, "a $len byte plaintext is refused");
    }
    my $m = MockVault->new(force_plain => '!!notbase64!!');
    like(exception(sub {
        File::SOPS->decrypt(encrypted => $yaml, format => 'yaml',
            vault_token => $TOKEN, vault_transport => $m) }),
        qr/malformed plaintext/, 'a non-base64 plaintext is refused');

    like(exception(sub {
        File::SOPS::Backend::HCVault->decrypt_data_key(
            hc_vault => [{}], token => $TOKEN, transport => {}) }),
        qr/transport must be an object/, 'transport must be an object with post');

    like(exception(sub {
        File::SOPS::Backend::HCVault->encrypt_data_key(
            data_key => 'k' x 32, recipients => [$URI], token => "a\r\nX-Evil: 1",
            transport => MockVault->new) }),
        qr/not allowed in a header/, 'a token with control characters is refused');
};

###############################################################################
safe_subtest 'created_at is written quoted (sops refuses a bare timestamp)' => sub {
    # the emitter alone, no backend involved. Bare, Go reads it as time.Time
    # and sops says "'hc_vault[0].created_at' expected type 'string'".
    my $entry = {
        created_at    => '2026-10-25T02:57:10Z',
        enc           => 'vault:v1:AAAA',
        engine_path   => 'transit',
        key_name      => 'k',
        vault_address => 'http://h:1',
    };
    my $meta = File::SOPS::Metadata->new(hc_vault => [$entry]);
    my $out  = File::SOPS::Format::YAML->serialize(data => { a => 'x' }, metadata => $meta);
    like($out, qr/^\s+- created_at: "2026-10-25T02:57:10Z"$/m,
        'the emitter quotes the first key of an entry');

    $meta = File::SOPS::Metadata->new(
        hc_vault     => [ { %$entry, created_at => '2026-10-25T02:57:10Z' } ],
        lastmodified => '2026-10-25T02:57:10Z',
    );
    $out = File::SOPS::Format::YAML->serialize(data => { a => 'x' }, metadata => $meta);
    like($out, qr/^\s+lastmodified: "2026-10-25T02:57:10Z"$/m, 'lastmodified still quoted');

    # narrow: a created_at of the user's own is not touched
    $out = File::SOPS::Format::YAML->serialize(
        data => { created_at => 'ENC[x]' }, metadata => $meta);
    like($out, qr/^created_at: ENC\[x\]$/m, "the user's own created_at key is left alone");

    # and through the backend: the document a real encrypt writes
    my ($yaml) = vault_doc(uris => [$URI, $URI2]);
    my @lines = $yaml =~ /^\s*(?:- )?created_at: (.*)$/mg;
    is(scalar @lines, 2, 'one created_at per entry');
    like($_, qr/\A"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ"\z/, 'quoted: ' . $_) for @lines;

};

###############################################################################
safe_subtest 'rotate and edit re-wrap through Vault' => sub {
    my ($yaml, $mock) = vault_doc(uris => [$URI, $URI2]);
    my $file   = file_with($yaml);
    my $before = Load($yaml)->{sops}{hc_vault};

    is(File::SOPS->rotate(file => $file, vault_token => $TOKEN, vault_transport => $mock), 1,
        'rotate works with a token and no identities');
    my $after = Load(read_binary($file))->{sops}{hc_vault};
    is(scalar @$after, 2, 'both entries are still there');
    for my $i (0, 1) {
        isnt($after->[$i]{enc}, $before->[$i]{enc}, "entry $i wraps the new data key");
        is($after->[$i]{$_}, $before->[$i]{$_}, "entry $i keeps $_")
            for qw(vault_address engine_path key_name);
    }
    is_deeply(File::SOPS->decrypt(encrypted => read_binary($file), format => 'yaml',
        vault_token => $TOKEN, vault_transport => $mock),
        { a => 'secret', b => { c => 3 } }, 'and the rotated file opens');
    like(read_binary($file), qr/created_at: "/, 'with created_at quoted');

    # edit
    my $seen = "$dir/editor-ran-" . ++$serial;
    my $ed   = "$dir/editor-$serial.pl";
    write_binary($ed,
        qq{open my \$o, '>', '$seen'; close \$o;\n}
        . qq{open my \$f, '>', \$ARGV[-1] or die; print \$f "a: edited\\nb:\\n  c: 4\\n"; close \$f;\n});
    my $pre = Load(read_binary($file))->{sops}{hc_vault};
    is(File::SOPS->edit(file => $file, editor => [ $^X, $ed ],
        vault_token => $TOKEN, vault_transport => $mock), 1, 'edit works with a token only');
    my $post = Load(read_binary($file))->{sops}{hc_vault};
    isnt($post->[0]{enc}, $pre->[0]{enc}, 'edit wraps a new data key');
    is($post->[1]{vault_address}, $pre->[1]{vault_address}, 'for the same targets');
    is_deeply(File::SOPS->decrypt(encrypted => read_binary($file), format => 'yaml',
        vault_token => $TOKEN, vault_transport => $mock),
        { a => 'edited', b => { c => 4 } }, 'and the edit is in it');

    # no token: nothing is written, nothing is sent, the editor never starts
    unlink $seen;
    my $bytes  = read_binary($file);
    my $silent = MockVault->new;
    for my $op (
        [ rotate => sub { File::SOPS->rotate(file => $file, identities => ['AGE-SECRET-KEY-1X'],
            vault_transport => $silent) } ],
        [ edit => sub { File::SOPS->edit(file => $file, identities => ['AGE-SECRET-KEY-1X'],
            editor => [ $^X, $ed ], vault_transport => $silent) } ],
    ) {
        my $err = exception($op->[1]);
        like($err, qr/Refusing to \Q$op->[0]\E.*no token/s, "$op->[0] without a token croaks");
        is(read_binary($file), $bytes, '... and writes nothing');
    }
    ok(!-e $seen, 'the editor was never started');
    is(scalar @{ $silent->calls }, 0, 'and no request was sent');

    # pinning applies to the rebuilt targets: refused before anything is sent
    my $m2  = MockVault->new(store => $mock->{store});
    my $err = exception(sub {
        File::SOPS->rotate(file => $file, vault_token => $TOKEN, vault_transport => $m2,
            vault_allowed_addresses => ['http://127.0.0.1:18201']) });
    like($err, qr/not in\s+vault_allowed_addresses/, 'rotate pins the rebuilt targets too');
    is(read_binary($file), $bytes, '... and leaves the file alone');
};

###############################################################################
safe_subtest '_assert_rekeyable lets hc_vault through and still refuses the rest' => sub {
    my $vault = [ {
        created_at    => '2026-10-25T02:57:10Z',
        enc           => 'vault:v1:AAAA',
        engine_path   => 'transit',
        key_name      => 'k',
        vault_address => 'http://h:1',
    } ];
    my $check = sub {
        File::SOPS::_assert_rekeyable(File::SOPS::Metadata->from_hash($_[0]),
            'f.yaml', verb => 'rotate', noun => 'Rotation');
    };

    ok($check->({ hc_vault => $vault, age => [] }), 'hc_vault alone is rekeyable');
    ok($check->({ hc_vault => $vault, age => [ { recipient => 'age1x', enc => 'e' } ] }),
        'hc_vault with age is rekeyable');

    my %foreign = (
        pgp        => [ { fp  => 'ABCD', enc => 'e' } ],
        kms        => [ { arn => 'arn:aws:kms:us-east-1:0:key/0', enc => 'e' } ],
        gcp_kms    => [ { resource_id => 'projects/p', enc => 'e' } ],
        azure_kv   => [ { vault_url => 'https://x', name => 'n', version => 'v', enc => 'e' } ],
        key_groups => [ [ { enc => 'e' } ] ],
    );
    for my $f (sort keys %foreign) {
        for my $mix (0, 1) {
            my $err = exception(sub {
                $check->({ $f => $foreign{$f}, ($mix ? (hc_vault => $vault) : ()) }) });
            like($err, qr/Refusing to rotate 'f\.yaml'.*\b\Q$f\E\b/s,
                "$f is refused" . ($mix ? ', also next to hc_vault' : ''));
            unlike($err // '', qr/\([^)]*hc_vault[^)]*\)/, 'and the list does not blame hc_vault')
                if $mix;
        }
    }

    # end to end: a real Vault document that also carries foreign key material
    for my $f (qw(pgp kms gcp_kms azure_kv)) {
        my ($yaml, $mock) = vault_doc();
        my $doc = Load($yaml);
        $doc->{sops}{$f} = $foreign{$f};
        # Dump drops the quotes sops writes on the timestamps; put them back
        # (see t/15-rotate.t), the document is ours so the order is safe.
        (my $re = Dump($doc)) =~ s/^(\s+(?:- )?(?:lastmodified|created_at): )(\S+)$/$1"$2"/mg;
        my $file  = file_with($re);
        my $bytes = read_binary($file);
        my $calls = scalar @{ $mock->calls };
        like(exception(sub {
            File::SOPS->rotate(file => $file, vault_token => $TOKEN, vault_transport => $mock) }),
            qr/\b\Q$f\E\b/, "rotate of vault + $f is refused");
        like(exception(sub {
            File::SOPS->edit(file => $file, editor => [ $^X, '-e', '1' ],
                vault_token => $TOKEN, vault_transport => $mock) }),
            qr/\b\Q$f\E\b/, "edit of vault + $f is refused");
        is(read_binary($file), $bytes, '... file untouched');
        is(scalar @{ $mock->calls }, $calls, '... and nothing was sent');
    }
};

###############################################################################
safe_subtest 'creation_rules_for hands out hc_vault_transit_uris' => sub {
    my ($pub) = Crypt::Age->generate_keypair();
    my $tree  = sub {
        my ($rule) = @_;
        my $root = "$dir/rules-" . ++$serial;
        make_path($root);
        write_binary("$root/.sops.yaml", "creation_rules:\n  - $rule\n");
        write_binary("$root/s.yaml", "k: v\n");
        return "$root/s.yaml";
    };
    my %got;

    %got = File::SOPS->creation_rules_for(
        file => $tree->("hc_vault_transit_uri: '$URI, $URI2'"));
    is_deeply($got{hc_vault_transit_uris}, [ $URI, $URI2 ], 'a comma-separated string is split');
    ok(!exists $got{recipients}, 'and, with only Vault, no recipients are invented');

    %got = File::SOPS->creation_rules_for(
        file => $tree->("hc_vault_transit_uri:\n      - $URI\n      - $URI2"));
    is_deeply($got{hc_vault_transit_uris}, [ $URI, $URI2 ], 'a YAML list is taken as is');

    %got = File::SOPS->creation_rules_for(
        file => $tree->("age: $pub\n    hc_vault_transit_uri: $URI"));
    is_deeply($got{recipients}, [$pub], 'age and Vault together: the age recipient');
    is_deeply($got{hc_vault_transit_uris}, [$URI], 'and the transit key');

    # the splat reaches encrypt and wraps through Vault
    my $yaml = File::SOPS->encrypt(data => { k => 'v' }, %got,
        vault_token => $TOKEN, vault_transport => MockVault->new);
    my $sops = Load($yaml)->{sops};
    is(scalar @{ $sops->{age} },      1, 'the splat yields an age entry');
    is(scalar @{ $sops->{hc_vault} }, 1, 'and a hc_vault entry');

    %got = File::SOPS->creation_rules_for(file => $tree->("age: $pub"));
    ok(!exists $got{hc_vault_transit_uris}, 'a rule without Vault returns no hc_vault_transit_uris');

    my %fields = (
        pgp              => '0000000000000000000000000000000000000000',
        kms              => 'arn:aws:kms:us-east-1:0:key/0',
        gcp_kms          => 'projects/p/locations/l/keyRings/r/cryptoKeys/k',
        azure_keyvault   => 'https://example.vault.azure.net/keys/k/v',
        shamir_threshold => '2',
    );
    for my $name (sort keys %fields) {
        for my $with ("age: $pub", "hc_vault_transit_uri: $URI") {
            my $err = exception(sub {
                File::SOPS->creation_rules_for(
                    file => $tree->("$with\n    $name: '$fields{$name}'")) });
            like($err, qr/Refusing to encrypt under creation rule 1.*\b\Q$name\E\b/s,
                "$name is refused next to " . ($with =~ /^age/ ? 'age' : 'hc_vault_transit_uri'));
        }
    }
    like(exception(sub {
        File::SOPS->creation_rules_for(file => $tree->(
            "hc_vault_transit_uri: $URI\n    key_groups:\n      - age:\n          - $pub")) }),
        qr/key_groups/, 'key_groups next to hc_vault_transit_uri is refused');
};

###############################################################################
# sops itself reading a Perl-written sops section. Vault is not needed to learn
# something: sops decodes the whole `sops:` mapping BEFORE it talks to any
# Vault, so a section it dislikes (a bare created_at) is a decode error and a
# section it likes is a connection error against an address nothing listens on.
safe_subtest 'the real sops parses our hc_vault section' => sub {
    my $sops_bin = find_sops_bin();
    plan skip_all => 'no sops binary (SOPS_BIN, PATH, .sops-bin/sops, /tmp/sops): '
        . 'the Perl-written direction is NOT checked against sops in this run'
        unless $sops_bin;

    my ($yaml) = vault_doc(uris => ['http://127.0.0.1:1/v1/transit/keys/sops-key']);
    my $f   = file_with($yaml);
    my $out = `VAULT_TOKEN=x $sops_bin decrypt $f 2>&1`;
    isnt($?, 0, 'sops cannot decrypt (nothing listens on the address)');
    unlike($out, qr/expected type|cannot unmarshal|decoding failed|unmarshal/i,
        'no decode error for hc_vault[0].created_at') or diag($out);
    like($out, qr/127\.0\.0\.1|connection refused|dial tcp|vault/i,
        'it got as far as reaching for the Vault') or diag($out);

    # control: with created_at bare the same file must be a decode error, or
    # the check above could not fail
    (my $bare = $yaml) =~ s/(created_at: )"([^"]+)"/$1$2/;
    my $fb = file_with($bare);
    $out = `VAULT_TOKEN=x $sops_bin decrypt $fb 2>&1`;
    like($out, qr/expected type|decoding|unmarshal/i,
        'control: a bare created_at IS a decode error in this sops') or diag($out);
};

done_testing;
