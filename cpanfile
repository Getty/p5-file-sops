requires 'perl', '5.010';

requires 'Crypt::Age', '0.001';
requires 'CryptX';
requires 'YAML::XS';
# Only used to recover document key order for MAC verification; YAML::XS stays
# the parser and emitter. See the MAC section of File::SOPS.
requires 'YAML::PP';
requires 'JSON::MaybeXS';
requires 'Moo';
requires 'namespace::clean';

# Core, but declared explicitly because this distribution has no AutoPrereqs
# B is used to read a scalar's IOK/NOK flags, which is how a value's SOPS type
# is determined -- see File::SOPS::Encrypted::detect_type and docs/adr/0002.
requires 'B';
requires 'Carp';
requires 'Cwd';
requires 'Digest::SHA';
requires 'Fcntl';
requires 'File::Basename';
requires 'File::Spec';
# In-place writes go to a temporary file next to the target and are renamed
# over it, and File::SOPS::edit puts the decrypted document in a temporary
# directory of its own -- see the edit method.
requires 'File::Temp';
requires 'MIME::Base64';
requires 'POSIX';
requires 'Scalar::Util';
# $EDITOR is split into words the way a shell would, as sops splits it too.
requires 'Text::ParseWords';

on test => sub {
    requires 'Test::More';
    requires 'File::Slurp';
    requires 'File::Temp';
    # t/22-creation-rules.t builds .sops.yaml fixture trees several levels deep.
    requires 'File::Path';
};
