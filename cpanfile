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
requires 'Carp';
requires 'Digest::SHA';
requires 'MIME::Base64';
requires 'POSIX';
requires 'Scalar::Util';

on test => sub {
    requires 'Test::More';
    requires 'File::Slurp';
    requires 'File::Temp';
};
